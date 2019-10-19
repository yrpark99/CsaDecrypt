/**
 * 목적: 입력 MPEG2 TS 파일을 입력 파일 정보로 CSAv2 decrypt 하여 출력 파일을 생성한다.
 * 참고: CSA 구현은 공개 소스인 libdvbcsa를 static library로 빌드하여 링크하였다.
 *       ES PID 값과 (odd/even) CW는 입력 인자로 받는 아래의 포맷을 갖는 입력 파일에서 파싱하도록 하였다.
 *       PID: PID1 PID2 ...
 *       EVEN_CW: 00 11 22 33 44 55 66 77, ODD_CW: 88 99 AA BB CC DD EE FF
 * CW 파일 예제
 *       # PID value can be decimal or hex(start with 0x)
 *       # CW values should be hex
 *       PID: 0x64 0xC8
 *       ODD_CW: 68 87 28 17 59 b1 5b 65, EVEN_CW: 56 94 61 4b 4d 9a 29 10
 *       ODD_CW: 68 87 28 17 59 b1 5b 65, EVEN_CW: ae c5 63 d6 d3 46 8f a8
 *       ODD_CW: 75 e9 6b c9 21 4c 22 8f, EVEN_CW: ae c5 63 d6 d3 46 8f a8
 *       ODD_CW: 75 e9 6b c9 21 4c 22 8f, EVEN_CW: 62 c0 01 23 4d 9d 6c 56
 *       ODD_CW: 4e bb 84 8d 17 da 33 24, EVEN_CW: 62 c0 01 23 4d 9d 6c 56
 *       ODD_CW: 4e bb 84 8d 17 da 33 24, EVEN_CW: 0c 16 5a 7c b4 09 9b 58
 *       ODD_CW: c3 b2 4b c0 45 db 65 85, EVEN_CW: 0c 16 5a 7c b4 09 9b 58
 *       ODD_CW: c3 b2 4b c0 45 db 65 85, EVEN_CW: f1 9e 5b ea e2 1f 29 2a
 *       ODD_CW: 4b d7 35 57 69 f0 af 08, EVEN_CW: f1 9e 5b ea e2 1f 29 2a
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dvbcsa.h"

#ifndef MAX_PATH
#define	MAX_PATH	(260)
#endif

#define TS_PACKET_LEN			188			// TS packet의 길이 (바이트 단위)
#define TS_SYNC_BYTE			0x47		// TS packet의 sync byte 값

#define CW_LEN					8			// CW 의 길이
#define MAX_PID_NUM				10			// CSA decrypt 할 target PID 최대 개수
#define MAX_CW_NUM				100			// CW 최대 개수
#define MAX_ARGV_NUM			110			// 파일 argv 최대 개수

/* 입력 문자열을 10진수로 간주할지, 16진수로 간주할지, 또는 자동으로 판단할지를 나타냄 */
typedef enum
{
	DETECT_MODE,
	HEX_MODE,
	DEC_MODE
} STR_PARSE_MODE_E;

/* CSA CW 구조체 */
typedef struct
{
	unsigned char cw[CW_LEN];
} csa_cw_t;

unsigned int target_PID[MAX_PID_NUM];				// PID 값 (A/V PID 등)
int target_pid_num = 0;								// target_PID[]의 유효 개수
csa_cw_t even_cw[MAX_CW_NUM], odd_cw[MAX_CW_NUM];	// even CW, odd CW
unsigned int even_cw_num = 0;						// even CW 유효 개수
unsigned int odd_cw_num = 0;						// odd CW 유효 개수

/**
 * 기능: 사용법을 출력한다.
 * 입력: exec_file_name = 실행 파일의 이름
 */
void show_usage(char *exec_file_name)
{
	char exec_name[MAX_PATH];
	char *p;

	/* 실행 파일 이름에 exe 확장자가 있으면 제거하여 exec_name[]에 넣는다. */
	strncpy(exec_name, exec_file_name, sizeof(exec_name) - 1);
	p = strstr(exec_name, ".exe");
	if (p != NULL)
	{
		*p = 0;
	}

	printf("Function: DVB CSAv2 decrypt with ControlWord information\n");
	printf("Usage: %s <TS_file> <CW_file>\n", exec_name);
	printf("Note: <CW_file> should have correct format as like below example\n");
	printf("      PID: 0x64 0xC8\n");
	printf("      ODD_CW: 68 87 28 17 59 b1 5b 65, EVEN_CW: 56 94 61 4b 4d 9a 29 10\n");
	printf("      ODD_CW: 68 87 28 17 59 b1 5b 65, EVEN_CW: ae c5 63 d6 d3 46 8f a8\n");
}

/**
 * 기능: 입력 문자열을 숫자로 변환하여 리턴한다.
 * 입력: str = 숫자를 나타내는 문자열 (단, "0x"로 시작하면 16진수로 간주함)
 *       mode = 16진수, 10진수 간주 모드
 * 리턴: 변환된 숫자
 */
unsigned int get_value_from_str(char *str, STR_PARSE_MODE_E mode)
{
	unsigned int value;

	if (str == NULL)
	{
		return 0;
	}

	switch (mode)
	{
	case DETECT_MODE:
		if (strstr(str, "0x") != NULL)			// "0x"로 시작하면 "0x" 건너뛰고 16진수로 얻음
		{
			value = strtoul(str + 2, NULL, 16);
		}
		else									// 아니면 10진수로 얻음
		{
			value = strtoul(str, NULL, 10);
		}
		break;

	case HEX_MODE:
		if (strstr(str, "0x") != NULL)			// "0x"로 시작하면 "0x" 건너뛰고 16진수로 얻음
		{
			value = strtoul(str + 2, NULL, 16);
		}
		else
		{
			value = strtoul(str, NULL, 16);
		}
		break;

	case DEC_MODE:
		value = strtoul(str, NULL, 10);
		break;

	default:
		return 0;
	}

	return value;
}

/**
 * 기능: 입력 문자열을 파싱하여 PID, CW 값을 얻는다.
 * 입력: str = 입력 문자열
 */
void get_pid_cw_from_str(char *str)
{
	char *dup_str = strdup(str);
	char *argv[MAX_ARGV_NUM];
	int argc = 0;
	int i;

	/* 입력 문자열을 tab, space, ',', ':' 으로 tokenize 하여 argc/argv를 얻는다. */
	argv[argc] = strtok(str, "\t ,:");
	while (argv[argc] != NULL)
	{
		if (argc++ >= MAX_ARGV_NUM)
		{
			break;
		}
		argv[argc] = strtok(NULL, "\t ,:");
	}
	if (argc <= 0)
	{
		return;
	}

	/* 시작 문자열에 따라 파싱한다. */
	if (strcmp(argv[0], "PID") == 0)
	{
		/* "PID" 문자열로 시작하면 이후 값을 읽어서 PID 값으로 얻는다. */
		for (i = 1; i < argc; i++)
		{
			target_PID[target_pid_num] = get_value_from_str(argv[i], DETECT_MODE);
			target_pid_num += 1;
		}
	}
	else if (strcmp(argv[0], "EVEN_CW") == 0)
	{
		if (argc < 9)
		{
			printf("Wrong line: %s", dup_str);
			return;
		}

		/* "EVEN_CW" 문자열로 시작하면 이후 값을 읽어서 even CW 값으로 얻는다. */
		for (i = 1; i <= CW_LEN; i++)
		{
			even_cw[even_cw_num].cw[i - 1] = get_value_from_str(argv[i], HEX_MODE);
		}
		even_cw_num += 1;

		if (argc >= 18 && strcmp(argv[9], "ODD_CW") == 0)
		{
			/* 이후에 "ODD_CW" 문자열이 있으면 이후 값을 읽어서 odd CW 값으로 얻는다. */
			for (i = 10; i < 10 + CW_LEN; i++)
			{
				odd_cw[odd_cw_num].cw[i - 10] = get_value_from_str(argv[i], HEX_MODE);
			}
			odd_cw_num += 1;
		}
	}
	else if (strcmp(argv[0], "ODD_CW") == 0)
	{
		if (argc < 9)
		{
			printf("Wrong line: %s", dup_str);
			return;
		}

		/* "ODD_CW" 문자열로 시작하면 이후 값을 읽어서 odd CW 값으로 얻는다. */
		for (i = 1; i <= CW_LEN; i++)
		{
			odd_cw[odd_cw_num].cw[i - 1] = get_value_from_str(argv[i], HEX_MODE);
		}
		odd_cw_num += 1;

		if (argc >= 18 && strcmp(argv[9], "EVEN_CW") == 0)
		{
			/* 이후에 "EVEN_CW" 문자열이 있으면 이후 값을 읽어서 even CW 값으로 얻는다. */
			for (i = 10; i < 10 + CW_LEN; i++)
			{
				even_cw[even_cw_num].cw[i - 10] = get_value_from_str(argv[i], HEX_MODE);
			}
			even_cw_num += 1;
		}
	}
}

int main(int argc, char *argv[])
{
	FILE *fd_in_ts, *fd_in_cw, *fd_out_ts;
	struct stat st;
	struct dvbcsa_key_s *key;
	size_t read_len, write_len, total_read_len = 0;
	char in_ts_file[MAX_PATH], in_cw_file[MAX_PATH], out_ts_file[MAX_PATH];
	unsigned char ts_packet[TS_PACKET_LEN], out_buf[TS_PACKET_LEN];
	unsigned char transport_scrambling_control, adaptation_field_control, adaptation_field_length;
	unsigned char transport_error_indicator;
	//unsigned char payload_unit_start_indicator;
	unsigned char prev_transport_scrambling_control = -1;
	unsigned int payload_start_offset = 0, payload_len = 0;
	unsigned int curPID;
	unsigned int cw_index = 0;
	unsigned char even_CW[CW_LEN], odd_CW[CW_LEN];
	char line_buf[256];
	int percent_prev = -1, percent_cur;
	int i, j;

	/* 아규먼트가 부족한 경우에는 사용법을 출력한다. */
	if (argc < 3)
	{
		show_usage(argv[0]);
		return -1;
	}

	/* 입력 파일의 이름을 저장한다. */
	strcpy(in_ts_file, argv[1]);
	strcpy(in_cw_file, argv[2]);
	printf("Input TS file: %s\n", in_ts_file);
	printf("Input CW file: %s\n", in_cw_file);

	/* 출력 파일의 이름을 세팅한다. (입력 파일 이름에 ".dec.ts"를 붙임) */
	snprintf(out_ts_file, sizeof(out_ts_file), "%s.dec.ts", in_ts_file);
	printf("Output TS file: %s\n", out_ts_file);

	/* 입력 TS 파일을 open 한다. */
	fd_in_ts = fopen(in_ts_file, "rb");
	if (fd_in_ts == NULL)
	{
		printf(" Fail to read TS input file. %s is not exist\n", in_ts_file);
		return -1;
	}

	/* 입력 CW 파일을 open 한다. */
	fd_in_cw = fopen(in_cw_file, "rb");
	if (fd_in_cw == NULL)
	{
		printf(" Fail to read CW input file. %s is not exist\n", in_cw_file);
		fclose(fd_in_ts);
		return -1;
	}

	/* 입력 TS 파일의 크기를 얻어서 출력한다. */
	stat(in_ts_file, &st);
#ifdef __MINGW64__
	printf("\nInput file size: %I64u (%I64u KiB, %I64u MiB)\n", st.st_size, st.st_size/1024, st.st_size/(1024*1024));
#else
	printf("\nInput file size: %ld(%ld KiB, %ld MiB)\n", st.st_size, st.st_size/1024, st.st_size/(1024*1024));
#endif

	/* CW 파일을 줄 단위로 파싱한다. */
	for (;;)
	{
		/* CW 파일에서 다음 한 줄을 읽어 들인다. */
		if (fgets(line_buf, sizeof(line_buf), fd_in_cw) == NULL)
		{
			break;
		}

		/* '#'으로 시작하면 해당 줄은 코멘트로 인식하여 처리하지 않는다. */
		if (line_buf[0] == '#')
		{
			continue;
		}
		if (strlen(line_buf) < 3)
		{
			continue;
		}

		/* 파싱하여 PID 값을 얻는다. */
		get_pid_cw_from_str(line_buf);
	}

	/* CW 파일에서 올바른 정보를 얻지 못한 경우에는 에러로 처리한다. */
	if (target_pid_num == 0)
	{
		printf("Fail to get PID value from input CW file\n");
		fclose(fd_in_ts);
		fclose(fd_in_cw);
		return -1;
	}

	/* 파일에서 파싱하여 얻은 PID 정보를 출력한다. */
	printf("Target PID number: %d\n", target_pid_num);
	for (i = 0; i < target_pid_num; i++)
	{
		printf(" target_PID[i]: 0x%X\n", target_PID[i]);
	}

	/* 파일에서 파싱하여 얻은 odd CW 정보를 출력한다. */
	printf("\nOdd CW number: %d\n", odd_cw_num);
	for (i = 0; i < odd_cw_num; i++)
	{
		printf(" odd_cw[%d]: ", i);
		for (j = 0; j < CW_LEN; j++)
		{
			printf("%02X ", odd_cw[i].cw[j]);
		}
		printf("\n");
	}

	/* 파일에서 파싱하여 얻은 even CW 정보를 출력한다. */
	printf("\nEven CW number: %d\n", even_cw_num);
	for (i = 0; i < even_cw_num; i++)
	{
		printf(" even_cw[%d]: ", i);
		for (j = 0; j < CW_LEN; j++)
		{
			printf("%02X ", even_cw[i].cw[j]);
		}
		printf("\n");
	}

	/* 출력 파일을 생성한다. */
	fd_out_ts = fopen(out_ts_file, "wb");
	if (fd_out_ts == NULL)
	{
		printf(" Fail to create fail '%s'. error=%s\n", out_ts_file, strerror(errno));
		fclose(fd_in_ts);
		fclose(fd_in_cw);
		return -1;
	}

	/* CSA key 메모리를 할당한다. */
	key = dvbcsa_key_alloc();
	if (key == NULL)
	{
		printf("Fail to allocate DVB CSA Key\n");
		fclose(fd_in_ts);
		fclose(fd_in_cw);
		fclose(fd_out_ts);
		return -1;
	}

	/* 입력 파일을 TS packet 단위로 읽어서 처리한다. */
	for (;;)
	{
		/* 1 TS packet을 읽는다. (TS packet 보다 작으면 for 문 빠져 나감) */
		read_len = fread(ts_packet, 1, TS_PACKET_LEN, fd_in_ts);
		if (read_len != TS_PACKET_LEN)
		{
			break;
		}
		if (ts_packet[0] != TS_SYNC_BYTE)
		{
			printf("\nWrong TS file. Not start with TS sync byte.\n");
			break;
		}
		total_read_len += read_len;

		/* transport_error_indicator 값을 얻는다. */
		transport_error_indicator = (ts_packet[1] >> 7) & 1;

		/* payload_unit_start_indicator 값을 얻는다. */
		//payload_unit_start_indicator = (ts_packet[1] >> 6) & 1;

		/* transport_error_indicator 값이 1 이면 packet 내용을 output 파일에 그대로 write 한다. */
		if (transport_error_indicator == 1)
		{
			write_len = fwrite(ts_packet, 1, TS_PACKET_LEN, fd_out_ts);
			if (write_len != TS_PACKET_LEN)
			{
				printf("\nFail to write output file\n");
				break;
			}
			continue;
		}

		/* 현재 packet의 PID를 얻는다. */
		curPID = ((unsigned short)(ts_packet[1] << 8) | ts_packet[2]) & 0x1FFF;

		/* 현재 PID 가 PID[]에 속하는지 찾는다. */
		for (i = 0; i < target_pid_num; i++)
		{
			if (curPID == target_PID[i])
			{
				break;
			}
		}

		/* 현재 PID가 target_PID[]에 속하지 않으면 packet 내용을 output 파일에 그대로 write 한다. */
		if (i >= target_pid_num)
		{
			write_len = fwrite(ts_packet, 1, TS_PACKET_LEN, fd_out_ts);
			if (write_len != TS_PACKET_LEN)
			{
				printf("\nFail to write output file\n");
				break;
			}
			continue;
		}

		/* 현재 packet의 transport_scrambling_control, adaptation_field_control 값을 얻는다. */
		transport_scrambling_control = (ts_packet[3] >> 6) & 0x03;
		adaptation_field_control = (ts_packet[3] >> 4) & 0x03;

		if (transport_scrambling_control == 0)		// not scrambled 이면 packet 내용을 output 파일에 그대로 write 한다.
		{
			write_len = fwrite(ts_packet, 1, TS_PACKET_LEN, fd_out_ts);
			if (write_len != TS_PACKET_LEN)
			{
				printf("\nFail to write output file\n");
				break;
			}
			continue;
		}

		// adaptation_field_control = 0: Reserved for future use by ISO/IEC
		// adaptation_field_control = 2: adaptation_field만 있고 payload는 없는 경우 (packet 내용을 output 파일에 그대로 write)
		if (adaptation_field_control == 0 || adaptation_field_control == 2)
		{
			write_len = fwrite(ts_packet, 1, TS_PACKET_LEN, fd_out_ts);
			if (write_len != TS_PACKET_LEN)
			{
				printf("\nFail to write output file\n");
				break;
			}
			continue;
		}
		else if (adaptation_field_control == 1)		// adaptation_field는 존재하지 않고 payload만 존재하는 경우
		{
			payload_start_offset = 4;
			payload_len = TS_PACKET_LEN - payload_start_offset;
		}
		else if (adaptation_field_control == 3)		// adaptation_field가 존재하고 payload도 존재하는 경우 (Adaptation_field은 decrypt 대상에서 제외 시킴)
		{
			adaptation_field_length = ts_packet[4];
			payload_start_offset = 4 + 1 + adaptation_field_length;
			payload_len = TS_PACKET_LEN - payload_start_offset;
		}

		/* Decrypt 할 데이터를 out_buf[]에 복사한다. */
		memcpy(out_buf, ts_packet + payload_start_offset, payload_len);

		/* transport_scrambling_control 값이 변경될 때 마다 (odd -> even -> odd) CW 값을 다음 CW 값으로 세팅한다. */
		if (transport_scrambling_control != prev_transport_scrambling_control)
		{
			if (transport_scrambling_control == 2)
			{
				printf("\nEven CW start.    ");
			}
			else if (transport_scrambling_control == 3)
			{
				printf("\n Odd CW start.    ");
			}
			if (cw_index < odd_cw_num)
			{
				memcpy(odd_CW, odd_cw[cw_index].cw, CW_LEN);
			}
			if (cw_index < even_cw_num)
			{
				memcpy(even_CW, even_cw[cw_index].cw, CW_LEN);
			}
			cw_index += 1;
		}
		prev_transport_scrambling_control = transport_scrambling_control;

		/* transport_scrambling_control 값에 따라 odd/even CW를 세팅한다. */
		if (transport_scrambling_control == 1)		// odd scrambled
		{
			dvbcsa_key_set(odd_CW, key);
		}
		else if (transport_scrambling_control == 2)	// even scrambled
		{
			dvbcsa_key_set(even_CW, key);
		}
		else if (transport_scrambling_control == 3)	// odd scrambled
		{
			dvbcsa_key_set(odd_CW, key);
		}

		/* 이 packet을 DVB CSA decrypt 한다. (입출력 버퍼는 모두 out_buf[]) */
		dvbcsa_decrypt(key, out_buf, payload_len);

		/* Decrypt 한 데이터를 ts_packet[]으로 복사한다. */
		memcpy(ts_packet + payload_start_offset, out_buf, payload_len);

		/* Decrypt 했으므로 transport_scrambling_control 값은 0 으로 clear 시킨다. */
		ts_packet[3] &= 0x3F;

		/* ts_packet[] 내용을 output 파일에 쓴다. */
		write_len = fwrite(ts_packet, 1, TS_PACKET_LEN, fd_out_ts);
		if (write_len != TS_PACKET_LEN)
		{
			printf("\nFail to write output file\n");
			break;
		}

		/* 진행도를 표시한다. */
		percent_cur = total_read_len * 100.0 / st.st_size;
		if (percent_cur != percent_prev)
		{
			printf("\b\b\b");
			printf("%2d%%", percent_cur);
			percent_prev = percent_cur;
		}
	}
	printf(" Done\n");

	/* 입출력 파일을 close 한다. */
	fclose(fd_in_ts);
	fclose(fd_in_cw);
	fclose(fd_out_ts);

	/* CSA key 메모리를 해제한다. */
	dvbcsa_key_free(key);

	return 0;
}
