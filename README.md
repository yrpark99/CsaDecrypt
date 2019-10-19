# CsaDecrypt

Using [libdvbcsa](https://github.com/glenvt18/libdvbcsa/blob/master/INSTALL), this Windows console tool decrypt input DVB CSAv2 transport stream file.

## CW file example
```
# PID value can be decimal or hex(start with 0x)
# CW values should be hex
PID: 0x64 0xC8
ODD_CW: 68 87 28 17 59 b1 5b 65, EVEN_CW: 56 94 61 4b 4d 9a 29 10
ODD_CW: 68 87 28 17 59 b1 5b 65, EVEN_CW: ae c5 63 d6 d3 46 8f a8
ODD_CW: 75 e9 6b c9 21 4c 22 8f, EVEN_CW: ae c5 63 d6 d3 46 8f a8
ODD_CW: 75 e9 6b c9 21 4c 22 8f, EVEN_CW: 62 c0 01 23 4d 9d 6c 56
ODD_CW: 4e bb 84 8d 17 da 33 24, EVEN_CW: 62 c0 01 23 4d 9d 6c 56
ODD_CW: 4e bb 84 8d 17 da 33 24, EVEN_CW: 0c 16 5a 7c b4 09 9b 58
ODD_CW: c3 b2 4b c0 45 db 65 85, EVEN_CW: 0c 16 5a 7c b4 09 9b 58
ODD_CW: c3 b2 4b c0 45 db 65 85, EVEN_CW: f1 9e 5b ea e2 1f 29 2a
ODD_CW: 4b d7 35 57 69 f0 af 08, EVEN_CW: f1 9e 5b ea e2 1f 29 2a
```

## Execution example
```
$ CsaDecrypt test1.ts test1.cw
D:\>CsaDecrypt test1.ts test1.cw
```
