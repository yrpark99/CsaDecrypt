ifeq ($(OS),Windows_NT)
	EXT = .exe
endif

CC = gcc
STRIP = strip
RM = rm -f

TARGET = CsaDecrypt$(EXT)
SRCS = ./src/CsaDecrypt.c

CFLAGS = -O2 -Wall -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -Iinclude

ifeq ($(OS),Windows_NT)
LDFLAGS := -Llib/Windows
else
LDFLAGS := -Llib/Linux
endif
LDFLAGS += -ldvbcsa

all:
	@$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)
	@$(STRIP) $(TARGET)

clean:
	@$(RM) $(TARGET)
