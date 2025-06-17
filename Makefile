CFLAGS= -Wall -Wextra -02
LDFLAGS= -Iinclude -lssl -lcrypto
TARGET= file
SRC= crypt/crypt.c cmd/ramsonware/ramsonware.c cmd/banner.c utils/utils.c

OPENSSL_INCLUDE = -IC:/OpenSSL-Win64/include
OPENSSL_LIB = -LC:/OpenSSL-Win64/lib

ifeq ($(OS),Windows_NT)
    TARGET := ramsonware.exe
    LDLIBS = -lssl -lcrypto -lws2_32
else
    LDLIBS = -lssl -lcrypto
endif

all: $(TARGET)

$(TARGET): $(SRC)
	gcc -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -fr output.bin
	rm -fr file
	rm -fr tmp