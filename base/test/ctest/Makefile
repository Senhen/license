CC = clang++
CFLAGS = -std=c++17 -I /opt/homebrew/Cellar/openssl@1.1/1.1.1w/include
LDFLAGS = -L /opt/homebrew/Cellar/openssl@1.1/1.1.1w/lib -lssl -lcrypto

all: license_sign

license_sign: license_sign.o
	$(CC) $(LDFLAGS) -o $@ $<

license_sign.o: /Users/zxz/Downloads/license/base/test/ctest/license_sign.cpp
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f license_sign license_sign.o