CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
           -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?=
CRYPTO_LIBS = -lcrypto

all: sender receiver device

sender: sender.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ sender.c

receiver: receiver.c common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ receiver.c

device: device.c crypto.c crypto.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ device.c crypto.c $(CRYPTO_LIBS)

clean:
	rm -f sender receiver device selftest

.PHONY: all clean

selftest: selftest.c crypto.c crypto.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ selftest.c crypto.c $(CRYPTO_LIBS)

test: selftest
	./selftest
