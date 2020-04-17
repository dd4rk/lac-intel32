# This Makefile can be used with GNU Make or BSD Make

HEADERS = aes.h api.h bch-light.h bch.h bch128.h bch192.h bch256.h bin-lwe.h ecc.h lac_param.h pke.h rand.h randombytes.h sha2.h test.h
OBJECTS = aes.o bch.o bin-lwe.o ecc.o kem.o pke.o rand.o randombytes.o sha2.o test.o

CFLAGS = -O3 -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -std=c99

all: lac

lac : $(OBJECTS)
	$(CC) -o $@ $^

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) $(OBJECTS)
	$(RM) lac
