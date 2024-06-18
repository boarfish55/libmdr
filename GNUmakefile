CC := cc
CFLAGS := -Wall -g -fstack-protector-strong \
	$(shell pkg-config --cflags libbsd-overlay libssl libcrypto)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay libssl libcrypto) \
	-Wl,-z,relro -Wl,-z,now

all: mdrc mdr_tests

mdr.o: mdr.c mdr.h
	$(CC) $(CFLAGS) -c mdr.c -o mdr.o

mdr_tests: mdr.o mdr_tests.c
	$(CC) $(CFLAGS) mdr_tests.c mdr.o $(LDFLAGS) -o mdr_tests

mdrc: mdr.o mdrc.c
	$(CC) $(CFLAGS) mdrc.c mdr.o $(LDFLAGS) -o mdrc

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

clean:
	rm -f mdr.o mdr_tests
