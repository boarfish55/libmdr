CC := cc
CFLAGS := -Wall -g $(shell pkg-config --cflags libbsd-overlay)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay)

all: mdr_tests

mdr.o: mdr.c mdr.h
	$(CC) $(CFLAGS) -c mdr.c -o mdr.o

mdr_tests: mdr.o mdr_tests.c
	$(CC) $(CFLAGS) mdr_tests.c mdr.o $(LDFLAGS) -o mdr_tests

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

clean:
	rm -f mdr.o mdr_tests
