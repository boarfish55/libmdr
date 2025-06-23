CC := cc
DEPDIR := .deps
CFLAGS := -Wall -g -fstack-protector-strong \
	$(shell pkg-config --cflags libbsd-overlay libbsd-ctor \
	libssl libcrypto)
LDFLAGS := $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	libssl libcrypto) \
	-Wl,-z,relro -Wl,-z,now
YACC := byacc

DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d

MDRC_SRCS = mdr.c mdrc.c
MDRC_OBJS = $(MDRC_SRCS:.c=.o)

MDRD_SRCS = mdr.c mdrd.c mdr_mdrd.c idxheap.c tlsev.c util.c flatconf.c \
	xlog.c counters.c
MDRD_OBJS = $(MDRD_SRCS:.c=.o)

MDRTESTS_SRCS = mdr.c mdr_tests.c util.c xlog.c
MDRTESTS_OBJS = $(MDRTESTS_SRCS:.c=.o)

MDRD_ECHO_SRCS = mdrd_backend_echo.c mdr.c mdr_mdrd.c xlog.c
MDRD_ECHO_OBJS = $(MDRD_ECHO_SRCS:.c=.o)

all: mdrc mdr_tests mdrd mdrd_backend_echo

.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $<

flatconf.c: flatconf.y flatconf.h
	$(YACC) -o flatconf.c flatconf.y

mdr.o: mdr.c mdr.h
	$(CC) $(CFLAGS) -c mdr.c -o mdr.o

mdr_tests: $(MDRTESTS_OBJS)
	$(CC) $(CFLAGS) -o mdr_tests $(MDRTESTS_OBJS) $(LDFLAGS)

mdrc: $(MDRC_OBJS)
	$(CC) $(CFLAGS) -o mdrc $(MDRC_OBJS) $(LDFLAGS)

mdrd: $(MDRD_OBJS)
	$(CC) $(CFLAGS) -o mdrd $(MDRD_OBJS) $(LDFLAGS)

mdrd_backend_echo: $(MDRD_ECHO_OBJS)
	$(CC) $(CFLAGS) -o mdrd_backend_echo $(MDRD_ECHO_OBJS) $(LDFLAGS)

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

clean:
	rm -f *.o mdr_tests mdrc mdrd mdrd_backend_echo flatconf.c

-include $(DEPDIR)/*
