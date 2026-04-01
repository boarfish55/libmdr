CC = cc
EXTRA_CFLAGS =
DEPDIR = .deps
CFLAGS = -Wall -g -I. -fstack-protector-strong -DYY_NO_LEAKS=1 -Wformat=0 \
	$(shell pkg-config --cflags libbsd-overlay libbsd-ctor \
	libssl libcrypto)
LDFLAGS = $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	libssl libcrypto) \
	-Wl,-z,relro -Wl,-z,now
DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d
YACC = byacc
PREFIX ?= /usr/local

SRCS = mdr.c mdrc.c mdr_mdrd.c mdr_tests.c flatconf.c idxheap.c tlsev.c \
	util.c xlog.c

MDR_LIBOBJS = mdr.pic.o tlsev.pic.o idxheap.pic.o util.pic.o xlog.pic.o
MDR_AROBJS = mdr.o tlsev.o idxheap.o util.o xlog.o
MDRD_OBJS = mdrd.o idxheap.o flatconf.o mdr.o mdr_mdrd.o tlsev.o util.o xlog.o
MDRC_OBJS = mdrc.o mdr.o
BE_ECHO_OBJS = mdrd_backend_echo.o mdr.o mdr_mdrd.o xlog.o
MDR_TESTS_OBJS = mdr_tests.o mdr.o util.o xlog.o

all: mdrc mdr_tests mdrd mdrd_backend_echo libmdr.a libmdr.so \
	libflatconf.a libflatconf.so

.SUFFIXES: .c .o .pic.o
.c.pic.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c -fPIC $< -o $@
.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $< -o $@

libflatconf.a: flatconf.o
	ar cr $@ flatconf.o

libflatconf.so: flatconf.pic.o
	${CC} -shared -o $@ flatconf.pic.o

libmdr.a: ${MDR_AROBJS}
	ar cr $@ ${MDR_AROBJS}

libmdr.so: ${MDR_LIBOBJS}
	${CC} -shared -o $@ ${MDR_LIBOBJS}

flatconf.c: flatconf.y flatconf.h
	${YACC} -o flatconf.c flatconf.y

mdr_tests: ${MDR_TESTS_OBJS}
	${CC} ${CFLAGS} ${MDR_TESTS_OBJS} ${LDFLAGS} -o $@

mdrc: ${MDRC_OBJS}
	${CC} ${CFLAGS} ${MDRC_OBJS} ${LDFLAGS} -o $@

mdrd: ${MDRD_OBJS}
	${CC} ${CFLAGS} ${MDRD_OBJS} ${LDFLAGS} -o $@

mdrd_backend_echo: ${BE_ECHO_OBJS}
	${CC} ${CFLAGS} ${BE_ECHO_OBJS} ${LDFLAGS} -o $@

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

install: all
	install -o root -g root -m 0755 mdrd ${PREFIX}/bin/
	install -o root -g root -m 0755 mdrc ${PREFIX}/bin/
	install -o root -g root -m 0755 libmdr.a ${PREFIX}/lib/
	install -o root -g root -m 0755 libmdr.so ${PREFIX}/lib/
	install -o root -g root -m 0755 libflatconf.a ${PREFIX}/lib/
	install -o root -g root -m 0755 libflatconf.so ${PREFIX}/lib/

clean:
	rm -f $(DEPDIR)/* *.o mdr_tests mdrc mdrd mdrd_backend_echo \
		flatconf.c *.core core .depend *.so *.a *.tmp

-include $(DEPDIR)/*
