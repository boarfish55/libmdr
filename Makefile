CC = cc
EXTRA_CFLAGS =
VERSION = 0.4.3
VERSION_MAJOR != echo ${VERSION} | cut -d. -f 1
CFLAGS = -Wall -g ${EXTRA_CFLAGS}
INCLUDES = -I.
LIBS = -lcrypto -lssl
YACC=yacc
PREFIX ?= /usr/local
INSTALL_OWNER ?= root

SRCS = mdr.c mdrc.c mdr_mdrd.c mdr_tests.c flatconf.c idxheap.c tlsev.c \
	util.c xlog.c

MDR_LIBOBJS = mdr.pic.o mdr_mdrd.pic.o tlsev.pic.o idxheap.pic.o util.pic.o \
	      xlog.pic.o
MDR_AROBJS = mdr.o mdr_mdrd.o tlsev.o idxheap.o util.o xlog.o
MDRD_OBJS = mdrd.o idxheap.o flatconf.o mdr.o mdr_mdrd.o tlsev.o util.o xlog.o
MDRC_OBJS = mdrc.o mdr.o
BE_ECHO_OBJS = mdrd_backend_echo.o mdr.o mdr_mdrd.o xlog.o
MDR_TESTS_OBJS = mdr_tests.o mdr.o util.o xlog.o

all: .depend mdrc mdr_tests mdrd mdrd_backend_echo libmdr.a libmdr.so \
	libflatconf.a libflatconf.so

.depend: ${SRCS}
	mkdep ${CFLAGS} ${INCLUDES} ${SRCS}

.SUFFIXES: .c .o .pic.o
.c.pic.o:
	${CC} ${CFLAGS} ${INCLUDES} -c -fPIC $< -o $@
.c.o:
	${CC} ${CFLAGS} ${INCLUDES} -c $< -o $@

libflatconf.a: flatconf.o
	ar cr $@ flatconf.o

libflatconf.so: flatconf.pic.o
	${CC} -shared -Wl,-soname,libflatconf.so.${VERSION_MAJOR} -o $@ flatconf.pic.o

libmdr.a: ${MDR_AROBJS}
	ar cr $@ ${MDR_AROBJS}

libmdr.so: ${MDR_LIBOBJS}
	${CC} -shared -Wl,-soname,libmdr.so.${VERSION_MAJOR} -o $@ ${MDR_LIBOBJS}

flatconf.c: flatconf.y mdr/flatconf.h
	${YACC} -o flatconf.c flatconf.y

mdr_tests: ${MDR_TESTS_OBJS}
	${CC} ${CFLAGS} ${MDR_TESTS_OBJS} ${LIBS} -o $@

mdrc: ${MDRC_OBJS}
	${CC} ${CFLAGS} ${MDRC_OBJS} ${LIBS} -o $@

mdrd: ${MDRD_OBJS}
	${CC} ${CFLAGS} ${MDRD_OBJS} ${LIBS} -o $@

mdrd_backend_echo: ${BE_ECHO_OBJS}
	${CC} ${CFLAGS} ${BE_ECHO_OBJS} ${LIBS} -o $@

test: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=none --leak-check=full \
		--track-origins=yes --show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

install: all
	install -d -o root -g bin -m 0555 mdrc ${PREFIX}/bin/
	install -d -o root -g bin -m 0555 mdrd ${PREFIX}/sbin/
	install -d -o root -g bin -m 0555 README.md ${PREFIX}/share/doc/libmdr/
	install -d -o root -g bin -m 0555 LICENSE ${PREFIX}/share/doc/libmdr/
	install -d -o root -g bin -m 0555 mdrd.conf.sample ${PREFIX}/share/doc/libmdr/
	install -d -o root -g bin -m 0555 libmdr.a ${PREFIX}/lib/
	install -d -o root -g bin -m 0555 libmdr.so ${PREFIX}/lib/
	install -d -o root -g bin -m 0555 libflatconf.a ${PREFIX}/lib/
	install -d -o root -g bin -m 0555 libflatconf.so ${PREFIX}/lib/
	install -d -o root -g bin -m 0555 mdrd_backend_echo ${PREFIX}/libexec/libmdr/

clean:
	rm -f *.o mdr_tests mdrc mdrd mdrd_backend_echo \
		flatconf.c *.core .depend *.so *.a *.tmp
