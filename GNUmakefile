CC = cc
EXTRA_CFLAGS =
VERSION = 0.3.1
VERSION_MAJOR = $(shell echo ${VERSION} | cut -d. -f 1)
DEPDIR = .deps
CFLAGS = -Wall -g -I. -pie -fstack-protector-strong -fstack-clash-protection \
	 -DYY_NO_LEAKS=1 -Wformat=0 -fcf-protection \
	 $(shell pkg-config --cflags libbsd-overlay libbsd-ctor \
	libssl libcrypto)
LDFLAGS = $(shell pkg-config --libs libbsd-overlay libbsd-ctor \
	libssl libcrypto) \
	-Wl,-z,relro -Wl,-z,now
DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d
YACC = byacc
DESTDIR ?= /usr/local

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
	${CC} -shared -Wl,-z,relro -Wl,-z,now \
		-Wl,-soname,libflatconf.so.${VERSION_MAJOR} -o $@ flatconf.pic.o

libmdr.a: ${MDR_AROBJS}
	ar cr $@ ${MDR_AROBJS}

libmdr.so: ${MDR_LIBOBJS}
	${CC} -shared -Wl,-z,relro -Wl,-z,now \
		-Wl,-soname,libmdr.so.${VERSION_MAJOR} -o $@ ${MDR_LIBOBJS}

flatconf.c: flatconf.y mdr/flatconf.h
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
	mkdir -p ${DESTDIR}/bin
	mkdir -p ${DESTDIR}/sbin
	mkdir -p ${DESTDIR}/lib
	mkdir -p ${DESTDIR}/include/mdr
	mkdir -p ${DESTDIR}/share/doc/libmdr/examples

	install -m 0755 mdrd ${DESTDIR}/sbin/
	install -m 0755 mdrc ${DESTDIR}/bin/
	install -m 0644 mdr/*.h ${DESTDIR}/include/mdr/
	install -m 0644 libmdr.a ${DESTDIR}/lib/
	install -m 0644 libmdr.so ${DESTDIR}/lib/
	install -m 0644 libflatconf.a ${DESTDIR}/lib/
	install -m 0644 libflatconf.so ${DESTDIR}/lib/
	install -m 0644 mdrd.conf.sample ${DESTDIR}/share/doc/libmdr/examples

clean:
	rm -f $(DEPDIR)/* *.o mdr_tests mdrc mdrd mdrd_backend_echo \
		flatconf.c *.core core .depend *.so *.a *.tmp

-include $(DEPDIR)/*
