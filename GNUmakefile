CC = cc
EXTRA_CFLAGS =
VERSION = 0.9.2
VERSION_MAJOR = $(shell echo ${VERSION} | cut -d. -f 1)
DEPDIR = .deps

# Project-mandatory flags. We *append* to CFLAGS/CPPFLAGS/LDFLAGS so that any
# flags supplied through the environment (notably dpkg-buildflags under Debian:
# hardening, -D_FORTIFY_SOURCE, -ffile-prefix-map, ...) are preserved instead of
# being clobbered. Libraries go in LIBS, not LDFLAGS.
CFLAGS += -Wall -Wmissing-prototypes -g -I. -pie -fstack-protector-strong \
	 -fstack-clash-protection -DYY_NO_LEAKS=1 -fcf-protection \
	 $(shell pkg-config --cflags libbsd-overlay libbsd-ctor \
	 libssl libcrypto)
LDFLAGS += -Wl,-z,relro -Wl,-z,now
LIBS = $(shell pkg-config --libs libbsd-overlay libbsd-ctor libssl libcrypto)
# Shared objects must not pull in libbsd-ctor: its constructor (libbsd_init_func)
# belongs in the final executable, not in libmdr.so's exported ABI.
SOLIBS = $(shell pkg-config --libs libbsd-overlay libssl libcrypto)
DEPFLAGS = -MMD -MP -MF $(DEPDIR)/$@.d
YACC = byacc

PREFIX ?= /usr/local
DESTDIR ?=
LIBDIRSUFFIX ?= lib
BINDIR = $(PREFIX)/bin
SBINDIR = $(PREFIX)/sbin
LIBDIR = $(PREFIX)/$(LIBDIRSUFFIX)
INCLUDEDIR = $(PREFIX)/include
MANDIR = $(PREFIX)/share/man
DOCDIR ?= $(PREFIX)/share/doc/libmdr

MDR_LIBOBJS = mdr.pic.o mdr_mdrd.pic.o tlsev.pic.o idxheap.pic.o util.pic.o \
	      xlog.pic.o
MDR_AROBJS = mdr.o mdr_mdrd.o tlsev.o idxheap.o util.o xlog.o
MDRD_OBJS = mdrd.o idxheap.o flatconf.o mdr.o mdr_mdrd.o tlsev.o util.o xlog.o
MDRC_OBJS = mdrc.o mdr.o
BE_ECHO_OBJS = mdrd_backend_echo.o mdr.o mdr_mdrd.o xlog.o util.o
MDR_TESTS_OBJS = mdr_tests.o mdr.o util.o xlog.o
XLOG_TESTS_OBJS = xlog_tests.o xlog.o

all: mdrc mdr_tests xlog_tests flatconf_tests mdrd mdrd_backend_echo libmdr.a \
	libflatconf.a \
	libmdr.so libmdr.so.${VERSION} libmdr.so.${VERSION_MAJOR} \
	libflatconf.so libflatconf.so.${VERSION} libflatconf.so.${VERSION_MAJOR}

.SUFFIXES: .c .o .pic.o
.c.pic.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c -fPIC $< -o $@
.c.o:
	@mkdir -p $(DEPDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(EXTRA_CFLAGS) $(DEPFLAGS) -c $< -o $@

libflatconf.a: flatconf.o
	ar cr $@ flatconf.o

libflatconf.so.${VERSION}: flatconf.pic.o
	${CC} -shared $(LDFLAGS) \
		-Wl,-soname,libflatconf.so.${VERSION_MAJOR} \
		-o $@ flatconf.pic.o

libflatconf.so.${VERSION_MAJOR}: libflatconf.so.${VERSION}
	ln -fs libflatconf.so.${VERSION} $@

libflatconf.so: libflatconf.so.${VERSION}
	ln -fs libflatconf.so.${VERSION} $@

libmdr.a: ${MDR_AROBJS}
	ar cr $@ ${MDR_AROBJS}

libmdr.so.${VERSION}: ${MDR_LIBOBJS}
	${CC} -shared $(LDFLAGS) \
		-Wl,-soname,libmdr.so.${VERSION_MAJOR} \
		-o $@ ${MDR_LIBOBJS} $(SOLIBS)

libmdr.so.${VERSION_MAJOR}: libmdr.so.${VERSION}
	ln -fs libmdr.so.${VERSION} $@

libmdr.so: libmdr.so.${VERSION}
	ln -fs libmdr.so.${VERSION} $@

flatconf.c: flatconf.y mdr/flatconf.h
	${YACC} -p flatconf_yy -o flatconf.c flatconf.y

flatconf_tests: flatconf_tests.c flatconf.o
	$(CC) $(CPPFLAGS) $(CFLAGS) flatconf_tests.c -o flatconf_tests \
		flatconf.o $(LDFLAGS) $(LIBS)

mdr_tests: ${MDR_TESTS_OBJS}
	${CC} ${CFLAGS} ${MDR_TESTS_OBJS} ${LDFLAGS} ${LIBS} -o $@

xlog_tests: ${XLOG_TESTS_OBJS}
	${CC} ${CFLAGS} ${XLOG_TESTS_OBJS} ${LDFLAGS} ${LIBS} -o $@

mdrc: ${MDRC_OBJS}
	${CC} ${CFLAGS} ${MDRC_OBJS} ${LDFLAGS} ${LIBS} -o $@

mdrd: ${MDRD_OBJS}
	${CC} ${CFLAGS} ${MDRD_OBJS} ${LDFLAGS} ${LIBS} -o $@

mdrd_backend_echo: ${BE_ECHO_OBJS}
	${CC} ${CFLAGS} ${BE_ECHO_OBJS} ${LDFLAGS} ${LIBS} -o $@

tests: mdr_tests
	test -x /usr/bin/valgrind \
		&& valgrind --keep-stacktraces=alloc-and-free \
		--leak-check=full --track-origins=yes \
		--show-leak-kinds=all -s ./mdr_tests \
		|| ./mdr_tests

install: all
	mkdir -p ${DESTDIR}${BINDIR}
	mkdir -p ${DESTDIR}${SBINDIR}
	mkdir -p ${DESTDIR}${LIBDIR}/pkgconfig
	mkdir -p ${DESTDIR}${INCLUDEDIR}/mdr
	mkdir -p ${DESTDIR}${DOCDIR}/examples
	mkdir -p ${DESTDIR}${MANDIR}/man3
	mkdir -p ${DESTDIR}${MANDIR}/man5
	mkdir -p ${DESTDIR}${MANDIR}/man8

	install -m 0755 mdrd ${DESTDIR}${SBINDIR}/
	install -m 0755 mdrc ${DESTDIR}${BINDIR}/
	install -m 0644 mdr/*.h ${DESTDIR}${INCLUDEDIR}/mdr/
	install -m 0644 libmdr.a ${DESTDIR}${LIBDIR}/
	install -m 0644 libflatconf.a ${DESTDIR}${LIBDIR}/
	install -m 0644 libmdr.so.${VERSION} ${DESTDIR}${LIBDIR}/
	ln -fs libmdr.so.${VERSION} ${DESTDIR}${LIBDIR}/libmdr.so.${VERSION_MAJOR}
	ln -fs libmdr.so.${VERSION} ${DESTDIR}${LIBDIR}/libmdr.so
	install -m 0644 libflatconf.so.${VERSION} ${DESTDIR}${LIBDIR}/
	ln -fs libflatconf.so.${VERSION} \
		${DESTDIR}${LIBDIR}/libflatconf.so.${VERSION_MAJOR}
	ln -fs libflatconf.so.${VERSION} ${DESTDIR}${LIBDIR}/libflatconf.so
	install -m 0644 mdrd.conf.sample ${DESTDIR}${DOCDIR}/examples/
	install -m 0644 man/*.3 ${DESTDIR}${MANDIR}/man3/
	install -m 0644 man/*.5 ${DESTDIR}${MANDIR}/man5/
	install -m 0644 man/*.8 ${DESTDIR}${MANDIR}/man8/
	PC_PREFIX=${PREFIX} VERSION=${VERSION} LIBDIRSUFFIX=${LIBDIRSUFFIX} \
		./mdr.pc.sh > ${DESTDIR}${LIBDIR}/pkgconfig/mdr.pc
	PC_PREFIX=${PREFIX} VERSION=${VERSION} LIBDIRSUFFIX=${LIBDIRSUFFIX} \
		./flatconf.pc.sh > ${DESTDIR}${LIBDIR}/pkgconfig/flatconf.pc

clean:
	rm -f $(DEPDIR)/* *.o mdr_tests xlog_tests mdrc mdrd mdrd_backend_echo \
		flatconf.c flatconf_tests *.core core .depend \
		*.so *.so.[0-9]* *.a *.tmp

-include $(DEPDIR)/*
