COMMENT =	Minimal Data Representation, a data serialization library
CATEGORIES =	devel
VERSION =	0.2.0
DISTNAME =	libmdr-${VERSION}
HOMEPAGE =	https://www.overnet.ca
MAINTAINER =	Pascal Lalonde <plalonde@overnet.ca>
SHARED_LIBS =	mdr		0.2
SHARED_LIBS +=	flatconf	0.2

GH_ACCOUNT =    boarfish55
GH_PROJECT =    libmdr
GH_TAGNAME =    ${VERSION}

PERMIT_PACKAGE =	Yes

# uses pledge()

MAKE_FLAGS =	EXTRA_CFLAGS=-O2

do-install:
	${INSTALL_PROGRAM} ${WRKBUILD}/mdrc ${PREFIX}/bin/
	${INSTALL_PROGRAM} ${WRKBUILD}/mdrd ${PREFIX}/sbin/

	${INSTALL_PROGRAM_DIR} ${PREFIX}/libexec/libmdr/
	${INSTALL_PROGRAM} ${WRKBUILD}/mdrd_backend_echo \
		${PREFIX}/libexec/libmdr/

	${INSTALL_DATA} ${WRKBUILD}/libmdr.so \
		${PREFIX}/lib/libmdr.so.${LIBmdr_VERSION}
	${INSTALL_DATA} ${WRKBUILD}/libmdr.a ${PREFIX}/lib/libmdr.a
	${INSTALL_DATA} ${WRKBUILD}/libflatconf.so \
		${PREFIX}/lib/libflatconf.so.${LIBflatconf_VERSION}
	${INSTALL_DATA} ${WRKBUILD}/libflatconf.a ${PREFIX}/lib/libflatconf.a

	${INSTALL_DATA_DIR} ${PREFIX}/include/mdr/
	${INSTALL_DATA} ${WRKBUILD}/mdr/*.h ${PREFIX}/include/mdr/

	${INSTALL_DATA_DIR} ${PREFIX}/share/doc/libmdr/
	${INSTALL_DATA} ${WRKBUILD}/README.md ${PREFIX}/share/doc/libmdr/
	${INSTALL_DATA} ${WRKBUILD}/LICENSE ${PREFIX}/share/doc/libmdr/
	${INSTALL_DATA} ${WRKBUILD}/mdrd.conf.sample ${PREFIX}/share/doc/libmdr/

	LIBDIRSUFFIX=lib ${WRKBUILD}/mdr.pc.sh > ${PREFIX}/lib/pkgconfig/mdr.pc
	LIBDIRSUFFIX=lib ${WRKBUILD}/flatconf.pc.sh > ${PREFIX}/lib/pkgconfig/flatconf.pc

.include <bsd.port.mk>
