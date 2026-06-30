#!/bin/sh

cd "$(dirname "$0")/.."
make libmdr.so libflatconf.so
version=$(dpkg-parsechangelog -SVersion | cut -d- -f 1)
dpkg-gensymbols -v${version} -plibmdr0 -elibmdr.so -elibflatconf.so \
	-Odebian/libmdr0.symbols
