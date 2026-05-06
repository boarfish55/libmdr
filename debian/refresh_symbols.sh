#!/bin/sh

cd ..
version=$(dpkg-parsechangelog -SVersion | cut -d- -f 1)
dpkg-gensymbols -v${version} -plibmdr0 -elibmdr.so -elibflatconf.so \
	-Odebian/libmdr0.symbols
