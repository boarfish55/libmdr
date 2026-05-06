#!/bin/sh

cd ..
dpkg-gensymbols -plibmdr0 -elibmdr.so -elibflatconf.so \
	-Odebian/libmdr0.symbols
