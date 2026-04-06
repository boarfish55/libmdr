#!/bin/sh

cat << EOF
prefix=$PREFIX
exec_prefix=\${prefix}
libdir=\${exec_prefix}/lib
includedir=\${prefix}/include
 
Name: Minimal Data Representation
Description: Minimal Data Representation
Version: $VERSION
Libs: -L\${libdir} -lmdr
Libs.private: -lssl -lcrypto
Cflags: -I\${includedir}
EOF
