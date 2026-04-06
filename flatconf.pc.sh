#!/bin/sh

cat << EOF
prefix=$PREFIX
exec_prefix=\${prefix}
libdir=\${exec_prefix}/$LIBDIRSUFFIX
includedir=\${prefix}/include
 
Name: Minimal Data Representation - Flatconf
Description: Minimal Data Representation - Flatconf configuration format
Version: $VERSION
Libs: -L\${libdir} -lflatconf
Cflags: -I\${includedir}
EOF
