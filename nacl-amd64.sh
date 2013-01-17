#!/bin/sh
# Workaround script for creating shared objects on 64-bit
# architectures with NaCl. Much thanks to Ivo Smits for
# doing all the hard work.

wget -O- http://hyperelliptic.org/nacl/nacl-20110221.tar.bz2 | bunzip2 | tar -xf -
cd nacl-20110221

rm -r crypto_onetimeauth/poly1305/amd64 # ./nacl will use an alternative

sed -i "s/$/ -fPIC/" okcompilers/c

./do

gcc okcompilers/abiname.c -o abiname
ABINAME="$(./abiname "" | cut -b 2-)"
BUILDDIR="build/$(hostname | sed 's/\..*//' | tr -cd '[a-z][A-Z][0-9]')"

mkdir -p /usr/include/nacl
cp "${BUILDDIR}/lib/${ABINAME}/"* /usr/lib/
cp "${BUILDDIR}/include/${ABINAME}/"* /usr/lib/
