#!/bin/sh
set -e
OPENSSL=openssl-1.0.1c
BASE=`pwd`

wget http://openssl.org/source/$OPENSSL.tar.gz -O - | tar xz

cd $OPENSSL
if [ -e ../$OPENSSL\-configure.patch ]; then
  patch -p1 < ../$OPENSSL\-configure.patch
fi
./config --cross-compile-prefix=x86_64-w64-mingw32- shared mingw64 --prefix=$BASE/openssl-w64/
make
make install
make clean
./config --cross-compile-prefix=i686-w64-mingw32- shared mingw --prefix=$BASE/openssl-w32/
make
make install
make clean
cd ..
rm -rf $OPENSSL
