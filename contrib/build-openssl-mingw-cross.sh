#!/bin/sh
set -e 
OPENSSL=openssl-1.0.0f
BASE=`pwd`

wget http://openssl.org/source/$OPENSSL.tar.gz -O - | tar xz

cd $OPENSSL
patch -p1 < ../openssl-1.0.0f-configure.patch
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
