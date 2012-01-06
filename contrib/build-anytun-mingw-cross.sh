#!/bin/sh
set -e
BASE=`pwd`

cd ../src
make distclean
./configure --target=mingw --use-ssl-crypto --with-boost=../contrib/boost-w32 --with-openssl=../contrib/openssl-w32 --cross-prefix=i686-w64-mingw32-
make -j 8
make strip
mkdir -p $BASE/anytun-w32
cp *.exe $BASE/anytun-w32
make distclean
./configure --target=mingw --use-ssl-crypto --with-boost=../contrib/boost-w64 --with-openssl=../contrib/openssl-w64 --cross-prefix=x86_64-w64-mingw32-
make -j 8
make strip
mkdir -p $BASE/anytun-w64
cp *.exe $BASE/anytun-w64
cd ../contrib
