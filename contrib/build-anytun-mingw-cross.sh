#!/bin/sh
set -e
BASE=`pwd`

cd ../src

for target in w32 w64; do
  if [ "$target" = "w32" ]; then
    target_name=i686
  else
    target_name=x86_64
  fi
  make distclean
  ./configure --target=mingw --use-ssl-crypto --with-boost=../contrib/boost-$target --with-openssl=../contrib/openssl-$target --cross-prefix=$target_name-w64-mingw32-
  make
  make strip
  mkdir -p $BASE/anytun-$target
  cp *.exe $BASE/anytun-$target
done

cd ../contrib

exit 0
