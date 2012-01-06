#!/bin/bash

VER=`cat ../version`

for target in w32 w64; do
  mkdir anytun-$VER-$target
  cp anytun-$target/*.exe anytun-$VER-$target
  cp boost-$target/lib/libboost_{date_time,serialization,system,thread_win32}.dll anytun-$VER-$target
  cp openssl-$target/bin/libeay32.dll anytun-$VER-$target
  cp anytun-example.bat anytun-$VER-$target
  cp ../{AUTHORS,ChangeLog,LICENSE,README,version} anytun-$VER-$target
  cp -r tap?? anytun-$VER-$target
  rm -rf anytun-$VER-$target/tap*/.svn

  zip -r anytun-$VER-$target.zip anytun-$VER-$target
  rm -rf anytun-$VER-$target
done

exit 0
