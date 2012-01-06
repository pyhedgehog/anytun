#!/bin/sh
set -e
BOOST=1.48.0

BOOST_DASH=`echo $BOOST | perl -ne 's/\./_/g; print'`
echo $BOOST_DASH
wget http://downloads.sourceforge.net/project/boost/boost/$BOOST/boost_${BOOST_DASH}.tar.bz2 -O - | tar xj

cd boost_${BOOST_DASH}
./bootstrap.sh

patch -p1 < ../boost_project-config.patch

for target in w32 w64; do
  ./b2 --layout=system variant=release threading=multi link=shared runtime-link=shared toolset=gcc-$target target-os=windows threadapi=win32 stage || true
  mkdir -p ../boost-$target/include
  mv stage/lib ../boost-$target/
  cp -r boost ../boost-$target/include
  ./b2 --layout=system variant=release threading=multi link=shared runtime-link=shared toolset=gcc-$target target-os=windows threadapi=win32 stage --clean || true
done
rm -rf ../boost_${BOOST_DASH}
