#!/bin/sh
if [ -z $1 ]
then
	VER="current"
else
	VER=${1}
fi

make clean
rm -rf releases/visited_${VER}
mkdir -p releases/visited_${VER} 2> /dev/null
cp * releases/visited_${VER}
# Better to don't compress the man page for Debian developers easy fix.
# gzip -9 releases/visited_${VER}/visited.1
cd releases
tar cvzf visited-${VER}.tar.gz visited_${VER}
cd ..
