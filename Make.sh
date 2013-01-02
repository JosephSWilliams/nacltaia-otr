#!/bin/sh

unset HEADERS

  if [ -e '/usr/include/python2.6/Python.h'       ] &&
     [ -e '/usr/include/python2.6/structmember.h' ] ;then
       HEADERS='/usr/include/python2.6'

elif [ -e '/usr/local/include/python2.6/Python.h'       ] &&
     [ -e '/usr/local/include/python2.6/structmember.h' ] ;then
       HEADERS='/usr/local/include/python2.6'
  fi

[ -z $HEADERS ] && exit 1

mkdir -p build || exit 1

gcc -O3  src/nacltaia.c -shared -I $HEADERS -o nacltaia.so -l python2.6 -l nacl -l tai || exit 1

if ! $(which cython 2>&1 >/dev/null); then

  cp src/stdio.pyx stdio || exit 1
  chmod +x stdio         || exit 1

  cp src/stdin.pyx stdin || exit 1
  chmod +x stdin         || exit 1

  cp src/stdout.pyx stdout || exit 1
  chmod +x stdout          || exit 1

  cp src/base91a.pyx base91a.py || exit 1

  rm -rf build || exit 1

  exit 0
fi

cython --embed src/stdio.pyx -o build/stdio.c         || exit 1
gcc -O2 -c build/stdio.c -I $HEADERS -o build/stdio.o || exit 1
gcc -O1 -o stdio build/stdio.o -l python2.6           || exit 1

cython --embed src/stdin.pyx -o build/stdin.c         || exit 1
gcc -O2 -c build/stdin.c -I $HEADERS -o build/stdin.o || exit 1
gcc -O1 -o stdin build/stdin.o -l python2.6           || exit 1

cython --embed src/stdout.pyx -o build/stdout.c          || exit 1
gcc -O2 -c build/stdout.c -I $HEADERS -o build/stdout.o  || exit 1
gcc -O1 -o stdout build/stdout.o -l python2.6            || exit 1

cython src/base91a.pyx -o build/base91a.c                                                                                                   || exit 1
gcc -pthread -fno-strict-aliasing -DNDEBUG -g -fwrapv -O2 -Wall -Wstrict-prototypes -fPIC -I $HEADERS -c build/base91a.c -o build/base91a.o || exit 1
gcc -pthread -shared -Wl,-O1 -Wl,-Bsymbolic-functions build/base91a.o -o base91a.so                                                         || exit 1

rm -rf build || exit 1
