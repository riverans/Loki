#!/bin/sh

gcc -c -o md5.o md5.c -fpic -Wall
gcc -c -o ospfmd5bf.o ospfmd5bf.c `python-config --cflags` -fpic -Wall
ld -shared -soname ospfmd5bf.so ospfmd5bf.o md5.o -o ospfmd5bf.so -lc
strip ospfmd5bf.so
