#!/bin/sh

gcc -c -o tcpmd5.o tcpmd5.c `python-config --cflags` -fpic -Wall
gcc -c -o md5.o md5.c -fpic -Wall
gcc -c -o tcpmd5bf.o tcpmd5bf.c `python-config --cflags` -fpic -Wall
ld -shared -soname tcpmd5.so tcpmd5.o -o tcpmd5.so -lc
ld -shared -soname tcpmd5bf.so tcpmd5bf.o md5.o -o tcpmd5bf.so -lc
strip tcpmd5.so
strip tcpmd5bf.so
