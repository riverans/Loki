#!/bin/sh

gcc -c -o tcpmd5.o tcpmd5.c `python-config --cflags` -fpic
gcc -c -o md5.o md5.c -fpic
gcc -c -o tcpmd5bf.o tcpmd5bf.c `python-config --cflags` -fpic
ld -shared -soname tcpmd5.so -o tcpmd5.so -lc tcpmd5.o
ld -shared -soname tcpmd5bf.so -o tcpmd5bf.so -lc tcpmd5bf.o md5.o
strip tcpmd5.so
strip tcpmd5bf.so
