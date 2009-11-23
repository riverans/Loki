#!/bin/sh

gcc -c -o tcpmd5.o tcpmd5.c `python-config --cflags` -fpic
ld -shared -soname tcpmd5.so -o tcpmd5.so -lc tcpmd5.o
strip tcpmd5.so
