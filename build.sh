#!/bin/sh

#Build Lib
gcc -c -o lib/md5.o lib/md5.c -fpic -Wall

#Build TCPMD5 Modules
gcc -c -o tcpmd5/tcpmd5.o tcpmd5/tcpmd5.c `python-config --cflags` -fpic -Wall
gcc -c -o tcpmd5/tcpmd5bf.o tcpmd5/tcpmd5bf.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname tcpmd5.so tcpmd5/tcpmd5.o -o tcpmd5/tcpmd5.so -lc
ld -shared -soname tcpmd5bf.so tcpmd5/tcpmd5bf.o lib/md5.o -o tcpmd5/tcpmd5bf.so -lc
strip tcpmd5/tcpmd5.so
strip tcpmd5/tcpmd5bf.so

#Build OSPF BF Module
gcc -c -o ospfmd5/ospfmd5bf.o ospfmd5/ospfmd5bf.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname ospfmd5bf.so ospfmd5/ospfmd5bf.o lib/md5.o -o ospfmd5/ospfmd5bf.so -lc
strip ospfmd5/ospfmd5bf.so

#Build ASLEAP
cd lib/asleap
make
cd ../..

#Build ASLEAP Module
gcc -g -c -o lib/asleap/asleap.o lib/asleap/asleap.c -fpic -Wall -I./lib/asleap 
gcc -g -c -o asleap/asleap.o asleap/asleap.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname asleap.so asleap/asleap.o lib/asleap/common.o lib/asleap/asleap.o lib/asleap/utils.o lib/asleap/sha1.o -o asleap/asleap.so -lc -lpcap -lcrypt -lcrypto
strip asleap/asleap.so
