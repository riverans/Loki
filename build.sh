#!/bin/sh

echo "#### FOR TESTING ONLY !!! ####"

#Build Lib
gcc -c -o lib/md5.o lib/md5.c -fpic -Wall

#Build ASLEAP
cd lib/asleap
make
cd ../..

#Build TCPMD5 Modules
gcc -c -o loki/tcpmd5/tcpmd5.o loki/tcpmd5/tcpmd5.c `python-config --cflags` -fpic -Wall
gcc -c -o loki/tcpmd5/tcpmd5bf.o loki/tcpmd5/tcpmd5bf.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname tcpmd5.so loki/tcpmd5/tcpmd5.o -o loki/tcpmd5/tcpmd5.so -lc
ld -shared -soname tcpmd5bf.so loki/tcpmd5/tcpmd5bf.o lib/md5.o -o loki/tcpmd5/tcpmd5bf.so -lc
strip loki/tcpmd5/tcpmd5.so
strip loki/tcpmd5/tcpmd5bf.so

#Build OSPF BF Module
gcc -c -o loki/ospfmd5/ospfmd5bf.o loki/ospfmd5/ospfmd5bf.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname ospfmd5bf.so loki/ospfmd5/ospfmd5bf.o lib/md5.o -o loki/ospfmd5/ospfmd5bf.so -lc
strip loki/ospfmd5/ospfmd5bf.so

#Build ASLEAP Module
gcc -g -c -o lib/asleap/asleap.o lib/asleap/asleap.c -fpic -Wall -I./lib/asleap 
gcc -g -c -o loki/asleap/asleap.o loki/asleap/asleap.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname asleap.so loki/asleap/asleap.o lib/asleap/common.o lib/asleap/asleap.o lib/asleap/utils.o lib/asleap/sha1.o -o loki/asleap/asleap.so -lc -lpcap -lcrypt -lcrypto
strip loki/asleap/asleap.so

#Build SHA1 Module
gcc -g -c -o loki/sha1/sha1_prf.o loki/sha1/sha1_prf.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname sha1_prf.so loki/sha1/sha1_prf.o  -o loki/sha1/sha1_prf.so -lssl
strip loki/sha1/sha1_prf.so
