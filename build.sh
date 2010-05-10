#!/bin/sh

echo "###########################################################"
echo "########## build.sh is FOR DEVELOPMENT ONLY !!! ###########"
echo "###########################################################"
echo ""
echo "to build from svn, run 'aclocal', 'automake --add-missing',"
echo "'autoconf' - followed by plain old './configure', 'make'"
echo "and 'make install'."
echo ""
echo "###########################################################"
echo "####### please report any bug to <bugs@c0decafe.de> #######"
echo "###########################################################"

read

#Build Lib
gcc -c -o lib/md5.o lib/md5.c -fpic -Wall
gcc -c -o lib/mplstun.o lib/mplstun.c -fpic -Wall -DHAVE_LINUX_IF_H -DHAVE_LINUX_IF_TUN_H -I.
gcc -c -o lib/mplsred.o lib/mplsred.c -fpic -Wall -DHAVE_LINUX_IF_H -DHAVE_LINUX_IF_TUN_H -I.

#Build ASLEAP
#cd lib/asleap
#make
#cd ../..

#Build TCPMD5 Modules
gcc -c -o loki_bindings/tcpmd5/tcpmd5.o loki_bindings/tcpmd5/tcpmd5.c `python-config --cflags` -fpic -Wall
gcc -c -o loki_bindings/tcpmd5/tcpmd5bf.o loki_bindings/tcpmd5/tcpmd5bf.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname tcpmd5.so loki_bindings/tcpmd5/tcpmd5.o -o loki_bindings/tcpmd5/tcpmd5.so -lc
ld -shared -soname tcpmd5bf.so loki_bindings/tcpmd5/tcpmd5bf.o lib/md5.o -o loki_bindings/tcpmd5/tcpmd5bf.so -lc

#Build OSPF BF Module
gcc -c -o loki_bindings/ospfmd5/ospfmd5bf.o loki_bindings/ospfmd5/ospfmd5bf.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname ospfmd5bf.so loki_bindings/ospfmd5/ospfmd5bf.o lib/md5.o -o loki_bindings/ospfmd5/ospfmd5bf.so -lc

#Build ASLEAP Module
gcc -c -o loki_bindings/asleap/common.o lib/asleap/common.c -I./lib/asleap -fpic -DHAVE_OPENSSL_MD4_H -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
gcc -c -o loki_bindings/asleap/utils.o lib/asleap/utils.c -I./lib/asleap -fpic -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
gcc -c -o loki_bindings/asleap/sha1.o lib/asleap/sha1.c -I./lib/asleap -fpic -DHAVE_ENDIAN_H -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
gcc -c -o loki_bindings/asleap/bin_asleap.o lib/asleap/asleap.c -I./lib/asleap -fpic -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
gcc -c -o loki_bindings/asleap/asleap.o loki_bindings/asleap/asleap.c `python-config --cflags` -fpic -Wall -I.
ld -shared -soname asleap.so loki_bindings/asleap/asleap.o loki_bindings/asleap/common.o loki_bindings/asleap/utils.o loki_bindings/asleap/sha1.o loki_bindings/asleap/bin_asleap.o -o loki_bindings/asleap/asleap.so -lc -lpcap -lcrypt -lcrypto -lssl

#Build MPLS Module
gcc -c -o loki_bindings/mpls/mplstun.o loki_bindings/mpls/mplstun.c `python-config --cflags` -fpic -Wall -I. -DHAVE_LINUX_IF_H -DHAVE_LINUX_IF_TUN_H
gcc -c -o loki_bindings/mpls/mplsred.o loki_bindings/mpls/mplsred.c `python-config --cflags` -fpic -Wall -I. -DHAVE_LINUX_IF_H -DHAVE_LINUX_IF_TUN_H
ld -shared -soname mplsred.so loki_bindings/mpls/mplsred.o lib/mplsred.o -o loki_bindings/mpls/mplsred.so -lc -lpcap -ldnet
ld -shared -soname mplstun.so loki_bindings/mpls/mplstun.o lib/mplstun.o -o loki_bindings/mpls/mplstun.so -lc -lpcap -ldnet

#Bulding mpls-tunnel
gcc -o src/mpls_tunnel.o -fpic -g -c src/mpls-tunnel.c -DVERSION=\"DEVEL\" -I. -DHAVE_LINUX_IF_H -DHAVE_LINUX_IF_TUN_H
gcc -g -O2 -o src/mpls_tunnel src/mpls_tunnel.o lib/mplstun.o -ldnet -lpcap

cat > loki << EOF
PYTHONPATH=. python src/loki.py
EOF

chmod +x loki
ln -s src/mpls_tunnel mpls_tunnel
