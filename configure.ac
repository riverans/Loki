# configure.in
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

AC_PREREQ([2.69])
AC_INIT([loki], [0.3.0], [bugs@c0decafe.de])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])

# Initialize prefix.
if test "$prefix" = "NONE"; then
   prefix="/usr/local"
fi

# Checks for programs.
AC_PROG_CC
AC_PROG_SED
AC_PROG_MAKE_SET
#AM_PATH_PYTHON([2.6])
PC_INIT([2.6], [2.9])

# Checks for libraries.
AC_CHECK_LIB(crypt, encrypt)
AC_CHECK_LIB(crypto, MD4)
AC_CHECK_LIB(ssl, [SHA1_Init, DES_ecb_encrypt])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h syslog.h unistd.h])
AC_CHECK_HEADERS([netpacket/packet.h crypt.h openssl/des.h endian.h sys/endian.h])
AC_CHECK_HEADERS([netinet/ether.h net/ethernet.h net/if.h])
AC_CHECK_HEADERS([openssl/md4.h])
AC_CHECK_HEADERS([sys/cdefs.h sys/time.h sys/socket.h linux/if.h linux/if_tun.h linux/wireless.h], [], [],
[[  #ifdef HAVE_SYS_CDEFS_H
     #include <sys/cdefs.h>
    #endif
    #ifdef HAVE_SYS_TIME_H
     #include <sys/time.h>
    #endif
    #ifdef HAVE_SYS_SOCKET_H
     #include <sys/socket.h>
    #endif
    #ifdef HAVE_LINUX_IF_H
     #include <linux/if.h>
    #endif
    #ifdef HAVE_LINUX_WIRELESS_H
     #include <linux/wireless.h>
    #endif
]])

dnl Checks for libpcap
AC_MSG_CHECKING(for libpcap)
AC_ARG_WITH(libpcap,
[  --with-libpcap=DIR      use libpcap build directory],
[ case "$withval" in
  yes|no)
     AC_MSG_RESULT(no)
     ;;
  *)
     AC_MSG_RESULT($withval)
     if test -f $withval/pcap.h -a -f $withval/libpcap.a; then
        owd=`pwd`
        if cd $withval; then withval=`pwd`; cd $owd; fi
	PCAPINC="-I$withval -I$withval/bpf"
	PCAPLIB="-L$withval -lpcap"
     else
        AC_ERROR(pcap.h or libpcap.a not found in $withval)
     fi
     ;;
  esac ],
[ if test -f ${prefix}/include/pcap.h; then
     PCAPINC="-I${prefix}/include"
     PCAPLIB="-L${prefix}/lib -lpcap"
  elif test -f /usr/include/pcap/pcap.h; then
     PCAPINC="-I/usr/include/pcap"
     PCAPLIB="-lpcap"
  elif test -f /usr/include/pcap.h; then
     PCAPLIB="-lpcap"
  else
     AC_MSG_RESULT(no)
     AC_ERROR(libpcap not found)
  fi
  AC_MSG_RESULT(yes) ]
)
AC_SUBST(PCAPINC)
AC_SUBST(PCAPLIB)

dnl Checks for (installed) libdnet
AC_ARG_WITH(libdnet,
[  --with-libdnet=DIR      use libdnet in DIR],
[ case "$withval" in
  yes|no)
     AC_ERROR([Please specify directory containing dnet-config when using --with-libdnet])
     ;;
  *)
     AC_MSG_CHECKING(for libdnet)
     AC_MSG_RESULT($withval)
     if test -f $withval/src/libdnet.a; then
    DNETINC="-I$withval/include"
	DNETLIB="-L$withval/src -ldnet `$withval/dnet-config --libs`"
     elif test -x $withval/bin/dnet-config; then
	DNETINC="`$withval/bin/dnet-config --cflags`"
	DNETLIB="`$withval/bin/dnet-config --libs`"
     else
        AC_MSG_RESULT(no)
        AC_ERROR(dnet-config not found in $withval/bin)
     fi
     ;;
  esac
  AC_MSG_RESULT(yes) ],
[ dnl This is the default case so lets just use AC_PATH_PROG! --CPK.
  AC_PATH_PROG(dnetconfig, dnet-config, "no")
  if test "$dnetconfig" = "no"; then
     AC_ERROR(dnet-config not found)
  else
     DNETINC="`$dnetconfig --cflags`"
     DNETLIB="`$dnetconfig --libs`"
  fi]
)

AC_ARG_WITH([gtk],
[AS_HELP_STRING([--with-gtk],
   [use gtk UI (default is no)])],
[USE_GTK=$withval
LOKI_GTK=loki_gtk.py],
[USE_GTK=no])

AC_ARG_WITH([urwid],
[AS_HELP_STRING([--with-urwid],
   [use urwid UI (default is no)])],
[USE_URWID=$withval
LOKI_URWID=loki_urw.py],
[USE_URWID=no])

AC_SUBST(DNETINC)
AC_SUBST(DNETLIB)
AC_SUBST(USE_GTK)
AC_SUBST(LOKI_GTK)
AC_SUBST(USE_URWID)
AC_SUBST(LOKI_URWID)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero getcwd gethostbyname gettimeofday inet_ntoa memset mkdir select socket strchr strerror strtoul])

# Error conditions
if test "$ac_cv_lib_pcap_pcap_open_live" = no ; then
    AC_ERROR(libpcap not found!)
fi
if test "$ac_cv_lib_ssl_SHA1_Init" = no ; then
    AC_ERROR(libssl not found!)
else
    if test "$ac_cv_lib_crypt_encrypt" = no ; then
        if test "$ac_cv_lib_ssl_DES_ecb_encrypt" = no ; then
            AC_ERROR(no usable DES implementation found!)
        fi
    fi
fi


AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 lib/asleap/Makefile
                 src/Makefile
                 modules/Makefile
                 setup.py])
AC_OUTPUT
