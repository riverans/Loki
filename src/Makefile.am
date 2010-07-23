# src/Makefile.am
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

INCLUDES = -I$(top_srcdir) @PCAPINC@ @DNETINC@
instdir = $(pkgdatadir)

AM_CPPFLAGS = -fpic

bin_SCRIPTS = loki.py
bin_PROGRAMS =   mpls_tunnel

mpls_tunnel_SOURCES = mpls-tunnel.c ../lib/mplstun.c
mpls_tunnel_LDADD = @DNETLIB@ @PCAPLIB@

noinst_SCRIPTS = loki-build

loki-build:
	$(SED) -i.bak 's#DATA_DIR="."#DATA_DIR="$(instdir)"#g' loki.py && $(SED) -i.bak 's#CONFIG_PATH="./etc"#CONFIG_PATH="~/.loki"#g' loki.py
	touch python-build

