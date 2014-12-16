# src/Makefile.am
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

instdir = $(pkgdatadir)

AM_CPPFLAGS = -fpic -I$(top_srcdir) @PCAPINC@ @DNETINC@

bin_SCRIPTS = @LOKI_GTK@ @LOKI_URWID@
EXTRA_SCRIPTS = 
bin_PROGRAMS = mpls_tunnel pppoe_tunnel

mpls_tunnel_SOURCES = mpls-tunnel.c ../lib/mplstun.c
mpls_tunnel_LDADD = @DNETLIB@ @PCAPLIB@

pppoe_tunnel_SOURCES = pppoe-tunnel.c ../lib/pppoetun.c
pppoe_tunnel_LDADD = @DNETLIB@ @PCAPLIB@

noinst_SCRIPTS = loki-build

loki-build:
	$(SED) -i.bak 's#DATA_DIR="."#DATA_DIR="$(instdir)"#g' loki.py
	touch python-build

