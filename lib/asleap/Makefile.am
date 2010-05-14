# lib/asleap/Makefile.am
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

INCLUDES = 			-I$(top_srcdir)/lib/asleap/ @PCAPINC@

AM_CPPFLAGS = 		-fpic -U_FORTIFY_SOURCE

noinst_PROGRAMS =   asleap genkeys

asleap_SOURCES =    asleap.c sha1.c common.c utils.c md4.c
asleap_LDADD = 		@PCAPLIB@

genkeys_SOURCES =   genkeys.c md4.c common.c utils.c
