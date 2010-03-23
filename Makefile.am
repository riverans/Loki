# Makefile.am
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

SUBDIRS =	lib

AUX_DIST =	install-sh

noinst_SCRIPTS = python-build

python-build:
	$(PYTHON) setup.py build
	touch python-build

python-clean:
	rm -rf *build

clean: clean-recursive python-clean

distclean: clean-recursive

python-install:
	$(PYTHON) setup.py install --prefix=$(DESTDIR)$(prefix)

install-exec-local: python-install
