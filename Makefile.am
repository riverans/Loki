# Makefile.am
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

instdir = $(pkgdatadir)
SUBDIRS =	lib modules

AUX_DIST =	install-sh

noinst_SCRIPTS = python-build loki-build
bin_SCRIPTS = loki.py

loki-build:
	$(SED) -i.bak 's#DATA_DIR="."#DATA_DIR="$(instdir)"#g' loki.py
	touch python-build

python-build:
	$(PYTHON) setup.py build
	touch python-build

python-clean:
	rm -rf *build
	rm -f py-installed-files

clean: clean-recursive python-clean

distclean: clean-recursive

python-install:
	$(PYTHON) setup.py install --prefix=$(DESTDIR)`python-config --prefix` --record py-installed-files

install-exec-local: python-install

python-uninstall:
	cat py-installed-files | xargs rm -f

uninstall-local: python-uninstall
