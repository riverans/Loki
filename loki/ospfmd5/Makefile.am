noinst_SCRIPTS = python-build

python-build: $(srcdir)/ospfmd5bf.c 
	$(PYTHON) setup.py build
	touch python-build

python-clean:
	rm -rf *build

clean: python-clean

distclean: clean

python-install:
	$(PYTHON) setup.py install --prefix=$(DESTDIR)$(prefix)

install-exec-local: python-install
