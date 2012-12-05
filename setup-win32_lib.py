# setup.py.in
# Copyright 2010 Daniel Mende <dmende@ernw.de> 

from distutils.core import setup, Extension

ospfmd5bf_srcs = [ 'loki_bindings/ospfmd5/ospfmd5bf.c', 'lib/md5.c' ]
ospfmd5bf_incdirs = [ '.' ]
ospfmd5bf_libdirs = []
ospfmd5bf_libs = []
ospfmd5bf_extargs = []
ospfmd5bf_extobj = []

tcpmd5bf_srcs = [ 'loki_bindings/tcpmd5/tcpmd5bf.c', 'lib/md5.c' ]
tcpmd5bf_incdirs = [ '.' ]
tcpmd5bf_libdirs = []
tcpmd5bf_libs = ['ws2_32']
tcpmd5bf_extargs = []
tcpmd5bf_extobj = []

#~ mplsred_srcs = [ 'loki_bindings/mpls/mplsred.c', 'lib/mplsred.c' ]
#~ mplsred_incdirs = [ '.', 'C:\\Users\\greif\\Downloads\\libdnet-1.12\\libdnet-1.12\\include' ]
#~ mplsred_libs = ['wpcap', 'dnet', 'ws2_32', 'packet', 'iphlpapi']
#~ mplsred_libdirs = [ 'C:\\Users\\greif\\Downloads\\libdnet-1.11-win32\\libdnet-1.11-win32\\lib',
                     #~ 'C:\\Users\\greif\\Downloads\\libdnet-1.12\\WpdPack\\Lib' ]
#~ mplsred_extargs = []
#~ mplsred_extobj = []


ospfmd5bf = Extension(  'loki_bindings.ospfmd5.ospfmd5bf',
                        ospfmd5bf_srcs,
                        include_dirs=ospfmd5bf_incdirs,
                        libraries=ospfmd5bf_libs,
                        extra_compile_args=ospfmd5bf_extargs,
                        extra_objects=ospfmd5bf_extobj)

tcpmd5bf = Extension(   'loki_bindings.tcpmd5.tcpmd5bf',
                        tcpmd5bf_srcs,
                        include_dirs=tcpmd5bf_incdirs,
                        libraries=tcpmd5bf_libs,
                        extra_compile_args=tcpmd5bf_extargs,
                        extra_objects=tcpmd5bf_extobj)

#~ mplsred = Extension(    'loki_bindings.mpls.mplsred',
                        #~ mplsred_srcs,
                        #~ include_dirs=mplsred_incdirs,
                        #~ libraries=mplsred_libs,
                        #~ library_dirs=mplsred_libdirs,
                        #~ extra_compile_args=mplsred_extargs,
                        #~ extra_objects=mplsred_extobj)

setup(name='loki_bindings',
      version='0.2.7',
      description='',
      author='Daniel Mende',
      author_email='dmende@ernw.de',
      url='https://c0decafe.de',
      packages=['loki_bindings', 'loki_bindings.asleap', 'loki_bindings.ospfmd5', 'loki_bindings.tcpmd5', 'loki_bindings.mpls'],
      ext_modules=[ospfmd5bf, tcpmd5bf]
     )
