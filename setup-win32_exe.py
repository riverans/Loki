from cx_Freeze import setup, Executable
import glob
import sys
import os

options = {
  'build_exe': {
    'includes': [ 'gtk.keysyms', 'dumbdbm', 'dbhash', 'new', 'numbers',
                  'hashlib', 'gtk.glade', 'hmac', 'IPy', 'dnet' ],
#    'base': 'Console',
    'base': 'Win32GUI',
    'include_files': [ 'modules' ]
    }
  }

setup(
  name='Loki',
  version='0.2.7',
  description='Loki',
  author='Daniel Mende',
  url='http://codecafe.de/loki.html',
  license='GPL',
  options=options,
  executables=[Executable('src/loki.py')],
) 

#os.system("mt.exe -manifest pkg_scripts\\loki.exe.manifest -outputresource:\"build\\exe.win32-2.6\\loki.exe;#1\"")
