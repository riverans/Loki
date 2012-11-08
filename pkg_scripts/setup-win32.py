from cx_Freeze import setup, Executable
import glob
import sys
import os

sys.path.append('src')
# Use local gtk folder instead of the one in PATH that is not latest gtk
if 'gtk' in os.listdir('.'):
  sys.path.append('gtk/bin')

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
