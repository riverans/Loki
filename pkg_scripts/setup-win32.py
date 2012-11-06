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
    'base': 'Console',
    'include_files': [ 'modules' ],
#    'bin_excludes': [
#                 'iconv.dll', 'intl.dll', 'libatk-1.0-0.dll',
#                 'libgdk_pixbuf-2.0-0.dll', 'libgdk-win32-2.0-0.dll',
#                 'libgio-2.0-0.dll',
#                 'libglib-2.0-0.dll', 'libgmodule-2.0-0.dll',
#                'libgobject-2.0-0.dll', 'libgthread-2.0-0.dll',
#                 'libgtk-win32-2.0-0.dll', 'libpango-1.0-0.dll',
#                 'libpangowin32-1.0-0.dll', 'libcairo-2.dll',
#                 'libpangocairo-1.0-0.dll', 'libpangoft2-1.0-0.dll',
#                 ]
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
