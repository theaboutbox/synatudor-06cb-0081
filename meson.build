project('synaTudor', ['c', 'cpp'],
    version: '1.0.0',
    meson_version: '>= 0.57.0',
    default_options: ['c_std=gnu17']
)

INSTALL_DIR = '/usr/bin/tudor'

subdir('libtudor')
subdir('cli')
subdir('tudor-host')
subdir('tudor-host-launcher')
if get_option('TOD')
    subdir('libfprint-tod')
endif
