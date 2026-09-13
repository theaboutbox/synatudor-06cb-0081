tudor_tod_src = [
    'src/device.c',
    'src/data.c',
    'src/ipc.c',
    'src/open.c',
    'src/suspend.c',
    'src/enroll.c',
    'src/verify.c',
    'src/identify.c'
]

libfprint_tod_dep = dependency('libfprint-2-tod-1')
udev_dep = dependency('udev')
libusb_dep = dependency('libusb-1.0')
gusb_dep = dependency('gusb')
json_glib_dep = dependency('json-glib-1.0')

tudor_tod = shared_module('tudor_tod',
    sources: tudor_tod_src,
    c_args: ['-D_GNU_SOURCE', '-Wno-missing-braces'],
    dependencies: [libfprint_tod_dep, libusb_dep, gusb_dep, json_glib_dep],
    include_directories: [libtudor_inc, tudor_host_inc, tudor_host_launcher_inc],
    install: true,
    install_dir: libfprint_tod_dep.get_variable(pkgconfig: 'tod_driversdir')
)

install_data('60-tudor-libfprint-tod.rules',
    install_dir: join_paths(udev_dep.get_variable(pkgconfig: 'udevdir'), 'rules.d'),
)

# The fixture includes open.c to exercise its actual initialization failure
# and disposal paths without invoking a USB probe.
cleanup_test_src = ['tests/host-cleanup.c']
foreach source : tudor_tod_src
    if source != 'src/open.c'
        cleanup_test_src += source
    endif
endforeach
cleanup_test = executable('tudor-host-cleanup-test',
    sources: cleanup_test_src,
    c_args: ['-D_GNU_SOURCE', '-Wno-missing-braces'],
    dependencies: [libfprint_tod_dep, dependency('libfprint-2'),
                   libusb_dep, gusb_dep, json_glib_dep],
    include_directories: [libtudor_inc, tudor_host_inc, tudor_host_launcher_inc],
    install: false,
)
test('tudor-host-cleanup', cleanup_test, timeout: 15,
     env: ['GIO_USE_VFS=local'])
