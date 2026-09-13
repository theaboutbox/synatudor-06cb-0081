tudor_cli_src = [
    'src/main.c',
    'src/cli.c',
    'src/datastore.c'
]

thread_dep = dependency('threads')
libcrypto_dep = dependency('libcrypto')
libusb_dep = dependency('libusb-1.0')

tudor_cli = executable('tudor_cli', tudor_cli_src,
    dependencies: [thread_dep, libcrypto_dep, libusb_dep, libtudor_dep],
    c_args: '-D_GNU_SOURCE',
    link_args: ['-Wl,-z,noexecstack', '-Wl,--copy-dt-needed-entries'],
    include_directories: ['src'],
    install_rpath: '$ORIGIN',
    install: true,
    install_dir: INSTALL_DIR
)

waits_test = executable('winapi-waits-test', 'tests/waits.c',
    dependencies: [thread_dep, libtudor_dep],
    include_directories: ['../libtudor/src', '../libtudor/src/winapi'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('winapi-waits', waits_test, timeout: 5)

crypt_context_test = executable('winapi-crypt-context-test',
    'tests/crypt-context.c',
    dependencies: [thread_dep, libtudor_dep, cryptbridge_dep],
    include_directories: ['../libtudor/src', '../libtudor/src/winapi'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('winapi-crypt-context', crypt_context_test, timeout: 5)

bcrypt_sha1_test = executable('bcrypt-sha1-test',
    'tests/bcrypt-sha1.c',
    dependencies: [libtudor_dep, cryptbridge_dep],
    include_directories: ['../libtudor/src', '../libtudor/src/winapi'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('bcrypt-sha1', bcrypt_sha1_test, timeout: 5)

bcrypt_ecc_test = executable('bcrypt-ecc-test',
    'tests/bcrypt-ecc.c',
    dependencies: [libtudor_dep, cryptbridge_dep],
    include_directories: ['../libtudor/src', '../libtudor/src/winapi'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('bcrypt-ecc', bcrypt_ecc_test, timeout: 10)

palcrypto_ecc_test = executable('palcrypto-ecc-test',
    'tests/palcrypto-ecc.cpp',
    dependencies: [libtudor_dep, cryptbridge_dep, libcrypto_dep],
    include_directories: ['../libtudor/src'],
    cpp_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('palcrypto-ecc', palcrypto_ecc_test,
    args: [driver_dlls[1]], timeout: 10)

loader_callsite_test = executable('loader-callsite-test',
    'tests/loader-callsite.c',
    dependencies: [libtudor_dep],
    include_directories: ['../libtudor/src'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('loader-callsite', loader_callsite_test,
    args: [driver_dlls[1]],
    timeout: 10)

winusb_borrowed_test = executable('winusb-borrowed-test',
    'tests/winusb-borrowed.c',
    dependencies: [thread_dep, libtudor_dep, libusb_dep],
    include_directories: ['../libtudor/src', '../libtudor/src/winapi'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    link_args: ['-Wl,--export-dynamic'],
    install: false)
test('winusb-borrowed', winusb_borrowed_test, timeout: 5)

strings_test = executable('winapi-strings-test', 'tests/strings.c',
    dependencies: [libtudor_dep],
    include_directories: ['../libtudor/src', '../libtudor/src/winapi'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('winapi-strings', strings_test, timeout: 5)

registry_state_test = executable('cryptbridge-registry-state-test',
    'tests/registry-state.c',
    dependencies: [cryptbridge_dep],
    include_directories: ['../subprojects/cryptbridge'],
    c_args: ['-D_GNU_SOURCE', '-UNDEBUG'],
    install: false)
test('cryptbridge-registry-state', registry_state_test, timeout: 5)
