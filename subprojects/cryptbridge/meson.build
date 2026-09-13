project('cryptbridge', 'c',
  version : '1.0.0',
  default_options : ['warning_level=0', 'c_std=gnu11']
)

# Vendored Wine-derived code; its warnings are not actionable here.
add_project_arguments('-w', language: 'c')

# List of source files
srcs = [
  'aes.c',
  'des.c',
  'handle.c',
  'identity_state.c',
  'implglue.c',
  'mpi.c',
  'rc2.c',
  'rc4.c',
  'rsa.c',
  'rsaenh.c',
  'registry.c',
  'registry_state.c',
  'bcrypt/bcrypt_main.c',
  'bcrypt/gnutls.c',
  'bcrypt/md2.c',
  'bcrypt/secrets.c',
  'bcrypt/sha1.c',
  'bcrypt/sha256.c',
  'bcrypt/sha512.c',
  # 'debug.c',
]

# Public headers (for installation)
headers = [
  'handle.h',
  'implglue.h',
  'tomcrypt.h',
]

openssl_dep = dependency('openssl', required: true)
gnutls = dependency('gnutls', required: true)
threads_dep = dependency('threads')

incdir = include_directories('.', 'include')

# Build shared (dynamic) library
libcryptbridge = library(
  'cryptbridge',
  srcs,
  include_directories: incdir,
  dependencies: [openssl_dep, gnutls, threads_dep],
  install: true,
  version: '1.0.0',
  soversion: '1'
)


# The bundled Wine-derived headers are exposed as system headers so that
# their internal #pragma pack juggling does not surface as warnings in the
# code that consumes them.
cryptbridge_dep = declare_dependency(
  link_with: libcryptbridge,
  include_directories: include_directories('include', is_system: true)
)

# Internal headers, for tests that exercise unexported state helpers.
cryptbridge_internal_inc = include_directories('.')

# Optionally install headers
# install_headers(headers)
#
# # Optional: define a pkg-config file (if you want)
# pkg = import('pkgconfig')
# pkg.generate(
#   libcryptbridge,
#   description: '',
#   version: meson.project_version(),
#   filebase: 'cryptbridge'
# )
#
