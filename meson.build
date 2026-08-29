project('sc-hsm-embedded', 'c',
  version : '2.13',
  default_options : ['warning_level=3'])

# libusb_dep = dependency('libusb-1.0', required: true)

libpcsclite_dep_test = dependency('libpcsclite', required: false)

if libpcsclite_dep_test.found()
  libpcsclite_dep = libpcsclite_dep_test
else
  applepcsc = dependency('PCSC', required: false)
  if applepcsc.found()
    libpcsclite_dep = applepcsc
  else
    libpcsclite_dep = meson.get_compiler('c').find_library('winscard', required: true)
  endif
endif

libcurl_dep = dependency('libcurl')

libcrypto_dep = dependency('libcrypto')

compiler = meson.get_compiler('c')

if compiler.has_function('memset_s', prefix : '#include <string.h>')
  add_project_arguments('-DHAVE_MEMSET_S', language: 'c')
endif

core_inc = include_directories('src')

subdir('src')
