project('sc-hsm-embedded', 'c',
  version : '2.13',
  default_options : ['warning_level=3'])

# curlproj = subproject('curl')

# libusb_dep = dependency('libusb-1.0', required: true)

libpcsclite_dep_test = dependency('libpcsclite', required: false)

if libpcsclite_dep_test.found()
  libpcsclite_dep = libpcsclite_dep_test
else
  libpcsclite_dep = meson.get_compiler('c').find_library('winscard', required: true)
endif

libcurl_dep = dependency('libcurl', fallback: [ 'curl', 'curl_dep'] )

core_inc = include_directories('src')

subdir('src')
