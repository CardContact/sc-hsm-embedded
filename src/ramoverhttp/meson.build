ramoverhttp_lib = static_library(['ramoverhttp', 'ramoverhttp.c'], include_directories : core_inc)

executable('ram-client', 'ram-client.c',
	include_directories: core_inc,
	dependencies: [libpcsclite_dep, libcurl_dep],
	link_with: ramoverhttp_lib,
	install : true
)

