pkcs11 = shared_library('sc-hsm-pkcs11', ['certificateobject.c','object.c','p11session.c','secretkeyobject.c','slot-pcsc.c','token-hba.c','token-starcos-dtrust.c',
'crc32.c','p11generic.c','p11slots.c','session.c','slot.c','token-sc-hsm.c','token-starcos.c',
'crypto-libcrypto.c','p11mechanisms.c','privatekeyobject.c','slot-ctapi.c','slotpool.c','token-starcos-bnotk.c','token.c',
'dataobject.c','p11objects.c','publickeyobject.c','slot-pcsc-event.c','strbpcpy.c','token-starcos-dgn.c'], 
	include_directories : core_inc,
	dependencies: [libpcsclite_dep, libcrypto_dep, libcurl_dep ],
	link_with: [ common_lib, ramoverhttp_lib ])
