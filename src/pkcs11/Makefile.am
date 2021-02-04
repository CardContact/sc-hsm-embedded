MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/src $(PCSC_CFLAGS)

if ENABLE_LIBCRYPTO
AM_CPPFLAGS += $(LIBCRYPTO_CFLAGS)
endif

lib_LTLIBRARIES = libsc-hsm-pkcs11.la

libsc_hsm_pkcs11_la_SOURCES = crc32.c dataobject.c object.c p11generic.c p11mechanisms.c p11objects.c \
			p11session.c p11slots.c session.c slot.c slot-ctapi.c slot-pcsc.c slot-pcsc-event.c slotpool.c strbpcpy.c \
			token.c token-sc-hsm.c certificateobject.c privatekeyobject.c publickeyobject.c \
			secretkeyobject.c \
			token-starcos.c token-starcos-bnotk.c token-starcos-dtrust.c token-starcos-dgn.c token-hba.c

if ENABLE_CTAPI
libsc_hsm_pkcs11_la_LIBADD = $(top_builddir)/src/ctccid/libctccid.la
else
libsc_hsm_pkcs11_la_LIBADD = $(PCSC_LIBS)
endif

if ENABLE_LIBCRYPTO
libsc_hsm_pkcs11_la_SOURCES += crypto-libcrypto.c
libsc_hsm_pkcs11_la_LIBADD += $(LIBCRYPTO_LIBS)
endif


libsc_hsm_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	$(top_builddir)/src/common/libcommon.la \
	-export-symbols "$(srcdir)/libpkcs11.exports" \
	-module -shared -avoid-version -no-undefined
