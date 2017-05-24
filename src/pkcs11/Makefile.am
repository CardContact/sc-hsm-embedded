MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/src $(PCSC_CFLAGS)

lib_LTLIBRARIES = libsc-hsm-pkcs11.la

libsc_hsm_pkcs11_la_SOURCES = bytestring.c bytebuffer.c crc32.c dataobject.c debug.c object.c p11generic.c p11mechanisms.c p11objects.c \
			p11session.c p11slots.c session.c slot.c slot-ctapi.c slot-pcsc.c slotpool.c strbpcpy.c \
			token.c token-sc-hsm.c certificateobject.c privatekeyobject.c publickeyobject.c asn1.c cvc.c pkcs15.c \
			token-starcos.c token-starcos-bnotk.c token-starcos-dtrust.c token-starcos-32-signtrust.c token-starcos-35-signtrust.c \
			token-starcos-dgn.c

if ENABLE_CTAPI
libsc_hsm_pkcs11_la_LIBADD = $(top_builddir)/src/ctccid/libctccid.la
endif

if ENABLE_PCSC
libsc_hsm_pkcs11_la_LIBADD = $(PCSC_LIBS)
endif

libsc_hsm_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	$(top_builddir)/src/common/libcommon.la \
	-export-symbols "$(srcdir)/libpkcs11.exports" \
	-module -shared -avoid-version -no-undefined
