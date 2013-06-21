MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CPPFLAGS = -I$(top_srcdir)/src $(PCSC_CFLAGS)

lib_LTLIBRARIES = libsc-hsm-pkcs11.la

libsc_hsm_pkcs11_la_SOURCES = dataobject.c debug.c object.c p11generic.c p11mechanisms.c p11objects.c \
			p11session.c p11slots.c session.c slot.c slot-ctapi.c slot-pcsc.c slotpool.c strbpcpy.c \
			token.c token-sc-hsm.c certificateobject.c privatekeyobject.c asn1.c pkcs15.c

# libsc_hsm_pkcs11_la_LIBADD = /usr/local/lib/libcteco5000.la
libsc_hsm_pkcs11_la_LIBADD = $(top_builddir)/src/ctccid/libctccid.la $(PCSC_LIBS)

libsc_hsm_pkcs11_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/libpkcs11.exports" \
	-module -shared -avoid-version -no-undefined
