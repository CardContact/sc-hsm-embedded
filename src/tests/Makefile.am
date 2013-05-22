MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

noinst_PROGRAMS = testctapi testpkcs11

AM_CPPFLAGS = -I$(top_srcdir)/src

testctapi_SOURCES = testctapi.c

testctapi_LDADD = $(top_builddir)/src/ctccid/libctccid.la

testpkcs11_SOURCES = testpkcs11.c

testpkcs11_LDFLAGS = -ldl
