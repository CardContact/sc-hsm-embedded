MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

noinst_PROGRAMS = sc-hsm-pkcs11-test

AM_CPPFLAGS = -I$(top_srcdir)/src

if ENABLE_CTAPI
noinst_PROGRAMS += ctccid-test

ctccid_test_SOURCES = ctccid-test.c

ctccid_test_LDADD = $(top_builddir)/src/ctccid/libctccid.la
endif

sc_hsm_pkcs11_test_SOURCES = sc-hsm-pkcs11-test.c

sc_hsm_pkcs11_test_LDFLAGS = -ldl -lpthread $(top_builddir)/src/common/libcommon.la
