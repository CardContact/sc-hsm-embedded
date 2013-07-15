MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

bin_PROGRAMS = sc-hsm-ultralite-test sc-hsm-ultralite-sample

AM_CPPFLAGS = -I$(top_srcdir)/src $(PCSC_CFLAGS)

sc_hsm_ultralite_test_SOURCES = sc-hsm-ultralite-test.c sc-hsm-ultralite.c utils.c sha256.c

sc_hsm_ultralite_test_LDADD = $(top_builddir)/src/ctccid/libctccid.la $(PCSC_LIBS)

sc_hsm_ultralite_sample_SOURCES = sc-hsm-ultralite-sample.c sc-hsm-ultralite.c utils.c sha256.c

sc_hsm_ultralite_sample_LDADD = $(top_builddir)/src/ctccid/libctccid.la $(PCSC_LIBS)
 