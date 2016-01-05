MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

noinst_LTLIBRARIES = libramoverhttp.la

libramoverhttp_la_SOURCES = ramoverhttp.c

libramoverhttp_la_LIBADD = $(LIBCURL_LIBS)

AM_CPPFLAGS = -I$(top_srcdir)/src $(PCSC_CFLAGS)

bin_PROGRAMS = ram-client

ram_client_SOURCES = ram-client.c

ram_client_LDFLAGS = libramoverhttp.la
ram_client_LDADD = $(PCSC_LIBS)

