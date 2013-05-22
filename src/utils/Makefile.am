MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

bin_PROGRAMS = SignHash

AM_CPPFLAGS = -I$(top_srcdir)/src

SignHash_SOURCES = SignHash.c utils.c sha256.c

SignHash_LDADD = $(top_builddir)/src/ctccid/libctccid.la

