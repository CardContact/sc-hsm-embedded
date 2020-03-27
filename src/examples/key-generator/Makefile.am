MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if ENABLE_CTAPI
noinst_PROGRAMS = key-generator

AM_CPPFLAGS = -I$(top_srcdir)/src

key_generator_SOURCES = key-generator.c sc-hsm-cardservice.c

key_generator_LDADD = $(top_builddir)/src/ctccid/libctccid.la
endif
