MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

nobase_include_HEADERS = sc-hsm/sc-hsm-pkcs11.h

SUBDIRS = common

if ENABLE_CTAPI
SUBDIRS += ctccid
nobase_include_HEADERS += ctccid/ctapi.h
endif

if ENABLE_RAM
SUBDIRS += ramoverhttp
endif

SUBDIRS += pkcs11 tests examples
