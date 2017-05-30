MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

nobase_include_HEADERS = sc-hsm/sc-hsm-pkcs11.h

SUBDIRS = common pkcs11 tests

if ENABLE_ULTRALITE
SUBDIRS += ultralite 
endif

if ENABLE_CTAPI
SUBDIRS += ctccid
endif

if ENABLE_RAM
SUBDIRS += ramoverhttp
endif
