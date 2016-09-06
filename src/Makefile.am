MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

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
