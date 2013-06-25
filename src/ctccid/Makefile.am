MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

lib_LTLIBRARIES = libctccid.la

AM_CPPFLAGS = $(LIBUSB_CFLAGS) -pthread

libctccid_la_LIBADD = $(LIBUSB_LIBS)
libctccid_la_SOURCES = ctapi.c ctbcs.c usb_device.c ccidT1.c ccid_usb.c ctccid_debug.c mutex.c

libctccid_la_LDFLAGS = $(AM_LDFLAGS) \
	-export-symbols "$(srcdir)/libctccid.exports" \
	-module -shared -avoid-version -no-undefined -pthread
