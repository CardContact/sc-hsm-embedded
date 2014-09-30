MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

lib_LTLIBRARIES = libctccid.la

AM_CPPFLAGS = -I$(top_srcdir)/src $(LIBUSB_CFLAGS) -pthread

libctccid_la_LIBADD = $(LIBUSB_LIBS)
libctccid_la_SOURCES = ctapi.c ctbcs.c usb_device.c ccidT1.c ccidAPDU.c ccid_usb.c ctccid_debug.c

libctccid_la_LDFLAGS = $(AM_LDFLAGS) \
	$(top_builddir)/src/common/libcommon.la \
	-export-symbols "$(srcdir)/libctccid.exports" \
	-module -shared -avoid-version -no-undefined -pthread
