# Process this file with autoconf to produce a configure script
#
# Support for em SmartCard-HSM
# (c) 2016 CardContact Systems GmbH (www.cardcontact.de)

AC_INIT(sc-hsm-embedded, 1.0)
AM_INIT_AUTOMAKE
LT_INIT

# Checks for programs.
AC_PROG_CC

AC_ARG_ENABLE(debug,
		AS_HELP_STRING([--enable-debug],[include debugging output]),
		[CPPFLAGS="$CPPFLAGS -DDEBUG"], [])

AC_ARG_ENABLE(ctapi,
		AS_HELP_STRING([--enable-ctapi],[enable CT-API support (disables PC/SC)]),
		[CPPFLAGS="$CPPFLAGS -DCTAPI"], [enable_pcsc="yes"])

AC_ARG_ENABLE(ram,
		AS_HELP_STRING([--enable-ram],[enable Remote Application Management (RAM)]),
		[CPPFLAGS="$CPPFLAGS -DRAM" enable_ram="yes"], [])

PKG_CHECK_MODULES(LIBUSB, libusb-1.0)

if test "${enable_ram}" = "yes"; then
	PKG_CHECK_MODULES(LIBCURL, libcurl)
fi
if test "${enable_pcsc}" = "yes"; then
	PKG_CHECK_MODULES(PCSC, libpcsclite)
fi

AM_CONDITIONAL([ENABLE_PCSC], [test "${enable_pcsc}" = "yes"])
AM_CONDITIONAL([ENABLE_CTAPI], [test "${enable_pcsc}" != "yes"])
AM_CONDITIONAL([ENABLE_RAM], [test "${enable_ram}" = "yes"])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/common/Makefile
    src/ctccid/Makefile
    src/pkcs11/Makefile
    src/tests/Makefile
    src/ultralite/Makefile
    src/ramoverhttp/Makefile
])

AC_OUTPUT

