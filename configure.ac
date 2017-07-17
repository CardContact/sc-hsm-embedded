# Process this file with autoconf to produce a configure script
#
# Support for em SmartCard-HSM
# (c) 2016 CardContact Systems GmbH (www.cardcontact.de)

define([PACKAGE_VERSION_MAJOR],[2])
define([PACKAGE_VERSION_MINOR],[10])

AC_INIT(sc-hsm-embedded, [PACKAGE_VERSION_MAJOR.PACKAGE_VERSION_MINOR])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE
LT_INIT
PKG_PROG_PKG_CONFIG

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

if test "${enable_ram}" = "yes"; then
	PKG_CHECK_MODULES(LIBCURL, libcurl)
fi

if test "${enable_pcsc}" = "yes"; then
	PKG_CHECK_EXISTS(
		[libpcsclite],
		[PKG_CHECK_MODULES(PCSC, libpcsclite)]
	)
	if test -z "${PCSC_CFLAGS}"; then
		# Make sure we link to the PCSC framework in OS X
		PCSC_LIBS="-framework PCSC"
	fi
else
	PKG_CHECK_MODULES(LIBUSB, libusb-1.0)
fi


AM_CONDITIONAL([ENABLE_PCSC], [test "${enable_pcsc}" = "yes"])
AM_CONDITIONAL([ENABLE_CTAPI], [test "${enable_pcsc}" != "yes"])
AM_CONDITIONAL([ENABLE_RAM], [test "${enable_ram}" = "yes"])

AC_DEFINE([VERSION_MAJOR], [PACKAGE_VERSION_MAJOR] )
AC_DEFINE([VERSION_MINOR], [PACKAGE_VERSION_MINOR] )

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/common/Makefile
    src/ctccid/Makefile
    src/pkcs11/Makefile
    src/tests/Makefile
    src/ramoverhttp/Makefile
])

AC_OUTPUT

