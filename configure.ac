# Process this file with autoconf to produce a configure script
#
# Support for em SmartCard-HSM
# (c) 2013 CardContact Software & System Consulting (www.cardcontact.de)

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

PKG_CHECK_MODULES(LIBUSB, libusb-1.0)

if test "${enable_pcsc}" = "yes"; then
	PKG_CHECK_MODULES(PCSC, libpcsclite)
fi

AM_CONDITIONAL([ENABLE_PCSC], [test "${enable_pcsc}" = "yes"])
AM_CONDITIONAL([ENABLE_CTAPI], [test "${enable_pcsc}" != "yes"])

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/ctccid/Makefile
    src/pkcs11/Makefile
    src/tests/Makefile
    src/ultralite/Makefile
])

AC_OUTPUT

