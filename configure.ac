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
		AC_HELP_STRING([--enable-debug],[include debugging output]),
		[CPPFLAGS="-DDEBUG"], [])

PKG_CHECK_MODULES(LIBUSB, libusb-1.0)

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/ctccid/Makefile
    src/pkcs11/Makefile
    src/tests/Makefile
    src/utils/Makefile
])

AC_OUTPUT
