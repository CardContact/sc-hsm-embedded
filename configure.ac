# Process this file with autoconf to produce a configure script
#
# Support for the SmartCard-HSM
# (c) 2016 CardContact Systems GmbH (www.cardcontact.de)
#

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
		[AS_HELP_STRING([--enable-debug],[include debugging output])],
		[AC_DEFINE([DEBUG])],
		[])

AC_ARG_ENABLE(ctapi,
		[AS_HELP_STRING([--enable-ctapi],[enable CT-API support (disables PC/SC)])],
		[AC_DEFINE([CTAPI])],
		[enable_pcsc="yes"])

AC_ARG_ENABLE(ram,
		[AS_HELP_STRING([--enable-ram],[enable Remote Application Management (RAM)])],
		[AC_DEFINE([RAM])],
		[])

AC_ARG_ENABLE(libcrypto,
		[AS_HELP_STRING([--enable-libcrypto],[enable libcrypto for public key crypto @<:@detect@:>@])],
		,
		[enable_libcrypto="detect"]
)

AS_IF([test "${enable_ram}" = "yes"],
	[PKG_CHECK_MODULES(LIBCURL, libcurl)])

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

AS_IF([test "${enable_libcrypto}" = "detect"],
	[ PKG_CHECK_EXISTS([libcrypto], [enable_libcrypto="yes"], [enable_libcrypto="no"]) ])

# OEAP with SHA-256 MGF requires libcrypto in at least 1.0.2
AS_IF([test "${enable_libcrypto}" = "yes"],
	[ PKG_CHECK_MODULES(LIBCRYPTO, [libcrypto >= 1.0.1], AC_DEFINE(ENABLE_LIBCRYPTO)) ])

AM_CONDITIONAL([ENABLE_PCSC], [test "${enable_pcsc}" = "yes"])
AM_CONDITIONAL([ENABLE_CTAPI], [test "${enable_pcsc}" != "yes"])
AM_CONDITIONAL([ENABLE_RAM], [test "${enable_ram}" = "yes"])
AM_CONDITIONAL([ENABLE_LIBCRYPTO], [test "${enable_libcrypto}" = "yes"])

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
    src/examples/Makefile
    src/examples/key-generator/Makefile
])

AC_OUTPUT

cat <<EOF

sc-hsm-embedded configuration options:


Version:                 ${PACKAGE_VERSION}

User binaries:           $(eval eval eval echo "${bindir}")

debug support:           ${enable_debug}
PC/SC support:           ${enable_pcsc}
RAM support:             ${enable_ram}
libcrypto support:       ${enable_libcrypto}

Host:                    ${host}
Compiler:                ${CC}
Preprocessor flags:      ${CPPFLAGS}
Compiler flags:          ${CFLAGS}
Linker flags:            ${LDFLAGS}
Libraries:               ${LIBS}

LIBCRYPTO_CFLAGS:        ${LIBCRYPTO_CFLAGS}
LIBCRYPTO_LIBS:          ${LIBCRYPTO_LIBS}
LIBCURL_CFLAGS:          ${LIBCURL_CFLAGS}
LIBCURL_LIBS:            ${LIBCURL_LIBS}
PCSC_CFLAGS:             ${PCSC_CFLAGS}
PCSC_LIBS:               ${PCSC_LIBS}
LIBUSB_CFLAGS:           ${LIBUSB_CFLAGS}
LIBUSB_LIBS:             ${LIBUSB_LIBS}

EOF

