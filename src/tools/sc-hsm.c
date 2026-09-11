/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2026, CardContact Systems GmbH, Minden, Germany
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of CardContact Systems GmbH nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CardContact Systems GmbH BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @file sc-hsm.c
 * @author Andreas Schwier
 * @brief Tool to manage a SmartCard-HSM
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/stat.h>

#ifndef _WIN32

#include <unistd.h>
#include <getopt.h>
#include <sys/wait.h>
#include <dlfcn.h>
#define LIB_HANDLE void*
#define P11LIBNAME "/usr/local/lib/libsc-hsm-pkcs11.so"

#else

#include <windows.h>
#include <malloc.h>
#define LIB_HANDLE HMODULE
#define P11LIBNAME "sc-hsm-pkcs11.dll"

#define dlopen(fn, flag) LoadLibrary(fn)
#define dlclose(h) FreeLibrary(h)
#define dlsym(h, n) GetProcAddress(h, n)
#define pthread_t HANDLE
#define pthread_create(t, a, f, p) (*t = CreateThread(0, 0, f, p, 0, 0), *t ? 0 : GetLastError())
#define pthread_join(t, s) WaitForSingleObject(t, INFINITE)
#define pthread_exit(r) ExitThread(0)
#define pthread_attr_t int
#define pthread_attr_init(a)
#define pthread_attr_setdetachstate(a, f)
#define pthread_attr_destroy(a)

char* dlerror()
{
	char* msg = "UNKNOWN";
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, (char*)&msg, 0, 0);
	return msg;
}

size_t getline(char** pp, size_t* pl, FILE* f)
{
	char buf[256];
	buf[0] = 0;
	fgets(buf, sizeof(buf), f);
	*pl = strlen(buf) + 1;
	if (*pp)
		free(*pp);
	*pp = (char*)malloc(*pl);
	if (*pp == 0) {
		printf("malloc(%zd) failed.", *pl);
		exit(1);
	}
	memcpy(*pp, buf, *pl);
	return *pl - 1;
}

#endif /* _WIN32 */

#include <common/asn1.h>
#include <common/cvc.h>


enum {
	OPT_SO_PIN = 0x100,
	OPT_PIN,
	OPT_TRANSPORT_PIN,
	OPT_RETRY,
	OPT_NO_RRC,
	OPT_NO_PIN_RESET,
	OPT_REPLACE_PKA_KEY,
	OPT_REQUIRE_PKA_AND_PIN,
	OPT_KEY_USE_COUNTER,
	OPT_CREATE_DKEK_KEY_DOMAIN,
	OPT_DELETE_KEY_DOMAIN,
	OPT_CLEAR_KEK,
	OPT_BIO1,
	OPT_BIO2,
	OPT_PASSWORD,
	OPT_PASSWORD_SHARES_THRESHOLD,
	OPT_PASSWORD_SHARES_TOTAL
};

static const struct option options[] = {
	{ "module",			1, NULL,		'm' },
	{ "verbose",			1, NULL,		'v' },
	{ "login",			0, NULL,		'l' },
	{ "pin",			1, NULL,		'p' },
	{ NULL, 0, NULL, 0 }
};



static const char *option_help[] = {
	"Select PKCS#11 module",
	"Increase verbose mode level",
	"Log into token",
	"Define PIN to use for login",
};



void usage()
{
	printf("sc-hsm [options]\n");

	for (int i = 0; options[i].name; i++) {
		char buf[40];
		const char *arg_str;

		/* Skip "hidden" options */
		if (option_help[i] == NULL)
			continue;

		switch (options[i].has_arg) {
		case 1:
			arg_str = " <arg>";
			break;
		case 2:
			arg_str = " [arg]";
			break;
		default:
			arg_str = "";
			break;
		}
		if (isascii(options[i].val) &&
		    isprint(options[i].val) && !isspace(options[i].val))
			sprintf(buf, "-%c, --%s%s", options[i].val, options[i].name, arg_str);
		else
			sprintf(buf, "    --%s%s", options[i].name, arg_str);

		/* print the line - wrap if necessary */
		if (strlen(buf) > 28) {
			printf("  %s\n", buf);
			buf[0] = '\0';
		}
		printf("  %-28s  %s\n", buf, option_help[i]);
	}
}



#include <pkcs11/cryptoki.h>
#include <sc-hsm/sc-hsm-pkcs11.h>

struct id2name_t {
	unsigned long       id;
	char                *name;
	unsigned long       attr;
};

struct id2name_t p11CKRName[] = {
		{ CKR_CANCEL                            , "CKR_CANCEL", 0 },
		{ CKR_HOST_MEMORY                       , "CKR_HOST_MEMORY", 0 },
		{ CKR_SLOT_ID_INVALID                   , "CKR_SLOT_ID_INVALID", 0 },
		{ CKR_GENERAL_ERROR                     , "CKR_GENERAL_ERROR", 0 },
		{ CKR_FUNCTION_FAILED                   , "CKR_FUNCTION_FAILED", 0 },
		{ CKR_ARGUMENTS_BAD                     , "CKR_ARGUMENTS_BAD", 0 },
		{ CKR_NO_EVENT                          , "CKR_NO_EVENT", 0 },
		{ CKR_NEED_TO_CREATE_THREADS            , "CKR_NEED_TO_CREATE_THREADS", 0 },
		{ CKR_CANT_LOCK                         , "CKR_CANT_LOCK", 0 },
		{ CKR_ATTRIBUTE_READ_ONLY               , "CKR_ATTRIBUTE_READ_ONLY", 0 },
		{ CKR_ATTRIBUTE_SENSITIVE               , "CKR_ATTRIBUTE_SENSITIVE", 0 },
		{ CKR_ATTRIBUTE_TYPE_INVALID            , "CKR_ATTRIBUTE_TYPE_INVALID", 0 },
		{ CKR_ATTRIBUTE_VALUE_INVALID           , "CKR_ATTRIBUTE_VALUE_INVALID", 0 },
		{ CKR_DATA_INVALID                      , "CKR_DATA_INVALID", 0 },
		{ CKR_DATA_LEN_RANGE                    , "CKR_DATA_LEN_RANGE", 0 },
		{ CKR_DEVICE_ERROR                      , "CKR_DEVICE_ERROR", 0 },
		{ CKR_DEVICE_MEMORY                     , "CKR_DEVICE_MEMORY", 0 },
		{ CKR_DEVICE_REMOVED                    , "CKR_DEVICE_REMOVED", 0 },
		{ CKR_ENCRYPTED_DATA_INVALID            , "CKR_ENCRYPTED_DATA_INVALID", 0 },
		{ CKR_ENCRYPTED_DATA_LEN_RANGE          , "CKR_ENCRYPTED_DATA_LEN_RANGE", 0 },
		{ CKR_FUNCTION_CANCELED                 , "CKR_FUNCTION_CANCELED", 0 },
		{ CKR_FUNCTION_NOT_PARALLEL             , "CKR_FUNCTION_NOT_PARALLEL", 0 },
		{ CKR_FUNCTION_NOT_SUPPORTED            , "CKR_FUNCTION_NOT_SUPPORTED", 0 },
		{ CKR_KEY_HANDLE_INVALID                , "CKR_KEY_HANDLE_INVALID", 0 },
		{ CKR_KEY_SIZE_RANGE                    , "CKR_KEY_SIZE_RANGE", 0 },
		{ CKR_KEY_TYPE_INCONSISTENT             , "CKR_KEY_TYPE_INCONSISTENT", 0 },
		{ CKR_KEY_NOT_NEEDED                    , "CKR_KEY_NOT_NEEDED", 0 },
		{ CKR_KEY_CHANGED                       , "CKR_KEY_CHANGED", 0 },
		{ CKR_KEY_NEEDED                        , "CKR_KEY_NEEDED", 0 },
		{ CKR_KEY_INDIGESTIBLE                  , "CKR_KEY_INDIGESTIBLE", 0 },
		{ CKR_KEY_FUNCTION_NOT_PERMITTED        , "CKR_KEY_FUNCTION_NOT_PERMITTED", 0 },
		{ CKR_KEY_NOT_WRAPPABLE                 , "CKR_KEY_NOT_WRAPPABLE", 0 },
		{ CKR_KEY_UNEXTRACTABLE                 , "CKR_KEY_UNEXTRACTABLE", 0 },
		{ CKR_MECHANISM_INVALID                 , "CKR_MECHANISM_INVALID", 0 },
		{ CKR_MECHANISM_PARAM_INVALID           , "CKR_MECHANISM_PARAM_INVALID", 0 },
		{ CKR_OBJECT_HANDLE_INVALID             , "CKR_OBJECT_HANDLE_INVALID", 0 },
		{ CKR_OPERATION_ACTIVE                  , "CKR_OPERATION_ACTIVE", 0 },
		{ CKR_OPERATION_NOT_INITIALIZED         , "CKR_OPERATION_NOT_INITIALIZED", 0 },
		{ CKR_PIN_INCORRECT                     , "CKR_PIN_INCORRECT", 0 },
		{ CKR_PIN_INVALID                       , "CKR_PIN_INVALID", 0 },
		{ CKR_PIN_LEN_RANGE                     , "CKR_PIN_LEN_RANGE", 0 },
		{ CKR_PIN_EXPIRED                       , "CKR_PIN_EXPIRED", 0 },
		{ CKR_PIN_LOCKED                        , "CKR_PIN_LOCKED", 0 },
		{ CKR_SESSION_CLOSED                    , "CKR_SESSION_CLOSED", 0 },
		{ CKR_SESSION_COUNT                     , "CKR_SESSION_COUNT", 0 },
		{ CKR_SESSION_HANDLE_INVALID            , "CKR_SESSION_HANDLE_INVALID", 0 },
		{ CKR_SESSION_PARALLEL_NOT_SUPPORTED    , "CKR_SESSION_PARALLEL_NOT_SUPPORTED", 0 },
		{ CKR_SESSION_READ_ONLY                 , "CKR_SESSION_READ_ONLY", 0 },
		{ CKR_SESSION_EXISTS                    , "CKR_SESSION_EXISTS", 0 },
		{ CKR_SESSION_READ_ONLY_EXISTS          , "CKR_SESSION_READ_ONLY_EXISTS", 0 },
		{ CKR_SESSION_READ_WRITE_SO_EXISTS      , "CKR_SESSION_READ_WRITE_SO_EXISTS", 0 },
		{ CKR_SIGNATURE_INVALID                 , "CKR_SIGNATURE_INVALID", 0 },
		{ CKR_SIGNATURE_LEN_RANGE               , "CKR_SIGNATURE_LEN_RANGE", 0 },
		{ CKR_TEMPLATE_INCOMPLETE               , "CKR_TEMPLATE_INCOMPLETE", 0 },
		{ CKR_TEMPLATE_INCONSISTENT             , "CKR_TEMPLATE_INCONSISTENT", 0 },
		{ CKR_TOKEN_NOT_PRESENT                 , "CKR_TOKEN_NOT_PRESENT", 0 },
		{ CKR_TOKEN_NOT_RECOGNIZED              , "CKR_TOKEN_NOT_RECOGNIZED", 0 },
		{ CKR_TOKEN_WRITE_PROTECTED             , "CKR_TOKEN_WRITE_PROTECTED", 0 },
		{ CKR_UNWRAPPING_KEY_HANDLE_INVALID     , "CKR_UNWRAPPING_KEY_HANDLE_INVALID", 0 },
		{ CKR_UNWRAPPING_KEY_SIZE_RANGE         , "CKR_UNWRAPPING_KEY_SIZE_RANGE", 0 },
		{ CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  , "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT", 0 },
		{ CKR_USER_ALREADY_LOGGED_IN            , "CKR_USER_ALREADY_LOGGED_IN", 0 },
		{ CKR_USER_NOT_LOGGED_IN                , "CKR_USER_NOT_LOGGED_IN", 0 },
		{ CKR_USER_PIN_NOT_INITIALIZED          , "CKR_USER_PIN_NOT_INITIALIZED", 0 },
		{ CKR_USER_TYPE_INVALID                 , "CKR_USER_TYPE_INVALID", 0 },
		{ CKR_USER_ANOTHER_ALREADY_LOGGED_IN    , "CKR_USER_ANOTHER_ALREADY_LOGGED_IN", 0 },
		{ CKR_USER_TOO_MANY_TYPES               , "CKR_USER_TOO_MANY_TYPES", 0 },
		{ CKR_WRAPPED_KEY_INVALID               , "CKR_WRAPPED_KEY_INVALID", 0 },
		{ CKR_WRAPPED_KEY_LEN_RANGE             , "CKR_WRAPPED_KEY_LEN_RANGE", 0 },
		{ CKR_WRAPPING_KEY_HANDLE_INVALID       , "CKR_WRAPPING_KEY_HANDLE_INVALID", 0 },
		{ CKR_WRAPPING_KEY_SIZE_RANGE           , "CKR_WRAPPING_KEY_SIZE_RANGE", 0 },
		{ CKR_WRAPPING_KEY_TYPE_INCONSISTENT    , "CKR_WRAPPING_KEY_TYPE_INCONSISTENT", 0 },
		{ CKR_RANDOM_SEED_NOT_SUPPORTED         , "CKR_RANDOM_SEED_NOT_SUPPORTED", 0 },
		{ CKR_RANDOM_NO_RNG                     , "CKR_RANDOM_NO_RNG", 0 },
		{ CKR_DOMAIN_PARAMS_INVALID             , "CKR_DOMAIN_PARAMS_INVALID", 0 },
		{ CKR_BUFFER_TOO_SMALL                  , "CKR_BUFFER_TOO_SMALL", 0 },
		{ CKR_SAVED_STATE_INVALID               , "CKR_SAVED_STATE_INVALID", 0 },
		{ CKR_INFORMATION_SENSITIVE             , "CKR_INFORMATION_SENSITIVE", 0 },
		{ CKR_STATE_UNSAVEABLE                  , "CKR_STATE_UNSAVEABLE", 0 },
		{ CKR_CRYPTOKI_NOT_INITIALIZED          , "CKR_CRYPTOKI_NOT_INITIALIZED", 0 },
		{ CKR_CRYPTOKI_ALREADY_INITIALIZED      , "CKR_CRYPTOKI_ALREADY_INITIALIZED", 0 },
		{ CKR_MUTEX_BAD                         , "CKR_MUTEX_BAD", 0 },
		{ CKR_MUTEX_NOT_LOCKED                  , "CKR_MUTEX_NOT_LOCKED", 0 },
		{ CKR_OK                                , "CKR_OK", 0 },
		{ 0, NULL, 0 }
};



#define CKT_BBOOL       1
#define CKT_BIN         2
#define CKT_DATE        3
#define CKT_LONG        4
#define CKT_ULONG       5

#define P11CKA			71

struct id2name_t p11CKAName[P11CKA + 1] = {
		{ CKA_CLASS                              , "CKA_CLASS", CKT_LONG },
		{ CKA_TOKEN                              , "CKA_TOKEN", CKT_BBOOL },
		{ CKA_PRIVATE                            , "CKA_PRIVATE", CKT_BBOOL },
		{ CKA_LABEL                              , "CKA_LABEL", 0 },
		{ CKA_APPLICATION                        , "CKA_APPLICATION", 0 },
		{ CKA_VALUE                              , "CKA_VALUE", CKT_BIN },
		{ CKA_OBJECT_ID                          , "CKA_OBJECT_ID", 0 },
		{ CKA_CERTIFICATE_TYPE                   , "CKA_CERTIFICATE_TYPE", CKT_ULONG },
		{ CKA_CERTIFICATE_CATEGORY               , "CKA_CERTIFICATE_CATEGORY", CKT_ULONG },
		{ CKA_ISSUER                             , "CKA_ISSUER", 0 },
		{ CKA_SERIAL_NUMBER                      , "CKA_SERIAL_NUMBER", 0 },
		{ CKA_AC_ISSUER                          , "CKA_AC_ISSUER", 0 },
		{ CKA_OWNER                              , "CKA_OWNER", 0 },
		{ CKA_ATTR_TYPES                         , "CKA_ATTR_TYPES", 0 },
		{ CKA_TRUSTED                            , "CKA_TRUSTED", CKT_BBOOL },
		{ CKA_KEY_TYPE                           , "CKA_KEY_TYPE", 0 },
		{ CKA_SUBJECT                            , "CKA_SUBJECT", 0 },
		{ CKA_ID                                 , "CKA_ID", CKT_BIN },
		{ CKA_SENSITIVE                          , "CKA_SENSITIVE", CKT_BBOOL },
		{ CKA_ENCRYPT                            , "CKA_ENCRYPT", CKT_BBOOL },
		{ CKA_DECRYPT                            , "CKA_DECRYPT", CKT_BBOOL },
		{ CKA_WRAP                               , "CKA_WRAP", CKT_BBOOL },
		{ CKA_UNWRAP                             , "CKA_UNWRAP", CKT_BBOOL },
		{ CKA_SIGN                               , "CKA_SIGN", CKT_BBOOL },
		{ CKA_SIGN_RECOVER                       , "CKA_SIGN_RECOVER", CKT_BBOOL },
		{ CKA_VERIFY                             , "CKA_VERIFY", CKT_BBOOL },
		{ CKA_VERIFY_RECOVER                     , "CKA_VERIFY_RECOVER", CKT_BBOOL },
		{ CKA_DERIVE                             , "CKA_DERIVE", CKT_BBOOL },
		{ CKA_START_DATE                         , "CKA_START_DATE", CKT_DATE },
		{ CKA_END_DATE                           , "CKA_END_DATE", CKT_DATE },
		{ CKA_MODULUS                            , "CKA_MODULUS", 0 },
		{ CKA_MODULUS_BITS                       , "CKA_MODULUS_BITS", CKT_ULONG },
		{ CKA_PUBLIC_EXPONENT                    , "CKA_PUBLIC_EXPONENT", 0 },
		{ CKA_PRIVATE_EXPONENT                   , "CKA_PRIVATE_EXPONENT", 0 },
		{ CKA_PRIME_1                            , "CKA_PRIME_1", 0 },
		{ CKA_PRIME_2                            , "CKA_PRIME_2", 0 },
		{ CKA_EXPONENT_1                         , "CKA_EXPONENT_1", 0 },
		{ CKA_EXPONENT_2                         , "CKA_EXPONENT_2", 0 },
		{ CKA_COEFFICIENT                        , "CKA_COEFFICIENT", 0 },
		{ CKA_PRIME                              , "CKA_PRIME", 0 },
		{ CKA_SUBPRIME                           , "CKA_SUBPRIME", 0 },
		{ CKA_BASE                               , "CKA_BASE", 0 },
		{ CKA_PRIME_BITS                         , "CKA_PRIME_BITS", 0 },
		{ CKA_SUBPRIME_BITS                      , "CKA_SUBPRIME_BITS", 0 },
		{ CKA_VALUE_BITS                         , "CKA_VALUE_BITS", 0 },
		{ CKA_VALUE_LEN                          , "CKA_VALUE_LEN", CKT_LONG },
		{ CKA_EXTRACTABLE                        , "CKA_EXTRACTABLE", CKT_BBOOL },
		{ CKA_LOCAL                              , "CKA_LOCAL", CKT_BBOOL },
		{ CKA_NEVER_EXTRACTABLE                  , "CKA_NEVER_EXTRACTABLE", CKT_BBOOL },
		{ CKA_ALWAYS_SENSITIVE                   , "CKA_ALWAYS_SENSITIVE", CKT_BBOOL },
		{ CKA_KEY_GEN_MECHANISM                  , "CKA_KEY_GEN_MECHANISM", CKT_LONG },
		{ CKA_MODIFIABLE                         , "CKA_MODIFIABLE", CKT_BBOOL },
		{ CKA_EC_PARAMS                          , "CKA_EC_PARAMS", 0 },
		{ CKA_EC_POINT                           , "CKA_EC_POINT", 0 },
		{ CKA_SECONDARY_AUTH                     , "CKA_SECONDARY_AUTH", 0 },
		{ CKA_AUTH_PIN_FLAGS                     , "CKA_AUTH_PIN_FLAGS", 0 },
		{ CKA_HW_FEATURE_TYPE                    , "CKA_HW_FEATURE_TYPE", 0 },
		{ CKA_RESET_ON_INIT                      , "CKA_RESET_ON_INIT", 0 },
		{ CKA_HAS_RESET                          , "CKA_HAS_RESET", 0 },
		{ CKA_ALWAYS_AUTHENTICATE                , "CKA_ALWAYS_AUTHENTICATE", CKT_BBOOL },

		{ CKA_CVC_INNER_CAR                      , "CKA_CVC_INNER_CAR", CKT_BIN },
		{ CKA_CVC_OUTER_CAR                      , "CKA_CVC_OUTER_CAR", CKT_BIN },
		{ CKA_CVC_CHR                            , "CKA_CVC_CHR", CKT_BIN },
		{ CKA_CVC_CED                            , "CKA_CVC_CED", CKT_BIN },
		{ CKA_CVC_CXD                            , "CKA_CVC_CXD", CKT_BIN },
		{ CKA_CVC_CHAT                           , "CKA_CVC_CHAT", CKT_BIN },
		{ CKA_CVC_CURVE_OID                      , "CKA_CVC_CURVE_OID", CKT_BIN },
		{ CKA_SC_HSM_PUBLIC_KEY_ALGORITHM        , "CKA_SC_HSM_PUBLIC_KEY_ALGORITHM", CKT_BIN },
		{ CKA_SC_HSM_KEY_USE_COUNTER             , "CKA_SC_HSM_KEY_USE_COUNTER", CKT_BIN },
		{ CKA_SC_HSM_ALGORITHM_LIST              , "CKA_SC_HSM_ALGORITHM_LIST", CKT_BIN },
		{ CKA_CVC_REQUEST                        , "CKA_CVC_REQUEST", CKT_BIN },
		{ 0, NULL, 0 }
};



struct id2name_t p11CKKName[] = {
		{ CKK_RSA                                , "CKK_RSA", 0 },
		{ CKK_DSA                                , "CKK_DSA", 0 },
		{ CKK_DH                                 , "CKK_DH", 0 },
		{ CKK_EC                                 , "CKK_EC", 0 },
		{ CKK_X9_42_DH                           , "CKK_X9_42_DH", 0 },
		{ CKK_KEA                                , "CKK_KEA", 0 },
		{ CKK_GENERIC_SECRET                     , "CKK_GENERIC_SECRET", 0 },
		{ CKK_RC2                                , "CKK_RC2", 0 },
		{ CKK_RC4                                , "CKK_RC4", 0 },
		{ CKK_DES                                , "CKK_DES", 0 },
		{ CKK_DES2                               , "CKK_DES2", 0 },
		{ CKK_DES3                               , "CKK_DES3", 0 },
		{ CKK_CAST                               , "CKK_CAST", 0 },
		{ CKK_CAST3                              , "CKK_CAST3", 0 },
		{ CKK_CAST128                            , "CKK_CAST128", 0 },
		{ CKK_RC5                                , "CKK_RC5", 0 },
		{ CKK_IDEA                               , "CKK_IDEA", 0 },
		{ CKK_SKIPJACK                           , "CKK_SKIPJACK", 0 },
		{ CKK_BATON                              , "CKK_BATON", 0 },
		{ CKK_JUNIPER                            , "CKK_JUNIPER", 0 },
		{ CKK_CDMF                               , "CKK_CDMF", 0 },
		{ CKK_AES                                , "CKK_AES", 0 },
		{ 0, NULL, 0 }
};



char *p11libname = P11LIBNAME;
static char namebuf[40]; /* used by main thread */
int optSlotId = -1;
int verbose = 0;
int optLogin = 0;
char *optPIN = NULL;



static char *id2name(struct id2name_t *p, unsigned long id, unsigned long *attr, char scr[40]) {

	if (attr)
		*attr = 0;

	while (p->name && (p->id != id)) {
		p++;
	}

	if (p->name) {
		strcpy(scr, p->name);
		if (attr)
			*attr = p->attr;
	} else {
		sprintf(scr, "*** Undefined 0x%lx ***", id);
	}
	return scr;
}



static char *p11string(CK_UTF8CHAR *str, size_t len)
{
	static char buffer[81];
	int i;

	if (len > sizeof(buffer) - 1)
		return "**Input too long***";

	memcpy(buffer, str, len);
	buffer[len] = 0;

	i = (int)len;
	while (i > 0) {
		i--;
		if (buffer[i] == ' ') {
			buffer[i] = 0;
		} else {
			break;
		}
	}
	return buffer;
}



void decodeArgs(int argc, char **argv)
{
	int err = 0, r, c, long_optind = 0;

	while (1) {
		c = getopt_long(argc, argv, "m:vlp:", options, &long_optind);
		if (c == -1)
			break;
		if (c == '?') {
			usage();
			exit(0);
		}
		switch (c) {
		case 'm':
			p11libname = optarg;
			break;
		case 'v':
			verbose++;
			break;
		case 'l':
			optLogin = 1;
			break;
		case 'p':
			optPIN = optarg;
			break;
		}
	}
}



static void bin2str(char *st, int stlen, unsigned char *data, int datalen)
{
	int ascii, i;
	unsigned char *d;

	ascii = 1;
	d = data;
	i = datalen;

	while (i && (stlen > 2)) {
		sprintf(st, "%02X", *d);

		if (ascii && !isprint(*d) && *d)
			ascii = 0;

		st += 2;
		stlen -= 2;
		i--;
		d++;
	}

	if (ascii && (stlen > datalen + 3)) {
		*st++ = ' ';
		*st++ = '"';
		memcpy(st, data, datalen);
		st += datalen;
		*st++ = '"';
	}

	*st = '\0';
}



int findAttribute(CK_ATTRIBUTE_PTR attr, int attrlen, CK_ATTRIBUTE_TYPE type)
{
	int rc = -1;

	for (int i = 0; i < attrlen; i++) {
		if (attr[i].type == type && attr[i].pValue != NULL) {
			rc = i;
			break;
		}
	}
	return rc;
}



void describeKey(CK_ATTRIBUTE_PTR attr, int attrlen, char *buff, int bufflen) {
	int rc;
	CK_ULONG keysize;

	*buff = 0;

	rc = findAttribute(attr, attrlen, CKA_KEY_TYPE);
	if (rc < 0)
		return;

	CK_KEY_TYPE kt = *(CK_KEY_TYPE *)attr[rc].pValue;

	switch(kt) {
	case CKK_RSA:
		rc = findAttribute(attr, attrlen, CKA_MODULUS_BITS);
		if (rc >= 0) {
			keysize = *(CK_ULONG *)attr[rc].pValue;
		} else {
			rc = findAttribute(attr, attrlen, CKA_MODULUS);
			if (rc < 0) {
				return;
			}
			keysize = attr[rc].ulValueLen << 3;
		}

		snprintf(buff, bufflen, "RSA:%d", (int)keysize);
		break;
	case CKK_EC:
		rc = findAttribute(attr, attrlen, CKA_EC_PARAMS);
		if (rc < 0)
			return;

		char *curvename = "*Unknown*";
		struct bytestring_s bs = { (unsigned char *)attr[rc].pValue + 2, attr[rc].ulValueLen - 2 };
		struct ec_curve *curve = cvcGetCurveForOID(&bs);
		if (curve != NULL) {
			curvename = curve->name;
		}
		snprintf(buff, bufflen, "EC:%s", curvename);
		break;
	case CKK_AES:
		rc = findAttribute(attr, attrlen, CKA_VALUE_LEN);
		if (rc < 0)
			return;

		keysize = *(CK_ULONG *)attr[rc].pValue;
		snprintf(buff, bufflen, "AES:%lu", keysize << 3);
		break;
	default:
		strncpy(buff, id2name(p11CKKName, kt, NULL, namebuf), bufflen);
	}
}



void dumpAttribute(CK_ATTRIBUTE_PTR attr)
{
	char attribute[30], scr[4096];
	unsigned long atype;

	strcpy(attribute, id2name(p11CKAName, attr->type, &atype, namebuf));

	switch(attr->type) {

	case CKA_KEY_TYPE:
		printf("  %s = %s\n", attribute, id2name(p11CKKName, *(CK_KEY_TYPE *)attr->pValue, NULL, namebuf));
		break;

	default:
		switch(atype) {
		case CKT_BBOOL:
			if (attr->pValue) {
				printf("  %s = %s [%d]\n", attribute, *(CK_BBOOL *)attr->pValue ? "TRUE" : "FALSE", *(CK_BBOOL *)attr->pValue);
			} else {
				printf("  %s\n", attribute);
			}
			break;
		case CKT_DATE:
			// pdate = (CK_DATE *)attr->pValue;
			// if (pdate != NULL) {
			//     sprintf(res, "  %s = %4s-%2s-%2s", attribute, pdate->year, pdate->month, pdate->day);
			// }
			printf("  %s\n", attribute);
			break;
		case CKT_LONG:
			printf("  %s = %d [0x%X]\n", attribute, (int)*(CK_LONG *)attr->pValue, (int)*(CK_LONG *)attr->pValue);
			break;
		case CKT_ULONG:
			printf("  %s = %u [0x%X]\n", attribute, (unsigned int)*(CK_ULONG *)attr->pValue, (unsigned int)*(CK_ULONG *)attr->pValue);
			break;
		case CKT_BIN:
		default:
			bin2str(scr, sizeof(scr), attr->pValue, attr->ulValueLen);
			printf("  %s = %s\n", attribute, scr);
			break;
		}
	}
}



int handleKey(CK_ATTRIBUTE_PTR attr, int attrlen)
{
	char keytype[20];
	char id[256];
	int rc;

	describeKey(attr, P11CKA, keytype, sizeof(keytype));

	char *label = "";
	rc = findAttribute(attr, attrlen, CKA_LABEL);
	if (rc >= 0) {
		label = p11string(attr[rc].pValue, attr[rc].ulValueLen);
	}

	id[0] = 0;
	rc = findAttribute(attr, attrlen, CKA_ID);
	if (rc >= 0) {
		bin2str(id, sizeof(id), attr[rc].pValue, attr[rc].ulValueLen);
	}

//	printf("%-18s %s  (%s)\n", keytype, label, id);
	printf("%-20s  (%s,%s)\n", label, keytype, id);

	return CKR_OK;
}



int dumpObject(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hnd, int (*handler)(CK_ATTRIBUTE_PTR, int))
{
	CK_ATTRIBUTE template[P11CKA];
	int rc, i;

	memset(template, 0, sizeof(template));
	for (i = 0; i < P11CKA; i++) {
		template[i].type = p11CKAName[i].id;
		template[i].pValue = NULL;
		template[i].ulValueLen = 0;
	}

	rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&template, P11CKA);
	if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
		fprintf(stderr, "C_GetAttributeValue failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	for (i = 0; i < P11CKA; i++) {
		if ((CK_LONG)template[i].ulValueLen > 0) {
			template[i].pValue = alloca(template[i].ulValueLen);
		}
	}

	rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&template, P11CKA);
	if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
		fprintf(stderr, "C_GetAttributeValue failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	if (verbose > 1) {
		for (i = 0; i < P11CKA; i++) {
			if ((CK_LONG)template[i].ulValueLen > 0) {
				dumpAttribute(&template[i]);
			}
		}
	}

	if (handler != NULL) {
		handler(template, P11CKA);
	}

	return CKR_OK;
}



int listObjects(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attr, int len, int (*handler)(CK_ATTRIBUTE_PTR, int))
{
	CK_OBJECT_HANDLE hnd;
	CK_ULONG cnt;
	int rc;

	rc = p11->C_FindObjectsInit(session, attr, len);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_FindObjectsInit failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	cnt = 1;
	while (rc == CKR_OK && cnt) {
		rc = p11->C_FindObjects(session, &hnd, 1, &cnt);

		if (rc == CKR_OK) {
			if (cnt == 1) {
				dumpObject(p11, session, hnd, handler);
			}
		} else {
			fprintf(stderr, "C_FindObjects failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		}
	}

	p11->C_FindObjectsFinal(session);

	return rc;
}



int listKeys(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, int loggedin)
{
	CK_OBJECT_CLASS classprk;
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &classprk, sizeof(classprk) }
	};
	int rc;

	classprk = loggedin ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	rc = listObjects(p11, session, template, sizeof(template) / sizeof(CK_ATTRIBUTE), handleKey);
	if (rc < 0) {
		return rc;
	}

	classprk = CKO_SECRET_KEY;
	rc = listObjects(p11, session, template, sizeof(template) / sizeof(CK_ATTRIBUTE), handleKey);
	if (rc < 0) {
		return rc;
	}

	return rc;
}



int main(int argc, char *argv[])
{
	int i;
	CK_RV rc;
	CK_ULONG slots;
	LIB_HANDLE dlhandle;
	CK_FUNCTION_LIST_PTR p11;
	CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_C_INITIALIZE_ARGS initArgs;
	CK_INFO info;
	CK_SLOT_ID_PTR slotlist = NULL;
	CK_SLOT_ID slotid;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	CK_SESSION_HANDLE session;

	decodeArgs(argc, argv);

	dlhandle = dlopen(p11libname, RTLD_NOW);

	if (!dlhandle) {
		fprintf(stderr, "dlopen() failed with %s\n", dlerror());
		exit(1);
	}

	C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(dlhandle, "C_GetFunctionList");

	(*C_GetFunctionList)(&p11);

	memset(&initArgs, 0, sizeof(initArgs));
	initArgs.flags = CKF_OS_LOCKING_OK;

	rc = p11->C_Initialize(&initArgs);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_Initialize failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(1);
	}

	rc = p11->C_GetInfo(&info);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GetInfo failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(1);
	}

	rc = p11->C_GetSlotList(TRUE, NULL, &slots);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GetSlotList failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(1);
	}

	slotlist = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots);

	rc = p11->C_GetSlotList(FALSE, slotlist, &slots);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GetSlotList failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(1);
	}

	i = 0;

	while (i < (int)slots) {
		slotid = *(slotlist + i);
		i++;

		if ((optSlotId != -1) && (optSlotId != slotid))
			continue;

		rc = p11->C_GetSlotInfo(slotid, &slotinfo);

		if (rc != CKR_OK) {
			fprintf(stderr, "C_GetSlotInfo failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
			free(slotlist);
			exit(1);
		}

		printf("Slot manufacturer   : %s\n", p11string(slotinfo.manufacturerID, sizeof(slotinfo.manufacturerID)));
		printf("Slot ID / desc      : %ld : %s\n", slotid, p11string(slotinfo.slotDescription, sizeof(slotinfo.slotDescription)));
		printf("Slot flags          : %x\n", (int)slotinfo.flags);

		rc = p11->C_GetTokenInfo(slotid, &tokeninfo);

		if (rc != CKR_OK) {
			fprintf(stderr, "C_GetTokenInfo failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
			free(slotlist);
			exit(1);
		}

		printf("Token label         : %s\n", p11string(tokeninfo.label, sizeof(tokeninfo.label)));
		printf("Token manufacturer  : %s\n", p11string(tokeninfo.manufacturerID, sizeof(tokeninfo.manufacturerID)));
		printf("Token model         : %s\n", p11string(tokeninfo.model, sizeof(tokeninfo.model)));
		printf("Serial              : %s\n", p11string(tokeninfo.serialNumber, sizeof(tokeninfo.serialNumber)));
		printf("Token flags         : %lx\n", tokeninfo.flags);

		rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);

		if (rc != CKR_OK) {
			fprintf(stderr, "C_OpenSession failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
			free(slotlist);
			exit(1);
		}

		int loggedin = 0;
		if (optLogin) {
			p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)optPIN, optPIN != NULL ? strlen(optPIN) : 0);
			if (rc != CKR_OK) {
				fprintf(stderr, "C_Login failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
				free(slotlist);
				exit(1);
			}
			loggedin = 1;
		}

		printf("------- Keys -------\n");

		rc = listKeys(p11, session, loggedin);
		if (rc != CKR_OK) {
			free(slotlist);
			exit(1);
		}
	}
}

