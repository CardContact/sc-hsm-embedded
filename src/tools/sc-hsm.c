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
	{ "login",			0, NULL,		'L' },
	{ "pin",			1, NULL,		'p' },
	{ "label",			1, NULL,		'l' },
	{ "algorithms",			1, NULL,		'a' },
	{ "key-domain",			1, NULL,		'd' },
	{ "key-use-counter",		1, NULL,		OPT_KEY_USE_COUNTER },
	{ "generate-key",		1, NULL,		'G' },
	{ "delete-key",			0, NULL,		'D' },
	{ NULL, 0, NULL, 0 }
};



static const char *option_help[] = {
	"Select PKCS#11 module",
	"Increase verbose mode level",
	"Log into token",
	"Define PIN to use for login",
	"Define label for key or key domain",
	"Define algorithms for key",
	"Define key domain number",
	"Define key use counter",
	"Generate key",
	"Delete key",
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

#define P11CKA			75

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
		{ CKA_SC_HSM_KEY_DOMAIN                  , "CKA_SC_HSM_KEY_DOMAIN", CKT_BIN },
		{ CKA_SC_HSM_ALGORITHM_LIST              , "CKA_SC_HSM_ALGORITHM_LIST", CKT_BIN },
		{ CKA_CVC_REQUEST                        , "CKA_CVC_REQUEST", CKT_BIN },
		{ CKA_SC_HSM_SHARE_STATUS                , "CKA_SC_HSM_SHARE_STATUS", CKT_BIN },
		{ CKA_SC_HSM_KEK_KCV                     , "CKA_SC_HSM_KEK_KCV", CKT_BIN },
		{ CKA_SC_HSM_KEY_DOMAIN_UID              , "CKA_SC_HSM_KEY_DOMAIN_UID", CKT_BIN },
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



struct id2name_t algoName[] = {
		 { SC_HSM_ALG_CBC_ENC               , "CBC_ENC", 0 },
		 { SC_HSM_ALG_CBC_DEC               , "CBC_DEC", 0 },
		 { SC_HSM_ALG_CMAC                  , "CMAC", 0 },
		 { SC_HSM_ALG_DERIVE_SP800_56C      , "DERIVE_SP800_56C", 0 },
		 { SC_HSM_ALG_REPLACE               , "REPLACE", 0 },

		 { SC_HSM_ALG_RSA_SIGN_RAW          , "RSA_RAW", 0 },
		 { SC_HSM_ALG_RSA_DECRYPT_RAW       , "RSA_DECRYPT_RAW", 0 },
		 { SC_HSM_ALG_RSA_DECRYPT_V15       , "RSA_DECRYPT_V15", 0 },
		 { SC_HSM_ALG_RSA_DECRYPT_OAEP      , "RSA_DECRYPT_OAEP", 0 },

		 { SC_HSM_ALG_RSA_SIGN_V15          , "RSA_V15", 0 },
		 { SC_HSM_ALG_RSA_SIGN_V15_SHA1     , "RSA_V15_SHA1", 0 },
		 { SC_HSM_ALG_RSA_SIGN_V15_SHA224   , "RSA_V15_SHA224", 0 },
		 { SC_HSM_ALG_RSA_SIGN_V15_SHA256   , "RSA_V15_SHA256", 0 },
		 { SC_HSM_ALG_RSA_SIGN_V15_SHA384   , "RSA_V15_SHA384", 0 },
		 { SC_HSM_ALG_RSA_SIGN_V15_SHA512   , "RSA_V15_SHA512", 0 },

		 { SC_HSM_ALG_RSA_SIGN_PSS          , "RSA_PSS", 0 },
		 { SC_HSM_ALG_RSA_SIGN_PSS_SHA1     , "RSA_PSS_SHA1", 0 },
		 { SC_HSM_ALG_RSA_SIGN_PSS_SHA224   , "RSA_PSS_SHA224", 0 },
		 { SC_HSM_ALG_RSA_SIGN_PSS_SHA256   , "RSA_PSS_SHA256", 0 },
		 { SC_HSM_ALG_RSA_SIGN_PSS_SHA384   , "RSA_PSS_SHA384", 0 },
		 { SC_HSM_ALG_RSA_SIGN_PSS_SHA512   , "RSA_PSS_SHA512", 0 },

		 { SC_HSM_ALG_ECDSA                 , "ECDSA", 0 },
		 { SC_HSM_ALG_ECDSA_SHA1            , "ECDSA_SHA1", 0 },
		 { SC_HSM_ALG_ECDSA_SHA224          , "ECDSA_SHA224", 0 },
		 { SC_HSM_ALG_ECDSA_SHA256          , "ECDSA_SHA256", 0 },
		 { SC_HSM_ALG_ECDSA_SHA384          , "ECDSA_SHA384", 0 },
		 { SC_HSM_ALG_ECDSA_SHA512          , "ECDSA_SHA512", 0 },

		 { SC_HSM_ALG_ECDH                  , "ECDH", 0 },
		 { SC_HSM_ALG_ECDHAutPuk            , "ECDH_AUTPUK", 0 },
		 { SC_HSM_ALG_ECDHXKEK              , "ECDH_XKEK", 0 },
		 { SC_HSM_ALG_DERIVE_EC_KEY         , "DERIVE_EC", 0 },

		 { SC_HSM_ALG_WRAP                  , "WRAP", 0 },
		 { SC_HSM_ALG_UNWRAP                , "UNWRAP", 0 },
		 { SC_HSM_ALG_SIGN_DEFAULT          , "SIGN_DEFAULT", 0 }
};



char *p11libname = P11LIBNAME;
static char namebuf[40]; /* used by main thread */
int optSlotId = -1;
int verbose = 0;
int optLogin = 0;
char *optPIN = NULL;
char *optLabel = NULL;
char *optKeyGen = NULL;
int optDeleteKey = 0;
int optKeyDomain = -1;
int optAlgorithms = -1;
unsigned char optAlgoList[40];
CK_ULONG optKeyUseCounter = 0;

CK_BBOOL _false = FALSE;
CK_BBOOL _true = TRUE;



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



static void bin2hex(char *st, int stlen, unsigned char *data, int datalen)
{
	int i;
	unsigned char *d;

	d = data;
	i = datalen;

	while (i && (stlen > 2)) {
		sprintf(st, "%02X", *d);

		st += 2;
		stlen -= 2;
		i--;
		d++;
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



void dumpAttribute(CK_ATTRIBUTE_PTR attr)
{
	char attribute[30], scr[4096];
	unsigned long atype;

	strcpy(attribute, id2name(p11CKAName, attr->type, &atype, namebuf));

	switch(attr->type) {

	case CKA_KEY_TYPE:
		printf("    %s = %s\n", attribute, id2name(p11CKKName, *(CK_KEY_TYPE *)attr->pValue, NULL, namebuf));
		break;

	default:
		switch(atype) {
		case CKT_BBOOL:
			if (attr->pValue) {
				printf("    %s = %s [%d]\n", attribute, *(CK_BBOOL *)attr->pValue ? "TRUE" : "FALSE", *(CK_BBOOL *)attr->pValue);
			} else {
				printf("    %s\n", attribute);
			}
			break;
		case CKT_DATE:
			// pdate = (CK_DATE *)attr->pValue;
			// if (pdate != NULL) {
			//     sprintf(res, "  %s = %4s-%2s-%2s", attribute, pdate->year, pdate->month, pdate->day);
			// }
			printf("    %s\n", attribute);
			break;
		case CKT_LONG:
			printf("    %s = %d [0x%X]\n", attribute, (int)*(CK_LONG *)attr->pValue, (int)*(CK_LONG *)attr->pValue);
			break;
		case CKT_ULONG:
			printf("    %s = %u [0x%X]\n", attribute, (unsigned int)*(CK_ULONG *)attr->pValue, (unsigned int)*(CK_ULONG *)attr->pValue);
			break;
		case CKT_BIN:
		default:
			bin2str(scr, sizeof(scr), attr->pValue, attr->ulValueLen);
			printf("    %s = %s\n", attribute, scr);
			break;
		}
	}
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
		printf("    ---8<------8<------8<---\n");
	}

	if (handler != NULL) {
		handler(template, P11CKA);
	}

	return CKR_OK;
}



int findAttr(CK_ATTRIBUTE_PTR attr, int len, CK_ATTRIBUTE_TYPE type)
{
	for (int i = 0; i < len; i++) {
		if (attr[i].type == type)
			return i;
	}
	return -1;
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



int getAttributes(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hnd, CK_ATTRIBUTE_PTR attr, int attrlen)
{
	int i, rc;

	rc = p11->C_GetAttributeValue(session, hnd, attr, attrlen);
	if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
		fprintf(stderr, "C_GetAttributeValue failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	for (i = 0; i < attrlen; i++) {
		if ((CK_LONG)attr[i].ulValueLen > 0) {
			attr[i].pValue = calloc(attr[i].ulValueLen, 1);

			if (attr[i].pValue == NULL)
				return CKR_HOST_MEMORY;
		}
	}

	rc = p11->C_GetAttributeValue(session, hnd, attr, attrlen);
	if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
		fprintf(stderr, "C_GetAttributeValue failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}
	return CKR_OK;
}



void freeAttributes(CK_ATTRIBUTE_PTR attr, int attrlen)
{
	while(attrlen--) {
		if (attr->pValue != NULL)
			free(attr->pValue);
		attr++;
	}
}



void describeAlgorithms(unsigned char *algos, size_t algoslen, char *buff, int bufflen)
{
	while(algoslen > 0 && bufflen > 4) {
		id2name(algoName, *algos++, NULL, buff);
		algoslen--;
		if (algoslen > 0) {
			strcat(buff, "+");
		}
		bufflen -= strlen(buff);
		buff += strlen(buff);
	}

	if (algoslen > 0) {
		strcat(buff, "...");
	}
}



int parseAlgorithms(char *spec, unsigned char *buff, size_t bufflen)
{
	char *str = spec;
	char *token;
	int algocnt = 0;

	do	{
		token = strtok(str, ",;+");
		str = NULL;
		if (token) {
			int i = 0;
			for (; i < sizeof(algoName) / sizeof(struct id2name_t); i++) {
				if (0 == strcasecmp(token, algoName[i].name)) {
					break;
				}
			}
			if (i == sizeof(algoName) / sizeof(struct id2name_t)) {
				fprintf(stderr, "%s is not a valid algorithm name\n", token);
				return -1;
			}

			if (bufflen == 0) {
				fprintf(stderr, "Too many algorithms in list\n");
				return -1;
			}
			*buff++ = (unsigned char)algoName[i].id;
			bufflen--;
			algocnt++;
		}
	} while(token != NULL);
	return algocnt;
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



void printKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hnd)
{
	CK_ATTRIBUTE attr[] = {
		{ CKA_KEY_TYPE, NULL, 0 },
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_EC_PARAMS, NULL, 0 },
		{ CKA_VALUE_LEN, NULL, 0 },
		{ CKA_SC_HSM_KEY_USE_COUNTER, NULL, 0 },
		{ CKA_SC_HSM_ALGORITHM_LIST, NULL, 0 }
	};
	char scr[256];
	char *label = "";
	int rc;

	rc = getAttributes(p11, session, hnd, attr, sizeof(attr) / sizeof(CK_ATTRIBUTE));
	if (rc != CKR_OK)
		return;

	describeKey(attr, sizeof(attr) / sizeof(CK_ATTRIBUTE), scr, sizeof(scr));

	if (attr[2].pValue != NULL) {
		label = p11string(attr[2].pValue, attr[2].ulValueLen);
	}

	int indent = 28 - strlen(label);
	if (indent < 4)
		indent = 4;

	printf("  '-- \"%s\"%*s(%s", label, indent, "", scr);

	if (attr[1].pValue != NULL) {
		bin2str(scr, sizeof(scr), attr[1].pValue, attr[1].ulValueLen);
		printf(",ID:%s", scr);
	}

	if (attr[6].pValue != NULL) {
		printf(",KUC:%lu", *(CK_ULONG*)attr[6].pValue);
	}

	if (attr[7].pValue != NULL) {
//		bin2str(scr, sizeof(scr), attr[7].pValue, attr[7].ulValueLen);
		describeAlgorithms(attr[7].pValue, attr[7].ulValueLen, scr, sizeof(scr));
		printf(",ALG:%s", scr);
	}

	printf(")\n");

	freeAttributes(attr, sizeof(attr) / sizeof(CK_ATTRIBUTE));
}



int listKeys(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, int loggedin, int keydomain)
{
	CK_OBJECT_CLASS classprk;
	unsigned char kdid[1];
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &classprk, sizeof(classprk) },
		{ CKA_SC_HSM_KEY_DOMAIN, &kdid, sizeof(kdid) }
	};
	CK_OBJECT_HANDLE hnd;
	CK_ULONG cnt;
	int rc,len;

	len = 1;

	if (keydomain >= 0) {
		kdid[0] = (unsigned char)keydomain;
		len++;
	}

	classprk = loggedin ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY;
	while(1) {
		rc = p11->C_FindObjectsInit(session, template, len);

		if (rc != CKR_OK) {
			fprintf(stderr, "C_FindObjectsInit failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
			return rc;
		}

		cnt = 1;
		while (rc == CKR_OK && cnt) {
			rc = p11->C_FindObjects(session, &hnd, 1, &cnt);

			if (rc == CKR_OK) {
				if (cnt == 1) {
					rc = p11->C_GetAttributeValue(session, hnd, &template[1], 1);
					if ((keydomain >= 0 && rc == CKR_OK) ||
					    (keydomain < 0 && rc != CKR_OK))
						printKey(p11, session, hnd);
					rc = CKR_OK;
				}
			} else {
				fprintf(stderr, "C_FindObjects failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
			}
		}

		p11->C_FindObjectsFinal(session);

		if (classprk == CKO_SECRET_KEY)
			break;

		classprk = CKO_SECRET_KEY;
	}

	return rc;
}



CK_RV findObjectByLabelOrId(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_CLASS classprk, CK_OBJECT_HANDLE_PTR phnd)
{
	CK_ATTRIBUTE template[2] = {
		{ CKA_CLASS, &classprk, sizeof(classprk) }
	};
	CK_ULONG cnt;
	int rc,len;

	len = 1;

	if (optLabel != NULL) {
		template[len].type = CKA_LABEL;
		template[len].pValue = optLabel;
		template[len].ulValueLen = strlen(optLabel);
		len++;
	}

	rc = p11->C_FindObjectsInit(session, template, len);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_FindObjectsInit failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	rc = p11->C_FindObjects(session, phnd, 1, &cnt);

	if (cnt < 1)
		rc = CKR_CANCEL;

	p11->C_FindObjectsFinal(session);

	return rc;
}



int printKeyDomain(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hnd)
{
	CK_ATTRIBUTE attr[] = {
		{ CKA_ID, NULL, 0 },
		{ CKA_LABEL, NULL, 0 },
		{ CKA_SC_HSM_SHARE_STATUS, NULL, 0 },
		{ CKA_SC_HSM_KEK_KCV, NULL, 0 },
		{ CKA_SC_HSM_KEY_DOMAIN_UID, NULL, 0 },
		{ 0, NULL, 0 }
	};
	int rc;

	rc = getAttributes(p11, session, hnd, attr, sizeof(attr) / sizeof(CK_ATTRIBUTE));
	if (rc != CKR_OK)
		return - 1;

	int i = *(unsigned char *)attr[0].pValue;

	printf("%3d: %s", i + 1, attr[2].pValue ? "DKEK" : "XKEK");

	if (attr[1].pValue) {
		printf(" \"%s\"", p11string((CK_UTF8CHAR *)attr[1].pValue, attr[1].ulValueLen));
	}

	if (attr[2].pValue) {
		int shares = *(unsigned char*)attr[2].pValue;
		int missing = *((unsigned char*)attr[2].pValue + 1);

		if (missing) {
			printf(" set-up in progress with %d of %d shares missing", missing, shares);
		}
	}

	if (attr[3].pValue) {
		char kcvstring[20];
		bin2hex(kcvstring, sizeof(kcvstring), attr[3].pValue, attr[3].ulValueLen);
		printf(" with KCV %s", kcvstring);
	}

	if (attr[4].pValue) {
		char uidstring[70];
		bin2hex(uidstring, sizeof(uidstring), attr[4].pValue, attr[4].ulValueLen);
		printf(" with Key Domain UID %s", uidstring);
	}

	printf("\n");

	freeAttributes(attr, sizeof(attr) / sizeof(CK_ATTRIBUTE));

	return i;
}



int listKeyDomains(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid, CK_SESSION_HANDLE session, int loggedin)
{
	CK_OBJECT_CLASS classkd = CKO_SC_HSM_KEY_DOMAIN;
	CK_ATTRIBUTE searchkd[] = {
		{ CKA_CLASS, &classkd, sizeof(classkd) }
	};
	CK_SESSION_HANDLE subsession;
	CK_OBJECT_HANDLE hnd;
	CK_ULONG cnt;
	int rc;

	printf("  0: Default\n");

	rc = listKeys(p11, session, loggedin, -1);
	if (rc != CKR_OK) {
		return rc;
	}

	rc = p11->C_FindObjectsInit(session, searchkd, sizeof(searchkd) / sizeof(CK_ATTRIBUTE));

	if (rc != CKR_OK) {
		fprintf(stderr, "C_FindObjectsInit failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	cnt = 1;
	while (rc == CKR_OK && cnt) {
		rc = p11->C_FindObjects(session, &hnd, 1, &cnt);

		if (rc == CKR_OK) {
			if (cnt == 1) {
				int kdid = printKeyDomain(p11, session, hnd);

				rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &subsession);

				if (rc != CKR_OK) {
					fprintf(stderr, "C_OpenSession failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
					return rc;
				}

				listKeys(p11, subsession, loggedin, kdid);

				p11->C_CloseSession(subsession);
			}
		} else {
			fprintf(stderr, "C_FindObjects failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		}
	}

	p11->C_FindObjectsFinal(session);

	return rc;
}



CK_RV addPrivateKeyAttributes(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_ATTRIBUTE *keyTemplate, int *keyAttributes, CK_OBJECT_CLASS class)
{
	CK_RV rv;
	CK_OBJECT_HANDLE hnd;

	if (optLabel != NULL) {
		rv = findObjectByLabelOrId(p11, session, class, &hnd);
		if (rv == CKR_OK) {
			fprintf(stderr, "A key with label '%s' does already exist\n", optLabel);
			return CKR_FUNCTION_FAILED;
		}

		keyTemplate[*keyAttributes].type = CKA_LABEL;
		keyTemplate[*keyAttributes].pValue = optLabel;
		keyTemplate[*keyAttributes].ulValueLen = strlen(optLabel);
		(*keyAttributes)++;
	}

	return CKR_OK;
}



CK_RV addPublicKeyAttributes(CK_ATTRIBUTE *keyTemplate, int *keyAttributes)
{
	if (optKeyUseCounter > 0) {
		keyTemplate[*keyAttributes].type = CKA_SC_HSM_KEY_USE_COUNTER;
		keyTemplate[*keyAttributes].pValue = &optKeyUseCounter;
		keyTemplate[*keyAttributes].ulValueLen = sizeof(optKeyUseCounter);
		(*keyAttributes)++;
	}

	if (optAlgorithms > 0) {
		keyTemplate[*keyAttributes].type = CKA_SC_HSM_ALGORITHM_LIST;
		keyTemplate[*keyAttributes].pValue = &optAlgoList;
		keyTemplate[*keyAttributes].ulValueLen = optAlgorithms;
		(*keyAttributes)++;
	}

	return CKR_OK;
}



CK_RV generateRSAKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_ULONG size)
{
	CK_MECHANISM mech_genrsa = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 };
	CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE publicKeyTemplate[20] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_MODULUS_BITS, &size, sizeof(size)},
			{ CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent)}
	};
	int publicKeyAttributes = 4;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE privateKeyTemplate[20] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_PRIVATE, &_true, sizeof(_true)},
			{ CKA_SENSITIVE, &_true, sizeof(_true)}
	};
	int privateKeyAttributes = 4;
	unsigned char kdid;
	CK_OBJECT_HANDLE hndPrivateKey, hndPublicKey;
	CK_RV rc;

	rc = addPrivateKeyAttributes(p11, session, privateKeyTemplate, &privateKeyAttributes, CKO_PRIVATE_KEY);
	if (rc != CKR_OK)
		return rc;

	if (optKeyDomain > 0) {
		kdid = (unsigned char)(optKeyDomain - 1);
		publicKeyTemplate[publicKeyAttributes].type = CKA_SC_HSM_KEY_DOMAIN;
		publicKeyTemplate[publicKeyAttributes].pValue = &kdid;
		publicKeyTemplate[publicKeyAttributes].ulValueLen = sizeof(kdid);
		publicKeyAttributes++;
	}

	addPublicKeyAttributes(publicKeyTemplate, &publicKeyAttributes);

	rc = p11->C_GenerateKeyPair(session, &mech_genrsa,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndPublicKey, &hndPrivateKey);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GenerateKeyPair failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	return CKR_OK;
}



CK_RV generateECKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, bytestring curve)
{
	CK_MECHANISM mech_genecc = { CKM_EC_KEY_PAIR_GEN, 0, 0 };
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	unsigned char curve_oid[16];
	CK_ATTRIBUTE publicKeyTemplate[20] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_EC_PARAMS, &curve_oid, sizeof(curve_oid)}
	};
	int publicKeyAttributes = 3;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE privateKeyTemplate[20] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_PRIVATE, &_true, sizeof(_true)},
			{ CKA_SENSITIVE, &_true, sizeof(_true)}
	};
	int privateKeyAttributes = 4;
	unsigned char kdid;
	CK_OBJECT_HANDLE hndPrivateKey, hndPublicKey;
	CK_RV rc;

	curve_oid[0] = ASN1_OBJECT_IDENTIFIER;
	curve_oid[1] = curve->len;
	memcpy(curve_oid + 2, curve->val, curve->len);
	publicKeyTemplate[2].ulValueLen = curve->len + 2;

	rc = addPrivateKeyAttributes(p11, session, privateKeyTemplate, &privateKeyAttributes, CKO_PRIVATE_KEY);
	if (rc != CKR_OK)
		return rc;

	if (optKeyDomain > 0) {
		kdid = (unsigned char)(optKeyDomain - 1);
		publicKeyTemplate[publicKeyAttributes].type = CKA_SC_HSM_KEY_DOMAIN;
		publicKeyTemplate[publicKeyAttributes].pValue = &kdid;
		publicKeyTemplate[publicKeyAttributes].ulValueLen = sizeof(kdid);
		publicKeyAttributes++;
	}

	addPublicKeyAttributes(publicKeyTemplate, &publicKeyAttributes);

	rc = p11->C_GenerateKeyPair(session, &mech_genecc,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndPublicKey, &hndPrivateKey);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GenerateKeyPair failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	return CKR_OK;
}



CK_RV generateAESKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_ULONG size)
{
	CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
	CK_MECHANISM mech_genaes = { CKM_AES_KEY_GEN, 0, 0 };
	CK_ULONG len = 16;
	CK_ATTRIBUTE secretKeyTemplate[20] = {
			{ CKA_CLASS, &secretKeyClass, sizeof(secretKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_PRIVATE, &_true, sizeof(_true)},
			{ CKA_SENSITIVE, &_true, sizeof(_true)},
			{ CKA_VALUE_LEN, &len, sizeof(len) },
			{ CKA_SIGN, &_true, sizeof(_true)},
			{ CKA_DERIVE, &_true, sizeof(_true)},
			{ CKA_ENCRYPT, &_true, sizeof(_true)},
			{ CKA_DECRYPT, &_true, sizeof(_true)}
	};
	int secretKeyAttributes = 9;
	unsigned char kdid;
	CK_OBJECT_HANDLE hndSecretKey;
	CK_RV rc;

	len = size >> 3;

	rc = addPrivateKeyAttributes(p11, session, secretKeyTemplate, &secretKeyAttributes, CKO_SECRET_KEY);
	if (rc != CKR_OK)
		return rc;

	if (optKeyDomain > 0) {
		kdid = (unsigned char)(optKeyDomain - 1);
		secretKeyTemplate[secretKeyAttributes].type = CKA_SC_HSM_KEY_DOMAIN;
		secretKeyTemplate[secretKeyAttributes].pValue = &kdid;
		secretKeyTemplate[secretKeyAttributes].ulValueLen = sizeof(kdid);
		secretKeyAttributes++;
	}

	addPublicKeyAttributes(secretKeyTemplate, &secretKeyAttributes);

	rc = p11->C_GenerateKey(session, &mech_genaes, secretKeyTemplate, secretKeyAttributes, &hndSecretKey);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GenerateKey failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		return rc;
	}

	return CKR_OK;
}



void generateKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	char scr[256],*po;
	int size;

	strncpy(scr, optKeyGen, sizeof(scr));
	po = strchr(scr, ':');

	if (po == NULL) {
		fprintf(stderr, "Key specification must be in format '<type>:<spec>'\n");
		return;
	}

	*po++ = 0;

	if (!strncasecmp("RSA", scr, 3)) {
		size = atoi(po);
		if (size != 1024 && size != 1536 && size != 2048 && size != 3072 && size != 4096) {
			fprintf(stderr, "RSA key size must be 1024, 1536, 2048, 3072 or 4096\n");
			return;
		}
		generateRSAKey(p11, session, size);
	} else if (!strncasecmp("EC", scr, 2)) {
		bytestring oid = cvcGetCurveOIDForName(po);
		if (oid == NULL) {
			fprintf(stderr, "Unknown curve for EC key\n");
			return;
		}
		generateECKey(p11, session, oid);
	} else if (!strncasecmp("AES", scr, 2)) {
		size = atoi(po);
		if (size != 128 && size != 196 && size != 256) {
			fprintf(stderr, "AES key size must be 128, 192 or 256\n");
			return;
		}
		generateAESKey(p11, session, size);
	} else {
		fprintf(stderr, "Key type must be one of 'RSA', 'EC' or 'AES'\n");
		return;
	}
}



void deleteKey(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	CK_OBJECT_HANDLE hnd;

	if (findObjectByLabelOrId(p11, session, CKO_PRIVATE_KEY, &hnd) == CKR_OK) {
		p11->C_DestroyObject(session, hnd);
	}

	if (findObjectByLabelOrId(p11, session, CKO_PUBLIC_KEY, &hnd) == CKR_OK) {
		p11->C_DestroyObject(session, hnd);
	}

	if (findObjectByLabelOrId(p11, session, CKO_CERTIFICATE, &hnd) == CKR_OK) {
		p11->C_DestroyObject(session, hnd);
	}

	if (findObjectByLabelOrId(p11, session, CKO_SECRET_KEY, &hnd) == CKR_OK) {
		p11->C_DestroyObject(session, hnd);
	}
}



void decodeArgs(int argc, char **argv)
{
	int c, long_optind = 0;

	while (1) {
		c = getopt_long(argc, argv, "m:vLp:G:Dl:a:d:", options, &long_optind);
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
		case 'L':
			optLogin = 1;
			break;
		case 'p':
			optPIN = optarg;
			break;
		case 'l':
			optLabel = optarg;
			break;
		case 'a':
			optAlgorithms = parseAlgorithms(optarg, optAlgoList, sizeof(optAlgoList));
			if (optAlgorithms < 0) {
				exit(EXIT_FAILURE);
			}
			break;
		case 'd':
			optKeyDomain = atoi(optarg);
			break;
		case OPT_KEY_USE_COUNTER:
			optKeyUseCounter = atoi(optarg);
			break;
		case 'G':
			optKeyGen = optarg;
			break;
		case 'D':
			optDeleteKey = 1;
			break;
		}
	}
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
		exit(EXIT_FAILURE);
	}

	C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(dlhandle, "C_GetFunctionList");

	(*C_GetFunctionList)(&p11);

	memset(&initArgs, 0, sizeof(initArgs));
	initArgs.flags = CKF_OS_LOCKING_OK;

	rc = p11->C_Initialize(&initArgs);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_Initialize failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(EXIT_FAILURE);
	}

	rc = p11->C_GetInfo(&info);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GetInfo failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(EXIT_FAILURE);
	}

	rc = p11->C_GetSlotList(TRUE, NULL, &slots);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GetSlotList failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(EXIT_FAILURE);
	}

	slotlist = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots);

	rc = p11->C_GetSlotList(TRUE, slotlist, &slots);

	if (rc != CKR_OK) {
		fprintf(stderr, "C_GetSlotList failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
		exit(EXIT_FAILURE);
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
			exit(EXIT_FAILURE);
		}

		printf("Slot manufacturer   : %s\n", p11string(slotinfo.manufacturerID, sizeof(slotinfo.manufacturerID)));
		printf("Slot ID / desc      : %ld / %s\n", slotid, p11string(slotinfo.slotDescription, sizeof(slotinfo.slotDescription)));
		printf("Slot flags          : %x\n", (int)slotinfo.flags);

		rc = p11->C_GetTokenInfo(slotid, &tokeninfo);

		if (rc != CKR_OK) {
			fprintf(stderr, "C_GetTokenInfo failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
			free(slotlist);
			exit(EXIT_FAILURE);
		}

		printf("Token label         : %s\n", p11string(tokeninfo.label, sizeof(tokeninfo.label)));
		printf("Token manufacturer  : %s\n", p11string(tokeninfo.manufacturerID, sizeof(tokeninfo.manufacturerID)));
		printf("Token model         : %s\n", p11string(tokeninfo.model, sizeof(tokeninfo.model)));
		printf("Firmware Version    : %d.%d\n", tokeninfo.firmwareVersion.major, tokeninfo.firmwareVersion.minor);
		printf("Serial              : %s\n", p11string(tokeninfo.serialNumber, sizeof(tokeninfo.serialNumber)));
		printf("Free memory         : %lu bytes", tokeninfo.ulFreePrivateMemory);
		if (tokeninfo.ulFreePrivateMemory == 32767L) {
			printf(" (at least)\n");
		} else {
			printf("\n");
		}
		printf("Token flags         : %lx\n", tokeninfo.flags);

		rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);

		if (rc != CKR_OK) {
			fprintf(stderr, "C_OpenSession failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
			free(slotlist);
			exit(EXIT_FAILURE);
		}

		int loggedin = 0;
		if (optLogin) {
			p11->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)optPIN, optPIN != NULL ? strlen(optPIN) : 0);
			if (rc != CKR_OK) {
				fprintf(stderr, "C_Login failed with %s\n", id2name(p11CKRName, rc, 0, namebuf));
				free(slotlist);
				exit(EXIT_FAILURE);
			}
			loggedin = 1;
		}

		if (verbose > 1) {
			listObjects(p11, session, NULL, 0, NULL);
		}

		if (optKeyGen != NULL) {
			generateKey(p11, session);
		}

		if (optDeleteKey) {
			if (optLabel == NULL) {
				fprintf(stderr, "--delete-key (-D) requires label\n");
				free(slotlist);
				exit(EXIT_FAILURE);
			}
			deleteKey(p11, session);
		}

		printf("----- Key Domains / Keys -----\n");
		if (!loggedin)
			printf("\nWithout login only public objects are shown !\n\n");

		rc = listKeyDomains(p11, slotid, session, loggedin);
		if (rc != CKR_OK) {
			free(slotlist);
			exit(EXIT_FAILURE);
		}
	}

	exit(EXIT_SUCCESS);
}

