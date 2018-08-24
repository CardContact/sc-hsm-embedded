/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2013, CardContact Systems GmbH, Minden, Germany
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
 * @file testpkcs11.c
 * @author Andreas Schwier
 * @brief Unit test for PKCS#11 interface
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <sc-hsm/sc-hsm-pkcs11.h>

#include <common/mutex.h>
#include <common/asn1.h>

/* Number of threads used for multi-threading test */
#define NUM_THREADS		30

/* Default PIN unless --pin is defined */
#define PIN_SC_HSM "648219"
#define PIN_STARCOS "123456"

/* Default SO-PIN unless --so-pin is defined */
#define SOPIN "3537363231383830"


#ifndef _WIN32

#include <unistd.h>
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
		printf("malloc(%d) failed.", *pl);
		exit(1);
	}
	memcpy(*pp, buf, *pl);
	return *pl - 1;
}

void usleep(unsigned int usec) 
{ 
    HANDLE timer; 
    LARGE_INTEGER ft; 
  
    ft.QuadPart = -(10 * (__int64)usec); 
  
    timer = CreateWaitableTimer(NULL, TRUE, NULL); 
    SetWaitableTimer(timer, &ft, 0, NULL, NULL, 0); 
    WaitForSingleObject(timer, INFINITE); 
    CloseHandle(timer); 
}

#endif /* _WIN32 */



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
		{ CKR_OK			                    , "CKR_OK", 0 },
		{ 0, NULL }
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

		{ 0, NULL }
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
		{ 0, NULL }
};

/* Data structure for parameters passed to thread */
struct thread_data {
	int thread_id;
	CK_SLOT_ID slotid;
	CK_FUNCTION_LIST_PTR p11;
	int iterations;
};


char *p11libname = P11LIBNAME;

CK_UTF8CHAR *pin = NULL;
CK_UTF8CHAR wrongpin[] = "111111";
CK_ULONG pinlen = 6;

CK_UTF8CHAR *sopin = (CK_UTF8CHAR *)SOPIN;
CK_ULONG sopinlen = 16;

static MUTEX verdictMutex; /* initialized in main */
static int testscompleted = 0;
static int testsfailed = 0;

static int optTestInsertRemove = 0;
static int optTestPINBlock = 0;
static int optTestMultiOnly = 0;
static int optTestHotplug = 0;
static int optTestEvent = 0;
static int optOneThreadPerToken = 0;
static int optNoClass3Tests = 0;
static int optMultiThreadingTests = 0;
static int optThreadsPerToken = 1;
static int optIteration = 1;
static int optUnlockPIN = 0;
static long optSlotId = -1;
static char *optTokenFilter = "";

static char namebuf[40]; /* used by main thread */

static struct bytestring_s ecparam_prime256v1 = { (unsigned char *)"\x30\x81\xE0\x02\x01\x01\x30\x2C\x06\x07\x2A\x86\x48\xCE\x3D\x01\x01\x02\x21\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\x30\x44\x04\x20\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC\x04\x20\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B\x04\x41\x04\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5\x02\x21\x00\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51\x02\x01\x01", 227 };




static char *verdict(int condition) {
	mutex_lock(&verdictMutex);
	testscompleted++;

	if (condition) {
		mutex_unlock(&verdictMutex);
		return "Passed";
	} else {
		testsfailed++;
		mutex_unlock(&verdictMutex);
		return "Failed";
	}
}



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



void dumpObject(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_OBJECT_HANDLE hnd)
{
	CK_ATTRIBUTE template[P11CKA];
	int rc, i;

	memset(template, 0, sizeof(template));
	for (i = 0; i < P11CKA; i++) {
		template[i].type = p11CKAName[i].id;
	}
	printf("Calling C_GetAttributeValue ");
	rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&template, P11CKA);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), (rc == CKR_OK) || (rc == CKR_ATTRIBUTE_TYPE_INVALID) ? "Passed" : "Failed");

	for (i = 0; i < P11CKA; i++) {
		if ((CK_LONG)template[i].ulValueLen > 0) {
			template[i].pValue = alloca(template[i].ulValueLen);
		}
	}

	printf("Calling C_GetAttributeValue ");
	rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&template, P11CKA);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), (rc == CKR_OK) || (rc == CKR_ATTRIBUTE_TYPE_INVALID) ? "Passed" : "Failed");

	for (i = 0; i < P11CKA; i++) {
		if ((CK_LONG)template[i].ulValueLen > 0) {
			dumpAttribute(&template[i]);
		}
	}
}



void listObjects(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attr, int len)
{
	CK_OBJECT_HANDLE hnd;
	CK_ULONG cnt;
	int rc;

	printf("Calling C_FindObjectsInit ");
	rc = p11->C_FindObjectsInit(session, attr, len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK) {
		return;
	}

	cnt = 1;
	while ((rc == CKR_OK) && (cnt)) {
		printf("Calling C_FindObjects ");
		rc = p11->C_FindObjects(session, &hnd, 1, &cnt);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if ((rc == CKR_OK) && (cnt == 1)) {
			dumpObject(p11, session, hnd);
		}
	}

	printf("Calling C_FindObjectsFinal ");
	p11->C_FindObjectsFinal(session);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
}



int findObject(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR attr, int len, int ofs, CK_OBJECT_HANDLE_PTR phnd)
{
	CK_ULONG cnt;
	CK_OBJECT_HANDLE hnd;
	int rc;

	printf("Calling C_FindObjectsInit ");
	rc = p11->C_FindObjectsInit(session, attr, len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK) {
		return rc;
	}

	do	{
		cnt = 1;
		printf("Calling C_FindObjects ");
		rc = p11->C_FindObjects(session, &hnd, 1, &cnt);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	} while ((rc == CKR_OK) && ofs--);

	printf("Calling C_FindObjectsFinal ");
	p11->C_FindObjectsFinal(session);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (cnt == 0) {
		return CKR_ARGUMENTS_BAD;
	}

	*phnd = hnd;
	return CKR_OK;
}



int testRSASigning(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid, int id, CK_MECHANISM_TYPE mt)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS classprk = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS classpuk = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BBOOL _true = CK_TRUE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &classprk, sizeof(classprk) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_SIGN, &_true, sizeof(_true) }
	};
	CK_BYTE keyid[256];
	CK_ATTRIBUTE puktemplate[] = {
			{ CKA_CLASS, &classpuk, sizeof(classpuk) },
			{ CKA_ID, keyid, sizeof(keyid) }
	};
	CK_OBJECT_HANDLE hnd,pubhnd;
	CK_MECHANISM mech = { CKM_SHA1_RSA_PKCS, 0, 0 };
	CK_SESSION_INFO sessioninfo;
	char *tbs = "Hello World";
	CK_BYTE signature[512];
	CK_ULONG len;
	char scr[1024];
	int rc, keyno;
	char namebuf[40]; /* each thread need its own buffer */

	keyno = 0;
	mech.mechanism = mt;

	rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
	printf("C_OpenSession (Thread %i, Slot=%ld) - %s : %s\n", id, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK)
		return rc;

	rc = p11->C_Login(session, CKU_USER, pin, pinlen);
	printf("C_Login User (Thread %i, Slot=%ld) - %s : %s\n", id, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK || rc == CKR_USER_ALREADY_LOGGED_IN));

	if (rc != CKR_OK && rc != CKR_USER_ALREADY_LOGGED_IN)
		goto out;

	switch(mt) {
	case CKM_RSA_PKCS:
	case CKM_SC_HSM_PSS_SHA1:
		tbs = "ThisIsA160BitHashStr"; break;
	case CKM_SC_HSM_PSS_SHA256:
		tbs = "ThisIsA256BitHashStringTestValue"; break;
	}

	while (1) {
		printf("Calling findObject (Thread %i, Session %ld, Slot=%ld)\n", id, session, slotid);
		rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), keyno, &hnd);

		if (rc != CKR_OK) {
			printf("Key %i not found (Thread %i, Session %ld, Slot=%ld)\n", keyno, id, session, slotid);
			rc = CKR_OK;
			break;
		}
		rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&puktemplate[1], 1);
		printf("C_GetAttributeValue (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_SignInit(session, &mech, hnd);
		printf("C_SignInit (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		len = 0;
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), NULL, &len);
		printf("C_Sign (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Signature size = %lu\n", len);

		len--;
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), signature, &len);
		printf("C_Sign (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_BUFFER_TOO_SMALL));

		printf("Signature size = %lu\n", len);

		len = sizeof(signature);
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), signature, &len);
		printf("C_Sign (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK || rc == CKR_DEVICE_REMOVED || rc == CKR_TOKEN_NOT_PRESENT));

		if (rc == CKR_DEVICE_REMOVED || rc == CKR_TOKEN_NOT_PRESENT)
			goto out;

		if (rc == CKR_OK) {
			bin2str(scr, sizeof(scr), signature, len);
			printf("Signature:\n%s\n", scr);
		}


		rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&puktemplate, sizeof(puktemplate) / sizeof(CK_ATTRIBUTE), 0, &pubhnd);
		printf("C_FindObject for public key (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc != CKR_OK) {
			keyno++;
			continue;
		}

#ifdef ENABLE_LIBCRYPTO
		rc = p11->C_VerifyInit(session, &mech, pubhnd);
		printf("C_VerifyInit (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_Verify(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), signature, len);
		printf("C_Verify (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
#endif

		// Need to log in again ?
		rc = p11->C_GetSessionInfo(session, &sessioninfo);
		if (sessioninfo.state == CKS_RW_PUBLIC_SESSION) {
			rc = p11->C_Login(session, CKU_USER, pin, pinlen);
			printf("C_Login User - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK || rc == CKR_USER_ALREADY_LOGGED_IN));

			rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), keyno, &hnd);

			if (rc != CKR_OK) {
				printf("Key %i not found (Thread %i, Session %ld, Slot=%ld)\n", keyno, id, session, slotid);
				break;
			}
		}

		rc = p11->C_SignInit(session, &mech, hnd);
		printf("C_SignInit (Thread %i, Session %ld, Slot=%ld) - Multipart - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

#if 1
		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)tbs, 6);
		printf("C_SignUpdate (Thread %i, Session %ld, Slot=%ld - Part #1) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)tbs + 6, (CK_ULONG)strlen(tbs) - 6);
		printf("C_SignUpdate (Thread %i, Session %ld, Slot=%ld - Part #2) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
#else
		largetbs = calloc(1, 1000);
		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)largetbs, 1000);
		printf("C_SignUpdate (Thread %i, Session %ld, Slot=%ld - Part #1) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)largetbs, 1000);
		printf("C_SignUpdate (Thread %i, Session %ld, Slot=%ld - Part #2) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
#endif

		len = 0;
		rc = p11->C_SignFinal(session, NULL, &len);
		printf("C_SignFinal (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Signature size = %lu\n", len);

		len--;
		rc = p11->C_SignFinal(session, signature, &len);
		printf("C_SignFinal (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_BUFFER_TOO_SMALL));

		printf("Signature size = %lu\n", len);

		len = sizeof(signature);
		rc = p11->C_SignFinal(session, signature, &len);
		printf("C_SignFinal (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK || rc == CKR_DEVICE_REMOVED || rc == CKR_TOKEN_NOT_PRESENT));

		if (rc == CKR_DEVICE_REMOVED || rc == CKR_TOKEN_NOT_PRESENT)
			goto out;

		if (rc == CKR_OK) {
			bin2str(scr, sizeof(scr), signature, len);
			printf("Signature:\n%s\n", scr);
		}

#ifdef ENABLE_LIBCRYPTO
		rc = p11->C_VerifyInit(session, &mech, pubhnd);
		printf("C_VerifyInit (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

#if 1
		rc = p11->C_VerifyUpdate(session, (CK_BYTE_PTR)tbs, 6);
		printf("C_VerifyUpdate (Thread %i, Session %ld, Slot=%ld - Part #1) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_VerifyUpdate(session, (CK_BYTE_PTR)tbs + 6, (CK_ULONG)strlen(tbs) - 6);
		printf("C_VerifyUpdate (Thread %i, Session %ld, Slot=%ld - Part #2) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
#else
		largetbs = calloc(1, 1000);
		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)largetbs, 1000);
		printf("C_SignUpdate (Thread %i, Session %ld, Slot=%ld - Part #1) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)largetbs, 1000);
		printf("C_SignUpdate (Thread %i, Session %ld, Slot=%ld - Part #2) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
#endif

		rc = p11->C_VerifyFinal(session, signature, len);
		printf("C_VerifyFinal (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
#endif
		keyno++;
	}

out:
	p11->C_CloseSession(session);

	return rc;
}



int testECSigning(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid, int id, CK_MECHANISM_TYPE mt)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_ECDSA;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_OBJECT_CLASS classpuk = CKO_PUBLIC_KEY;
	CK_BYTE keyid[256];
	CK_ATTRIBUTE puktemplate[] = {
			{ CKA_CLASS, &classpuk, sizeof(classpuk) },
			{ CKA_ID, keyid, sizeof(keyid) }
	};
	CK_OBJECT_HANDLE hnd,pubhnd;
	CK_MECHANISM mech = { CKM_ECDSA_SHA1, 0, 0 };
	char *tbs = "----Hello World-----";
	CK_BYTE signature[512];
	CK_ULONG len;
	char scr[1024];
	int rc,keyno;

	mech.mechanism = mt;
	keyno = 0;

	rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
	printf("C_OpenSession (Thread %i, Slot=%ld) - %s : %s\n", id, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK)
		return rc;

	rc = p11->C_Login(session, CKU_USER, pin, pinlen);
	printf("C_Login User (Thread %i, Slot=%ld) - %s : %s\n", id, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK || rc == CKR_USER_ALREADY_LOGGED_IN));

	if (rc != CKR_OK && rc != CKR_USER_ALREADY_LOGGED_IN)
		goto out;

	while (1) {
		rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), keyno, &hnd);

		if (rc != CKR_OK) {
			rc = CKR_OK;
			break;
		}
		printf("Calling C_SignInit()");
		rc = p11->C_SignInit(session, &mech, hnd);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Calling C_Sign()");

		len = 0;
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), NULL, &len);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Signature size = %lu\n", len);

		len = sizeof(signature);
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), signature, &len);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		bin2str(scr, sizeof(scr), signature, len);
		printf("Signature:\n%s\n", scr);


		rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&puktemplate[1], 1);
		printf("C_GetAttributeValue (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&puktemplate, sizeof(puktemplate) / sizeof(CK_ATTRIBUTE), 0, &pubhnd);
		printf("C_FindObject for public key (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc != CKR_OK) {
			keyno++;
			continue;
		}

#ifdef ENABLE_LIBCRYPTO
		rc = p11->C_VerifyInit(session, &mech, pubhnd);
		printf("C_VerifyInit (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_Verify(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), signature, len);
		printf("C_Verify (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
#endif

		keyno++;
	}

	out:
		p11->C_CloseSession(session);
	return rc;
}



#ifndef _WIN32
void*
#else
DWORD WINAPI
#endif
SignThread(void *arg) {

	struct thread_data *d;
	int rc;

	d = (struct thread_data *) arg;

	rc = CKR_OK;
	while (d->iterations && rc == CKR_OK) {
		rc = testRSASigning(d->p11, d->slotid, d->thread_id, CKM_SHA1_RSA_PKCS);
		if (rc == CKR_OK)
			rc = testECSigning(d->p11, d->slotid, d->thread_id, CKM_ECDSA_SHA1);
		d->iterations--;
	}

	d->iterations = 0;
	return 0;
}



void testSigningMultiThreading(CK_FUNCTION_LIST_PTR p11)
{
	CK_ULONG slots, slotindex;
	CK_SLOT_ID slotid;
	CK_SLOT_ID_PTR slotlist;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	pthread_t threads[NUM_THREADS];
	time_t start, stop;
#ifndef _WIN32
	pthread_attr_t attr;
	void *status;
#endif
	struct thread_data data[NUM_THREADS];
	int rc, tokens, firstloop, nothreads;
	long t;

	/* Initialize and set thread detached attribute */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	printf("Calling C_GetSlotList ");

	rc = p11->C_GetSlotList(FALSE, NULL, &slots);

	if (rc != CKR_OK) {
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
		return;
	}

	slotlist = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots);

	rc = p11->C_GetSlotList(FALSE, slotlist, &slots);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK) {
		return;
	}

	time(&start);

	slotindex = 0;
	tokens = 0;
	firstloop = 1;
	nothreads = 0;

	for (t = 0; t < NUM_THREADS; t++) {
		while(1) {
			if (slotindex >= slots) {
				if (!tokens) {
					printf("No slot with a token found\n");
					return;
				}
				slotindex = 0;
				firstloop = 0;
			}
			slotid = slotlist[slotindex++];

			printf("Calling C_GetSlotInfo for slot %lu ", slotid);

			rc = p11->C_GetSlotInfo(slotid, &slotinfo);
			printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

			if (rc != CKR_OK) {
				printf("C_GetSlotInfo() failed\n");
				return;
			}

			if (!(slotinfo.flags & CKF_TOKEN_PRESENT))
				continue;

			if ((optSlotId != -1) && (optSlotId != slotid))
				continue;

			rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
			if (*optTokenFilter && strncmp(optTokenFilter, (const char *)tokeninfo.label, strlen(optTokenFilter)))
				continue;

			break;
		}

		if (firstloop) {
			tokens++;
		} else {
			if (optOneThreadPerToken)
				break;
		}

		data[t].p11 = p11;
		data[t].slotid = slotid;
		data[t].thread_id = t;
		data[t].iterations = optIteration;

		rc = pthread_create(&threads[t], &attr, SignThread, (void *)&data[t]);

		if (rc) {
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			exit(1);
		}
		nothreads++;
	}

	/* Free attribute and wait for the other threads */
	pthread_attr_destroy(&attr);

	for (t = 0; t < nothreads; t++) {
		rc = pthread_join(threads[t], &status);

		if (rc) {
			printf("ERROR; return code from pthread_join() is %d\n", rc);
			exit(1);
		}

		printf("Thread %ld completed\n", t);
	}

	time(&stop);
	printf("Testing with %d threads on %d token\n", nothreads, tokens);
	printf("Multithreading test started at %s\n", asctime(localtime(&start)));
	printf("Multithreading test stopped at %s\n", asctime(localtime(&stop)));
	printf("Elapsed time is %.2lf seconds.\n", difftime (stop, start) );
}



void testRSADecryption(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mt)
{
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BBOOL _true = CK_TRUE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_DECRYPT, &_true, sizeof(_true) }
	};
	CK_OBJECT_CLASS classpuk = CKO_PUBLIC_KEY;
	CK_BYTE keyid[256];
	CK_ATTRIBUTE puktemplate[] = {
			{ CKA_CLASS, &classpuk, sizeof(classpuk) },
			{ CKA_ID, keyid, sizeof(keyid) }
	};
	CK_BYTE plain[512];
	CK_ATTRIBUTE modulus = { CKA_MODULUS, &plain, sizeof(plain) };
	CK_OBJECT_HANDLE hnd,pubhnd;
	CK_MECHANISM mech = { CKM_RSA_PKCS, 0, 0 };
	CK_BYTE cipher[512];
	CK_BYTE secret[512];
	CK_ULONG len, cipherlen,secretlen;
	char scr[2048];
	char *secretstr = "*SECRET*";
	int rc, keyno;

	mech.mechanism = mt;

	secretlen = (CK_ULONG)strlen(secretstr);
	memcpy(secret, secretstr, secretlen);

	keyno = 0;
	while (1) {
		rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), keyno, &hnd);

		if (rc != CKR_OK) {
			printf("No more keys for decryption found\n");
			return;
		}

		rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&puktemplate[1], 1);
		printf("C_GetAttributeValue (Session %ld) - %s : %s\n", session, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&puktemplate, sizeof(puktemplate) / sizeof(CK_ATTRIBUTE), 0, &pubhnd);
		printf("C_FindObject for public key (Session %ld) - %s : %s\n", session, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc != CKR_OK) {
			return;
		}

		if (mt == CKM_RSA_X_509) {
			rc = p11->C_GetAttributeValue(session, hnd, (CK_ATTRIBUTE_PTR)&modulus, 1);
			printf("C_GetAttributeValue (Session %ld) - %s : %s\n", session, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

			memset(secret, 0, sizeof(secret));
			strcpy((char *)secret + 1, secretstr);
			secretlen = modulus.ulValueLen;
		}

		printf("Calling C_EncryptInit()");
		rc = p11->C_EncryptInit(session, &mech, pubhnd);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Calling C_Encrypt()");
		cipherlen = sizeof(cipher);
		rc = p11->C_Encrypt(session, secret, secretlen, NULL, &cipherlen);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Cipher size = %lu\n", cipherlen);

		printf("Calling C_Encrypt()");
		cipherlen = sizeof(cipher);
		rc = p11->C_Encrypt(session, secret, secretlen, cipher, &cipherlen);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Calling C_DecryptInit()");
		rc = p11->C_DecryptInit(session, &mech, hnd);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Calling C_Decrypt()");

		len = 0;
		rc = p11->C_Decrypt(session, cipher, cipherlen, NULL, &len);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Plain size = %lu\n", len);

		len = sizeof(plain);
		rc = p11->C_Decrypt(session, cipher, cipherlen, plain, &len);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		bin2str(scr, sizeof(scr), plain, len);
		printf("Plain:\n%s\n%s\n", scr, verdict(!memcmp(plain, secret, len)));

		keyno++;
	}
}



void testRandom(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	int rc;
	CK_BYTE scr[4096];

	printf("Calling C_GenerateRandom(1) ");
	rc = p11->C_GenerateRandom(session, scr, 1);

	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_GenerateRandom(4096) ");
	rc = p11->C_GenerateRandom(session, scr, sizeof(scr));

	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
}



void testKeyGeneration(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	int rc;
	CK_CHAR label[] = "TestKey";
	CK_BBOOL _false = FALSE;
	CK_BBOOL _true = TRUE;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE publicKeyTemplate[20] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_LABEL, &label, (CK_ULONG)strlen((char *)label) }
	};
	int publicKeyAttributes = 3;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE privateKeyTemplate[20] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_PRIVATE, &_true, sizeof(_true)},
			{ CKA_SENSITIVE, &_true, sizeof(_true)},
			{ CKA_LABEL, &label, (CK_ULONG)strlen((char *)label) }
	};
	int privateKeyAttributes = 5;
	unsigned char cvcreq[512];
	CK_ATTRIBUTE template[] = {
			{ CKA_CVC_REQUEST, &cvcreq, sizeof(cvcreq)},
	};
	unsigned char oid[20];
	CK_ATTRIBUTE oidTemplate[] = {
			{ CKA_CVC_CURVE_OID, &oid, sizeof(oid)},
	};
	CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_CVC_TR3110;
	CK_BYTE id[100];
	CK_ATTRIBUTE certTemplate[20] = {
			{ CKA_CLASS, &certClass, sizeof(certClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
			{ CKA_VALUE, NULL, 0 },
			{ CKA_ID, id, sizeof(id) }
	};
	int certAttributes = 5;
	CK_ATTRIBUTE changeTemplate[2] = {
			{ CKA_LABEL, &label, (CK_ULONG)strlen((char *)label) },
			{ CKA_ID, id, sizeof(id) }
	};
	CK_OBJECT_HANDLE hndPrivateKey, hndPublicKey, hndCert, hndCACert, hndSessionCACert, hndRSAPrivateKey, hndRSAPublicKey;
	CK_MECHANISM mech_genecc = { CKM_EC_KEY_PAIR_GEN, 0, 0 };
	CK_MECHANISM mech_genrsa = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 };
	CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
	CK_ULONG keysize = 1024;
	CK_BYTE innerCAR[] = { 'D','E','T','E','S','T','0','0','0','0','0' };
	unsigned char *po, *val;
	int tag, len, vlen;

	publicKeyTemplate[publicKeyAttributes].type = CKA_EC_PARAMS;
	publicKeyTemplate[publicKeyAttributes].pValue = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
	publicKeyTemplate[publicKeyAttributes].ulValueLen = 10;
	publicKeyAttributes++;

	privateKeyTemplate[privateKeyAttributes].type = CKA_SIGN;
	privateKeyTemplate[privateKeyAttributes].pValue = &_true;
	privateKeyTemplate[privateKeyAttributes].ulValueLen = sizeof(_true);
	privateKeyAttributes++;

	privateKeyTemplate[privateKeyAttributes].type = CKA_DERIVE;
	privateKeyTemplate[privateKeyAttributes].pValue = &_true;
	privateKeyTemplate[privateKeyAttributes].ulValueLen = sizeof(_true);
	privateKeyAttributes++;

	printf("Calling C_GenerateKeyPair(EC, prime256v1) ");
	rc = p11->C_GenerateKeyPair(session, &mech_genecc,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndPublicKey, &hndPrivateKey);

	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Private Key:\n");
		dumpObject(p11, session, hndPrivateKey);
		printf("Public Key:\n");
		dumpObject(p11, session, hndPublicKey);
	}

	printf("Calling C_GetAttributeValue ");
	rc = p11->C_GetAttributeValue(session, hndPublicKey, (CK_ATTRIBUTE_PTR)&template, 1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	po = template[0].pValue;
	len = template[0].ulValueLen;
	asn1Next(&po, &len, &tag, &vlen, &val);

	certTemplate[certAttributes - 2].pValue = val;
	certTemplate[certAttributes - 2].ulValueLen = vlen;

	printf("Calling C_GetAttributeValue ");
	rc = p11->C_GetAttributeValue(session, hndPublicKey, (CK_ATTRIBUTE_PTR)&certTemplate[certAttributes - 1], 1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_CreateObject ");
	rc = p11->C_CreateObject(session, certTemplate, certAttributes, &hndCert);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Certificate [%d]:\n", (int)hndCert);
		dumpObject(p11, session, hndCert);
	}

	printf("Calling C_CreateObject as second time to overwrite ");
	rc = p11->C_CreateObject(session, certTemplate, certAttributes, &hndCert);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Certificate [%d]:\n", (int)hndCert);
		dumpObject(p11, session, hndCert);
	}

	printf("Calling C_CreateObject to create CA certificate ");
	rc = p11->C_CreateObject(session, certTemplate, certAttributes - 1, &hndCACert); 	// Ignore CKA_ID
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Certificate [%d]:\n", (int)hndCACert);
		dumpObject(p11, session, hndCACert);
	}


	// Create a CKO_CERTIFICATE session object to parse and determine certain certificate fields
	printf("Calling C_CreateObject to create session CA certificate ");
	certTemplate[1].pValue = &_false;
	rc = p11->C_CreateObject(session, certTemplate, certAttributes - 1, &hndSessionCACert);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Certificate [%d]:\n", (int)hndSessionCACert);
		dumpObject(p11, session, hndSessionCACert);
	}

	printf("Calling C_GetAttributeValue ");
	rc = p11->C_GetAttributeValue(session, hndSessionCACert, (CK_ATTRIBUTE_PTR)&oidTemplate, 1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(Session CACert) ");
	rc = p11->C_DestroyObject(session, hndSessionCACert);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(ECPublicKey) ");
	rc = p11->C_DestroyObject(session, hndPublicKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(ECPrivateKey) ");
	rc = p11->C_DestroyObject(session, hndPrivateKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));


	publicKeyTemplate[3].pValue = ecparam_prime256v1.val;
	publicKeyTemplate[3].ulValueLen = (CK_ULONG)ecparam_prime256v1.len;

	printf("Calling C_GenerateKeyPair(EC, explicit parameter) ");

	rc = p11->C_GenerateKeyPair(session, &mech_genecc,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndPublicKey, &hndPrivateKey);

	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Private Key:\n");
		dumpObject(p11, session, hndPrivateKey);
		printf("Public Key:\n");
		dumpObject(p11, session, hndPublicKey);
	}


	publicKeyAttributes = 3;
	publicKeyTemplate[publicKeyAttributes].type = CKA_MODULUS_BITS;
	publicKeyTemplate[publicKeyAttributes].pValue = &keysize;
	publicKeyTemplate[publicKeyAttributes].ulValueLen = sizeof(keysize);
	publicKeyAttributes++;

	publicKeyTemplate[publicKeyAttributes].type = CKA_PUBLIC_EXPONENT;
	publicKeyTemplate[publicKeyAttributes].pValue = publicExponent;
	publicKeyTemplate[publicKeyAttributes].ulValueLen = sizeof(publicExponent);
	publicKeyAttributes++;

	publicKeyTemplate[publicKeyAttributes].type = CKA_CVC_INNER_CAR;
	publicKeyTemplate[publicKeyAttributes].pValue = innerCAR;
	publicKeyTemplate[publicKeyAttributes].ulValueLen = sizeof(innerCAR);
	publicKeyAttributes++;

	privateKeyAttributes = 5;
	privateKeyTemplate[privateKeyAttributes].type = CKA_SIGN;
	privateKeyTemplate[privateKeyAttributes].pValue = &_true;
	privateKeyTemplate[privateKeyAttributes].ulValueLen = sizeof(_true);
	privateKeyAttributes++;

	privateKeyTemplate[privateKeyAttributes].type = CKA_DECRYPT;
	privateKeyTemplate[privateKeyAttributes].pValue = &_true;
	privateKeyTemplate[privateKeyAttributes].ulValueLen = sizeof(_true);
	privateKeyAttributes++;

	printf("Calling C_GenerateKeyPair(RSA, 1024) ");
	rc = p11->C_GenerateKeyPair(session, &mech_genrsa,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndRSAPublicKey, &hndRSAPrivateKey);

	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Private Key:\n");
		dumpObject(p11, session, hndRSAPrivateKey);
		printf("Public Key:\n");
		dumpObject(p11, session, hndRSAPublicKey);
	}

	printf("Calling C_SetAttributeValue(Label, ID) ");
	changeTemplate[0].pValue = "New Label";
	changeTemplate[0].ulValueLen = (CK_ULONG)strlen(changeTemplate[0].pValue);

	changeTemplate[1].pValue = "\xCA\xFF\xEE";
	changeTemplate[1].ulValueLen = 3;

	rc = p11->C_SetAttributeValue(session, hndRSAPrivateKey, changeTemplate, 2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));


	printf("Calling C_SetAttributeValue(Label, ID) ");
	changeTemplate[0].pValue = "New Certificate Label";
	changeTemplate[0].ulValueLen = (CK_ULONG)strlen(changeTemplate[0].pValue);

	rc = p11->C_SetAttributeValue(session, hndCACert, changeTemplate, 1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));


	printf("Calling C_DestroyObject(CACert) ");
	rc = p11->C_DestroyObject(session, hndCACert);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(EECert) ");
	rc = p11->C_DestroyObject(session, hndCert);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(RSAPublicKey) ");
	rc = p11->C_DestroyObject(session, hndRSAPublicKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(RSAPrivateKey) ");
	rc = p11->C_DestroyObject(session, hndRSAPrivateKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(ECPublicKey) ");
	rc = p11->C_DestroyObject(session, hndPublicKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(ECPrivateKey) ");
	rc = p11->C_DestroyObject(session, hndPrivateKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
}



void testKeyDerivation(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	int rc;
	CK_CHAR labelBase[] = "TestBaseKey", labelDerived[] = "TestDerivedKey";
	CK_BBOOL _true = TRUE;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS deriveClass = CKO_PRIVATE_KEY;

	CK_ATTRIBUTE publicKeyTemplate[5] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_LABEL, &labelBase, (CK_ULONG)strlen((char *)labelBase) }
	};
	int publicKeyAttributes = 3;

	CK_ATTRIBUTE privateKeyTemplate[7] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true) },
			{ CKA_PRIVATE, &_true, sizeof(_true) },
			{ CKA_SENSITIVE, &_true, sizeof(_true) },
			{ CKA_LABEL, &labelBase, (CK_ULONG)strlen((char *)labelBase) },
			{ CKA_SIGN, &_true, sizeof(_true) },
			{ CKA_DERIVE, &_true, sizeof(_true) }
	};
	int privateKeyAttributes = 7;

	CK_KEY_TYPE keyType = CKK_EC;
	CK_ATTRIBUTE deriveTemplate[5] = {
			{ CKA_CLASS, &deriveClass, sizeof(deriveClass) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{ CKA_SIGN, &_true, sizeof(_true)},
			{ CKA_LABEL, &labelDerived, (CK_ULONG)strlen((char *)labelDerived) },
	};
	int derivedAttributes = 5;

	CK_OBJECT_HANDLE hndPrivateKey, hndPublicKey, hndDerivedKey;
	CK_MECHANISM mech_genecc = { CKM_EC_KEY_PAIR_GEN, 0, 0 };
	unsigned char offset[32] = {0xA9,0xFB,0x57,0xDB,0xA1,0xEE,0xA9,0xBC,0x3E,0x66,0x0A,0x90,0x9D,0x83,0x8D,0x72,0x6E,0x3B,0xF6,0x23,0xD5,0x26,0x20,0x28,0x20,0x13,0x48,0x1D,0x1F,0x6E,0x53,0x76};
	CK_MECHANISM mech_derive = { CKM_SC_HSM_EC_DERIVE, &offset, sizeof(offset) };
	CK_MECHANISM signMech = { CKM_SC_HSM_ECDSA_SHA256, 0, 0 };
	char *tbs = "----Hello World-----";
	CK_BYTE signature[512];
	CK_ULONG signatureLen;
	char scr[1024];

	publicKeyTemplate[publicKeyAttributes].type = CKA_EC_PARAMS;
	publicKeyTemplate[publicKeyAttributes].pValue = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
	publicKeyTemplate[publicKeyAttributes].ulValueLen = 10;
	publicKeyAttributes++;

	publicKeyTemplate[publicKeyAttributes].type = CKA_SC_HSM_ALGORITHM_LIST;
	publicKeyTemplate[publicKeyAttributes].pValue = "\xA0\x73\x98";
	publicKeyTemplate[publicKeyAttributes].ulValueLen = 3;
	publicKeyAttributes++;

	printf("Calling C_GenerateKeyPair(EC, prime256v1) ");
	rc = p11->C_GenerateKeyPair(session, &mech_genecc,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndPublicKey, &hndPrivateKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DeriveKey ");
	rc = p11->C_DeriveKey(session, &mech_derive, hndPrivateKey, deriveTemplate, derivedAttributes, &hndDerivedKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc == CKR_OK) {
		printf("Derived Private Key:\n");
		dumpObject(p11, session, hndDerivedKey);
	}

	printf("Calling C_SignInit()");
	rc = p11->C_SignInit(session, &signMech, hndDerivedKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_Sign()");
	signatureLen = sizeof(signature);
	rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, (CK_ULONG)strlen(tbs), signature, &signatureLen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	bin2str(scr, sizeof(scr), signature, signatureLen);
	printf("Signature:\n%s\n", scr);

	printf("Calling C_DestroyObject(DerivedKey) ");
	rc = p11->C_DestroyObject(session, hndDerivedKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DestroyObject(BaseKey) ");
	rc = p11->C_DestroyObject(session, hndPrivateKey);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
}



void testDigest(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session, CK_MECHANISM_TYPE mt)
{
	CK_BYTE hash1[64],hash2[64];
	CK_ULONG hashlen1, hashlen2, msglen;
	CK_BYTE *message = (CK_BYTE *)"Hello World, read this is a hash message";
	CK_MECHANISM mech;
	CK_RV rc;
	char scr[1024];

	msglen = (CK_ULONG)strlen((char *)message);

	mech.mechanism = mt;

	printf("Calling C_DigestInit ");
	rc = p11->C_DigestInit(session, &mech);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_Digest - query size");
	hashlen1 = 0;
	rc = p11->C_Digest(session, message, msglen, NULL, &hashlen1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Hashlen = %ld\n", hashlen1);

	hashlen1--;
	rc = p11->C_Digest(session, message, msglen, hash1, &hashlen1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_BUFFER_TOO_SMALL));
	printf("Hashlen = %ld\n", hashlen1);

	printf("Calling C_Digest ");
	rc = p11->C_Digest(session, message, msglen, hash1, &hashlen1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	bin2str(scr, sizeof(scr), hash1, hashlen1);
	printf("Plain: %s\n", scr);


	printf("Calling C_DigestInit ");
	rc = p11->C_DigestInit(session, &mech);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DigestUpdate ");
	rc = p11->C_DigestUpdate(session, message, msglen - 20);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DigestUpdate ");
	rc = p11->C_DigestUpdate(session, message + msglen - 20, 20);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_DigestFinal - query size");
	hashlen2 = 0;
	rc = p11->C_DigestFinal(session, NULL, &hashlen2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Hashlen = %ld - %s\n", hashlen2, verdict(hashlen1 == hashlen2));

	hashlen2--;
	rc = p11->C_DigestFinal(session, hash2, &hashlen2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_BUFFER_TOO_SMALL));
	printf("Hashlen = %ld - %s\n", hashlen2, verdict(hashlen1 == hashlen2));

	rc = p11->C_DigestFinal(session, hash2, &hashlen2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	bin2str(scr, sizeof(scr), hash2, hashlen2);
	printf("Plain:%s - %s\n", scr, verdict(!memcmp(hash1, hash2, hashlen1)));
}



void testSessions(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid)
{
	int rc;
	CK_SESSION_INFO sessioninfo;
	CK_SESSION_HANDLE session1, session2, session3;

	printf("Calling C_OpenSession ");
	rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_OpenSession ");
	rc = p11->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session1, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session2, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RO_PUBLIC_SESSION));

	printf("Calling C_CloseSession ");
	rc = p11->C_CloseSession(session2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_CloseSession with wrong handle ");
	rc = p11->C_CloseSession(session2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_SESSION_HANDLE_INVALID));

	printf("Calling C_CloseSession ");
	rc = p11->C_CloseSession(session1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	// Sequence inspired by PKCS#11 example
	printf("Calling C_OpenSession ");
	rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_OpenSession ");
	rc = p11->C_OpenSession(slotid, CKF_SERIAL_SESSION, NULL, NULL, &session2);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_Login(SO) ");
	rc = p11->C_Login(session1, CKU_SO, sopin, sopinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_SESSION_READ_ONLY_EXISTS));

	printf("Calling C_Login(SO) ");
	rc = p11->C_Login(session2, CKU_SO, sopin, sopinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_SESSION_READ_ONLY));

	printf("Calling C_Login(USER) ");
	rc = p11->C_Login(session1, CKU_USER, pin, pinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session1, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_USER_FUNCTIONS));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session2, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RO_USER_FUNCTIONS));

	printf("Calling C_OpenSession ");
	rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session3);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session3, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_USER_FUNCTIONS));

	printf("Calling C_CloseSession ");
	rc = p11->C_CloseSession(session3);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_Logout ");
	rc = p11->C_Logout(session1);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session1, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session2, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RO_PUBLIC_SESSION));

	printf("Calling C_CloseAllSessions ");
	rc = p11->C_CloseAllSessions(slotid);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
}



void testTransportPIN(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid)
{
	int rc;
	CK_SESSION_HANDLE session;

	printf("Calling C_OpenSession ");
	rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_SetPIN User ");
	rc = p11->C_SetPIN(session, (CK_UTF8CHAR_PTR)"835212", 6, (CK_UTF8CHAR_PTR)pin, pinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_CloseSession ");
	rc = p11->C_CloseSession(session);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
}



void testLogin(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	int rc;
	CK_SESSION_INFO sessioninfo;
	CK_TOKEN_INFO tokeninfo;
	CK_OBJECT_HANDLE hnd;
	CK_MECHANISM mech = { CKM_SHA1_RSA_PKCS, 0, 0 };
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
//	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) }
//			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};


	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

	printf("Calling C_Login User ");
	rc = p11->C_Login(session, CKU_USER, pin, pinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK) {
		exit(1);
	}

	printf("Find a private key after login");
	rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), 0, &hnd);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_USER_FUNCTIONS));

	printf("Calling C_Logout ");
	rc = p11->C_Logout(session);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Find a private key after logout");
	rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), 0, &hnd);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_ARGUMENTS_BAD));

	rc = p11->C_SignInit(session, &mech, hnd);
	printf("C_SignInit - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_KEY_HANDLE_INVALID));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

	printf("Calling C_GetTokenInfo ");
	rc = p11->C_GetTokenInfo(sessioninfo.slotID, &tokeninfo);
	printf("Token flags %lx - %s\n", tokeninfo.flags, verdict((tokeninfo.flags & (CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED)) == 0));


	printf("Calling C_Login User ");
	rc = p11->C_Login(session, CKU_USER, wrongpin, pinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_PIN_INCORRECT));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

	printf("Calling C_GetTokenInfo ");
	rc = p11->C_GetTokenInfo(sessioninfo.slotID, &tokeninfo);
	printf("Token flags %lx - %s\n", tokeninfo.flags, verdict((tokeninfo.flags & (CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED)) == CKF_USER_PIN_COUNT_LOW));


	printf("Calling C_Login User ");
	rc = p11->C_Login(session, CKU_USER, wrongpin, pinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_PIN_INCORRECT));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

	printf("Calling C_GetTokenInfo ");
	rc = p11->C_GetTokenInfo(sessioninfo.slotID, &tokeninfo);
	printf("Token flags %lx - %s\n", tokeninfo.flags, verdict((tokeninfo.flags & (CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED)) == (CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY)));

	if (optTestPINBlock) {
		printf("Calling C_Login User ");
		rc = p11->C_Login(session, CKU_USER, wrongpin, pinlen);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_PIN_LOCKED));

		printf("Calling C_GetSessionInfo ");
		rc = p11->C_GetSessionInfo(session, &sessioninfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
		printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

		printf("Calling C_GetTokenInfo ");
		rc = p11->C_GetTokenInfo(sessioninfo.slotID, &tokeninfo);
		printf("Token flags %lx - %s\n", tokeninfo.flags, verdict((tokeninfo.flags & (CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED)) == (CKF_USER_PIN_LOCKED)));

		printf("Calling C_Login(SO) ");
		rc = p11->C_Login(session, CKU_SO, sopin, sopinlen);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Calling C_InitPIN() ");
		rc = p11->C_InitPIN(session, pin, pinlen);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Calling C_GetTokenInfo ");
		rc = p11->C_GetTokenInfo(sessioninfo.slotID, &tokeninfo);
		printf("Token flags %lx - %s\n", tokeninfo.flags, verdict((tokeninfo.flags & (CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED)) == 0));

		printf("Calling C_SetPIN SO-PIN ");
		rc = p11->C_SetPIN(session, sopin, sopinlen, sopin, sopinlen);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Calling C_Logout ");
		rc = p11->C_Logout(session);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	}

	printf("Calling C_Login User ");
	rc = p11->C_Login(session, CKU_USER, pin, pinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_GetSessionInfo ");
	rc = p11->C_GetSessionInfo(session, &sessioninfo);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
	printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_USER_FUNCTIONS));

	printf("Calling C_GetTokenInfo ");
	rc = p11->C_GetTokenInfo(sessioninfo.slotID, &tokeninfo);
	printf("Token flags %lx - %s\n", tokeninfo.flags, verdict((tokeninfo.flags & (CKF_USER_PIN_COUNT_LOW|CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_LOCKED)) == 0));

//	printf("Calling C_SetPIN User ");
//	rc = p11->C_SetPIN(session, pin, pinlen, pin, pinlen);
//	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if ((tokeninfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) && !optNoClass3Tests) {

		printf("Calling C_Logout ");
		rc = p11->C_Logout(session);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Testing CKF_PROTECTED_AUTHENTICATION_PATH - Please enter correct PIN on pin-pad\n");
		printf("Calling C_Login User");
		rc = p11->C_Login(session, CKU_USER, NULL, 0);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc != CKR_OK) {
			exit(1);
		}

		printf("Calling C_GetSessionInfo ");
		rc = p11->C_GetSessionInfo(session, &sessioninfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
		printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_USER_FUNCTIONS));

		printf("Calling C_Logout ");
		rc = p11->C_Logout(session);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));


		printf("Testing CKF_PROTECTED_AUTHENTICATION_PATH - Please enter wrong PIN on pin-pad\n");
		printf("Calling C_Login User ");
		rc = p11->C_Login(session, CKU_USER, NULL, 0);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_PIN_INCORRECT));

		printf("Calling C_GetSessionInfo ");
		rc = p11->C_GetSessionInfo(session, &sessioninfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
		printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_PUBLIC_SESSION));

		/*
		 * Reset the PIN counter
		 */
		printf("Calling C_Login User ");
		rc = p11->C_Login(session, CKU_USER, pin, pinlen);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc != CKR_OK) {
			exit(1);
		}

		printf("Calling C_GetSessionInfo ");
		rc = p11->C_GetSessionInfo(session, &sessioninfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
		printf("Session state %lu - %s\n", sessioninfo.state, verdict(sessioninfo.state == CKS_RW_USER_FUNCTIONS));

	}
}



void testInsertRemove(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid)
{
	CK_RV rc;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	char *inp = NULL;
	size_t inplen;
	int loop;

	for (loop = 0; loop < 2; loop++) {
		printf("Please remove card from slot %lu and press <ENTER>\n", slotid);
		inp = NULL;
		if (getline(&inp, &inplen, stdin) < 0) {
			return;
		}
		free(inp);

		printf("Calling C_GetSlotInfo for slot %lu ", slotid);
		rc = p11->C_GetSlotInfo(slotid, &slotinfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (slotinfo.flags & CKF_TOKEN_PRESENT) {
			printf("slotinfo.flags - Failed\n");
		}

		printf("Calling C_GetTokenInfo ");
		rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_TOKEN_NOT_PRESENT));

		printf("Please insert card in slot %lu and press <ENTER>\n", slotid);
		inp = NULL;
		if (getline(&inp, &inplen, stdin) < 0) {
			return;
		}
		free(inp);

		printf("Calling C_GetSlotInfo for slot %lu ", slotid);
		rc = p11->C_GetSlotInfo(slotid, &slotinfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (!(slotinfo.flags & CKF_TOKEN_PRESENT)) {
			printf("slotinfo.flags - Failed\n");
		}

		printf("Calling C_GetTokenInfo ");
		rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc == CKR_OK) {
			printf("Token label: %s\n", p11string(tokeninfo.label, sizeof(tokeninfo.label)));
		}
	}
}



void testEvent(CK_FUNCTION_LIST_PTR p11)
{
	CK_SLOT_ID slotid;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	int rc;

	do	{
		rc = p11->C_WaitForSlotEvent(0, &slotid, NULL);

		if (rc != CKR_OK) {
			printf("C_WaitForSlotEvent - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
			return;
		}

		rc = p11->C_GetSlotInfo(slotid, &slotinfo);

		if (rc != CKR_OK) {
			printf("C_GetSlotInfo - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
			return;
		}

		printf("Slot manufacturer: %s\n", p11string(slotinfo.manufacturerID, sizeof(slotinfo.manufacturerID)));
		printf("Slot ID : Slot description: %ld : %s\n", slotid, p11string(slotinfo.slotDescription, sizeof(slotinfo.slotDescription)));
		printf("Slot flags: %08x\n", (int)slotinfo.flags);

		rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), rc == CKR_OK ? "Passed" : rc == CKR_TOKEN_NOT_PRESENT ? "No token" : "Failed");

		if (rc == CKR_OK) {
			printf("Token label: %s\n", p11string(tokeninfo.label, sizeof(tokeninfo.label)));
			printf("Token flags: %08lx\n", tokeninfo.flags);
		}
	} while (1);
}



void testHotplug(CK_FUNCTION_LIST_PTR p11)
{
	CK_ULONG slots, slotindex;
	CK_SLOT_ID slotid;
	CK_SLOT_ID_PTR slotlist;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	pthread_t threads[100];
#ifndef _WIN32
	pthread_attr_t attr;
#endif
	void *status;
	struct thread_data data[100];
	int rc, tokens, nothreads = 0, t;

	/* Initialize and set thread detached attribute */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	memset(&data, 0, sizeof(data));

	do	{
		rc = p11->C_GetSlotList(FALSE, NULL, &slots);

		if (rc != CKR_OK) {
			printf("C_GetSlotList - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
			return;
		}

		slotlist = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots);

		rc = p11->C_GetSlotList(FALSE, slotlist, &slots);
		printf("C_GetSlotList - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc != CKR_OK) {
			return;
		}

		tokens = 0;
		for (slotindex = 0; slotindex < slots; slotindex++) {
			slotid = slotlist[slotindex];

			rc = p11->C_GetSlotInfo(slotid, &slotinfo);
			printf("C_GetSlotInfo for slot %lu - %s : %s\n", slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

			if (rc != CKR_OK) {
				printf("C_GetSlotInfo() failed\n");
				return;
			}

			if (slotinfo.flags & CKF_TOKEN_PRESENT) {
				rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
				if (*optTokenFilter && strncmp(optTokenFilter, (const char *)tokeninfo.label, strlen(optTokenFilter)))
					continue;

				tokens++;

				for (t = slotindex * optThreadsPerToken; t < (int)(slotindex + 1) * optThreadsPerToken; t++) {
					if (t >= 100) {
						printf("ERROR: Can not handle more than 100 threads");
						exit(1);
					}
					if (!data[t].p11) {
						data[t].p11 = p11;
						data[t].slotid = slotid;
						data[t].thread_id = t;
						data[t].iterations = 1;

						rc = pthread_create(&threads[t], &attr, SignThread, (void *)&data[t]);

						if (rc) {
							printf("ERROR: return code from pthread_create() is %d\n", rc);
							exit(1);
						}

						nothreads++;
					} else {
						if (!data[t].iterations) {
							status = NULL;
							rc = pthread_join(threads[t], &status);
							free(status);
							printf("Thread %d completed\n", t);
							data[t].p11 = NULL;
						}
					}
				}
			}
		}
		free(slotlist);
		if (tokens > 0) {
			usleep(5000000);
		} else {
			usleep(500000);
		}
//	} while (tokens > 0);
	} while (testsfailed == 0);

	/* Free attribute and wait for the other threads */
	pthread_attr_destroy(&attr);

	for (t = 0; t < NUM_THREADS; t++) {
		if (data[t].p11) {
			rc = pthread_join(threads[t], &status);
			free(status);
			printf("Thread %d completed\n", t);
		}
	}
}



void unlockPIN(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid)
{
	CK_RV rc;
	CK_SESSION_HANDLE session;

	rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
	printf("Calling C_OpenSession - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	rc = p11->C_Login(session, CKU_SO, sopin, sopinlen);
	printf("Calling C_Login(SO) - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	rc = p11->C_InitPIN(session, NULL, 0);
	printf("Calling C_InitPIN() - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	rc = p11->C_CloseSession(session);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
}



void usage()
{
	printf("sc-hsm-tool [--module <p11-file>] [--pin <user-pin>] [--token <tokenname>] [--optThreadsPerToken <count>] [--iterations <count>]\n");
	printf("  --test-insert-remove       Enable insert / remove test\n");
	printf("  --test-pin-block           Enable PIN blocking test\n");
	printf("  --test-multithreading-only Perform multithreading tests only\n");
	printf("  --test-hotplug-only        Perform hotplug tests only\n");
	printf("  --one-thread-per-token     Create a single thread per token rather than distributing %d\n", NUM_THREADS);
	printf("  --no-class3-tests          No PIN tests with attached class 3 PIN PAD\n");
	printf("  --multithreading-tests     Perform multithreading tests\n");
	printf("  --unlock-pin               Unlock PIN without setting a new value\n");
}



void decodeArgs(int argc, char **argv)
{
	argv++;
	argc--;

	while (argc--) {
		if (!strcmp(*argv, "--pin")) {
			if (argc < 0) {
				printf("Argument for --pin missing\n");
				exit(1);
			}
			argv++;
			pin = (CK_UTF8CHAR_PTR)*argv;
			pinlen = (CK_ULONG)strlen((char *)pin);
			argc--;
		} else if (!strcmp(*argv, "--so-pin")) {
			if (argc < 0) {
				printf("Argument for --so-pin missing\n");
				exit(1);
			}
			argv++;
			sopin = (CK_UTF8CHAR_PTR)*argv;
			sopinlen = (CK_ULONG)strlen((char *)sopin);
			argc--;
		} else if (!strcmp(*argv, "--module")) {
			if (argc < 0) {
				printf("Argument for --module missing\n");
				exit(1);
			}
			argv++;
			p11libname = *argv;
			argc--;
		} else if (!strcmp(*argv, "--token")) {
			if (argc < 0) {
				printf("Argument for --token missing\n");
				exit(1);
			}
			argv++;
			optTokenFilter = *argv;
			argc--;
		} else if (!strcmp(*argv, "--slotid")) {
			if (argc < 0) {
				printf("Argument for --slotid missing\n");
				exit(1);
			}
			argv++;
			optSlotId = atol(*argv);
			argc--;
		} else if (!strcmp(*argv, "--threads")) {
			if (argc < 0) {
				printf("Argument for --threads missing\n");
				exit(1);
			}
			argv++;
			optThreadsPerToken = atol(*argv);
			argc--;
		} else if (!strcmp(*argv, "--iterations")) {
			if (argc < 0) {
				printf("Argument for --iterations missing\n");
				exit(1);
			}
			argv++;
			optIteration = atol(*argv);
			argc--;
		} else if (!strcmp(*argv, "--test-insert-remove")) {
			optTestInsertRemove = 1;
		} else if (!strcmp(*argv, "--test-pin-block")) {
			optTestPINBlock = 1;
		} else if (!strcmp(*argv, "--test-multithreading-only")) {
			optTestMultiOnly = 1;
		} else if (!strcmp(*argv, "--test-hotplug-only")) {
			optTestHotplug = 1;
		} else if (!strcmp(*argv, "--test-event-only")) {
			optTestEvent = 1;
		} else if (!strcmp(*argv, "--one-thread-per-token")) {
			optOneThreadPerToken = 1;
		} else if (!strcmp(*argv, "--no-class3-tests")) {
			optNoClass3Tests = 1;
		} else if (!strcmp(*argv, "--multithreading-tests")) {
			optMultiThreadingTests = 1;
		} else if (!strcmp(*argv, "--unlock-pin")) {
			optUnlockPIN = 1;
		} else {
			printf("Unknown argument %s\n", *argv);
			usage();
			exit(1);
		}
		argv++;
	}
}



int main(int argc, char *argv[])
{
	int i;
	CK_RV rc;
	CK_ULONG slots;
	CK_SESSION_HANDLE session;
	CK_INFO info;
	CK_SLOT_ID_PTR slotlist = NULL;
	CK_SLOT_ID slotid;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	CK_ATTRIBUTE attr[6];
	CK_FUNCTION_LIST_PTR p11;
	LIB_HANDLE dlhandle;
	CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
	CK_C_INITIALIZE_ARGS initArgs;

	decodeArgs(argc, argv);

	printf("PKCS11 unittest running.\n");

	dlhandle = dlopen(p11libname, RTLD_NOW);

	if (!dlhandle) {
		printf("dlopen failed with %s\n", dlerror());
		exit(1);
	}

	C_GetFunctionList = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))dlsym(dlhandle, "C_GetFunctionList");

	printf("Calling C_GetFunctionList ");

	(*C_GetFunctionList)(&p11);

	memset(&initArgs, 0, sizeof(initArgs));
	initArgs.flags = CKF_OS_LOCKING_OK;

	printf("Calling C_Initialize ");

	rc = p11->C_Initialize(&initArgs);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK) {
		exit(1);
	}

	printf("Calling C_GetInfo ");

	rc = p11->C_GetInfo(&info);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK) {
		exit(1);
	}

	if (optTestHotplug) {
		testHotplug(p11);
	} else if (optTestEvent) {
		testEvent(p11);
	} else {
		printf("Calling C_GetSlotList ");

		rc = p11->C_GetSlotList(TRUE, NULL, &slots);

		if (rc != CKR_OK) {
			printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
			exit(1);
		}

		rc = p11->C_GetSlotList(FALSE, NULL, &slots);

		if (rc != CKR_OK) {
			printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
			exit(1);
		}

		slotlist = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots);

		rc = p11->C_GetSlotList(FALSE, slotlist, &slots);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		if (rc != CKR_OK) {
			exit(1);
		}

		i = 0;

		while (i < (int)slots) {
			slotid = *(slotlist + i);
			i++;

			if ((optSlotId != -1) && (optSlotId != slotid))
				continue;

			if (optTestInsertRemove)
				testInsertRemove(p11, slotid);

			printf("Calling C_GetSlotInfo for slot %lu ", slotid);

			rc = p11->C_GetSlotInfo(slotid, &slotinfo);
			printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

			if (rc != CKR_OK) {
				printf("Error getting slot information from cryptoki. slotid = %lu, rc = %lu = %s\n", slotid, rc, id2name(p11CKRName, rc, NULL, namebuf));
				free(slotlist);
				exit(1);
			}

			printf("Slot manufacturer: %s\n", p11string(slotinfo.manufacturerID, sizeof(slotinfo.manufacturerID)));
			printf("Slot ID : Slot description: %ld : %s\n", slotid, p11string(slotinfo.slotDescription, sizeof(slotinfo.slotDescription)));
			printf("Slot flags: %x\n", (int)slotinfo.flags);

			printf("Calling C_GetTokenInfo ");

			rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
			printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), rc == CKR_OK ? "Passed" : rc == CKR_TOKEN_NOT_PRESENT ? "No token" : "Failed");

			if (rc != CKR_OK && rc != CKR_TOKEN_NOT_PRESENT) {
				printf("Error getting token information from cryptoki. slotid = %lu, rc = %lu = %s\n", slotid, rc, id2name(p11CKRName, rc, NULL, namebuf));
				free(slotlist);
				exit(1);
			}

			if (rc == CKR_OK) {
				printf("Token label       : %s\n", p11string(tokeninfo.label, sizeof(tokeninfo.label)));
				printf("Token manufacturer: %s\n", p11string(tokeninfo.manufacturerID, sizeof(tokeninfo.manufacturerID)));
				printf("Token model       : %s\n", p11string(tokeninfo.model, sizeof(tokeninfo.model)));
				printf("Token flags       : %lx\n", tokeninfo.flags);

				if (pin == NULL) {
					if (!strncmp("STARCOS", (char *)tokeninfo.label, 7)) {
						pin = (CK_UTF8CHAR_PTR)PIN_STARCOS;
						pinlen = (CK_ULONG)strlen(PIN_STARCOS);
					} else {
						pin = (CK_UTF8CHAR_PTR)PIN_SC_HSM;
						pinlen = (CK_ULONG)strlen(PIN_SC_HSM);
					}
					printf("Using PIN %s\n", pin);
				}

				if (optTestMultiOnly)
					continue;

				if (*optTokenFilter && strncmp(optTokenFilter, (const char *)tokeninfo.label, strlen(optTokenFilter)))
					continue;


				if (strncmp("STARCOS", (char *)tokeninfo.label, 7)) {
					if (tokeninfo.flags & CKF_USER_PIN_TO_BE_CHANGED) {
						testTransportPIN(p11, slotid);
					}
				}

				if (optUnlockPIN) {
					unlockPIN(p11, slotid);
					break;
				}

				testSessions(p11, slotid);

				rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
				printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

				if (rc != CKR_OK) {
					exit(1);
				}

				// List public objects
				memset(attr, 0, sizeof(attr));
				listObjects(p11, session, attr, 0);

#ifdef ENABLE_LIBCRYPTO
				testDigest(p11, session, CKM_SHA_1);
				testDigest(p11, session, CKM_SHA224);
				testDigest(p11, session, CKM_SHA256);
				testDigest(p11, session, CKM_SHA384);
				testDigest(p11, session, CKM_SHA512);
#endif

				testLogin(p11, session);

				// List all objects
				memset(attr, 0, sizeof(attr));
				listObjects(p11, session, attr, 0);

				testRandom(p11, session);

				if (strncmp("STARCOS", (char *)tokeninfo.label, 7)) {
					testKeyGeneration(p11, session);

					testKeyDerivation(p11, session);
				}

				testRSASigning(p11, slotid, 0, CKM_RSA_PKCS);

				if (strncmp("STARCOS", (char *)tokeninfo.label, 7) || !strncmp("3.5ID ECC C1 BNK", (char *)tokeninfo.model, 16)) {
					testRSASigning(p11, slotid, 0, CKM_SHA1_RSA_PKCS);
					testRSASigning(p11, slotid, 0, CKM_SHA256_RSA_PKCS_PSS);
					testRSASigning(p11, slotid, 0, CKM_SC_HSM_PSS_SHA1);
					testRSASigning(p11, slotid, 0, CKM_SC_HSM_PSS_SHA256);
				}

#ifdef ENABLE_LIBCRYPTO
				testRSADecryption(p11, session, CKM_RSA_PKCS);
				testRSADecryption(p11, session, CKM_RSA_PKCS_OAEP);

				if (strncmp("STARCOS", (char *)tokeninfo.label, 7)) {
					testRSADecryption(p11, session, CKM_RSA_X_509);
				}
#endif

				if (strncmp("3.5ID ECC C1 DGN", (char *)tokeninfo.model, 16)) {
					testECSigning(p11, slotid, 0, CKM_ECDSA_SHA1);
				}
				testECSigning(p11, slotid, 0, CKM_ECDSA);

				if (strncmp("STARCOS", (char *)tokeninfo.label, 7)) {
					testECSigning(p11, slotid, 0, CKM_SC_HSM_ECDSA_SHA224);
					testECSigning(p11, slotid, 0, CKM_SC_HSM_ECDSA_SHA256);
				}

				printf("Calling C_CloseSession ");
				rc = p11->C_CloseSession(session);
				printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
			}
		}
		free(slotlist);

#ifndef _WIN32
		if (optMultiThreadingTests)
			testSigningMultiThreading(p11);
#endif
	}

	printf("Calling C_Finalize ");

	rc = p11->C_Finalize(NULL);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	if (rc != CKR_OK) {
		exit(1);
	}

	dlclose(dlhandle);

	printf("Unit test finished.\n");
	printf("%d tests performed.\n", testscompleted);
	printf("%d tests failed.\n", testsfailed);

	exit(testsfailed ? 1 : 0);
}
