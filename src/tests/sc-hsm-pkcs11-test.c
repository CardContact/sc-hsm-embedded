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

#include <common/mutex.h>

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

#define P11CKA			60

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
static int optTestRSADecryption = 0;
static int optTestPINBlock = 0;
static int optTestMultiOnly = 0;
static int optTestHotplug = 0;
static int optOneThreadPerToken = 0;
static int optNoClass3Tests = 0;
static int optNoMultiThreadingTests = 0;
static int optThreadsPerToken = 1;
static int optIteration = 1;
static int optUnlockPIN = 0;
static long optSlotId = -1;
static char *optTokenFilter = "";

static char namebuf[40]; /* used by main thread */



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

	if (id & 0x80000000) {
		sprintf(scr, "Vendor defined 0x%lx", id);
	} else {
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

	i = len;
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



int testRSASigning(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid, int id)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BBOOL _true = CK_TRUE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_SIGN, &_true, sizeof(_true) }
	};
	CK_OBJECT_HANDLE hnd;
	CK_MECHANISM mech = { CKM_SHA1_RSA_PKCS, 0, 0 };
//	CK_MECHANISM mech = { CKM_SHA256_RSA_PKCS_PSS, 0, 0 };
	char *tbs = "Hello World";
	CK_BYTE signature[256];
	CK_ULONG len;
	char scr[1024];
	int rc, keyno;
	char namebuf[40]; /* each thread need its own buffer */

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
		printf("Calling findObject (Thread %i, Session %ld, Slot=%ld)\n", id, session, slotid);
		rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), keyno, &hnd);

		if (rc != CKR_OK) {
			printf("Key %i not found (Thread %i, Session %ld, Slot=%ld)\n", keyno, id, session, slotid);
			rc = CKR_OK;
			break;
		}
		rc = p11->C_SignInit(session, &mech, hnd);
		printf("C_SignInit (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		len = 0;
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, strlen(tbs), NULL, &len);
		printf("C_Sign (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Signature size = %lu\n", len);

		len--;
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, strlen(tbs), signature, &len);
		printf("C_Sign (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_BUFFER_TOO_SMALL));

		printf("Signature size = %lu\n", len);

		len = sizeof(signature);
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, strlen(tbs), signature, &len);
		printf("C_Sign (Thread %i, Session %ld, Slot=%ld) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK || rc == CKR_DEVICE_REMOVED || rc == CKR_TOKEN_NOT_PRESENT));

		if (rc == CKR_DEVICE_REMOVED || rc == CKR_TOKEN_NOT_PRESENT)
			goto out;

		if (rc == CKR_OK) {
			bin2str(scr, sizeof(scr), signature, len);
			printf("Signature:\n%s\n", scr);
		}

		rc = p11->C_SignInit(session, &mech, hnd);
		printf("C_SignInit (Thread %i, Session %ld, Slot=%ld) - Multipart - %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf));

		if (rc == CKR_OBJECT_HANDLE_INVALID) {
			rc = p11->C_Login(session, CKU_USER, pin, pinlen);
			printf("C_Login User - %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK || rc == CKR_USER_ALREADY_LOGGED_IN));

			rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), keyno, &hnd);

			if (rc != CKR_OK) {
				printf("Key %i not found (Thread %i, Session %ld, Slot=%ld)\n", keyno, id, session, slotid);
				break;
			}

			rc = p11->C_SignInit(session, &mech, hnd);
			printf("C_SignInit (Thread %i, Session %ld, Slot=%ld) - Multipart - %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf));
		} else {
			verdict(rc == CKR_OK);
		}
#if 1
		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)tbs, 6);
		printf("C_SignUpdate (Thread %i, Session %ld, Slot=%ld - Part #1) - %s : %s\n", id, session, slotid, id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		rc = p11->C_SignUpdate(session, (CK_BYTE_PTR)tbs + 6, strlen(tbs) - 6);
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

		keyno++;
	}

out:
	p11->C_CloseSession(session);

	return rc;
}



int testECSigning(CK_FUNCTION_LIST_PTR p11, CK_SLOT_ID slotid, int id)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_ECDSA;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
	};
	CK_OBJECT_HANDLE hnd;
	CK_MECHANISM mech = { CKM_ECDSA_SHA1, 0, 0 };
	char *tbs = "Hello World";
	CK_BYTE signature[256];
	CK_ULONG len;
	char scr[1024];
	int rc,keyno;

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
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, strlen(tbs), NULL, &len);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		printf("Signature size = %lu\n", len);

		len = sizeof(signature);
		rc = p11->C_Sign(session, (CK_BYTE_PTR)tbs, strlen(tbs), signature, &len);
		printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

		bin2str(scr, sizeof(scr), signature, len);
		printf("Signature:\n%s\n", scr);
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
		rc = testRSASigning(d->p11, d->slotid, d->thread_id);
		if (rc == CKR_OK)
			rc = testECSigning(d->p11, d->slotid, d->thread_id);
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
	pthread_attr_t attr;
	void *status;
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



void testRSADecryption(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_CHAR label[] = "C.CH.AUT";
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_LABEL, &label, strlen((char *)label) }
	};
	CK_OBJECT_HANDLE hnd;
//	CK_MECHANISM mech_raw = { CKM_RSA_X_509, 0, 0 };
	CK_MECHANISM mech_p15 = { CKM_RSA_PKCS, 0, 0 };
	CK_MECHANISM mech_oaep = { CKM_RSA_PKCS_OAEP, 0, 0 };
	// Place valid cryptograms from use case tests here
//	char *raw_cryptogram = "\xCD\x6A\x28\xD1\x4A\x4A\x07\xED\x33\x24\x61\xFC\xF7\x3A\x51\x1B\x4F\x15\xF7\xC6\x95\xFC\xB4\xBE\x00\xE4\xA1\x17\x95\x98\x2F\xB5\x7A\x26\xB7\xDA\xF9\x31\x9F\xA9\xB0\xBE\xF9\xCB\x94\xFF\x88\xF1\x4D\x35\x57\xF8\x56\x51\xAF\xD9\x00\xB0\x3C\xE3\x82\x8E\xF1\xC9\xED\x68\x95\xAF\xDE\xF1\x6D\x7C\x67\x39\x3C\x68\xD9\x02\xFD\x39\x24\x15\xA3\x66\x03\xB9\x9E\x96\xAC\x28\x50\x02\xC9\x0E\x87\x92\xDC\x3B\x9E\x35\x6E\x06\x79\xB7\xBC\x9F\x68\x5A\xAA\xC0\x08\x0F\xB4\x92\xC7\xC1\xE6\xCE\x17\xBC\xB8\x16\xF5\xBD\x41\x7E\x10\xC6\x51\xC5\xA2\x12\x89\xE5\x8A\x7F\x98\xCA\x6A\x44\x5D\x9E\x5B\x9C\xA3\xB6\x64\x52\xD0\xF1\xA1\x9D\xC3\x81\x89\xB5\x6E\xB6\xB8\x0C\x4B\xB1\x31\xD1\x37\x68\x2F\xB4\x0F\x7F\x03\x2F\x8A\x65\x7F\x98\xDF\x05\x15\x78\xC5\x14\x00\xB9\xF2\x82\x3A\xDA\x62\x85\xAF\xAB\x7C\x5B\x7E\x2F\x7C\xE4\xCA\xB0\xE5\xD7\x3A\x6D\x68\x5C\x48\x16\x4B\x36\x2E\xD9\xF3\xC7\x88\x11\x0B\x6B\xBB\x50\x39\x3D\x6C\x20\x24\x5E\x1C\x83\x80\x13\x3E\x59\x62\xEF\x94\x1D\xC9\x9D\x40\x18\x14\x51\x1E\x80\x07\x30\x74\x4A\xD9\x16\xFA\xFF\x60\x4B\x5C\xE4";
//	char *p15_cryptogram = "\xAA\x80\xBF\x66\x99\x0A\x6E\xF3\x83\xA2\x7B\x2F\x89\x56\x0F\x7D\xC7\xFD\x44\x36\x86\x56\xC5\xC6\xA3\x3E\x89\xFC\x37\x87\x8A\xB0\xD5\xEB\x46\x20\x1D\xE4\xB7\xA7\xDE\xAC\x1E\x70\xBD\x66\x97\x91\xA3\xAC\xFA\x70\x80\x27\x8E\x7E\x8C\x06\x23\xA1\xB6\x83\x1A\x04\x96\xE7\x87\x1C\x61\xEC\xE0\x1A\x7D\xA9\x85\x85\x75\xBB\xDA\x77\x07\x65\x2A\x7A\x27\xCC\x14\xE4\x34\xBC\x70\xDF\x46\x67\xA0\x5B\x62\x2C\xF7\x2D\xFD\xF7\xA7\xFF\x89\x16\xC0\xE3\x2B\xEF\xDB\x1E\x11\x2A\xAE\x81\xDE\xDA\x96\xE4\xD3\xE4\x31\xE8\x31\xE9\xFD\xCD\x48\x0B\x9D\x95\xC0\x45\x14\x38\x03\x41\x00\xB0\xF9\xF0\x5A\x22\xBF\x2D\x81\xB4\x20\x7E\x05\x68\x90\x2D\x67\x9E\xEA\xC1\xFC\x7C\x92\x99\xD1\xDE\xE7\xEA\xE3\x0A\x14\x52\x19\xD0\x7C\xDE\x8C\x37\xBC\xA6\x52\xAB\x3D\x7A\xAE\x60\x11\xC7\x41\xAB\x53\x48\x08\xBA\xC6\x80\xC3\x72\xB7\x13\x15\xD7\x7E\x40\x8C\x0E\x29\x33\xB4\x11\xBB\x1B\x96\x7B\x2A\x52\x98\x24\xEE\xC0\x51\xD7\x55\x25\x59\x55\xD8\xB3\xAB\x06\x26\x28\x7F\x0F\xB2\x44\xF3\xBA\xEE\xA7\xA2\xDB\xAA\xD2\xE7\xB7\x79\x51\xB2\xFB\x1B\x7F\x1D\xE4\xA7\x08\x7D\xAF";
	char *p15_cryptogram = "\x0A\x01\x74\xAD\x63\xD4\xB1\x34\x65\x9D\xEE\xC9\x14\x0A\x1D\xE9\x2E\x27\x38\xE4\x41\x75\x90\x59\xD2\x4F\xC7\xA5\x15\xB3\x69\xB7\x44\x14\xD7\xA0\xDA\xD7\xEE\xBB\xDC\x6B\x9F\x3D\x91\x1D\x15\xA9\xCF\x48\xFC\x11\x78\x89\x8D\xFA\x8C\x63\x1D\xD4\xFF\xD5\x71\xBB\x81\x4C\xA4\xB3\x06\x14\x5E\x34\xF7\xE8\x73\x39\x86\xB9\x31\x31\xE1\xC7\xAB\xCF\xEB\x1C\xA8\x2E\x1B\x3D\x05\x60\x0F\x32\xEF\x1C\x89\x30\x50\x4A\xC9\x90\x83\x6A\xAA\x12\x8A\x2B\xF6\x39\x2C\xF1\xEC\x4F\x01\x20\x50\xF0\x36\x49\x25\x11\x04\xB0\x94\xAA\xEF\x7D\xFE\xAA\x60\x34\x32\x6E\x65\x30\x66\x26\x6D\x8F\xB6\xE6\xF7\xED\x7A\xC9\xE8\x77\xD8\x5E\x84\x7B\x06\xE5\x0D\xC2\xA1\xC6\x46\x0B\x90\xCF\xF2\x9D\xA6\xC3\xEA\x29\xB0\xE2\xDE\x15\x1B\x72\x63\x01\x23\x85\xB3\x25\xAD\x43\x50\x7F\x1E\x7F\xBF\x6E\x22\x4A\x13\x33\x55\x55\xAA\xE1\x87\xDD\xE5\x16\x0F\x2A\x29\x34\xBB\xFA\x27\xD2\x03\x17\xAB\xF2\x91\x97\xE2\x3B\xCA\x74\x2E\xEA\xA6\x82\x10\x74\xDD\x7A\x99\x52\xA0\x44\x36\xB7\x85\xB4\x88\xE0\xD9\x00\x75\xC5\xD9\xBF\x5D\x5B\x32\xFD\xBD\xD6\x8F\x9B\x3D\x12\xD6\x5E\x15\x32";
	char *oaep_cryptogram = "\x96\x1B\x87\x4A\x68\xD0\x17\xDC\x74\x3E\x22\x6B\xB0\x97\x36\x35\xE1\x05\xCB\xA8\x23\x97\xEF\xCB\x58\xE7\x70\x04\x6B\x85\x7B\x30\x8E\x7D\x23\x7F\x66\x3F\x5D\x80\xC3\x93\x0F\x30\xA2\x01\x34\x7C\x85\x8D\x94\x22\xE7\xBE\x3A\x59\x33\xD7\xCB\x69\xA5\xAB\xA4\x02\xAB\x33\xE6\x41\xF0\x5D\x85\xF0\x09\x7E\x9D\x88\xDD\x59\x63\xDB\xF3\x89\x8D\x1F\x8B\xE6\x22\x7D\xC1\x31\x42\xAE\x67\x68\xBA\x2A\x10\x51\x09\xF7\x4F\x2E\x0E\xF7\xB4\xF2\xE3\x53\x68\x97\x27\xD8\xAD\x6F\x8B\x40\x96\x69\x84\x08\x55\x43\xC7\xA0\xD8\x89\x7B\x72\x87\xDE\xC7\xDC\xD1\x22\x7B\x75\xA5\xBC\xEB\x73\x56\x97\xBE\xA1\xD1\x7B\x98\xF2\x5B\x84\x1D\x6E\xBA\x47\xEE\x96\x95\x81\xC8\xCC\x00\xB1\x43\xBA\xF7\xB7\x29\x79\x7A\x1D\x1E\x57\x05\xAF\xF5\x96\x2E\x8C\xC6\xC7\x51\x26\x74\x73\x4D\x06\xB7\xB3\xC1\x74\xA4\xC8\x8E\xC2\x8F\x1A\x6B\x80\x9D\xF7\x99\xD4\x05\x54\x38\x5D\xA3\x45\xE2\x4A\x4D\x3B\x53\xC3\xAE\x83\xF0\xDB\x90\xA6\xA4\xDD\x18\xF3\xD8\x36\x2C\x5C\x82\x04\xB2\x78\x32\x3A\x78\x58\x9B\x29\x2D\x45\x85\x4E\x4A\x08\xED\xDF\x36\x73\xFA\xD9\xB9\x4E\x0D\x8F\xCC\x50";

	CK_BYTE plain[256];
	CK_ULONG len;
	char scr[1024];
	int rc;

	rc = findObject(p11, session, (CK_ATTRIBUTE_PTR)&template, sizeof(template) / sizeof(CK_ATTRIBUTE), 0, &hnd);

	if (rc != CKR_OK) {
		printf("Key %s not found\n", label);
		return;
	}
#if 0
	printf("Calling C_DecryptInit()");
	rc = p11->C_DecryptInit(session, &mech_raw, hnd);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_Decrypt()");

	len = 0;
	rc = p11->C_Decrypt(session, (CK_BYTE_PTR)raw_cryptogram, 256, NULL, &len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Plain size = %lu\n", len);

	len = sizeof(plain);
	rc = p11->C_Decrypt(session, (CK_BYTE_PTR)raw_cryptogram, 256, plain, &len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	bin2str(scr, sizeof(scr), plain, len);
	printf("Plain:\n%s\n", scr);
#endif

	printf("Calling C_DecryptInit()");
	rc = p11->C_DecryptInit(session, &mech_p15, hnd);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_Decrypt()");

	len = 0;
	rc = p11->C_Decrypt(session, (CK_BYTE_PTR)p15_cryptogram, 256, NULL, &len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Plain size = %lu\n", len);

	len = sizeof(plain);
	rc = p11->C_Decrypt(session, (CK_BYTE_PTR)p15_cryptogram, 256, plain, &len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	bin2str(scr, sizeof(scr), plain, len);
	printf("Plain:\n%s\n", scr);


	printf("Calling C_DecryptInit()");
	rc = p11->C_DecryptInit(session, &mech_oaep, hnd);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Calling C_Decrypt()");

	len = 0;
	rc = p11->C_Decrypt(session, (CK_BYTE_PTR)oaep_cryptogram, 256, NULL, &len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	printf("Plain size = %lu\n", len);

	len = sizeof(plain);
	rc = p11->C_Decrypt(session, (CK_BYTE_PTR)oaep_cryptogram, 256, plain, &len);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));

	bin2str(scr, sizeof(scr), plain, len);
	printf("Plain:\n%s\n", scr);

}



void testKeyGeneration(CK_FUNCTION_LIST_PTR p11, CK_SESSION_HANDLE session)
{
	int rc;
	CK_CHAR label[] = "TestKey";
	CK_BBOOL _true = TRUE;
	CK_OBJECT_CLASS publicKeyClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE publicKeyTemplate[20] = {
			{ CKA_CLASS, &publicKeyClass, sizeof(publicKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_LABEL, &label, strlen((char *)label) }
	};
	int publicKeyAttributes = 3;
	CK_OBJECT_CLASS privateKeyClass = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE privateKeyTemplate[20] = {
			{ CKA_CLASS, &privateKeyClass, sizeof(privateKeyClass) },
			{ CKA_TOKEN, &_true, sizeof(_true)},
			{ CKA_PRIVATE, &_true, sizeof(_true)},
			{ CKA_SENSITIVE, &_true, sizeof(_true)},
			{ CKA_LABEL, &label, strlen((char *)label) }
	};
	int privateKeyAttributes = 5;
	CK_OBJECT_HANDLE hndPrivateKey, hndPublicKey;
	CK_MECHANISM mech_genecc = { CKM_EC_KEY_PAIR_GEN, 0, 0 };
	CK_MECHANISM mech_genrsa = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 };
	CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
	CK_ULONG keysize = 1024;

	publicKeyTemplate[publicKeyAttributes].type = CKA_EC_PARAMS;
	publicKeyTemplate[publicKeyAttributes].pValue = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
	publicKeyTemplate[publicKeyAttributes].ulValueLen = 10;
	publicKeyTemplate[publicKeyAttributes].type = CKA_EC_PARAMS;
	publicKeyAttributes++;

	privateKeyTemplate[privateKeyAttributes].type = CKA_SIGN;
	privateKeyTemplate[privateKeyAttributes].pValue = &_true;
	privateKeyTemplate[privateKeyAttributes].ulValueLen = sizeof(_true);
	privateKeyAttributes++;

	privateKeyTemplate[privateKeyAttributes].type = CKA_DERIVE;
	privateKeyTemplate[privateKeyAttributes].pValue = &_true;
	privateKeyTemplate[privateKeyAttributes].ulValueLen = sizeof(_true);
	privateKeyAttributes++;

	rc = p11->C_GenerateKeyPair(session, &mech_genecc,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndPublicKey, &hndPrivateKey);

	publicKeyAttributes = 3;
	publicKeyTemplate[publicKeyAttributes].type = CKA_MODULUS_BITS;
	publicKeyTemplate[publicKeyAttributes].pValue = &keysize;
	publicKeyTemplate[publicKeyAttributes].ulValueLen = sizeof(keysize);
	publicKeyAttributes++;

	publicKeyTemplate[publicKeyAttributes].type = CKA_PUBLIC_EXPONENT;
	publicKeyTemplate[publicKeyAttributes].pValue = publicExponent;
	publicKeyTemplate[publicKeyAttributes].ulValueLen = sizeof(publicExponent);
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

	rc = p11->C_GenerateKeyPair(session, &mech_genrsa,
		publicKeyTemplate, publicKeyAttributes,
		privateKeyTemplate, privateKeyAttributes,
		&hndPublicKey, &hndPrivateKey);
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
	rc = p11->C_SetPIN(session, (CK_UTF8CHAR_PTR)"12345", 5, (CK_UTF8CHAR_PTR)pin, pinlen);
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
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) }
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



void testHotplug(CK_FUNCTION_LIST_PTR p11)
{
	CK_ULONG slots, slotindex;
	CK_SLOT_ID slotid;
	CK_SLOT_ID_PTR slotlist;
	CK_SLOT_INFO slotinfo;
	CK_TOKEN_INFO tokeninfo;
	pthread_t threads[100];
	pthread_attr_t attr;
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

				for (t = slotindex * optThreadsPerToken; t < (slotindex + 1) * optThreadsPerToken; t++) {
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
	printf("  --test-rsa-decryption      Enable RSA decryption test (requires matching cryptogram in testRSADecryption()\n");
	printf("  --test-pin-block           Enable PIN blocking test\n");
	printf("  --test-multithreading-only Perform multihreading tests only\n");
	printf("  --test-hotplug-only        Perform hotplug tests only\n");
	printf("  --one-thread-per-token     Create a single thread per token rather than distributing %d\n", NUM_THREADS);
	printf("  --no-class3-tests          No PIN tests with attached class 3 PIN PAD\n");
	printf("  --no-multithreading-tests  No multihreading tests\n");
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
			pinlen = strlen((char *)pin);
			argc--;
		} else if (!strcmp(*argv, "--so-pin")) {
			if (argc < 0) {
				printf("Argument for --so-pin missing\n");
				exit(1);
			}
			argv++;
			sopin = (CK_UTF8CHAR_PTR)*argv;
			sopinlen = strlen((char *)sopin);
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
		} else if (!strcmp(*argv, "--test-rsa-decryption")) {
			optTestRSADecryption = 1;
		} else if (!strcmp(*argv, "--test-pin-block")) {
			optTestPINBlock = 1;
		} else if (!strcmp(*argv, "--test-multithreading-only")) {
			optTestMultiOnly = 1;
		} else if (!strcmp(*argv, "--test-hotplug-only")) {
			optTestHotplug = 1;
		} else if (!strcmp(*argv, "--one-thread-per-token")) {
			optOneThreadPerToken = 1;
		} else if (!strcmp(*argv, "--no-class3-tests")) {
			optNoClass3Tests = 1;
		} else if (!strcmp(*argv, "--no-multithreading-tests")) {
			optNoMultiThreadingTests = 1;
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
	} else {
		printf("Calling C_GetSlotList ");

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

		while (i < slots) {
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
				printf("Token label: %s\n", p11string(tokeninfo.label, sizeof(tokeninfo.label)));
				printf("Token flags: %lx\n", tokeninfo.flags);

				if (pin == NULL) {
					if (!strncmp("STARCOS", (char *)tokeninfo.label, 7)) {
						pin = (CK_UTF8CHAR_PTR)PIN_STARCOS;
						pinlen = strlen(PIN_STARCOS);
					} else {
						pin = (CK_UTF8CHAR_PTR)PIN_SC_HSM;
						pinlen = strlen(PIN_SC_HSM);
					}
					printf("Using PIN %s\n", pin);
				}

				if (optTestMultiOnly)
					continue;

				if (*optTokenFilter && strncmp(optTokenFilter, (const char *)tokeninfo.label, strlen(optTokenFilter)))
					continue;

#if 0
				if (tokeninfo.flags & CKF_USER_PIN_TO_BE_CHANGED) {
					testTransportPIN(p11, slotid);
				}
#endif

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

				testLogin(p11, session);

				// List all objects
				memset(attr, 0, sizeof(attr));
				listObjects(p11, session, attr, 0);

				testKeyGeneration(p11, session);

				testRSASigning(p11, slotid, 0);

				//	Test requires valid crypto matching card used for testing
				if (optTestRSADecryption)
					testRSADecryption(p11, session);

				testECSigning(p11, slotid, 0);

				printf("Calling C_CloseSession ");
				rc = p11->C_CloseSession(session);
				printf("- %s : %s\n", id2name(p11CKRName, rc, 0, namebuf), verdict(rc == CKR_OK));
			}
		}
		free(slotlist);

#ifndef WIN32
		if (!optNoMultiThreadingTests)
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
