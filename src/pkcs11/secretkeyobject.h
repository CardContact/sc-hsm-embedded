/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2003. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  --------- 
 *
 * The Smart Card Development Platform (SCDP) provides a basic framework to
 * implement smartcard aware applications.
 *
 * Abstract :       Functions for secret key object management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

#ifndef ___SECRETKEYOBJECT_H_INC___
#define ___SECRETKEYOBJECT_H_INC___


#include <pkcs11/p11generic.h>
#include <pkcs11/session.h>
#include <pkcs11/cryptoki.h>
#include <pkcs11/object.h>

#define NEEDED_ATTRIBUTES_SECRETKEYOBJECT   12

static struct attributesForObject_t attributesSecretKeyObject[] = {
    {{CKA_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_ENCRYPT, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_DECRYPT, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_SIGN, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_VERIFY, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_WRAP, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_UNWRAP, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_ALWAYS_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_NEVER_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_VALUE, 0, 0}, FALSE},
    {{CKA_VALUE_LEN, 0, 0}, TRUE}
};

int createSecretKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *object);

int secretKeyEncryptInit(CK_MECHANISM_PTR);
int secretKeyEncrypt(CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
int secretKeyEncryptUpdate(CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
int secretKeyEncryptFinal(CK_BYTE_PTR, CK_ULONG_PTR);


#endif /* ___SECRETKEYOBJECT_H_INC___ */
