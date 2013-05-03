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

int createSecretKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *object);

int secretKeyEncryptInit(CK_MECHANISM_PTR);
int secretKeyEncrypt(CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
int secretKeyEncryptUpdate(CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
int secretKeyEncryptFinal(CK_BYTE_PTR, CK_ULONG_PTR);


#endif /* ___SECRETKEYOBJECT_H_INC___ */
