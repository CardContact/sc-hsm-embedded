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
 * Abstract :       Functions for token authentication and token management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

#ifndef ___TOKEN_H_INC___
#define ___TOKEN_H_INC___

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>

int newToken(struct p11Slot_t *slot, struct p11Token_t **token);

int freeToken(struct p11Slot_t *slot);

int logIn(struct p11Slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);

int logOut(struct p11Slot_t *slot);

int addObject(struct p11Token_t *token, struct p11Object_t *object, int publicObject);

int findObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, struct p11Object_t **object, int publicObject);

int removeObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject);

int removeObjectLeavingAttributes(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject);

int loadObjects(struct p11Slot_t *slot, struct p11Token_t *token, int publicObject);

int saveObjects(struct p11Slot_t *slot, struct p11Token_t *token, int publicObject);

int destroyObject(struct p11Slot_t *slot, struct p11Token_t *token, struct p11Object_t *object);

int synchronizeToken(struct p11Slot_t *slot, struct p11Token_t *token);

#endif /* ___TOKEN_H_INC___ */
