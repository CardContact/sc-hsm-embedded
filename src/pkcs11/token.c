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
 * @file    token.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for token authentication and token management
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <pkcs11/strbpcpy.h>

#include <pkcs11/token.h>
#include <pkcs11/object.h>
#include <pkcs11/dataobject.h>

#include <pkcs11/token-sc-hsm.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

extern struct p11Context_t *context;

extern struct p11TokenDriver *getSmartCardHSMTokenDriver();
extern struct p11TokenDriver *getBNotKTokenDriver();
extern struct p11TokenDriver *getDTrustTokenDriver();
extern struct p11TokenDriver *getSigntrust32TokenDriver();
extern struct p11TokenDriver *getSigntrust35TokenDriver();
extern struct p11TokenDriver *getDGNTokenDriver();

typedef struct p11TokenDriver *(*tokenDriver_t)();

static tokenDriver_t tokenDriver[] = {
		getSmartCardHSMTokenDriver,
		getBNotKTokenDriver,
		getDTrustTokenDriver,
		getSigntrust32TokenDriver,
		getSigntrust35TokenDriver,
		getDGNTokenDriver,
		NULL
};



/**
 * Return list of supported mechanisms for token
 *
 * @param token           The token for which the list should be obtained
 * @param pMechanismList  The buffer receiving the list of mechanisms
 * @param pulCount        The size of the buffer at call and return
 *
 */
int getMechanismList(struct p11Token_t *token, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (token->drv->C_GetMechanismList == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return token->drv->C_GetMechanismList(pMechanismList, pulCount);
}



/**
 * Return details for a mechanism
 *
 * @param token           The token for which the info should be obtained
 * @param type            The mechanism for which details should be obtained
 * @param pInfo           The buffer to receive the info
 *
 */
int getMechanismInfo(struct p11Token_t *token, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	if (token->drv->C_GetMechanismInfo == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return token->drv->C_GetMechanismInfo(type, pInfo);
}



/**
 * Add token object to list of public or private objects
 *
 * @param token     The token for which an object shell be added
 * @param object    The object
 * @param publicObject true to add as public object, false to add as private object
 *
 * @return          0 or -1 if error
 */
int addObject(struct p11Token_t *token, struct p11Object_t *object, int publicObject)
{
	object->token = token;

	p11LockMutex(token->mutex);

	if (!object->handle) {
		object->handle = token->freeObjectNumber++;
	}

	if (publicObject) {
		addObjectToList(&token->tokenObjList, object);
		token->numberOfTokenObjects++;
	} else {
		addObjectToList(&token->tokenPrivObjList, object);
		token->numberOfPrivateTokenObjects++;
	}

	p11UnlockMutex(token->mutex);

	object->dirtyFlag = 1;

	return CKR_OK;
}



/**
 * Find public or private object in list of token objects
 *
 * @param token     The token whose object shall be searched
 * @param handle    The objects handle
 */
int findObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, struct p11Object_t **object, int publicObject)
{
	struct p11Object_t *obj;
	int pos = 0;            /* remember the current position in the list */

	if (!publicObject && (token->user != CKU_USER)) {
		return -1;
	}

	obj = publicObject == TRUE ? token->tokenObjList : token->tokenPrivObjList;
	*object = NULL;

	while (obj != NULL) {
		if (obj->handle == handle) {
			*object = obj;
			return pos;
		}

		obj = obj->next;
		pos++;
	}

	return -1;
}



/**
 * Find token object that matches the given search criteria
 *
 * @param token     The token whose object shall be searched
 * @param pTemplate The search template
 * @param ulCount   The number of attributes in the search template
 * @param pObject   Variable receiving the object reference
 */
int findMatchingTokenObject(struct p11Token_t *token, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t **pObject)
{
	struct p11Object_t *p;

	/* public token objects */
	p = token->tokenObjList;

	while (p != NULL) {
		if (isMatchingObject(p, pTemplate, ulCount)) {
			*pObject = p;
			return CKR_OK;
		}
		p = p->next;
	}

	/* private token objects */
	p = token->tokenPrivObjList;

	while (p != NULL) {
		if (isMatchingObject(p, pTemplate, ulCount)) {
			*pObject = p;
			return CKR_OK;
		}
		p = p->next;
	}

	return CKR_ARGUMENTS_BAD;
}



/**
 * Find token object of given class matching the CKA_ID passed as argument
 *
 * @param token     The token whose object shall be searched
 * @param class     The value of the CKA_CLASS attribute
 * @param id        The id value
 * @param idlen     The length of the id
 * @param pObject   The variable receiving the found object
 */
int findMatchingTokenObjectById(struct p11Token_t *token, CK_OBJECT_CLASS class, unsigned char *id, int idlen, struct p11Object_t **pObject)
{
	CK_ATTRIBUTE template[] = {
		{ CKA_CLASS, &class, sizeof(class) },
		{ CKA_ID, id, idlen }
	};
	return findMatchingTokenObject(token, template, 2, pObject);
}



/**
 * Enumerate private objects
 *
 * @param token     The token whose object shall be enumerated
 * @param pObject	Pointer to a pointer containing the current object on input and the next object or NULL on output
 */
void enumerateTokenPrivateObjects(struct p11Token_t *token, struct p11Object_t **pObject)
{
	if (*pObject == NULL) {
		*pObject = token->tokenPrivObjList;
	} else {
		*pObject = (*pObject)->next;
	}
}



/**
 * Remove object from list of token objects
 *
 * @param token     The token whose object shall be removed
 * @param handle    The objects handle
 * @param publicObject true to remove public object, false to remove private object
 *
 * @return          0 or -1 if error
 */
int removeTokenObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject)
{
	int rc;

	p11LockMutex(token->mutex);

	if (publicObject) {
		rc = removeObjectFromList(&token->tokenObjList, handle);
		if (rc != CKR_OK) {
			p11UnlockMutex(token->mutex);
			return rc;
		}
		token->numberOfTokenObjects--;
	} else {
		rc = removeObjectFromList(&token->tokenPrivObjList, handle);
		if (rc != CKR_OK) {
			p11UnlockMutex(token->mutex);
			return rc;
		}
		token->numberOfPrivateTokenObjects--;
	}

	p11UnlockMutex(token->mutex);
	return CKR_OK;
}



/**
 * Remove all private objects for token from internal list
 *
 * @param token     The token whose objects shall be removed
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
static void removePrivateObjects(struct p11Token_t *token)
{
	p11LockMutex(token->mutex);
	removeAllObjectsFromList(&token->tokenPrivObjList);
	token->numberOfPrivateTokenObjects = 0;
	p11UnlockMutex(token->mutex);
}



/**
 * Remove all public objects for token from internal list
 *
 * @param token     The token whose objects shall be removed
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
static void removePublicObjects(struct p11Token_t *token)
{
	p11LockMutex(token->mutex);
	removeAllObjectsFromList(&token->tokenObjList);
	token->numberOfTokenObjects = 0;
	p11UnlockMutex(token->mutex);
}



/**
 * Remove object from token but keep attributes as these are transfered into a new object
 */
int removeObjectLeavingAttributes(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject)
{
	struct p11Object_t *object = NULL;
	struct p11Object_t *prev = NULL;
	int rc;

	rc = findObject(token, handle, &object, publicObject);

	/* no object with this handle found */
	if (rc < 0) {
		return rc;
	}

	if (rc > 0) {      /* there is more than one element in the pool */

		prev = publicObject == TRUE ? token->tokenObjList : token->tokenPrivObjList;

		while (prev->next->handle != handle) {
			prev = prev->next;
		}

		prev->next = object->next;

	}

	free(object);

	token->numberOfTokenObjects--;

	if (rc == 0) {      /* We removed the last element from the list */
		if (publicObject) {
			token->tokenObjList = NULL;
		} else {
			token->tokenPrivObjList = NULL;
		}
	}

	return CKR_OK;
}



/**
 * Remove object from token
 *
 * @param slot      The slot in which the token is inserted
 * @param object    The object to destroy
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int destroyObject(struct p11Slot_t *slot, struct p11Object_t *object)
{
	if (slot->token->drv->destroyObject == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}

	return slot->token->drv->destroyObject(slot, object);
}



/**
 * Create a token object
 *
 * @param slot      The slot in which the token is inserted
 * @param pTemplate The PKCS11 attribute to be used for key creation
 * @param ulCount   The number of attributes in the template
 * @param phObject  The variable receiving the newly created PKCS11 object
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int createTokenObject(struct p11Slot_t *slot, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t **phObject)
{
	if (slot->token->drv->C_CreateObject == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return slot->token->drv->C_CreateObject(slot, pTemplate, ulCount, phObject);
}



/**
 * Create a new key pair on the token object
 *
 * @param slot                          The slot in which the token is inserted
 * @param pMechanism                    The key generation mechanism
 * @param pPublicKeyTemplate            The template for the public key
 * @param ulPublicKeyAttributeCount     The length of the template for the public key
 * @param pPrivateKeyTemplate           The template for the private key
 * @param ulPrivateKeyAttributeCount    The length of the template for the private key
 * @param p11PublicKey                  The variable receiving the newly created PKCS11 public key object
 * @param p11PrivateKey                 The variable receiving the newly created PKCS11 private key object
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int generateTokenKeypair(struct p11Slot_t *slot,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		CK_ULONG ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG ulPrivateKeyAttributeCount,
		struct p11Object_t **p11PublicKey,
		struct p11Object_t **p11PrivateKey)
{
	if (slot->token->drv->C_GenerateKeyPair == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return slot->token->drv->C_GenerateKeyPair(slot, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, p11PublicKey, p11PrivateKey);
}



/**
 * Create random data using token
 *
 * @param slot                          The slot in which the token is inserted
 * @param pRandomData                   The buffer receiving random data
 * @param ulRandomLen                   The requested number of random bytes
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int generateTokenRandom(struct p11Slot_t *slot,
		CK_BYTE_PTR pRandomData,
		CK_ULONG ulRandomLen)
{
	if (slot->token->drv->C_GenerateRandom == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return slot->token->drv->C_GenerateRandom(slot, pRandomData, ulRandomLen);
}



/**
 * Update attribute for token object
 *
 * @param slot                          The slot in which the token is inserted
 * @param object                        The token object to be updates
 * @param pTemplate                     The list of attributes to update
 * @param ulCount                       The number of attributes to update
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int setTokenObjectAttributes(struct p11Slot_t *slot, struct p11Object_t *object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	if (slot->token->drv->C_SetAttributeValue == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return slot->token->drv->C_SetAttributeValue(slot, object, pTemplate, ulCount);
}



/**
 * Synchronize a token objects that have been changed (e.g. have the dirty flag set)
 *
 * @param slot      The slot in which the token is inserted
 * @param token     The token to update
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int synchronizeToken(struct p11Slot_t *slot, struct p11Token_t *token)
{
	return CKR_OK;
}



/**
 * Log into token
 *
 * This token method is called from the C_Login function at the PKCS#11 interface and
 * make all private objects visible at the PKCS#11 interface
 *
 * @param slot      The slot in which the token is inserted
 * @param userType  One of CKU_SO or CKU_USER
 * @param pPin      Pointer to PIN value or NULL is PIN shall be verified using PIN-Pad
 * @param ulPinLen  The length of the PIN supplied in pPin
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int logIn(struct p11Slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return slot->token->drv->login(slot, userType, pPin, ulPinLen);
}



/**
 * Log out from token, removing private objects from the list of visible token objects
 *
 * This token method is called from the C_Logout function at the PKCS#11 interface
 *
 * @param slot      The slot in which the token is inserted
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int logOut(struct p11Slot_t *slot)
{
	slot->token->user = 0xFF;

	return slot->token->drv->logout(slot);
}



/**
 * Initialize PIN
 *
 * This token method is called from the C_InitPIN function at the PKCS#11 interface
 *
 * @param slot      The slot in which the token is inserted
 * @param pPin      Pointer to PIN value or NULL is PIN shall be verified using PIN-Pad
 * @param ulPinLen  The length of the PIN supplied in pPin
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int initPIN(struct p11Slot_t *slot, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (slot->token->drv->initpin == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return slot->token->drv->initpin(slot, pPin, ulPinLen);
}



/**
 * Set PIN
 *
 * This token method is called from the C_SetPIN function at the PKCS#11 interface
 *
 * @param slot         The slot in which the token is inserted
 * @param pOldPin      Pointer to old PIN value or NULL is PIN shall be changed using PIN-Pad
 * @param ulOldPinLen  The length of the PIN supplied in pOldPin
 * @param pNewPin      Pointer to new PIN value or NULL is PIN shall be verified using PIN-Pad
 * @param ulNewPinLen  The length of the PIN supplied in pNewPin
 *
 * @return          CKR_OK or any other Cryptoki error code
 */
int setPIN(struct p11Slot_t *slot, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{
	if (slot->token->drv->setpin == NULL) {
		return CKR_FUNCTION_NOT_SUPPORTED;
	}
	return slot->token->drv->setpin(slot, pOldPin, ulOldPinLen, pNewPin, ulNewPinLen);
}



/**
 * Allocate and initialize token structure
 *
 * @param token     Pointer to pointer updated with newly created token structure
 * @param extraMem  The extra amount of memory allocated for private token data
 */
int allocateToken(struct p11Token_t **token, int extraMem)
{
	struct p11Token_t *ptoken;

	FUNC_CALLED();

	ptoken = (struct p11Token_t *)calloc(sizeof(struct p11Token_t) + extraMem, 1);

	if (ptoken == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	p11CreateMutex(&ptoken->mutex);

	*token = ptoken;
	FUNC_RETURNS(CKR_OK);
}



/**
 * Detect a newly inserted token in the designated slot
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
int newToken(struct p11Slot_t *slot, unsigned char *atr, size_t atrlen, struct p11Token_t **token)
{
	int rc;
	tokenDriver_t *t;
	struct p11TokenDriver *drv;

	FUNC_CALLED();

	for (t = tokenDriver; *t != NULL; t++) {
		drv = (*t)();
		if (drv->isCandidate(atr, atrlen)) {
			rc = drv->newToken(slot, token);
			if (rc == CKR_OK)
				FUNC_RETURNS(rc);

			if (rc != CKR_TOKEN_NOT_RECOGNIZED)
				FUNC_FAILS(rc, "Token detection failed for recognized token");
		}
	}

	FUNC_RETURNS(CKR_TOKEN_NOT_RECOGNIZED);
}



/**
 * Release memory allocated for token
 *
 * @param slot      The slot in which the token is inserted
 */
void freeToken(struct p11Token_t *token)
{
	if (token) {
#ifndef MINIDRIVER
		closeSessionsForSlot(&context->sessionPool, token->slot->id);
#endif
		if (token->drv->freeToken)
			token->drv->freeToken(token);

		removePrivateObjects(token);
		removePublicObjects(token);
		p11DestroyMutex(token->mutex);
		free(token);
	}
}



/**
 * Return the base token if this token is in a virtual slot
 *
 * @param token     Pointer to token
 * @return          The same or related base token
 */
struct p11Token_t *getBaseToken(struct p11Token_t *token)
{
	if (!token->slot->primarySlot)
		return token;
	return token->slot->primarySlot->token;
}
