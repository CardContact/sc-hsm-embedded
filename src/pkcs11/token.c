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

#include <token-sc-hsm.h>

// #define USE_CRYPTO
// #define USE_MAC

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

extern struct p11Context_t *context;



int addObject(struct p11Token_t *token, struct p11Object_t *object, int publicObject)
{
	struct p11Object_t *obj, *tmp;

	object->token = token;

	tmp = publicObject == TRUE ? token->tokenObjList : token->tokenPrivObjList;

	if (tmp == NULL) {

		object->next = NULL;

		if (publicObject) {
			token->numberOfTokenObjects = 1;
			token->tokenObjList = object;
		} else {
			token->numberOfPrivateTokenObjects = 1;
			token->tokenPrivObjList = object;
		}

		if (!object->handle) {
			object->handle = token->freeObjectNumber++;
		}

	} else {

		obj = tmp;

		while (obj->next != NULL) {
			obj = obj->next;
		}

		obj->next = object;

		if (publicObject) {
			token->numberOfTokenObjects++;
		} else {
			token->numberOfPrivateTokenObjects++;
		}

		if (!object->handle) {
			object->handle = token->freeObjectNumber++;
		}

		object->next = NULL;

	}

	object->dirtyFlag = 1;

	return CKR_OK;
}



int findObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, struct p11Object_t **object, int publicObject)
{
	struct p11Object_t *obj;
	int pos = 0;            /* remember the current position in the list */

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



int removeObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject)
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

	removeAllAttributes(object);

	free(object);

	if (publicObject) {
		token->numberOfTokenObjects--;
	} else {
		token->numberOfPrivateTokenObjects--;
	}

	if (rc == 0) {      /* We removed the last element from the list */
		if (publicObject) {
			token->tokenObjList = NULL;
		} else {
			token->tokenPrivObjList = NULL;
		}
	}

	return CKR_OK;
}



static void removePrivateObjects(struct p11Token_t *token)
{
	struct p11Object_t *pObject = NULL;
	struct p11Object_t *tmp = NULL;

	/* clear the private token objects */
	pObject = token->tokenPrivObjList;

	while (pObject) {
		tmp = pObject->next;

		removeAllAttributes(pObject);
		free(pObject);

		pObject = tmp;
	}

	token->tokenPrivObjList = NULL;
	token->numberOfPrivateTokenObjects = 0;
}



static void removePublicObjects(struct p11Token_t *token)
{
	struct p11Object_t *pObject = NULL;
	struct p11Object_t *tmp = NULL;

	/* clear the public token objects */
	pObject = token->tokenObjList;

	while (pObject) {
		tmp = pObject->next;

		removeAllAttributes(pObject);
		free(pObject);

		pObject = tmp;
	}

	token->tokenObjList = NULL;
	token->numberOfTokenObjects = 0;
}



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



int saveObjects(struct p11Slot_t *slot, struct p11Token_t *token, int publicObjects)
{
	return CKR_OK;
}



int destroyObject(struct p11Slot_t *slot, struct p11Token_t *token, struct p11Object_t *object)
{
	return CKR_OK;
}



int synchronizeToken(struct p11Slot_t *slot, struct p11Token_t *token)
{
	return CKR_OK;
}



int logIn(struct p11Slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	return sc_hsm_login(slot, userType, pPin, ulPinLen);
}



int logOut(struct p11Slot_t *slot)
{
	removePrivateObjects(slot->token);

	return sc_hsm_logout(slot);
}



int newToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	return newSmartCardHSMToken(slot, token);
}



int freeToken(struct p11Slot_t *slot)
{
	if (slot->token) {
		removePrivateObjects(slot->token);
		removePublicObjects(slot->token);
		free(slot->token);
		slot->token = NULL;
	}
}

