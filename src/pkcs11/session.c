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
 * @file    session.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Data types and functions for session management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkcs11/session.h>



/**
 * Initialize the session-pool structure
 *
 * @param pool       Pointer to session-pool structure.
 */
void initSessionPool(struct p11SessionPool_t *pool)
{
	pool->list = NULL;
	pool->nextSessionHandle = 1;     /* Set initial value of session handles to 1 */
	                                 /* Valid handles have a non-zero value       */
	pool->numberOfSessions = 0;
}



/**
 * Terminate the session pool, removing all objects and freeing allocated memory
 *
 * @param pool       Pointer to session-pool structure.
 */
void terminateSessionPool(struct p11SessionPool_t *pool)
{
	while(pool->list) {
		if (removeSession(pool, pool->list->handle) != CKR_OK)
			return;
	}
}



/**
 * Add a session to the session-pool
 *
 * This function sets the handle of the session object to a valid value.
 *
 * @param pool       Pointer to session-pool structure
 * @param session    Pointer to session structure
 */
void addSession(struct p11SessionPool_t *pool, struct p11Session_t *session)
{
	struct p11Session_t **pSession;

	session->next = NULL;

	pSession = &pool->list;
	while(*pSession)
		pSession = &(*pSession)->next;

	*pSession = session;

	session->handle = pool->nextSessionHandle++;
	pool->numberOfSessions++;
}



/**
 * Find a slot in the slot-pool by it's slot handle
 *
 * @param pool       Pointer to slot-pool structure.
 * @param handle     The handle of the session.
 * @param session    Pointer to session structure.
 *                   If the session is found, this pointer holds the specific session structure - otherwise NULL.
 *
 * @return CKR_OK or CKR_SESSION_HANDLE_INVALID
 */
int findSessionByHandle(struct p11SessionPool_t *pool, CK_SESSION_HANDLE handle, struct p11Session_t **session)
{
	struct p11Session_t *psession;

	psession = pool->list;
	*session = NULL;

	while (psession != NULL) {
		if (psession->handle == handle) {
			*session = psession;
			return CKR_OK;
		}

		psession = psession->next;
	}

	return CKR_SESSION_HANDLE_INVALID;
}



/**
 * Find a slot in the slot-pool by it's related slot
 *
 * @param pool       Pointer to slot-pool structure
 * @param slotID     The slot identifier
 * @param session    Pointer to session structure
 *                   If the session is found, this pointer holds the specific session structure - otherwise NULL.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>>=0                                    </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>-1                                     </TD>
 *                   <TD>The specified session was not found    </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int findSessionBySlotID(struct p11SessionPool_t *pool, CK_SLOT_ID slotID, struct p11Session_t **session)
{
	struct p11Session_t *psession;
	int pos;

	psession = pool->list;
	pos = 0;

	while (psession != NULL) {
		if (psession->slotID == slotID) {
			*session = psession;
			return pos;
		}

		psession = psession->next;
		pos++;
	}

	return -1;
}



/**
 * Remove a session from the session-pool
 *
 * @param pool       Pointer to session-pool structure
 * @param handle     The handle of the session
 *
 * @return CKR_OK, CKR_SESSION_HANDLE_INVALID, CKR_GENERAL_ERROR
 */
int removeSession(struct p11SessionPool_t *pool, CK_SESSION_HANDLE handle)
{
	struct p11Session_t *session;
	struct p11Session_t **pSession;

	pSession = &pool->list;
	while (*pSession && (*pSession)->handle != handle) {
		pSession = &((*pSession)->next);
	}

	session = *pSession;

	if (!session) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	*pSession = session->next;

	clearSearchList(session);

	while(session->sessionObjList) {
		if (removeSessionObject(session, session->sessionObjList->handle) != CKR_OK)
			return CKR_GENERAL_ERROR;
	}

	if (session->cryptoBuffer) {
		free(session->cryptoBuffer);
		session->cryptoBuffer = NULL;
		session->cryptoBufferMax = 0;
		session->cryptoBufferSize = 0;
	}

	free(session);

	pool->numberOfSessions--;

	return CKR_OK;
}



/**
 * Return the current session state
 *
 * @param session    the session
 * @param token      the token this session is bound to (prevent duplicate slot lookup)
 * @return One of the CK_STATE values
 */
CK_STATE getSessionState(struct p11Session_t *session, struct p11Token_t *token)
{
	CK_STATE state;

	switch (token->user) {
	case CKU_USER:
		state = (session->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
		break;

	case CKU_SO:
		state = CKS_RW_SO_FUNCTIONS;
		break;

	default:
		state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
		break;
	}
	return state;
}



/**
 * Add an object to the list of session objects
 *
 * @param session    the session
 * @param object     the object to add
 */
void addSessionObject(struct p11Session_t *session, struct p11Object_t *object)
{
	if (session->freeSessionObjNumber == 0) {
		session->freeSessionObjNumber = 0xA000;
	}

	object->handle = session->freeSessionObjNumber++;
	object->dirtyFlag = 0;

	addObjectToList(&session->sessionObjList, object);

	session->numberOfSessionObjects++;
}



/**
 * Find a session object by it's handle
 */
int findSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle, struct p11Object_t **object)
{
	struct p11Object_t *obj;
	int pos = 0;            /* remember the current position in the list */

	obj = session->sessionObjList;
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
 * Remove a session object
 */
int removeSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle)
{
	int rc;

	rc = removeObjectFromList(&session->sessionObjList, handle);

	if (rc != CKR_OK)
		return rc;

	session->numberOfSessionObjects--;

	return CKR_OK;
}



/**
 * Add an object to the search list by make a shallow copy of the object
 */
int addObjectToSearchList(struct p11Session_t *session, struct p11Object_t *object)
{
	struct p11Object_t *obj;
	struct p11Object_t *tmp;

	tmp = (struct p11Object_t *)calloc(1, sizeof(struct p11Object_t));

	if (tmp == NULL) {
		return -1;
	}

	*tmp = *object;

	if (session->searchObj.searchList == NULL) {
		session->searchObj.searchList = tmp;
		tmp->next = NULL;
		session->searchObj.searchNumOfObjects = 1;
		session->searchObj.objectsCollected = 0;
	} else {
		obj = session->searchObj.searchList;

		while (obj->next != NULL) {
			obj = obj->next;
		}

		obj->next = tmp;
		session->searchObj.searchNumOfObjects++;
		tmp->next = NULL;
	}

	return CKR_OK;
}



/**
 * Clear the search results list
 */
void clearSearchList(struct p11Session_t *session)
{
	struct p11Object_t *pObject, *pTempObject;

	pObject = session->searchObj.searchList;

	// Objects on the search list are not a deep copy of the actual object
	// thats why we don't use removeAllObjectsFromList() here
	while (pObject) {
		pTempObject = pObject->next;
		free(pObject);
		pObject = pTempObject;
	}

	session->searchObj.searchNumOfObjects = 0;
	session->searchObj.objectsCollected = 0;
	session->searchObj.searchList = NULL;
}



/**
 * Append data to an internal buffer for token that don not implement an update() function
 *
 * @param session   the session
 * @param data      the data to be added
 * @param length    length of the data to be added
 * @return CKR_OK or CKR_HOST_MEMORY
 */
int appendToCryptoBuffer(struct p11Session_t *session, CK_BYTE_PTR data, CK_ULONG length)
{
	if (session->cryptoBufferMax < session->cryptoBufferSize + length) {
		if (session->cryptoBufferMax == 0) {
			session->cryptoBufferMax = 256;
		}
		while (session->cryptoBufferMax < session->cryptoBufferSize + length) {
			session->cryptoBufferMax <<= 1;
		}

		session->cryptoBuffer = (CK_BYTE_PTR)realloc(session->cryptoBuffer, session->cryptoBufferMax);
		if (session->cryptoBuffer == NULL) {
			session->cryptoBufferMax = 0;
			return CKR_HOST_MEMORY;
		}
	}

	memcpy(session->cryptoBuffer + session->cryptoBufferSize, data, length);
	session->cryptoBufferSize += length;

	return CKR_OK;
}



/**
 * Clear crypto buffer used to collect input data
 *
 * @param session   the session
 */
void clearCryptoBuffer(struct p11Session_t *session)
{
	if (session->cryptoBuffer) {
		memset(session->cryptoBuffer, 0, session->cryptoBufferMax);
		session->cryptoBufferSize = 0;
	}
}
