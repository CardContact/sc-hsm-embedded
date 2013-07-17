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
 * initSessionPool initializes the session-pool structure.
 *
 * @param pool       Pointer to session-pool structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int initSessionPool(struct p11SessionPool_t *pool)
{
	pool->list = NULL;
	pool->nextSessionHandle = 1;     /* Set initial value of session handles to 1 */
	                                 /* Valid handles have a non-zero value       */
	pool->numberOfSessions = 0;

	return CKR_OK;
}



int terminateSessionPool(struct p11SessionPool_t *pool)
{
	struct p11Session_t *pSession, *pFreeSession;
	struct p11Object_t *pObject, *tmp;

	pSession = pool->list;

	/* clear the session pool */
	while (pSession) {

		free(pSession->cryptoBuffer);

		/* clear the search objects */
		pObject = pSession->searchObj.searchList;

		while (pObject) {
			tmp = pObject->next;

			removeAllAttributes(pObject);
			free(pObject);

			pObject = tmp;
		}

		/* clear the session */
		pObject = pSession->sessionObjList;

		while (pObject) {
			tmp = pObject->next;

			removeAllAttributes(pObject);
			free(pObject);

			pObject = tmp;
		}

		pFreeSession = pSession;

		pSession = pSession->next;

		free(pFreeSession);

	}

	return 0;
}



/**
 * addSession adds a session to the session-pool.
 *
 * This funcions sets the handle of the session object to a valid value.
 *
 * @param pool       Pointer to session-pool structure.
 * @param session    Pointer to session structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int addSession(struct p11SessionPool_t *pool, struct p11Session_t *session)
{
	struct p11Session_t *prevSession;

	session->next = NULL;

	if (pool->list == NULL) {

		pool->list = session;

	} else {

		prevSession = pool->list;

		while (prevSession->next != NULL) {
			prevSession = prevSession->next;
		}

		prevSession->next = session;

	}

	session->handle = pool->nextSessionHandle++;
	pool->numberOfSessions++;

	return CKR_OK;
}



/**
 * findSessionByHandle finds a slot in the slot-pool.
 * The session is specified by its handle.
 *
 * @param pool       Pointer to slot-pool structure.
 * @param handle     The handle of the session.
 * @param session    Pointer to session structure.
 *                   If the session is found, this pointer holds the specific session structure - otherwise NULL.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_SESSION_HANDLE_INVALID             </TD>
 *                   <TD>The specified session was not found    </TD>
 *                   </TR>
 *                   </TABLE></P>
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
 * findSessionBySlotID finds a slot in the slot-pool.
 * The session is specified by the slotID of the used slot..
 *
 * @param pool       Pointer to slot-pool structure.
 * @param slotID     The slot identifier.
 * @param session    Pointer to session structure.
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
 * removeSession removes a session from the session-pool.
 * The session to remove is specified by the session handle.
 *
 * @param pool       Pointer to session-pool structure.
 * @param handle     The handle of the session.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                              </TD>
 *                   <TD>Success                             </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_SESSION_HANDLE_INVALID          </TD>
 *                   <TD>The specified session was not found </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int removeSession(struct p11SessionPool_t *pool, CK_SESSION_HANDLE handle)
{
	struct p11Session_t *session;
	struct p11Session_t **pSession;
	struct p11Object_t *object, *tmp;

	pSession = &pool->list;
	while (*pSession && (*pSession)->handle != handle) {
		pSession = &((*pSession)->next);
	}

	session = *pSession;

	if (!session) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	*pSession = session->next;

	object = session->sessionObjList;

	while (object) {
		tmp = object->next;
		removeAllAttributes(object);
		free(object);
		object = tmp;
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



int addSessionObject(struct p11Session_t *session, struct p11Object_t *object)
{
	struct p11Object_t *obj;

	if (session->sessionObjList == NULL) {

		session->sessionObjList = object;
		object->next = NULL;
		session->numberOfSessionObjects = 1;
		session->freeSessionObjNumber = 0xA000;
		object->handle = session->freeSessionObjNumber++;

	} else {

		obj = session->sessionObjList;

		while (obj->next != NULL) {
			obj = obj->next;
		}

		obj->next = object;
		session->numberOfSessionObjects++;
		object->handle = session->freeSessionObjNumber++;
		object->next = NULL;

	}

	object->dirtyFlag = 0;

	return CKR_OK;
}



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



int removeSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle)
{
	struct p11Object_t *object = NULL;
	struct p11Object_t *prev = NULL;
	int rc;

	rc = findSessionObject(session, handle, &object);

	/* no object with this handle found */
	if (rc < 0) {
		return rc;
	}

	if (rc > 0) {      /* there is more than one element in the pool */

		prev = session->sessionObjList;

		while (prev->next->handle != handle) {
			prev = prev->next;
		}

		prev->next = object->next;

	}

	removeAllAttributes(object);

	free(object);

	session->numberOfSessionObjects--;

	if (rc == 0) {      /* We removed the last element from the list */
		session->sessionObjList = NULL;
	}

	object->dirtyFlag = 0;

	return CKR_OK;
}



int addObjectToSearchList(struct p11Session_t *session, struct p11Object_t *object)
{
	struct p11Object_t *obj;
	struct p11Object_t *tmp;

	tmp = (struct p11Object_t *) malloc(sizeof(*object));

	if (tmp == NULL) {
		return -1;
	}

	memset(tmp, 0x00, sizeof(*tmp));
	memcpy(tmp, object, sizeof(*object));

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



void clearCryptoBuffer(struct p11Session_t *session)
{
	if (session->cryptoBuffer) {
		memset(session->cryptoBuffer, 0, session->cryptoBufferMax);
		session->cryptoBufferSize = 0;
	}
}
