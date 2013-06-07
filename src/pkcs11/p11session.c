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
 * @file    p11session.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Session management functions at the PKCS#11 interface
 */

#include <stdio.h>
#include <memory.h>

#include <pkcs11/cryptoki.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>

#include <strbpcpy.h>

extern struct p11Context_t *context;


/*  C_OpenSession opens a session between an application and a 
    token in a particular slot. */

CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)(
		CK_SLOT_ID slotID,
		CK_FLAGS flags,
		CK_VOID_PTR pApplication,
		CK_NOTIFY Notify,
		CK_SESSION_HANDLE_PTR phSession
)
{
	int rc;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	struct p11Session_t *session;

	if (!(flags & CKF_SERIAL_SESSION)) {
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	}

	findSlot(context->slotPool, slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	rc = getToken(slot, &token);

	if (rc != CKR_OK) {
		return rc;
	}

	if (!(flags & CKF_RW_SESSION) && (token->user == CKU_SO)) { /* there is already an active r/w session for SO */
		return CKR_SESSION_READ_WRITE_SO_EXISTS;
	}

	session = (struct p11Session_t *) malloc(sizeof(struct p11Session_t));

	if (session == NULL) {
		return CKR_HOST_MEMORY;
	}

	memset(session, 0x00, sizeof(struct p11Session_t));

	session->slotID = slotID;
	session->flags = flags;
	session->activeObjectHandle = -1;

	/* initial session state */
	session->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

	addSession(context->sessionPool, session);

	*phSession = session->handle;               /* we got a valid handle by calling addSession() */

	if (!(flags & CKF_RW_SESSION)) {
		token->rosessions++;
	}
	return CKR_OK;
}


/*  C_CloseSession closes a session between an application and a token. */

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(
		CK_SESSION_HANDLE hSession
)
{
	int rc;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	struct p11Session_t *session;
	struct p11Object_t *object, *tmp;

	rc = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rc < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	findSlot(context->slotPool, session->slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	rc = getToken(slot, &token);

	if (rc != CKR_OK) {
		return rc;
	}

	if (!(session->flags & CKF_RW_SESSION)) {
		token->rosessions--;
	}

	object = session->sessionObjList;

	while (object) {
		tmp = object->next;
		removeAllAttributes(object);
		free(object);
		object = tmp;
	}

	rc = removeSession(context->sessionPool, hSession);

	if (rc < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	return CKR_OK;
}


/*  C_CloseAllSessions closes all sessions an application has with a token. */

CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)(
		CK_SLOT_ID slotID
)
{
	int rc;
	struct p11Session_t *session, *tmp;

	if (context->sessionPool == NULL) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	while(session = context->sessionPool->list) {
		C_CloseSession(session->handle);
	}

	return CKR_OK;
}


/*  C_GetSessionInfo obtains information about a session. */

CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)(
		CK_SESSION_HANDLE hSession,
		CK_SESSION_INFO_PTR pInfo
)
{
	int rv;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	struct p11Session_t *session;

	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	rv = findSlot(context->slotPool, session->slotID, &slot);

	if (rv < 0) {
		return CKR_GENERAL_ERROR;   /* normally we should never be here */
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		C_CloseSession(hSession);
		return CKR_SESSION_CLOSED;
	}

	pInfo->slotID = session->slotID;
	pInfo->flags = session->flags;
	pInfo->ulDeviceError = 0;

	switch (token->user) {
	case CKU_USER:
		pInfo->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
		break;

	case CKU_SO:
		pInfo->state = CKS_RW_SO_FUNCTIONS;
		break;

	default:
		pInfo->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
		break;
	}

	return CKR_OK;

}


/*  C_GetOperationState obtains a copy of the cryptographic operations state of a session. */

CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOperationState,
		CK_ULONG_PTR pulOperationStateLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	return rv;
}


/*  C_SetOperationState restores the cryptographic operations state of a session. */

CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pOperationState,
		CK_ULONG ulOperationStateLen,
		CK_OBJECT_HANDLE hEncryptionKey,
		CK_OBJECT_HANDLE hAuthenticationKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	return rv;
}


/*  C_Login logs a user into a token. */

CK_DECLARE_FUNCTION(CK_RV, C_Login)(
		CK_SESSION_HANDLE hSession,
		CK_USER_TYPE userType,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen
)
{
	int rv, l;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	unsigned char tmp[8];

	if (userType != CKU_USER && userType != CKU_SO) {
		return CKR_USER_TYPE_INVALID;
	}

	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	rv = findSlot(context->slotPool, session->slotID, &slot);

	if (rv < 0) {
		return CKR_GENERAL_ERROR;   /* normally we should never be here */
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		return rv;
	}

	if ((token->user == CKU_USER) || (token->user == CKU_SO)) {
		return CKR_USER_ALREADY_LOGGED_IN;
	}

	if (userType == CKU_USER) {
		if (!(token->info.flags & CKF_USER_PIN_INITIALIZED)) {
			return CKR_USER_PIN_NOT_INITIALIZED;
		}
	} else {
		if (!(session->flags & CKF_RW_SESSION)) {
			return CKR_SESSION_READ_ONLY;
		}
		if (token->rosessions) {
			return CKR_SESSION_READ_ONLY_EXISTS;
		}
	}

	rv = logIn(slot, userType, pPin, ulPinLen);

	if (rv != CKR_OK) {
		return rv;
	}

	token->user = userType;

	if (token->user == CKU_SO) {
		session->state = CKS_RW_SO_FUNCTIONS;
	} else {
		session->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
	}

	return CKR_OK;
}


/*  C_Logout logs a user out from a token. */

CK_DECLARE_FUNCTION(CK_RV, C_Logout)(
		CK_SESSION_HANDLE hSession
)
{
	int rv;
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	struct p11Object_t *object, *tmp;

	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	rv = findSlot(context->slotPool, session->slotID, &slot);

	if (rv < 0) {
		return CKR_GENERAL_ERROR;   /* normally we should never be here */
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		return rv;
	}

	slot->token->user = 0xFF;

	rv = logOut(slot);

	if (rv != CKR_OK) {
		return rv;
	}

	// reset initital session state
	session->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;

	return CKR_OK;
}
