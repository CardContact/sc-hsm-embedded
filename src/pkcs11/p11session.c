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
 * Abstract :       <Short description of what is done with this file>
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

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

	rc = findSessionBySlotID(context->sessionPool, slotID, &session);

	if (rc < 0) {   /* there is no open session for this slot */

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

		session->user = 0xFF;                       /* no user is logged in  */

		addSession(context->sessionPool, session);

		*phSession = session->handle;               /* we got a valid handle by calling addSession() */


	} else { /* there is an active session - check the state */

		if ((session->flags & CKF_RW_SESSION) && (session->user == CKU_SO)) { /* there is already an active r/w session for SO */
			return CKR_SESSION_READ_WRITE_SO_EXISTS;
		}

		return CKR_SESSION_EXISTS;
	}

	return CKR_OK;
}


/*  C_CloseSession closes a session between an application and a token. */

CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)(
		CK_SESSION_HANDLE hSession
)
{
	int rc;
	struct p11Session_t *session;
	struct p11Object_t *object, *tmp;

	rc = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rc < 0) {
		return CKR_SESSION_HANDLE_INVALID;
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

	session = context->sessionPool->list;

	while (session != NULL) {

		tmp = session->next;

		rc = removeSession(context->sessionPool, session->handle);

		if (rc < 0) {
			return CKR_SESSION_HANDLE_INVALID;
		}

		session = tmp;
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
	struct p11Session_t *session;


	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	pInfo->slotID = session->slotID;
	pInfo->flags = session->flags;
	pInfo->ulDeviceError = 0;

	switch (session->user) {
	case CKU_USER:
		pInfo->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_USER_FUNCTIONS : CKS_RO_USER_FUNCTIONS;
		break;

	case CKU_SO:
		pInfo->state = CKS_RW_SO_FUNCTIONS;
		break;

	default:
		pInfo->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
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

	if ((session->user == CKU_USER) || (session->user == CKU_SO)) {
		return CKR_USER_ALREADY_LOGGED_IN;
	}

	if (!(token->info.flags & CKF_USER_PIN_INITIALIZED) && (userType == CKU_USER)) {
		return CKR_USER_PIN_NOT_INITIALIZED;
	}

	rv = logIn(slot, userType, pPin, ulPinLen);

	if (rv != CKR_OK) {
		return rv;
	}

	session->user = userType;

	if (session->user == CKU_SO) {
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

	/* remove the private objects - they are no longer available */
	object = token->tokenPrivObjList;

	while (object) {
		tmp = object->next;
		removeAllAttributes(object);
		free(object);
		object = tmp;
	}

	token->tokenPrivObjList = NULL;

	// reset initital session state
	session->state = (session->flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	session->user = 0xFF;                       /* no user is logged in  */

	return CKR_OK;
}
