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
 * @file    p11slots.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Slots management functions at the PKCS#11 interface
 */

#include <string.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/session.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <common/debug.h>

extern struct p11Context_t *context;



/*  C_GetSlotList obtains a list of slots in the system. */
CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)(
		CK_BBOOL tokenPresent,
		CK_SLOT_ID_PTR pSlotList,
		CK_ULONG_PTR pulCount
)
{
	CK_RV rv = CKR_OK;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	CK_ULONG i;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pulCount)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (pSlotList && !isValidPtr(pSlotList)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	// updateSlots() potentially changes a lot of internal structures
	// which is why both are protected here using the global lock
	p11LockMutex(context->mutex);

	rv = updateSlots(&context->slotPool);

	p11UnlockMutex(context->mutex);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	slot = context->slotPool.list;
	i = 0;

	while (slot != NULL) {
		if (!tokenPresent || (getValidatedToken(slot, &token) == CKR_OK)) {
			if (pSlotList && (i < *pulCount)) {
				pSlotList[i] = slot->id;
			}
			i++;
		}

		slot = slot->next;
	}

	if (pSlotList) {
		if (i > *pulCount) {
			rv = CKR_BUFFER_TOO_SMALL;
		}
	} else {
#ifdef DEBUG
		debug("Size inquiry returns %d slots\n", i);
#endif
	}
	*pulCount = i;

	FUNC_RETURNS(rv);
}



/*  C_GetSlotInfo obtains information about a particular slot. */
CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(
		CK_SLOT_ID slotID,
		CK_SLOT_INFO_PTR pInfo
)
{
	int rv;
	struct p11Slot_t *slot = NULL;
	struct p11Token_t *token = NULL;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pInfo)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	// updateSlots() and getToken() potentially change a lot of internal structures
	// which is why both are protected here using the global lock
	p11LockMutex(context->mutex);

	rv = updateSlots(&context->slotPool);

	p11UnlockMutex(context->mutex);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	getValidatedToken(slot, &token);				// Update token status

	memcpy(pInfo, &(slot->info), sizeof(CK_SLOT_INFO));

	FUNC_RETURNS(CKR_OK);
}



/*  C_GetTokenInfo obtains information about a particular token in the system. */
CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(
		CK_SLOT_ID slotID,
		CK_TOKEN_INFO_PTR pInfo
)
{
	int rv;
	struct p11Slot_t *slot;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pInfo)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSlot(&context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getValidatedToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	memcpy(pInfo, &token->info, sizeof(CK_TOKEN_INFO));

	FUNC_RETURNS(CKR_OK);
}



/*  C_WaitForSlotEvent waits for a slot event to occur. */
CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
		CK_FLAGS flags,
		CK_SLOT_ID_PTR pSlot,
		CK_VOID_PTR pReserved
)
{
	struct p11Slot_t *slot;
	CK_RV rv;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pSlot)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (flags & ~CKF_DONT_BLOCK) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid flags argument");
	}

	// Update slot list if that was never done before
	if (context->slotPool.list == NULL) {
		// updateSlots() and getToken() potentially change a lot of internal structures
		// which is why both are protected here using the global lock
		p11LockMutex(context->mutex);

		rv = updateSlots(&context->slotPool);

		p11UnlockMutex(context->mutex);

		if (rv != CKR_OK) {
			FUNC_FAILS(rv, "Failed to update slot list");
		}
	}

	while (1) {
		rv = nextSlotEvent(&context->slotPool, &slot);

		if ((rv != CKR_OK) && (rv != CKR_NO_EVENT)) {
			FUNC_FAILS(rv, "Could not get next slot event");
		}

		if ((rv == CKR_NO_EVENT) && !(flags & flags & ~CKF_DONT_BLOCK)) {
			rv = waitForSlotEvent(&context->slotPool);

			if (rv != CKR_OK) {
				FUNC_FAILS(rv, "Error waiting for slot event");
			}
			continue;
		}
		break;
	}

	if (rv == CKR_OK)
		*pSlot = slot->id;

	FUNC_RETURNS(rv);
}



/*  C_GetMechanismList obtains a list of mechanisms supported by a token. */
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(
		CK_SLOT_ID slotID,
		CK_MECHANISM_TYPE_PTR pMechanismList,
		CK_ULONG_PTR pulCount
)
{
	int rv;
	struct p11Slot_t *slot;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (pMechanismList && !isValidPtr(pMechanismList)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulCount)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSlot(&context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getValidatedToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	FUNC_RETURNS(getMechanismList(token, pMechanismList, pulCount));
}



/*  C_GetMechanismInfo obtains information about a particular mechanism
    supported by a token. */
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)(
		CK_SLOT_ID slotID,
		CK_MECHANISM_TYPE type,
		CK_MECHANISM_INFO_PTR pInfo
)
{
	CK_RV rv = CKR_OK;
	struct p11Slot_t *slot;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pInfo)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSlot(&context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getValidatedToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	FUNC_RETURNS(getMechanismInfo(token, type, pInfo));
}



/*  C_InitToken initializes a token. */
CK_DECLARE_FUNCTION(CK_RV, C_InitToken)(
		CK_SLOT_ID slotID,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen,
		CK_UTF8CHAR_PTR pLabel
)
{
	int rv = CKR_OK;
	struct p11Slot_t *slot = NULL;
	struct p11Session_t *session = NULL;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	/* Check the slot ID */
	rv = findSlot(&context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	/* Check if there is an open session */
	findSessionBySlotID(&context->sessionPool, slotID, &session);

	if (session != NULL) {
		FUNC_FAILS(CKR_SESSION_EXISTS, "A session on the token exists");
	}

	FUNC_RETURNS(CKR_FUNCTION_NOT_SUPPORTED);
}



/*  C_InitPIN initializes the normal user's pin. */
CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(
		CK_SESSION_HANDLE hSession,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen
)
{
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	int rv;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if ((pPin != NULL) && !isValidPtr(pPin)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &session);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, session->slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getValidatedToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (getSessionState(session, token) != CKS_RW_SO_FUNCTIONS) {
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "SO not logged in");
	}

	rv = initPIN(slot, pPin, ulPinLen);

	FUNC_RETURNS(rv);
}



/*  C_SetPIN modifies the PIN of the user that is currently logged in,
    or the CKU_USER PIN if the session is not logged in. */
CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)(
		CK_SESSION_HANDLE hSession,
		CK_UTF8CHAR_PTR pOldPin,
		CK_ULONG ulOldLen,
		CK_UTF8CHAR_PTR pNewPin,
		CK_ULONG ulNewLen
)
{
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	int rv;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if ((pOldPin != NULL) && !isValidPtr(pOldPin)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if ((pNewPin != NULL) && !isValidPtr(pNewPin)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &session);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, session->slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getValidatedToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = setPIN(slot, pOldPin, ulOldLen, pNewPin, ulNewLen);

	FUNC_RETURNS(rv);
}
