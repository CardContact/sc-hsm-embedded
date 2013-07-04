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
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>
#include <pkcs11/debug.h>

extern struct p11Context_t *context;


static const CK_MECHANISM_TYPE p11MechanismList[] = {
		CKM_RSA_X_509,
		CKM_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA1_RSA_PKCS_PSS,
		CKM_SHA256_RSA_PKCS_PSS,
		CKM_ECDSA,
		CKM_ECDSA_SHA1
};



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

	rv = updateSlots(context->slotPool);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	slot = context->slotPool->list;
	i = 0;

	while (slot != NULL) {
		if (!tokenPresent || (getToken(slot, &token) == CKR_OK)) {
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

	rv = updateSlots(context->slotPool);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	getToken(slot, &token);				// Update token status

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

	rv = findSlot(context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	memcpy(pInfo, &(slot->token->info), sizeof(CK_TOKEN_INFO));

	FUNC_RETURNS(CKR_OK);
}



/*  C_WaitForSlotEvent waits for a slot event to occur. */
CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)(
		CK_FLAGS flags,
		CK_SLOT_ID_PTR pSlot,
		CK_VOID_PTR pReserved
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

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
	CK_ULONG numberOfMechanisms = 0;
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

	rv = findSlot(context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	numberOfMechanisms = sizeof(p11MechanismList) / sizeof(p11MechanismList[0]);

	if (pMechanismList == NULL) {
		*pulCount = numberOfMechanisms;
		FUNC_RETURNS(CKR_OK);
	}

	if (*pulCount < numberOfMechanisms) {
		*pulCount = numberOfMechanisms;
		FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "Buffer provided by caller too small");
	}

	memcpy(pMechanismList, p11MechanismList, sizeof(p11MechanismList));

	FUNC_RETURNS(CKR_OK);
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

	rv = findSlot(context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	switch (type) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
		pInfo->flags = CKF_SIGN;
		pInfo->flags |= CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_GENERATE_KEY_PAIR;	// Quick fix for Peter Gutmann's cryptlib
		pInfo->ulMinKeySize = 1024;
		pInfo->ulMaxKeySize = 2048;
		break;

	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
		pInfo->flags = CKF_SIGN;
		pInfo->flags |= CKF_HW|CKF_VERIFY|CKF_GENERATE_KEY_PAIR; // Quick fix for Peter Gutmann's cryptlib
		pInfo->ulMinKeySize = 192;
		pInfo->ulMaxKeySize = 320;
		break;

	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

	FUNC_RETURNS(rv);
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
	rv = findSlot(context->slotPool, slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	/* Check if there is an open session */
	findSessionBySlotID(context->sessionPool, slotID, &session);

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

	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (session->state != CKS_RW_SO_FUNCTIONS) {
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "SO not logged in");
	}

	rv = findSlot(context->slotPool, session->slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
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

	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(context->slotPool, session->slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getToken(slot, &token);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}
