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
 * Abstract :       PKCS#11 functions for slot management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

#include <stdio.h>
#include <memory.h>

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>

#include <strbpcpy.h>

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

	updateSlots(context->slotPool);

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

	return rv;
}



/*  C_GetSlotInfo obtains information about a particular slot. */
CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)(
		CK_SLOT_ID slotID,
		CK_SLOT_INFO_PTR pInfo
)
{
	struct p11Slot_t *slot = NULL;
	struct p11Token_t *token = NULL;

	FUNC_CALLED();

	updateSlots(context->slotPool);

	findSlot(context->slotPool, slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	getToken(slot, &token);

	memcpy(pInfo, &(slot->info), sizeof(CK_SLOT_INFO));

	return CKR_OK;
}



/*  C_GetTokenInfo obtains information about a particular token in the system. */
CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)(
		CK_SLOT_ID slotID,
		CK_TOKEN_INFO_PTR pInfo
)
{
	struct p11Slot_t *slot;

	FUNC_CALLED();

	findSlot(context->slotPool, slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	if (slot->token != NULL) {
		memcpy(pInfo, &(slot->token->info), sizeof(CK_TOKEN_INFO));
	} else {
		return CKR_TOKEN_NOT_PRESENT;
	}

	return CKR_OK;
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

	return rv;
}



/*  C_GetMechanismList obtains a list of mechanisms supported by a token. */
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)(
		CK_SLOT_ID slotID,
		CK_MECHANISM_TYPE_PTR pMechanismList,
		CK_ULONG_PTR pulCount
)
{
	CK_ULONG numberOfMechanisms = 0;
	struct p11Slot_t *slot;

	FUNC_CALLED();

	findSlot(context->slotPool, slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	if (slot->token == NULL) {
		return CKR_TOKEN_NOT_PRESENT;
	}

	numberOfMechanisms = sizeof(p11MechanismList) / sizeof(p11MechanismList[0]);

	if (pMechanismList == NULL) {
		*pulCount = numberOfMechanisms;
		return CKR_OK;
	}

	if (*pulCount < numberOfMechanisms) {
		*pulCount = numberOfMechanisms;
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(pMechanismList, p11MechanismList, sizeof(p11MechanismList));

	return CKR_OK;
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

	FUNC_CALLED();

	findSlot(context->slotPool, slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	if (slot->token == NULL) {
		return CKR_TOKEN_NOT_PRESENT;
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

	return rv;
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
	struct p11Token_t *token = NULL;
	struct p11Session_t *session = NULL;
	struct dirent *dirent;
	unsigned char dirname[_MAX_PATH];
	unsigned char scr[256];
	unsigned char tmp[8];
	unsigned char noBlankLabel[32];
	int l;

	FUNC_CALLED();

	/* Check the slot ID */
	findSlot(context->slotPool, slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	/* Check if there is an open session */
	findSessionBySlotID(context->sessionPool, slotID, &session);

	if (session != NULL) {
		return CKR_SESSION_EXISTS;
	}

#if 0
	token = slot->token;

	// Determine the length of the label
	l = 0;
	while (noBlankLabel[l] != 0x00) {
		l++;
	}
	strbpcpy(token->info.label, noBlankLabel, l);

	strbpcpy(token->info.manufacturerID, "CardContact", sizeof(token->info.manufacturerID));

	/* indicate that the token is now (re-)initialized */
	token->info.flags |= CKF_TOKEN_INITIALIZED;

	token->info.ulMaxPinLen = 8;
	token->info.ulMinPinLen = 4;
	token->info.ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
	token->info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	token->info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	token->info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	token->info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	token->info.ulMaxSessionCount = CK_UNAVAILABLE_INFORMATION;
	token->info.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	token->info.ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
	token->info.ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;

	token->freeObjectNumber = 1;

	addToken(slot, token);
#endif

return CKR_FUNCTION_NOT_SUPPORTED;
}



/*  C_InitPIN initializes the normal user�s pin. */
CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)(
		CK_SESSION_HANDLE hSession,
		CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen
)
{
	struct p11Session_t *session;
	struct p11Slot_t *slot;
	struct p11Token_t *token;
	unsigned char tmp[8];
	int rv, l;

	FUNC_CALLED();

	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	if (session->state != CKS_RW_SO_FUNCTIONS) {
		return CKR_USER_NOT_LOGGED_IN;
	}

	rv = findSlot(context->slotPool, session->slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	if (slot->token == NULL) {
		return CKR_TOKEN_NOT_PRESENT;
	}

	token = slot->token;

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
	unsigned char tmp[8];
	int rv, l;

	FUNC_CALLED();

	rv = findSessionByHandle(context->sessionPool, hSession, &session);

	if (rv < 0) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	rv = findSlot(context->slotPool, session->slotID, &slot);

	if (slot == NULL) {
		return CKR_SLOT_ID_INVALID;
	}

	if (slot->token == NULL) {
		return CKR_TOKEN_NOT_PRESENT;
	}

	token = slot->token;

	return CKR_FUNCTION_NOT_SUPPORTED;
}
