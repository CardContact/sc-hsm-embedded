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
 * @file    p11mechanisms.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Crypto mechanisms at the PKCS#11 interface
 */

#ifndef _WIN32
#include <unistd.h>
#endif

#include <pkcs11/p11generic.h>
#include <pkcs11/session.h>
#include <pkcs11/slot.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/token.h>
#include <common/debug.h>


extern struct p11Context_t *context;



/*  C_EncryptInit initializes an encryption operation. */
CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pMechanism)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if ((findSessionObject(pSession, hKey, &pObject) < 0) && (findObject(pSlot->token, hKey, &pObject, TRUE) < 0)) {
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "Can not find key for handle");
	}

	if (pObject->C_EncryptInit != NULL) {
		rv = pObject->C_EncryptInit(pObject, pMechanism);
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported");
	}

	if (rv == CKR_OK) {
		pSession->activeObjectHandle = pObject->handle;
		pSession->activeMechanism = pMechanism->mechanism;
	}

	FUNC_RETURNS(rv);
}



/*  C_Encrypt encrypts single-part data. */
CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pData)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (pEncryptedData && !isValidPtr(pEncryptedData)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulEncryptedDataLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if ((findSessionObject(pSession, pSession->activeObjectHandle, &pObject) < 0) && (findObject(pSlot->token, pSession->activeObjectHandle, &pObject, TRUE) < 0)) {
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "Can not find key for handle");
	}

	if (pObject->C_Encrypt != NULL) {
		rv = pObject->C_Encrypt(pObject, pSession->activeMechanism, pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);

		if ((pEncryptedData != NULL) && (rv != CKR_BUFFER_TOO_SMALL)) {
			pSession->activeObjectHandle = CK_INVALID_HANDLE;
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported");
	}

	FUNC_RETURNS(rv);
}



/*  C_EncryptUpdate continues a multiple-part encryption operation,
    processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG_PTR pulEncryptedPartLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (pEncryptedPart && !isValidPtr(pEncryptedPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulEncryptedPartLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_EncryptUpdate != NULL) {
		rv = pObject->C_EncryptUpdate(pObject, pSession->activeMechanism, pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	FUNC_RETURNS(rv);
}



/*  C_EncryptFinal finishes a multiple-part encryption operation. */
CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastEncryptedPart,
		CK_ULONG_PTR pulLastEncryptedPartLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (pLastEncryptedPart && !isValidPtr(pLastEncryptedPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulLastEncryptedPartLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_EncryptFinal != NULL) {
		rv = pObject->C_EncryptFinal(pObject, pSession->activeMechanism, pLastEncryptedPart, pulLastEncryptedPartLen);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	if (!rv) {
		pSession->activeObjectHandle = CK_INVALID_HANDLE;
		rv = CKR_OK;
	}

	FUNC_RETURNS(rv);
}



/*  C_DecryptInit initializes a decryption operation. */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pMechanism)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, hKey, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_DecryptInit != NULL) {
		rv = pObject->C_DecryptInit(pObject, pMechanism);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	if (!rv) {
		pSession->activeObjectHandle = pObject->handle;
		pSession->activeMechanism = pMechanism->mechanism;
		rv = CKR_OK;
	}

	FUNC_RETURNS(rv);
}



/*  C_Decrypt decrypts encrypted data in a single part. */
CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pEncryptedData)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (pData && !isValidPtr(pData)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulDataLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pData != NULL) {
		pSession->activeObjectHandle = CK_INVALID_HANDLE;
	}

	if (pObject->C_Decrypt != NULL) {
		rv = pObject->C_Decrypt(pObject, pSession->activeMechanism, pEncryptedData, ulEncryptedDataLen, pData, pulDataLen);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	FUNC_RETURNS(rv);
}



/*  C_DecryptUpdate continues a multiple-part decryption operation,
    processing another encrypted data part. */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pEncryptedPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (pPart && !isValidPtr(pPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulPartLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_DecryptUpdate != NULL) {
		rv = pObject->C_DecryptUpdate(pObject, pSession->activeMechanism, pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	FUNC_RETURNS(rv);
}



/*  C_DecryptFinal finishes a multiple-part decryption operation. */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pLastPart,
		CK_ULONG_PTR pulLastPartLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (pLastPart && !isValidPtr(pLastPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulLastPartLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}
	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_DecryptFinal != NULL) {
		rv = pObject->C_DecryptFinal(pObject, pSession->activeMechanism, pLastPart, pulLastPartLen);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	if (!rv) {
		pSession->activeObjectHandle = CK_INVALID_HANDLE;
		rv = CKR_OK;
	}

	FUNC_RETURNS(rv);
}



/*  C_DigestInit initializes a message-digesting operation. */
CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_Digest digests data in a single part. */
CK_DECLARE_FUNCTION(CK_RV, C_Digest)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pDigest,
		CK_ULONG_PTR pulDigestLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DigestUpdate continues a multiple-part message-digesting operation,
    processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DigestKey continues a multiple-part message-digesting operation by
    digesting the value of a secret key. */
CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)(
		CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DigestFinal finishes a multiple-part message-digesting operation. */
CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pDigest,
		CK_ULONG_PTR pulDigestLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_SignInit initializes a signature operation,
    here the signature is an appendix to the data. */
CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	int rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pMechanism)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, hKey, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_SignInit != NULL) {
		rv = pObject->C_SignInit(pObject, pMechanism);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	if (!rv) {
		pSession->activeObjectHandle = pObject->handle;
		pSession->activeMechanism = pMechanism->mechanism;
		rv = CKR_OK;
	}

	FUNC_RETURNS(rv);
}



/*  C_Sign signs data in a single part, where the signature is an appendix to the data. */
CK_DECLARE_FUNCTION(CK_RV, C_Sign)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	int rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pData)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (pSignature && !isValidPtr(pSignature)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulSignatureLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_Sign != NULL) {
		rv = pObject->C_Sign(pObject, pSession->activeMechanism, pData, ulDataLen, pSignature, pulSignatureLen);

		if ((pSignature != NULL) && (rv != CKR_BUFFER_TOO_SMALL)) {
			pSession->activeObjectHandle = CK_INVALID_HANDLE;
		}

		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
	}

	FUNC_RETURNS(rv);
}



/*  C_SignUpdate continues a multiple-part signature operation,
    processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_SignUpdate != NULL) {
		rv = pObject->C_SignUpdate(pObject, pSession->activeMechanism, pPart, ulPartLen);
		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		rv = appendToCryptoBuffer(pSession, pPart, ulPartLen);
	}

	FUNC_RETURNS(rv);
}



/*  C_SignFinal finishes a multiple-part signature operation. */
CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (pSignature && !isValidPtr(pSignature)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pulSignatureLen)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlotKey(pSlot, pSession->activeObjectHandle, &pObject);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pObject->C_SignFinal != NULL) {
		rv = pObject->C_SignFinal(pObject, pSession->activeMechanism, pSignature, pulSignatureLen);

		if ((pSignature != NULL) && (rv != CKR_BUFFER_TOO_SMALL)) {
			pSession->activeObjectHandle = CK_INVALID_HANDLE;
			clearCryptoBuffer(pSession);
		}

		if (rv == CKR_DEVICE_ERROR) {
			rv = handleDeviceError(hSession);
			FUNC_FAILS(rv, "Device error reported");
		}
	} else {
		if (pObject->C_Sign != NULL) {
			rv = pObject->C_Sign(pObject, pSession->activeMechanism, pSession->cryptoBuffer, pSession->cryptoBufferSize, pSignature, pulSignatureLen);

			if ((pSignature != NULL) && (rv != CKR_BUFFER_TOO_SMALL)) {
				pSession->activeObjectHandle = CK_INVALID_HANDLE;
				clearCryptoBuffer(pSession);
			}

			if (rv == CKR_DEVICE_ERROR) {
				rv = handleDeviceError(hSession);
				FUNC_FAILS(rv, "Device error reported");
			}
		} else {
			FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported by token");
		}
	}

	FUNC_RETURNS(rv);
}



/*  C_SignRecoverInit initializes a signature operation, where the data
    can be recovered from the signature. */
CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_SignRecover signs data in a single operation, where the data can be
    recovered from the signature. */
CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG_PTR pulSignatureLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_VerifyInit initializes a verification operation, where the signature is
    an appendix to the data. */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pMechanism)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if ((findSessionObject(pSession, hKey, &pObject) < 0) && (findObject(pSlot->token, hKey, &pObject, TRUE) < 0)) {
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "Can not find key for handle");
	}

	if (pObject->C_VerifyInit != NULL) {
		rv = pObject->C_VerifyInit(pObject, pMechanism);
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported");
	}

	if (rv == CKR_OK) {
		pSession->activeObjectHandle = pObject->handle;
		pSession->activeMechanism = pMechanism->mechanism;
	}

	FUNC_RETURNS(rv);
}



/*  C_Verify verifies a signature in a single-part operation, where the signature
    is an appendix to the data. */
CK_DECLARE_FUNCTION(CK_RV, C_Verify)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pData,
		CK_ULONG ulDataLen,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen
)
{
	int rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pData)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (pSignature && !isValidPtr(pSignature)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if ((findSessionObject(pSession, pSession->activeObjectHandle, &pObject) < 0) && (findObject(pSlot->token, pSession->activeObjectHandle, &pObject, TRUE) < 0)) {
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "Can not find key for handle");
	}

	if (pObject->C_Verify != NULL) {
		rv = pObject->C_Verify(pObject, pSession->activeMechanism, pData, ulDataLen, pSignature, ulSignatureLen);
		pSession->activeObjectHandle = CK_INVALID_HANDLE;
	} else {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported");
	}

	FUNC_RETURNS(rv);
}



/*  C_VerifyUpdate continues a multiple-part verification operation,
    processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pPart)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if ((findSessionObject(pSession, pSession->activeObjectHandle, &pObject) < 0) && (findObject(pSlot->token, pSession->activeObjectHandle, &pObject, TRUE) < 0)) {
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "Can not find key for handle");
	}

	if (pObject->C_VerifyUpdate != NULL) {
		rv = pObject->C_VerifyUpdate(pObject, pSession->activeMechanism, pPart, ulPartLen);
	} else {
		rv = appendToCryptoBuffer(pSession, pPart, ulPartLen);
	}

	FUNC_RETURNS(rv);
}



/*  C_VerifyFinal finishes a multiple-part verification operation,
    checking the signature. */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen
)
{
	CK_RV rv;
	struct p11Object_t *pObject;
	struct p11Slot_t *pSlot;
	struct p11Session_t *pSession;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pSignature)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if (pSession->activeObjectHandle == CK_INVALID_HANDLE) {
		FUNC_FAILS(CKR_OPERATION_NOT_INITIALIZED, "Operation not initialized");
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &pSlot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	if ((findSessionObject(pSession, pSession->activeObjectHandle, &pObject) < 0) && (findObject(pSlot->token, pSession->activeObjectHandle, &pObject, TRUE) < 0)) {
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "Can not find key for handle");
	}

	if (pObject->C_VerifyFinal != NULL) {
		rv = pObject->C_VerifyFinal(pObject, pSession->activeMechanism, pSignature, ulSignatureLen);

		pSession->activeObjectHandle = CK_INVALID_HANDLE;
		clearCryptoBuffer(pSession);
	} else {
		if (pObject->C_Verify != NULL) {
			rv = pObject->C_Verify(pObject, pSession->activeMechanism, pSession->cryptoBuffer, pSession->cryptoBufferSize, pSignature, ulSignatureLen);

			pSession->activeObjectHandle = CK_INVALID_HANDLE;
			clearCryptoBuffer(pSession);
		} else {
			FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "Operation not supported");
		}
	}

	FUNC_RETURNS(rv);
}



/*  C_VerifyRecoverInit initializes a signature verification operation,
    where the data is recovered from the signature. */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_VerifyRecover verifies a signature in a single-part operation,
    where the data is recovered from the signature. */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen,
		CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DigestEncryptUpdate continues multiple-part digest and encryption
    operations, processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG_PTR pulEncryptedPartLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DecryptDigestUpdate continues a multiple-part combined decryption and
    digest operation, processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_SignEncryptUpdate continues a multiple-part combined signature and
    encryption operation, processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_SignEncryptUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG_PTR pulEncryptedPartLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DecryptVerifyUpdate continues a multiple-part combined decryption and verification
    operation, processing another data part. */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG ulEncryptedPartLen,
		CK_BYTE_PTR pPart,
		CK_ULONG_PTR pulPartLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_GenerateKey generates a secret key or set of domain parameters,
    creating a new object. */
CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_GenerateKeyPair generates a public/private key pair, creating new key objects. */
CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		CK_ULONG ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG ulPrivateKeyAttributeCount,
		CK_OBJECT_HANDLE_PTR phPublicKey,
		CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	CK_RV rv;
	int pos;
	struct p11Slot_t *slot;
	struct p11Session_t *pSession;
	struct p11Token_t *token;
	struct p11Object_t *p11PriKey, *p11PubKey;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pMechanism)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pPublicKeyTemplate)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(pPrivateKeyTemplate)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(phPublicKey)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	if (!isValidPtr(phPrivateKey)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

#ifdef DEBUG
	debug("Private Key Template\n");
	dumpAttributes(pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	debug("Public Key Template\n");
	dumpAttributes(pPublicKeyTemplate, ulPublicKeyAttributeCount);
#endif

	pos = findAttributeInTemplate(CKA_TOKEN, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if (pos < 0) {
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_TOKEN not found in private key template");
	}

	rv = validateAttribute(&pPrivateKeyTemplate[pos], sizeof(CK_BBOOL));
	if (rv != CKR_OK)
		FUNC_FAILS(rv, "CKA_TOKEN has invalid value");

	if (*(CK_BBOOL *)pPrivateKeyTemplate[pos].pValue == 0) {
		FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "Generating session key pairs not supported");
	}

	rv = getValidatedToken(slot, &token);

	if (rv != CKR_OK) {
		return rv;
	}

	if (getSessionState(pSession, token) != CKS_RW_USER_FUNCTIONS) {
		FUNC_FAILS(CKR_SESSION_READ_ONLY, "Session is read/only");
	}

	rv = generateTokenKeypair(slot, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, &p11PubKey, &p11PriKey);

	if (rv == CKR_DEVICE_ERROR) {
		rv = handleDeviceError(hSession);
		FUNC_FAILS(rv, "Device error reported");
	}

	if (rv != CKR_OK) {
		FUNC_FAILS(rv, "Generating key pair on token failed");
	}

	*phPublicKey = p11PubKey->handle;
	*phPrivateKey = p11PriKey->handle;

	FUNC_RETURNS(rv);
}



/*  C_WrapKey wraps (i.e., encrypts) a private or secret key. */
CK_DECLARE_FUNCTION(CK_RV, C_WrapKey)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey,
		CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG_PTR pulWrappedKeyLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_UnwrapKey unwraps (i.e. decrypts) a wrapped key, creating a new private key
    or secret key object. */
CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKey)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hUnwrappingKey,
		CK_BYTE_PTR pWrappedKey,
		CK_ULONG ulWrappedKeyLen,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_DeriveKey derives a key from a base key, creating a new key object. */
CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)(
		CK_SESSION_HANDLE hSession,
		CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hBaseKey,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		CK_OBJECT_HANDLE_PTR phKey
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_SeedRandom mixes additional seed material into the token�s random number generator. */
CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSeed,
		CK_ULONG ulSeedLen
)
{
	CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(rv);
}



/*  C_GenerateRandom generates random or pseudo-random data. */
CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)(
		CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pRandomData,
		CK_ULONG ulRandomLen
)
{
	CK_RV rv;
	struct p11Slot_t *slot;
	struct p11Session_t *pSession;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	if (!isValidPtr(pRandomData)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Invalid pointer argument");
	}

	rv = findSessionByHandle(&context->sessionPool, hSession, &pSession);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = findSlot(&context->slotPool, pSession->slotID, &slot);

	if (rv != CKR_OK) {
		FUNC_RETURNS(rv);
	}

	rv = getValidatedToken(slot, &token);

	if (rv != CKR_OK) {
		return rv;
	}

	rv = generateTokenRandom(slot, pRandomData, ulRandomLen);

	if (rv == CKR_DEVICE_ERROR) {
		rv = handleDeviceError(hSession);
		FUNC_FAILS(rv, "Device error reported");
	}

	if (rv != CKR_OK) {
		FUNC_FAILS(rv, "Generating random on token failed");
	}

	FUNC_RETURNS(rv);
}



/*  C_GetFunctionStatus obtained the status of a function
    running in parallel with an application. Now legacy! */
CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(
		CK_SESSION_HANDLE hSession
)
{
	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(CKR_FUNCTION_NOT_PARALLEL);
}


/*  C_CancelFunction cancelled a function running in parallel
    with an application. Now legacy! */
CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(
		CK_SESSION_HANDLE hSession
)
{
	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "C_Initialize not called");
	}

	FUNC_RETURNS(CKR_FUNCTION_NOT_PARALLEL);
}
