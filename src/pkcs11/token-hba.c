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
 * @file    token-starcos-hba.c
 * @author  Andreas Schwier
 * @brief   Token implementation for a German Heilberufsausweis (HBA)
 */

#include <string.h>
#include "token-starcos.h"

#include <common/bytestring.h>
#include <common/asn1.h>
#include <common/pkcs15.h>
#include <common/debug.h>

#include <pkcs11/slot.h>
#include <pkcs11/object.h>
#include <pkcs11/token.h>
#include <pkcs11/certificateobject.h>
#include <pkcs11/privatekeyobject.h>
#include <pkcs11/publickeyobject.h>
#include <pkcs11/strbpcpy.h>


#define ALG_SIGN_PKCS1_V15		0x02;
#define ALG_SIGN_PSS			0x05;

#define ALG_DECRYPT_PKCS1_V15	0x81;
#define ALG_DECRYPT_OEAP		0x85;


static unsigned char atrHBA[] = { 0x3B,0xD3,0x96,0xFF,0x81,0xB1,0xFE,0x45,0x1F,0x07,0x80,0x81,0x05,0x2D };



static struct p15PrivateKeyDescription prkd_eSign[] = {
		{
			P15_KT_RSA,
			{ "C.CH.AUT" },
			1,
			{ (unsigned char *)"\x03", 1 },
			P15_SIGN,
			2048,
			0x82
		},
		{
			P15_KT_RSA,
			{ "C.CH.ENC" },
			1,
			{ (unsigned char *)"\x04", 1 },
			P15_DECIPHER,
			2048,
			0x83
		}
};



static struct p15CertificateDescription certd_eSign[] = {
	{
		0,                                          // isCA
		0,                                          // isModifiable
		P15_CT_X509,                                // Certificate type
		{ "C.CH.AUT" },                             // Label
		{ (unsigned char *)"\x03", 1 },				// Id
		{ (unsigned char *)"\xC5\x00", 2 }			// efifOrPath
	},
	{
		0,                                          // isCA
		0,                                          // isModifiable
		P15_CT_X509,                                // Certificate type
		{ "C.CH.ENC" },                             // Label
		{ (unsigned char *)"\x04", 1 },				// Id
		{ (unsigned char *)"\xC2\x00", 2 }			// efifOrPath
	}
};



static unsigned char aid_eSign[] = { 0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E };


static struct starcosApplication starcosApplications[] = {
		{
				"HBA.eSign",
				{ aid_eSign, sizeof(aid_eSign) },
				1,
				0x01,
				0,
				prkd_eSign,
				sizeof(prkd_eSign) / sizeof(struct p15PrivateKeyDescription),
				certd_eSign,
				sizeof(certd_eSign) / sizeof(struct p15CertificateDescription)
		}
};



static const CK_MECHANISM_TYPE p11MechanismList[] = {
		CKM_RSA_PKCS,
		CKM_RSA_PKCS_OAEP,
		CKM_RSA_PKCS_PSS
#ifdef ENABLE_LIBCRYPTO
		,
		CKM_SHA_1,
		CKM_SHA224,
		CKM_SHA256,
		CKM_SHA384,
		CKM_SHA512
#endif
};



static int getSignatureSize(CK_MECHANISM_TYPE mech, struct p11Object_t *pObject)
{
	switch(mech) {
	case CKM_RSA_PKCS:
	case CKM_RSA_PKCS_PSS:
		return pObject->keysize >> 3;
	default:
		return -1;
	}
}



static int getAlgorithmIdForSigning(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char *algo)
{
	switch(mech) {
	case CKM_RSA_PKCS:
		*algo = ALG_SIGN_PKCS1_V15;
		break;
	case CKM_RSA_PKCS_PSS:
		*algo = ALG_SIGN_PSS;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}



static int getAlgorithmIdForDecryption(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char *algo)
{
	switch(mech) {
	case CKM_RSA_PKCS:
		*algo = ALG_DECRYPT_PKCS1_V15;
		break;
	case CKM_RSA_PKCS_OAEP:
		*algo = ALG_DECRYPT_OEAP;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}



static int hba_C_SignInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	unsigned char algo;

	FUNC_CALLED();

	FUNC_RETURNS(getAlgorithmIdForSigning(pObject->token, mech->mechanism, &algo));
}



static int hba_C_Sign(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	int rc, len, signaturelen;
	unsigned short SW1SW2;
	unsigned char scr[256], *d;
	unsigned char algo;
	struct p11Slot_t *slot;

	FUNC_CALLED();

	rc = getSignatureSize(mech, pObject);
	if (rc < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Unknown mechanism");
	}
	signaturelen = rc;

	if (pSignature == NULL) {
		*pulSignatureLen = signaturelen;
		FUNC_RETURNS(CKR_OK);
	}

	if (*pulSignatureLen < (CK_ULONG)signaturelen) {
		*pulSignatureLen = signaturelen;
		FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "Signature length is larger than buffer");
	}

	slot = pObject->token->slot;
	starcosLock(pObject->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = starcosSelectApplication(pObject->token);
	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "selecting application failed");
	}

	rc = getAlgorithmIdForSigning(pObject->token, mech, &algo);
	if (rc != CKR_OK) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(rc, "getAlgorithmIdForSigning() failed");
	}

	d = scr;
	*d++ = 0x84;
	*d++ = 0x01;
	*d++ = (unsigned char)pObject->tokenid;
	*d++ = 0x80;
	*d++ = 0x01;
	*d++ = algo;

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x22, 0x41, 0xB6,
		(int)(d - scr), scr,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "MANAGE SE failed");
	}

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x2A, 0x9E, 0x9A,
			ulDataLen, pData,
			0, pSignature, *pulSignatureLen, &SW1SW2);

	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		starcosUnlock(pObject->token);
		switch(SW1SW2) {
		case 0x6A81:
			FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Signature operation not allowed for key");
			break;
		case 0x6982:
			pObject->token->user = INT_CKU_NO_USER;
			FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
			break;
		}
		FUNC_FAILS(CKR_DEVICE_ERROR, "Signature operation failed");
	}

	*pulSignatureLen = rc;

	if ((pObject->token->user == CKU_USER) && (pObject->token->pinUseCounter == 1)) {
		pObject->token->user = INT_CKU_NO_USER;
	}

	starcosUnlock(pObject->token);
	FUNC_RETURNS(CKR_OK);
}



static int hba_C_DecryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	unsigned char algo;

	FUNC_CALLED();

	FUNC_RETURNS(getAlgorithmIdForDecryption(pObject->token, mech->mechanism, &algo));
}



static int hba_C_Decrypt(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	int rc, len;
	unsigned char *d,*s,algo;
	unsigned short SW1SW2;
	unsigned char scr[257];
	struct p11Slot_t *slot;

	FUNC_CALLED();

	if (ulEncryptedDataLen != 256)
		FUNC_FAILS(CKR_ENCRYPTED_DATA_LEN_RANGE, "Cryptogram size must be 256 byte");

	if (pData == NULL) {
		*pulDataLen = pObject->keysize >> 3;
		FUNC_RETURNS(CKR_OK);
	}

	slot = pObject->token->slot;
	starcosLock(pObject->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = starcosSelectApplication(pObject->token);
	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "selecting application failed");
	}

	rc = getAlgorithmIdForDecryption(pObject->token, mech, &algo);
	if (rc != CKR_OK) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(rc, "getAlgorithmIdForDecryption() failed");
	}

	d = scr;
	*d++ = 0x84;
	*d++ = 0x01;
	*d++ = (unsigned char)pObject->tokenid;
	*d++ = 0x80;
	*d++ = 0x01;
	*d++ = algo;

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x22, 0x41, 0xB8,
		(int)(d - scr), scr,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "MANAGE SE failed");
	}

	scr[0] = 0x81;
	memcpy(scr + 1, pEncryptedData, ulEncryptedDataLen);

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x2A, 0x80, 0x86,
			257, scr,
			0, scr, sizeof(scr), &SW1SW2);

	starcosUnlock(pObject->token);

	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		starcosUnlock(pObject->token);
		switch(SW1SW2) {
		case 0x6A81:
			FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Decryption operation not allowed for key");
			break;
		case 0x6982:
			FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
			break;
		}
		FUNC_FAILS(CKR_DEVICE_ERROR, "Decryption operation failed");
	}

	*pulDataLen = rc;
	if (rc > (int)*pulDataLen) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
	}

	if ((pObject->token->user == CKU_USER) && (pObject->token->pinUseCounter == 1)) {
		pObject->token->user = INT_CKU_NO_USER;
	}

	memcpy(pData, scr, rc);

	starcosUnlock(pObject->token);
	FUNC_RETURNS(CKR_OK);
}



static int isCandidate(unsigned char *atr, size_t atrLen)
{
	if ((atrLen == sizeof(atrHBA)) && !memcmp(atr, atrHBA, atrLen))
		return 1;

	return 0;
}



struct p11TokenDriver *getHBATokenDriver();

/**
 * Create a new HBA token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
static int newHBAToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	struct p11Token_t *ptoken;
	int rc;

	FUNC_CALLED();

	rc = createStarcosToken(slot, &ptoken, getHBATokenDriver(), &starcosApplications[0]);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Token creation failed");

	rc = addToken(slot, ptoken);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "addToken() failed");
	}

	*token = ptoken;
	FUNC_RETURNS(CKR_OK);
}



static int hba_C_GetMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	CK_ULONG numberOfMechanisms;

	FUNC_CALLED();

	numberOfMechanisms = sizeof(p11MechanismList) / sizeof(p11MechanismList[0]);

	if (pMechanismList == NULL) {
		*pulCount = numberOfMechanisms;
		FUNC_RETURNS(CKR_OK);
	}

	if (*pulCount < numberOfMechanisms) {
		*pulCount = numberOfMechanisms;
		FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "Buffer provided by caller too small");
	}

	*pulCount = numberOfMechanisms;
	memcpy(pMechanismList, p11MechanismList, sizeof(p11MechanismList));

	FUNC_RETURNS(CKR_OK);
}



struct p11TokenDriver *getStarcosTokenDriver();

struct p11TokenDriver *getHBATokenDriver()
{
	static struct p11TokenDriver token;

	token = *getStarcosTokenDriver();

	token.name = "HBA";
	token.isCandidate = isCandidate;
	token.newToken = newHBAToken;
	token.C_SignInit = hba_C_SignInit;
	token.C_Sign = hba_C_Sign;
	token.C_DecryptInit = hba_C_DecryptInit;
	token.C_Decrypt = hba_C_Decrypt;
	token.C_GetMechanismList = hba_C_GetMechanismList;

	return &token;
}
