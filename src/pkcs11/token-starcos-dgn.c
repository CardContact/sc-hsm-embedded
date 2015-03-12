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
 * @file    token-starcos-dgn.c
 * @author  Andreas Schwier
 * @brief   Token implementation for a Starcos 3.5 ID ECC C1 based card with DGN profile
 */

#include <string.h>
#include "token-starcos.h"

#include "bytestring.h"

#include <pkcs11/slot.h>
#include <pkcs11/object.h>
#include <pkcs11/token.h>
#include <pkcs11/certificateobject.h>
#include <pkcs11/privatekeyobject.h>
#include <pkcs11/publickeyobject.h>
#include <pkcs11/strbpcpy.h>
#include <pkcs11/asn1.h>
#include <pkcs11/pkcs15.h>
#include <pkcs11/debug.h>



static unsigned char atr35[] = { 0x3B,0xD9,0x96,0xFF,0x81,0x31,0xFE,0x45,0x80,0x31,0xB8,0x73,0x86,0x01,0xE0,0x81,0x05,0x22 };



static struct p15PrivateKeyDescription prkd_eSign[] = {
		{
			P15_KT_RSA,
			{ "C.CH.DS" },
			1,
			{ (unsigned char *)"\x01", 1 },
			P15_SIGN|P15_NONREPUDIATION,
			2048,
			0x84
		}
};



static struct p15CertificateDescription certd_eSign[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.DS" },                              // Label
		{ (unsigned char *)"\x01", 1 },				// Id
		{ (unsigned char *)"\xC0\x00", 2 }			// efifOrPath
	}
};




static struct p15PrivateKeyDescription prkd_eUserPKI[] = {
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



static struct p15CertificateDescription certd_eUserPKI[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.AUT" },                             // Label
		{ (unsigned char *)"\x03", 1 },				// Id
		{ (unsigned char *)"\xC5\x00", 2 }			// efifOrPath
	},
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.ENC" },                             // Label
		{ (unsigned char *)"\x04", 1 },				// Id
		{ (unsigned char *)"\xC2\x00", 2 }			// efifOrPath
	}
};



static unsigned char aid_eUserPKI[] = { 0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E };
static unsigned char aid_QES[] = { 0xD2,0x76,0x00,0x00,0x66,0x01 };


static struct starcosApplication starcosApplications[] = {
		{
				"STARCOS.QES",
				{ aid_QES, sizeof(aid_QES) },
				1,
				0x81,
				1,
				prkd_eSign,
				sizeof(prkd_eSign) / sizeof(struct p15PrivateKeyDescription),
				certd_eSign,
				sizeof(certd_eSign) / sizeof(struct p15CertificateDescription)
		},
		{
				"STARCOS.eUserPKI",
				{ aid_eUserPKI, sizeof(aid_eUserPKI) },
				2,
				0x06,
				0,
				prkd_eUserPKI,
				sizeof(prkd_eUserPKI) / sizeof(struct p15PrivateKeyDescription),
				certd_eUserPKI,
				sizeof(certd_eUserPKI) / sizeof(struct p15CertificateDescription)
		}
};


static unsigned char algo_PKCS15[] =           { 0x89, 0x02, 0x23, 0x13 };
static unsigned char algo_PSS_SHA1[] =         { 0x89, 0x03, 0x23, 0x53, 0x10 };
static unsigned char algo_PSS_SHA224[] =       { 0x89, 0x03, 0x23, 0x53, 0x60 };
static unsigned char algo_PSS_SHA256[] =       { 0x89, 0x03, 0x23, 0x53, 0x30 };
static unsigned char algo_PSS_SHA384[] =       { 0x89, 0x03, 0x23, 0x53, 0x40 };
static unsigned char algo_PSS_SHA512[] =       { 0x89, 0x03, 0x23, 0x53, 0x50 };


extern struct p11Context_t *context;


static int getSignatureSize(CK_MECHANISM_TYPE mech, struct p11Object_t *pObject)
{
	switch(mech) {
	case CKM_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
		return pObject->keysize >> 3;
	default:
		return -1;
	}
}



static int getAlgorithmIdForSigning(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char **algotlv)
{
	switch(mech) {
	case CKM_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
		*algotlv = algo_PKCS15;
		break;
	case CKM_SHA1_RSA_PKCS_PSS:
		*algotlv = algo_PSS_SHA1;
		break;
	case CKM_SHA224_RSA_PKCS_PSS:
		*algotlv = algo_PSS_SHA224;
		break;
	case CKM_SHA256_RSA_PKCS_PSS:
		*algotlv = algo_PSS_SHA256;
		break;
	case CKM_SHA384_RSA_PKCS_PSS:
		*algotlv = algo_PSS_SHA384;
		break;
	case CKM_SHA512_RSA_PKCS_PSS:
		*algotlv = algo_PSS_SHA512;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}



static int esign_C_Sign(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	int rc, len, signaturelen;
	unsigned short SW1SW2;
	unsigned char scr[256],*s, *d;
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

	if (*pulSignatureLen < signaturelen) {
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

	rc = getAlgorithmIdForSigning(pObject->token, mech, &s);
	if (rc != CKR_OK) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(rc, "getAlgorithmIdForSigning() failed");
	}

	d = scr;
	*d++ = *s++;
	len = *s;
	*d++ = *s++;
	while (len--) {
		*d++ = *s++;
	}
	*d++ = 0x84;
	*d++ = 0x01;
	*d++ = (unsigned char)pObject->tokenid;

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x22, 0x41, 0xA4,
		d - scr, scr,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "MANAGE SE failed");
	}

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x88, 0x00, 0x00,
			ulDataLen, pData,
			0, pSignature, *pulSignatureLen, &SW1SW2);

	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 == 0x6982) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
	}

	if (SW1SW2 != 0x9000) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Signature operation failed");
	}

	*pulSignatureLen = rc;

	if ((pObject->token->user == CKU_USER) && (pObject->token->pinUseCounter == 1)) {
		pObject->token->user = INT_CKU_NO_USER;
	}

	starcosUnlock(pObject->token);
	FUNC_RETURNS(CKR_OK);
}



static int isCandidate(unsigned char *atr, size_t atrLen)
{
	if ((atrLen == sizeof(atr35)) && !memcmp(atr, atr35, atrLen))
		return 1;

	return 0;
}



struct p11TokenDriver *getDGNTokenDriver();
struct p11TokenDriver *getStarcosTokenDriver();


/**
 * Create a new DGN token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
static int newDGNToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	static struct p11TokenDriver esign_token;
	struct p11Token_t *ptoken;
	struct p11TokenDriver *drv;
	struct p11Slot_t *vslot;
	int rc;

	FUNC_CALLED();

	esign_token = *getStarcosTokenDriver();
	esign_token.name = "3.5ID ECC C1 DGN";
	esign_token.isCandidate = isCandidate;
	esign_token.newToken = newDGNToken;
	esign_token.C_Sign = esign_C_Sign;

	rc = createStarcosToken(slot, &ptoken, &esign_token, &starcosApplications[1]);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Base token creation failed");

	rc = addToken(slot, ptoken);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "addToken() failed");
	}

	*token = ptoken;

	if (context->caller == CALLER_FIREFOX) {
		FUNC_RETURNS(CKR_OK);
	}

	rc = getVirtualSlot(slot, 0, &vslot);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Virtual slot creation failed");

	drv = getDGNTokenDriver();
	rc = createStarcosToken(vslot, &ptoken, drv, &starcosApplications[0]);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Token creation failed");

	rc = addToken(vslot, ptoken);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "addToken() failed");

	FUNC_RETURNS(CKR_OK);
}



struct p11TokenDriver *getDGNTokenDriver()
{
	static struct p11TokenDriver starcos_token;

	starcos_token = *getStarcosTokenDriver();

	starcos_token.name = "3.5ID ECC C1 DGN";
	starcos_token.isCandidate = isCandidate;
	starcos_token.newToken = newDGNToken;

	return &starcos_token;
}
