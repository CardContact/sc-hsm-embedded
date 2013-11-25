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
 * @file    token-starcos-dtrust.c
 * @author  Andreas Schwier
 * @brief   Token implementation for a Starcos 3.4 QES C1 based card with D-Trust Profile
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


static unsigned char atr34[] = { 0x3B,0xD8,0x18,0xFF,0x81,0xB1,0xFE,0x45,0x1F,0x03,0x80,0x64,0x04,0x1A,0xB4,0x03,0x81,0x05,0x61 };


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
		{ (unsigned char *)"\xC1\x03", 2 }			// efifOrPath
	},
	{
		1,
		P15_CT_X509,
		{ "C.CA.DS" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC1\x04", 2 }
	},
	{
		1,
		P15_CT_X509,
		{ "C.RCA.DS" },
		{ (unsigned char *)"\x12", 1 },
		{ (unsigned char *)"\xC1\x05", 2 }
	}
};



static struct p15PrivateKeyDescription prkd_eUserPKI[] = {
		{
			P15_KT_RSA,
			{ "C.CH.AUT" },
			1,
			{ (unsigned char *)"\x03", 1 },
			P15_SIGN|P15_DECIPHER,
			2048,
			0x81
		}
};



static struct p15CertificateDescription certd_eUserPKI[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.AUT" },                             // Label
		{ (unsigned char *)"\x03", 1 },				// Id
		{ (unsigned char *)"\xC1\x00", 2 }			// efifOrPath
	},
	{
		1,
		P15_CT_X509,
		{ "C.CA.AUT" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC1\x01", 2 }
	},
	{
		1,
		P15_CT_X509,
		{ "C.RCA.AUT" },
		{ (unsigned char *)"\x12", 1 },
		{ (unsigned char *)"\xC1\x02", 2 }
	}
};



static unsigned char aid_QES[] = { 0xD2,0x76,0x00,0x00,0x66,0x01 };
static unsigned char aid_eUserPKI[] = { 0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E };
static unsigned char aid_certs[] = { 0xA0,0x00,0x00,0x02,0x44,0x46,0x5F,0x43,0x65,0x72,0x74,0x73 };


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
				0x01,
				0,
				prkd_eUserPKI,
				sizeof(prkd_eUserPKI) / sizeof(struct p15PrivateKeyDescription),
				certd_eUserPKI,
				sizeof(certd_eUserPKI) / sizeof(struct p15CertificateDescription)
		},
		{		// Virtual application containing certificates
				"",
				{ aid_certs, sizeof(aid_certs) },
				3,
				0,
				0,
				0,
				0,
				0,
				0
		}
};



static unsigned char algo_PKCS15[] =           { 0x89, 0x02, 0x13, 0x23 };
static unsigned char algo_PSS_SHA256[] =       { 0x89, 0x03, 0x13, 0x33, 0x30 };
static unsigned char algo_SHA256[] =           { 0x89, 0x02, 0x14, 0x30 };
static unsigned char algo_PKCS15_DECRYPT[] =   { 0x89, 0x02, 0x11, 0x30 };


static const CK_MECHANISM_TYPE p11MechanismList[] = {
		CKM_RSA_PKCS,
		CKM_SHA256_RSA_PKCS_PSS
};



static int isCandidate(unsigned char *atr, size_t atrLen)
{
	if ((atrLen == sizeof(atr34)) && !memcmp(atr, atr34, atrLen))
		return 1;

	return 0;
}



static struct starcosPrivateData *getPrivateData(struct p11Token_t *token)
{
	return (struct starcosPrivateData *)(token + 1);
}



static struct p11Token_t *getBaseToken(struct p11Token_t *token)
{
	if (!token->slot->primarySlot)
		return token;
	return token->slot->primarySlot->token;
}



static void lock(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = getPrivateData(getBaseToken(token));
	p11LockMutex(sc->mutex);

#ifdef DEBUG
	debug("Lock released\n");
#endif
}



static void unlock(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = getPrivateData(getBaseToken(token));
	p11UnlockMutex(sc->mutex);
}



static int switchApplication(struct p11Token_t *token, struct starcosApplication *application)
{
	int rc, *sa;
	unsigned short SW1SW2;
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = getPrivateData(token);

	if (token->slot->primarySlot) {
		sa = &(getPrivateData(getBaseToken(token))->selectedApplication);
	} else {
		sa = &sc->selectedApplication;
	}

	if (application->aidId == *sa) {
		return 0;
	}

	rc = transmitAPDU(token->slot, 0x00, 0xA4, 0x04, 0x0C,
			application->aid.len, application->aid.val,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Selecting application failed");
	}

	*sa = application->aidId;

	FUNC_RETURNS(0);
}



static int selectApplication(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = getPrivateData(token);
	FUNC_RETURNS(switchApplication(token, sc->application));
}



static int readCertEF(struct p11Slot_t *slot, bytestring fid, unsigned char *content, size_t len)
{
	int rc, le, ne, ofs, maxapdu;
	unsigned short SW1SW2;
	unsigned char *po;

	FUNC_CALLED();

	// Select EF
	rc = transmitAPDU(slot, 0x00, 0xA4, 0x02, 0x0C,
			fid->len, fid->val,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "File not found");
	}

	// Read first 5 bytes to determine tag and length
	ofs = 0;
	rc = transmitAPDU(slot, 0x00, 0xB0, ofs >> 8, ofs & 0xFF,
			0, NULL,
			5, content + ofs, len - ofs, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Read EF failed");
	}

	ofs += rc;

	// Restrict the number of bytes in Le to either the maximum APDU size of STARCOS or
	// the maximum APDU size of the reader, if any.
	maxapdu = 584;
	if (slot->maxRAPDU && (slot->maxRAPDU < maxapdu))
		maxapdu = slot->maxRAPDU;
	maxapdu -= 2;		// Accommodate SW1/SW2

	le = 65536;			// Read all if no certificate found
	if (*content == 0x30) {
		po = content;
		asn1Tag(&po);
		rc = asn1Length(&po);
		rc += po - content;
		le = rc - ofs;
	}

	do	{
		ne = le;
		// Restrict Ne to the maximum APDU length allowed
		if (((le != 65536) || slot->noExtLengthReadAll) && (le > maxapdu))
			ne = maxapdu;

		rc = transmitAPDU(slot, 0x00, 0xB0, ofs >> 8, ofs & 0xFF,
				0, NULL,
				ne, content + ofs, len - ofs, &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(rc, "transmitAPDU failed");
		}

		if ((SW1SW2 != 0x9000) && (SW1SW2 != 0x6B00) && (SW1SW2 != 0x6282)) {
			FUNC_FAILS(-1, "Read EF failed");
		}
		ofs += rc;
		if (le != 65536)
			le -= rc;
	} while ((rc > 0) && (ofs < len) && (le > 0));

	FUNC_RETURNS(ofs);
}



static int determinePinUseCounter(struct p11Slot_t *slot, unsigned char recref, int *useCounter, int *lifeCycle)
{
	int rc;
	unsigned short SW1SW2;
	unsigned char rec[256], *p;
	FUNC_CALLED();

	// Select EF
	rc = transmitAPDU(slot, 0x00, 0xA4, 0x02, 0x0C,
			2, (unsigned char *)"\x00\x15",
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "File not found");
	}

	// Read record, but leave 3 bytes to add encapsulating 30 81 FF later
	rc = transmitAPDU(slot, 0x00, 0xB2, recref, 0x04,
			0, NULL,
			0, rec, sizeof(rec) - 3, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "File not found");
	}

	rc = asn1Encap(0x30, rec, rc);
	rc = asn1Validate(rec, rc);

	if (rc > 0) {
		FUNC_FAILS(rc, "ASN.1 structure invalid");
	}

	*useCounter = 0;
	p = asn1Find(rec, (unsigned char *)"\x30\x7B\x9F\x22", 3);

	if (p) {
		asn1Tag(&p);
		asn1Length(&p);

		*useCounter = (*p == 0xFF ? 0 : *p);
	}

	p = asn1Find(rec, (unsigned char *)"\x30\x8A", 2);

	if (p) {
		asn1Tag(&p);
		asn1Length(&p);

		*lifeCycle = *p;
	}

	FUNC_RETURNS(CKR_OK);
}



static int checkPINStatus(struct p11Slot_t *slot, unsigned char pinref)
{
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x00, 0x20, 0x00, pinref,
			0, NULL,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	FUNC_RETURNS(SW1SW2);
}



static int getSignatureSize(CK_MECHANISM_TYPE mech, struct p11Object_t *pObject)
{
	switch(mech) {
	case CKM_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS_PSS:
		return pObject->keysize >> 3;
	default:
		return -1;
	}
}



static int getAlgorithmIdForSigning(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char **algotlv)
{
	switch(mech) {
	case CKM_RSA_PKCS:
		*algotlv = algo_PKCS15;
		break;
	case CKM_SHA256_RSA_PKCS_PSS:
		*algotlv = algo_PSS_SHA256;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}



static int getAlgorithmIdForDigest(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char **algotlv)
{
	switch(mech) {
	case CKM_SHA256_RSA_PKCS_PSS:
		*algotlv = algo_SHA256;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}



static int getAlgorithmIdForDecryption(CK_MECHANISM_TYPE mech, unsigned char **algotlv)
{
	switch(mech) {
	case CKM_RSA_PKCS:
		*algotlv = algo_PKCS15_DECRYPT;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}



/**
 * Update internal PIN status based on SW1/SW2 received from token
 */
static int updatePinStatus(struct p11Token_t *token, int pinstatus)
{
	int rc = CKR_OK;

	token->info.flags &= ~(CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED | CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_TO_BE_CHANGED );

	if (pinstatus != 0x6984) {
		token->info.flags |= CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
	}

	switch(pinstatus) {
	case 0x9000:
		rc = CKR_OK;
		break;
	case 0x6985:
		token->info.flags |= CKF_USER_PIN_TO_BE_CHANGED;
		rc = CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case 0x6983:
	case 0x63C0:
		token->info.flags |= CKF_USER_PIN_LOCKED;
		rc = CKR_PIN_LOCKED;
		break;
	case 0x63C1:
		token->info.flags |= CKF_USER_PIN_FINAL_TRY|CKF_USER_PIN_COUNT_LOW;
		rc = CKR_PIN_INCORRECT;
		break;
	case 0x63C2:
		token->info.flags |= CKF_USER_PIN_COUNT_LOW;
		rc = CKR_PIN_INCORRECT;
		break;
	default:
		rc = CKR_PIN_INCORRECT;
		break;
	}
	return rc;
}



static int digest(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char *data, size_t len)
{
	int rc,chunk;
	unsigned short SW1SW2;
	unsigned char scr[1008],*algo, *po;

	FUNC_CALLED();

	rc = getAlgorithmIdForDigest(token, mech, &algo);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "getAlgorithmIdForDigest() failed");
	}

	po = algo;
	asn1Tag(&po);
	rc = asn1Length(&po);
	rc += po - algo;

	rc = transmitAPDU(token->slot, 0x00, 0x22, 0x41, 0xAA,
		rc, algo,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "MANAGE SE failed");
	}

	if (len <= 1000) {
		scr[0] = 0x90;
		scr[1] = 0x00;
		memcpy(scr + 2, data, len);
		rc = asn1Encap(0x80, scr + 2, len) + 2;

		rc = transmitAPDU(token->slot, 0x00, 0x2A, 0x90, 0xA0,
				rc, scr,
				0, NULL, 0, &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
		}

		if (SW1SW2 != 0x9000) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Hash operation failed");
		}
	} else {
		scr[0] = 0x90;
		scr[1] = 0x00;

		rc = transmitAPDU(token->slot, 0x10, 0x2A, 0x90, 0xA0,
				2, scr,
				0, NULL, 0, &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
		}

		if (SW1SW2 != 0x9000) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Hash operation failed");
		}

		while (len > 0) {
			chunk = (len > 576 ? 576 : len);

			memcpy(scr, data, chunk);
			rc = asn1Encap(0x80, scr, chunk);

			rc = transmitAPDU(token->slot, len > chunk ? 0x10 : 0x00, 0x2A, 0x90, 0xA0,
					rc, scr,
					0, NULL, 0, &SW1SW2);

			if (rc < 0) {
				FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
			}

			if (SW1SW2 != 0x9000) {
				FUNC_FAILS(CKR_DEVICE_ERROR, "Hash operation failed");
			}

			len -= chunk;
			data += chunk;
		}
	}

	return CKR_OK;
}



static int starcos_C_SignInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	unsigned char *algotlv;

	FUNC_CALLED();

	FUNC_RETURNS(getAlgorithmIdForSigning(pObject->token, mech->mechanism, &algotlv));
}



static int starcos_C_Sign(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
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
	lock(pObject->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = selectApplication(pObject->token);
	if (rc < 0) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "selecting application failed");
	}

	if (mech != CKM_RSA_PKCS) {
		rc = digest(pObject->token, mech, pData, ulDataLen);
		if (rc != CKR_OK) {
			unlock(pObject->token);
			FUNC_FAILS(rc, "digesting failed");
		}
		pData = NULL;
		ulDataLen = 0;
	}

	rc = getAlgorithmIdForSigning(pObject->token, mech, &s);
	if (rc != CKR_OK) {
		unlock(pObject->token);
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

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x22, 0x41, 0xB6,
		d - scr, scr,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "MANAGE SE failed");
	}

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x2A, 0x9E, 0x9A,
			ulDataLen, pData,
			0, pSignature, *pulSignatureLen, &SW1SW2);

	if (rc < 0) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 == 0x6982) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
	}

	if (SW1SW2 != 0x9000) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Signature operation failed");
	}


	// The D-Trust token has a use counter of 1. It requires a new login after each crypto operation.
	pObject->token->user = INT_CKU_NO_USER;

	*pulSignatureLen = rc;

	unlock(pObject->token);
	FUNC_RETURNS(CKR_OK);
}



static int starcos_C_DecryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	unsigned char *algotlv;

	FUNC_CALLED();

	FUNC_RETURNS(getAlgorithmIdForDecryption(mech->mechanism, &algotlv));
}



static int starcos_C_Decrypt(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	int rc, len;
	unsigned char *d,*s;
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
	lock(pObject->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = selectApplication(pObject->token);
	if (rc < 0) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "selecting application failed");
	}

	rc = getAlgorithmIdForDecryption(mech, &s);
	if (rc != CKR_OK) {
		unlock(pObject->token);
		FUNC_FAILS(rc, "getAlgorithmIdForDecryption() failed");
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

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x22, 0x41, 0xB8,
		d - scr, scr,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		unlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "MANAGE SE failed");
	}

	scr[0] = 0x81;
	memcpy(scr + 1, pEncryptedData, ulEncryptedDataLen);

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x2A, 0x80, 0x86,
			257, scr,
			0, scr, sizeof(scr), &SW1SW2);

	unlock(pObject->token);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Decryption operation failed");
	}

	// The D-Trust token has a use counter of 1. It requires a new login after each crypto operation.
	pObject->token->user = INT_CKU_NO_USER;

	*pulDataLen = rc;
	if (rc > *pulDataLen) {
		FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
	}

	memcpy(pData, scr, rc);

	FUNC_RETURNS(CKR_OK);
}



static int addCertificateObject(struct p11Token_t *token, struct p15CertificateDescription *p15)
{
	unsigned char certValue[MAX_CERTIFICATE_SIZE];
	struct p11Object_t *pObject;
	int rc;

	FUNC_CALLED();

	rc = readCertEF(token->slot, &p15->efidOrPath, certValue, sizeof(certValue));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate");
	}

	rc = createCertificateObjectFromP15(p15, certValue, rc, &pObject);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create P11 certificate object");
	}

	addObject(token, pObject, TRUE);

	FUNC_RETURNS(CKR_OK);
}



static int addPrivateKeyObject(struct p11Token_t *token, struct p15PrivateKeyDescription *p15)
{
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_ID, NULL, 0 }
	};
	struct p11Object_t *p11prikey, *p11pubkey, *p11cert;
	int rc,useAA;

	FUNC_CALLED();

	template[1].pValue = p15->id.val;
	template[1].ulValueLen = p15->id.len;

	rc = findMatchingTokenObject(token, template, 2, &p11cert);

	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "Could not find matching certificate");
	}

	useAA = (p15->usage & P15_NONREPUDIATION) && (token->pinUseCounter == 1);

	rc = createPrivateKeyObjectFromP15(p15, p11cert, useAA, &p11prikey);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create private key object");
	}

	p11prikey->C_SignInit = starcos_C_SignInit;
	p11prikey->C_Sign = starcos_C_Sign;
	p11prikey->C_DecryptInit = starcos_C_DecryptInit;
	p11prikey->C_Decrypt = starcos_C_Decrypt;

	p11prikey->tokenid = p15->keyReference;
	p11prikey->keysize = p15->keysize;
	addObject(token, p11prikey, useAA ? TRUE : FALSE);

	rc = createPublicKeyObjectFromCertificate(p15, p11cert, &p11pubkey);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create public key object");
	}

	addObject(token, p11pubkey, TRUE);

	FUNC_RETURNS(CKR_OK);
}



static int loadObjects(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;
	int rc,i;

	FUNC_CALLED();

	sc = getPrivateData(token);

	rc = switchApplication(token, &starcosApplications[2]);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "Could not switch to DF.Certs");
	}

	for (i = 0; i < sc->application->certsLen; i++) {
		struct p15CertificateDescription *p15 = &sc->application->certs[i];

		rc = addCertificateObject(token, p15);
		if (rc != CKR_OK) {
#ifdef DEBUG
			debug("addCertificateObject failed with rc=%d\n", rc);
#endif
		}
	}

	selectApplication(token);

	for (i = 0; i < sc->application->privateKeysLen; i++) {
		struct p15PrivateKeyDescription *p15 = &sc->application->privateKeys[i];

		rc = addPrivateKeyObject(token, p15);
		if (rc != CKR_OK) {
#ifdef DEBUG
			debug("addPrivateKeyObject failed with rc=%d\n", rc);
#endif
		}
	}

	FUNC_RETURNS(CKR_OK);
}



/**
 * Create a new STARCOS token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
static int createDTrustToken(struct p11Slot_t *slot, struct p11Token_t **token, struct p11TokenDriver *drv, struct starcosApplication *application)
{
	struct p11Token_t *ptoken;
	struct starcosPrivateData *sc;
	int rc, lc;

	FUNC_CALLED();

	ptoken = (struct p11Token_t *)calloc(sizeof(struct p11Token_t) + sizeof(struct starcosPrivateData), 1);

	if (ptoken == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	ptoken->slot = slot;
	ptoken->freeObjectNumber = 1;
	strbpcpy(ptoken->info.manufacturerID, "Giesecke & Devrient", sizeof(ptoken->info.manufacturerID));
	strbpcpy(ptoken->info.model, drv->name, sizeof(ptoken->info.model));
	ptoken->info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulMinPinLen = 6;
	ptoken->info.ulMaxPinLen = 16;
	ptoken->info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	ptoken->info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	ptoken->info.ulSessionCount = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.firmwareVersion.major = 3;
	ptoken->info.firmwareVersion.minor = 4;

	ptoken->info.flags = CKF_WRITE_PROTECTED;
	ptoken->user = INT_CKU_NO_USER;
	ptoken->drv = drv;

	sc = getPrivateData(ptoken);
	sc->selectedApplication = 0;
	sc->application = application;

	p11CreateMutex(&sc->mutex);

	strbpcpy(ptoken->info.label, sc->application->name, sizeof(ptoken->info.label));

	rc = selectApplication(ptoken);

	if (rc < 0) {
		drv->freeToken(ptoken);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Application not found on token");
	}

	if (sc->application->qESKeyDRec) {
		lc = 0;
		rc = determinePinUseCounter(slot, sc->application->qESKeyDRec, &ptoken->pinUseCounter, &lc);

		if (rc < 0) {
			drv->freeToken(ptoken);
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error querying PIN key use counter");
		}

		if (lc == 0x23) {
			ptoken->pinChangeRequired = TRUE;
		}
	}

	if (ptoken->pinUseCounter != 1)
		ptoken->info.flags |= CKF_LOGIN_REQUIRED;

	rc = loadObjects(ptoken);

	if (rc < 0) {
		drv->freeToken(ptoken);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error loading objects from token");
	}

	rc = checkPINStatus(slot, sc->application->pinref);

	if (rc < 0) {
		drv->freeToken(ptoken);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error querying PIN status");
	}

	updatePinStatus(ptoken, rc);

	*token = ptoken;

	FUNC_RETURNS(CKR_OK);
}



struct p11TokenDriver *getDTrustTokenDriver();

/**
 * Create a new STARCOS token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
static int newDTrustToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	struct p11Token_t *ptoken;
	struct p11TokenDriver *drv;
	struct p11Slot_t *vslot;
	int rc;

	FUNC_CALLED();

	drv = getDTrustTokenDriver();
	rc = createDTrustToken(slot, &ptoken, drv, &starcosApplications[0]);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Base token creation failed");

	if (slot->hasFeatureVerifyPINDirect)
		ptoken->info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;

	rc = addToken(slot, ptoken);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "addToken() failed");
	}

	*token = ptoken;

	rc = getVirtualSlot(slot, 0, &vslot);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Virtual slot creation failed");

	rc = createDTrustToken(vslot, &ptoken, drv, &starcosApplications[1]);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Token creation failed");

	if (vslot->hasFeatureVerifyPINDirect)
		ptoken->info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;

	rc = addToken(vslot, ptoken);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "addToken() failed");

	FUNC_RETURNS(CKR_OK);
}



static int getMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	int numberOfMechanisms;

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

	memcpy(pMechanismList, p11MechanismList, sizeof(p11MechanismList));

	FUNC_RETURNS(CKR_OK);
}



static int getMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	FUNC_CALLED();

	switch (type) {
	case CKM_RSA_PKCS:
		pInfo->flags = CKF_SIGN|CKF_DECRYPT;
		break;
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS_PSS:
		pInfo->flags = CKF_SIGN;
		break;

	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

	pInfo->ulMinKeySize = 2048;
	pInfo->ulMaxKeySize = 2048;
	FUNC_RETURNS(rv);
}



struct p11TokenDriver *getStarcosTokenDriver();

struct p11TokenDriver *getDTrustTokenDriver()
{
	static struct p11TokenDriver token;

	token = *getStarcosTokenDriver();

	token.name = "3.4 QES C1 DTR";
	token.isCandidate = isCandidate;
	token.newToken = newDTrustToken,
	token.getMechanismList = getMechanismList;
	token.getMechanismInfo = getMechanismInfo;

	return &token;
}
