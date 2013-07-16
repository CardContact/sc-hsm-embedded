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
 * @file    token-starcos.c
 * @author  Andreas Schwier
 * @brief   Token implementation for a Starcos 3.5 ID ECC C1 based card
 */

#include <string.h>
#include "token-starcos.h"

#include "bytestring.h"

#include <pkcs11/slot.h>
#include <pkcs11/object.h>
#include <pkcs11/token.h>
#include <pkcs11/certificateobject.h>
#include <pkcs11/privatekeyobject.h>
#include <pkcs11/strbpcpy.h>
#include <pkcs11/asn1.h>
#include <pkcs11/pkcs15.h>
#include <pkcs11/debug.h>



static unsigned char atr35[] = { 0x3B,0x9B,0x96,0xC0,0x0A,0x31,0xFE,0x45,0x80,0x67,0x04,0x1E,0xB5,0x01,0x00,0x89,0x4C,0x81,0x05,0x45 };
static unsigned char atr352[] = { 0x3B,0xDB,0x96,0xFF,0x81,0x31,0xFE,0x45,0x80,0x67,0x05,0x34,0xB5,0x02,0x01,0xC0,0xA1,0x81,0x05,0x3C };


struct p15PrivateKeyDescription prkd_eSign1[] = {
		{
			P15_KT_RSA,
			{ "C.CH.DS" },
			1,
			{ (unsigned char[]){ 0x01 }, 1 },
			P15_SIGN|P15_NONREPUDIATION,
			2048,
			0x84
		}
};



struct p15PrivateKeyDescription prkd_eSign2[] = {
		{
			P15_KT_RSA,
			{ "C2.CH.DS" },
			1,
			{ (unsigned char[]){ 0x02 }, 1 },
			P15_SIGN|P15_NONREPUDIATION,
			2048,
			0x85
		}
};



struct p15CertificateDescription certd_eSign1[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.DS" },                              // Label
		{ (unsigned char[]){ 0x01 }, 1 },           // Id
		{ (unsigned char[]){ 0xC0, 0x01}, 2 }       // efifOrPath
	},
	{
		1,
		P15_CT_X509,
		{ "C.CA.DS" },
		{ (unsigned char[]){ 0x11 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x11 }, 2 }
	},
	{
		0,
		P15_CT_X509_ATTRIBUTE,
		{ "C.ATTRIBUTE.DS" },
		{ (unsigned char[]){ 0x21 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x13 }, 2 }
	},
};




struct p15CertificateDescription certd_eSign2[] = {
	{
		0,
		P15_CT_X509,
		{ "C2.CH.DS" },
		{ (unsigned char[]){ 0x02 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x02 }, 2 }
	},
	{
		1,
		P15_CT_X509,
		{ "C2.CA.DS" },
		{ (unsigned char[]){ 0x12 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x12 }, 2 }
	},
	{
		0,
		P15_CT_X509_ATTRIBUTE,
		{ "C2.ATTRIBUTE.DS" },
		{ (unsigned char[]){ 0x22 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x14 }, 2 }
	}
};




struct p15PrivateKeyDescription prkd_eUserPKI[] = {
		{
			P15_KT_RSA,
			{ "C.CH.AUT" },
			1,
			{ (unsigned char[]){ 0x01 }, 1 },
			P15_SIGN|P15_DECIPHER,
			2048,
			0x82
		}
};



struct p15CertificateDescription certd_eUserPKI[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.AUT" },                             // Label
		{ (unsigned char[]){ 0x01 }, 1 },           // Id
		{ (unsigned char[]){ 0xC0, 0x03 }, 2 }      // efifOrPath
	},
	{
		0,
		P15_CT_X509,
		{ "C.CA.AUT" },
		{ (unsigned char[]){ 0x11 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x01 }, 2 }
	}
};



struct starcosApplication {
	char *name;
	struct bytestring_s aid;
	unsigned char pinref;
	int isQES;
	struct p15PrivateKeyDescription *privateKeys;
	size_t privateKeysLen;
	struct p15CertificateDescription *certs;
	size_t certsLen;
};


static unsigned char aid_eSign[] = { 0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E };
static unsigned char aid_eUserPKI[] = { 0xA0,0x00,0x00,0x05,0x25,0x65,0x55,0x73,0x65,0x72,0x01 };

struct starcosApplication starcosApplications[] = {
		{
				"STARCOS.eSign1",
				{ aid_eSign, sizeof(aid_eSign) },
				0x81,
				1,
				prkd_eSign1,
				sizeof(prkd_eSign1) / sizeof(struct p15PrivateKeyDescription),
				certd_eSign1,
				sizeof(certd_eSign1) / sizeof(struct p15CertificateDescription)
		},
		{
				"STARCOS.eSign2",
				{ aid_eSign, sizeof(aid_eSign) },
				0x86,
				1,
				prkd_eSign2,
				sizeof(prkd_eSign2) / sizeof(struct p15PrivateKeyDescription),
				certd_eSign2,
				sizeof(certd_eSign2) / sizeof(struct p15CertificateDescription)
		},
		{
				"STARCOS.eUserPKI",
				{ aid_eUserPKI, sizeof(aid_eUserPKI) },
				0x06,
				0,
				prkd_eUserPKI,
				sizeof(prkd_eUserPKI) / sizeof(struct p15PrivateKeyDescription),
				certd_eUserPKI,
				sizeof(certd_eUserPKI) / sizeof(struct p15CertificateDescription)
		}
};



unsigned char algo_PKCS15[] =           { 0x89, 0x02, 0x13, 0x23 };
unsigned char algo_PSS_SHA1[] =         { 0x89, 0x03, 0x13, 0x33, 0x10 };
unsigned char algo_PSS_SHA224[] =       { 0x89, 0x03, 0x13, 0x33, 0x60 };
unsigned char algo_PSS_SHA256[] =       { 0x89, 0x03, 0x13, 0x33, 0x30 };
unsigned char algo_PSS_SHA384[] =       { 0x89, 0x03, 0x13, 0x33, 0x40 };
unsigned char algo_PSS_SHA512[] =       { 0x89, 0x03, 0x13, 0x33, 0x50 };
unsigned char algo_SHA1[] =             { 0x89, 0x02, 0x14, 0x10 };
unsigned char algo_SHA224[] =           { 0x89, 0x02, 0x14, 0x60 };
unsigned char algo_SHA256[] =           { 0x89, 0x02, 0x14, 0x30 };
unsigned char algo_SHA384[] =           { 0x89, 0x02, 0x14, 0x40 };
unsigned char algo_SHA512[] =           { 0x89, 0x02, 0x14, 0x50 };


static const CK_MECHANISM_TYPE p11MechanismList[] = {
		CKM_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA224_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS,
		CKM_SHA512_RSA_PKCS,
		CKM_SHA1_RSA_PKCS_PSS,
		CKM_SHA224_RSA_PKCS_PSS,
		CKM_SHA256_RSA_PKCS_PSS,
		CKM_SHA384_RSA_PKCS_PSS,
		CKM_SHA512_RSA_PKCS_PSS
};



static int isCandidate(unsigned char *atr, size_t atrLen)
{
	if ((atrLen == sizeof(atr352)) && !memcmp(atr, atr352, atrLen))
		return 1;

	if ((atrLen == sizeof(atr35)) && !memcmp(atr, atr35, atrLen))
		return 1;

	return 0;
}



static struct starcosPrivateData *getPrivateData(struct p11Token_t *token)
{
	return (struct starcosPrivateData *)(token + 1);
}



static int selectApplication(struct p11Token_t *token)
{
	int rc, *sa;
	unsigned short SW1SW2;
	struct starcosPrivateData *sc;
	struct starcosApplication *appl;

	FUNC_CALLED();

	sc = getPrivateData(token);

	appl = &starcosApplications[sc->application];

	if (sc->primaryToken) {
		sa = &(getPrivateData(sc->primaryToken)->selectedApplication);
	} else {
		sa = &sc->selectedApplication;
	}

	if (sc->application == *sa) {
		return CKR_OK;
	}

	rc = transmitAPDU(token->slot, 0x00, 0xA4, 0x04, 0x0C,
			appl->aid.len, appl->aid.val,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Selecting application failed");
	}

	*sa = sc->application;

	FUNC_RETURNS(CKR_OK);
}



static int readEF(struct p11Slot_t *slot, bytestring fid, unsigned char *content, size_t len)
{
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x00, 0xA4, 0x02, 0x0C,
			fid->len, fid->val,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "File not found");
	}

	rc = transmitAPDU(slot, 0x00, 0xB0, 0, 0,
			0, NULL,
			65536, content, len, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Read EF failed");
	}

	FUNC_RETURNS(rc);
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



static int getAlgorithmIdForDigest(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char **algotlv)
{
	switch(mech) {
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS_PSS:
		*algotlv = algo_SHA1;
		break;
	case CKM_SHA224_RSA_PKCS:
	case CKM_SHA224_RSA_PKCS_PSS:
		*algotlv = algo_SHA224;
		break;
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS_PSS:
		*algotlv = algo_SHA256;
		break;
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS_PSS:
		*algotlv = algo_SHA384;
		break;
	case CKM_SHA512_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS_PSS:
		*algotlv = algo_SHA512;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}



static int getAlgorithmIdForDecryption(CK_MECHANISM_TYPE mech)
{
	switch(mech) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
//		return ALGO_RSA_DECRYPT;
	default:
		return -1;
	}
}



/**
 * Update internal PIN status based on SW1/SW2 received from token
 */
static int updatePinStatus(struct p11Token_t *token, int pinstatus)
{
	int rc = CKR_OK;

	token->info.flags &= ~(CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED | CKF_USER_PIN_COUNT_LOW);

	if (pinstatus != 0x6984) {
		token->info.flags |= CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
	}

	switch(pinstatus) {
	case 0x9000:
		rc = CKR_OK;
		break;
	case 0x6984:
		rc = CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case 0x6983:
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
	int rc;
	unsigned short SW1SW2;
	unsigned char scr[4106],*algo, *po;

	FUNC_CALLED();

	if (len > 4096) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Data to be hashed must not exceed 4K");
	}

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
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "MANAGE SE failed");
	}

	scr[0] = 0x90;
	scr[1] = 0x00;
	memcpy(scr + 2, data, len);
	rc = asn1Encap(0x80, scr + 2, len) + 2;

	rc = transmitAPDU(token->slot, 0x00, 0x2A, 0x90, 0xA0,
		rc, scr,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Signature operation failed");
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
	int rc, len;
	unsigned short SW1SW2;
	unsigned char scr[256],*s, *d;
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	if (pSignature == NULL) {
		rc = getSignatureSize(mech, pObject);
		if (rc < 0) {
			FUNC_FAILS(CKR_MECHANISM_INVALID, "Unknown mechanism");
		}
		*pulSignatureLen = rc;
		FUNC_RETURNS(CKR_OK);
	}

	rc = selectApplication(pObject->token);
	if (rc < 0) {
		FUNC_FAILS(rc, "selecting application failed");
	}

	if (mech != CKM_RSA_PKCS) {
		rc = digest(pObject->token, mech, pData, ulDataLen);
		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "digesting failed");
		}
		pData = NULL;
		ulDataLen = 0;
	}

	rc = getAlgorithmIdForSigning(pObject->token, mech, &s);
	if (rc != CKR_OK) {
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
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "MANAGE SE failed");
	}

	rc = transmitAPDU(pObject->token->slot, 0x00, 0x2A, 0x9E, 0x9A,
			ulDataLen, pData,
			0, pSignature, *pulSignatureLen, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 == 0x6982) {
		logOut(pObject->token->slot);
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Signature operation failed");
	}

	*pulSignatureLen = rc;

	// For QES the signature PIN verification status is cleared after the signature operation
	// if the use counter is set to 1. However the use counter can also be limited to 100
	// or be unlimited, depending on the card profile. If the PIN remains verified after the
	// first signature, then the check is disabled to save a VERIFY APDU for performance reasons
	if (pObject->token->checkPINAfterSigning) {
		sc = getPrivateData(pObject->token);
		rc = checkPINStatus(pObject->token->slot, starcosApplications[sc->application].pinref);
		if (rc != 0x9000) {
			logOut(pObject->token->slot);
		} else {
			pObject->token->checkPINAfterSigning = 0;
		}
	}

	FUNC_RETURNS(CKR_OK);
}



static int starcos_C_DecryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	int algo;

	FUNC_CALLED();

	algo = getAlgorithmIdForDecryption(mech->mechanism);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	FUNC_RETURNS(CKR_OK);
}



static int stripPKCS15Padding(unsigned char *scr, int len, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	int c1,c2,c3;

	c1 = *scr++ == 0x00;
	c2 = *scr++ == 0x02;
	len -= 2;
	while ((len > 0) && *scr) {
		scr++;
		len--;
	}
	c3 = len > 0;

	if (!(c1 && c2 && c3)) {
		return CKR_ENCRYPTED_DATA_INVALID;
	}

	scr++;
	len--;

	if (len > *pulDataLen) {
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(pData, scr, len);
	*pulDataLen = len;

	return CKR_OK;
}



static int starcos_C_Decrypt(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	int rc, algo;
	unsigned short SW1SW2;
	unsigned char scr[256];

	FUNC_CALLED();

	if (pData == NULL) {
		*pulDataLen = pObject->keysize >> 3;
		FUNC_RETURNS(CKR_OK);
	}

	algo = getAlgorithmIdForDecryption(mech);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	rc = transmitAPDU(pObject->token->slot, 0x80, 0x62, (unsigned char)pObject->tokenid, (unsigned char)algo,
			ulEncryptedDataLen, pEncryptedData,
			0, scr, sizeof(scr), &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Decryption operation failed");
	}

	if (mech == CKM_RSA_X_509) {
		if (rc > *pulDataLen) {
			FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
		}
		*pulDataLen = rc;
		memcpy(pData, scr, rc);
	} else {
		rc = stripPKCS15Padding(scr, rc, pData, pulDataLen);
		if (rc < 0) {
			FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Invalid PKCS#1 padding");
		}
	}

	FUNC_RETURNS(CKR_OK);
}



static int addCertificateObject(struct p11Token_t *token, struct p15CertificateDescription *p15)
{
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_UTF8CHAR label[10];
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_BYTE certValue[MAX_CERTIFICATE_SIZE];
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
			{ CKA_TOKEN, &true, sizeof(true) },
			{ CKA_PRIVATE, &false, sizeof(false) },
			{ CKA_LABEL, label, sizeof(label) - 1 },
			{ CKA_ID, NULL, 0 },
			{ CKA_VALUE, certValue, sizeof(certValue) }
	};
	struct p11Object_t *pObject;
	struct starcosPrivateData *sc;
	unsigned char *spk, *po;
	int rc, len;

	FUNC_CALLED();

	rc = readEF(token->slot, &p15->efidOrPath, certValue, sizeof(certValue));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate");
	}

	if (certValue[0] != ASN1_SEQUENCE) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error not a certificate");
	}

	po = certValue;
	asn1Tag(&po);
	len = asn1Length(&po);
	po += len;

	if ((po - certValue) > rc) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Certificate corrupted");
	}

	template[6].ulValueLen = po - certValue;

	certType = (p15->certtype == P15_CT_X509) ? CKC_X_509 : CKC_X_509_ATTR_CERT;

	template[4].pValue = p15->coa.label;
	template[4].ulValueLen = strlen(template[4].pValue);

	if (p15->id.len) {
		template[5].pValue = p15->id.val;
		template[5].ulValueLen = p15->id.len;
	}

	pObject = calloc(sizeof(struct p11Object_t), 1);

	if (pObject == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	rc = createCertificateObject(template, 7, pObject);

	if (rc != CKR_OK) {
		free(pObject);
		FUNC_FAILS(rc, "Could not create certificate key object");
	}

	rc = populateIssuerSubjectSerial(pObject);

	if (rc != CKR_OK) {
#ifdef DEBUG
		debug("populateIssuerSubjectSerial() failed\n");
#endif
	}

	if (getSubjectPublicKeyInfo(pObject, &spk) == CKR_OK) {
		sc = getPrivateData(token);
		sc->publickeys[p15->id.val[p15->id.len - 1]] = spk;
	}

	addObject(token, pObject, TRUE);
	FUNC_RETURNS(CKR_OK);
}



static int addPrivateKeyObject(struct p11Token_t *token, struct p15PrivateKeyDescription *p15)
{
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_UTF8CHAR label[10];
	CK_MECHANISM_TYPE genMechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_TOKEN, &true, sizeof(true) },
			{ CKA_PRIVATE, &true, sizeof(true) },
			{ CKA_LABEL, label, sizeof(label) - 1 },
			{ CKA_ID, NULL, 0 },
			{ CKA_LOCAL, &true, sizeof(true) },
			{ CKA_KEY_GEN_MECHANISM, &genMechType, sizeof(genMechType) },
			{ CKA_SENSITIVE, &true, sizeof(true) },
			{ CKA_DECRYPT, &true, sizeof(true) },
			{ CKA_SIGN, &true, sizeof(true) },
			{ CKA_SIGN_RECOVER, &true, sizeof(true) },
			{ CKA_UNWRAP, &false, sizeof(false) },
			{ CKA_EXTRACTABLE, &false, sizeof(false) },
			{ CKA_ALWAYS_SENSITIVE, &true, sizeof(true) },
			{ CKA_NEVER_EXTRACTABLE, &true, sizeof(true) },
			{ 0, NULL, 0 },
			{ 0, NULL, 0 }
	};
	struct starcosPrivateData *sc;
	struct p11Object_t *pObject;
	int rc,attributes,id;

	FUNC_CALLED();

	pObject = calloc(sizeof(struct p11Object_t), 1);

	if (pObject == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	template[4].pValue = p15->coa.label;
	template[4].ulValueLen = strlen(template[4].pValue);

	id = 0;
	if (p15->id.val) {
		template[5].pValue = p15->id.val;
		template[5].ulValueLen = p15->id.len;
		id = p15->id.val[p15->id.len - 1];
	}

	template[9].pValue = p15->usage & P15_DECIPHER ? &true : &false;
	template[10].pValue = p15->usage & P15_SIGN ? &true : &false;
	template[11].pValue = p15->usage & P15_SIGNRECOVER ? &true : &false;

	attributes = sizeof(template) / sizeof(CK_ATTRIBUTE) - 2;

	switch(p15->keytype) {
	case P15_KEYTYPE_RSA:
		keyType = CKK_RSA;
		sc = getPrivateData(token);
		if (sc->publickeys[id]) {
			decodeModulusExponentFromSPKI(sc->publickeys[id], &template[attributes], &template[attributes + 1]);
			attributes += 2;
		}
		break;
	case P15_KEYTYPE_ECC:
		keyType = CKK_ECDSA;
		sc = getPrivateData(token);
		if (sc->publickeys[id]) {
			decodeECParamsFromSPKI(sc->publickeys[id], &template[attributes]);
			attributes += 1;
		}
		break;
	default:
		free(pObject);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Unknown key type in PRKD");
	}

	rc = createPrivateKeyObject(template, attributes, pObject);

	if (rc != CKR_OK) {
//		freePrivateKeyDescription(&p15);
		free(pObject);
		FUNC_FAILS(rc, "Could not create private key object");
	}

	pObject->C_SignInit = starcos_C_SignInit;
	pObject->C_Sign = starcos_C_Sign;
	pObject->C_DecryptInit = starcos_C_DecryptInit;
	pObject->C_Decrypt = starcos_C_Decrypt;

	pObject->tokenid = p15->keyReference;
	pObject->keysize = p15->keysize;
	addObject(token, pObject, FALSE);

	FUNC_RETURNS(CKR_OK);
}



static int loadPublicObjects(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;
	struct starcosApplication *appl;
	int rc,i;

	FUNC_CALLED();

	rc = selectApplication(token);
	if (rc < 0) {
		FUNC_FAILS(rc, "selecting application failed");
	}

	sc = getPrivateData(token);
	appl = &starcosApplications[sc->application];

	for (i = 0; i < appl->certsLen; i++) {
		struct p15CertificateDescription *p15 = &appl->certs[i];

		rc = addCertificateObject(token, p15);
		if (rc != CKR_OK) {
#ifdef DEBUG
			debug("addCertificateObject failed with rc=%d\n", rc);
#endif
		}
	}

	FUNC_RETURNS(CKR_OK);
}



static int loadPrivateObjects(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;
	struct starcosApplication *appl;
	int rc,i;

	FUNC_CALLED();

	rc = selectApplication(token);
	if (rc < 0) {
		FUNC_FAILS(rc, "selecting application failed");
	}

	sc = getPrivateData(token);
	appl = &starcosApplications[sc->application];

	for (i = 0; i < appl->privateKeysLen; i++) {
		struct p15PrivateKeyDescription *p15 = &appl->privateKeys[i];

		rc = addPrivateKeyObject(token, p15);
		if (rc != CKR_OK) {
#ifdef DEBUG
			debug("addPrivateKeyObject failed with rc=%d\n", rc);
#endif
		}
	}

	FUNC_RETURNS(CKR_OK);
}



static int encodeF2B(unsigned char *pin, int pinlen, unsigned char *f2b)
{
	unsigned char *po;
	int i;

	FUNC_CALLED();

	if ((pinlen <= 4) || (pinlen > 14)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "PIN length must be between 4 and 14");
	}

	memset(f2b, 0xFF, 8);
	f2b[0] = 0x20 | pinlen;

	po = f2b + 1;
	for (i = 0; i < pinlen; i++) {
		if ((*pin < 0x30) || (*pin > 0x39)) {
			FUNC_FAILS(CKR_ARGUMENTS_BAD, "PIN must be numeric");
		}
		if (i & 1) {
			*po = (*po & 0xF0) | (*pin & 0x0F);
			po++;
		} else {
			*po = (*po & 0x0F) | ((*pin & 0x0F) << 4);
		}
		pin++;
	}
	return CKR_OK;
}



/**
 * Perform PIN verification and make private objects visible
 *
 * @param slot      The slot in which the token is inserted
 * @param userType  One of CKU_SO or CKU_USER
 * @param pin       Pointer to PIN value or NULL is PIN shall be verified using PIN-Pad
 * @param pinLen    The length of the PIN supplied in pin
 * @return          CKR_OK or any other Cryptoki error code
 */
static int login(struct p11Slot_t *slot, int userType, unsigned char *pin, int pinlen)
{
	int rc = CKR_OK;
	unsigned short SW1SW2;
	unsigned char f2b[8];
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = getPrivateData(slot->token);

	if (userType == CKU_SO) {
		if (pinlen != 16) {
			FUNC_FAILS(CKR_ARGUMENTS_BAD, "SO-PIN must be 16 characters long");
		}
		// Store SO PIN
	} else {

		if (slot->hasFeatureVerifyPINDirect && !pinlen && !pin) {
#ifdef DEBUG
			debug("Verify PIN using CKF_PROTECTED_AUTHENTICATION_PATH\n");
#endif
			memset(f2b, 0xFF, 8);
			f2b[0] = 0x20;

			rc = transmitVerifyPinAPDU(slot, 0x00, 0x20, 0x00, starcosApplications[sc->application].pinref,
					8, f2b,
					&SW1SW2,
					PIN_SYSTEM_UNIT_BYTES + PIN_POSITION_1 + PIN_LEFT_JUSTIFICATION + PIN_FORMAT_BCD, /* bmFormatString */
					0x06, 0x0F, /* Minimum and maximum length of PIN */
					0x47, /* bmPINBlockString: inserted PIN length is 4 bits, 7 bytes PIN block*/
					0x04 /* bmPINLengthFormat: system units are bits, PIN length position is 4 bits*/
					);
		} else {
#ifdef DEBUG
			debug("Verify PIN using provided PIN value\n");
#endif
			rc = encodeF2B(pin, pinlen, f2b);

			if (rc != CKR_OK) {
				FUNC_FAILS(rc, "Could not encode PIN");
			}

			rc = transmitAPDU(slot, 0x00, 0x20, 0x00, starcosApplications[sc->application].pinref,
					8, f2b,
					0, NULL, 0, &SW1SW2);
		}


		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
		}

		rc = updatePinStatus(slot->token, SW1SW2);

		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "login failed");
		}

		rc = loadPrivateObjects(slot->token);
	}

	FUNC_RETURNS(rc);
}



/**
 * Reselect applet in order to reset authentication state
 *
 * @param slot      The slot in which the token is inserted
 * @return          CKR_OK or any other Cryptoki error code
 */
static int logout(struct p11Slot_t *slot)
{
	FUNC_CALLED();
#if 0
	rc = selectApplet(slot);
	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "applet selection failed");
	}

	rc = checkPINStatus(slot);
	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "checkPINStatus failed");
	}

	updatePinStatus(slot->token, rc);
#endif
	FUNC_RETURNS(CKR_OK);
}



struct p11TokenDriver starcos_token;

/**
 * Create a new STARCOS token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
static int newStarcosToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	struct p11Token_t *ptoken;
	struct starcosPrivateData *sc;
	int rc;

	FUNC_CALLED();

	ptoken = (struct p11Token_t *)calloc(sizeof(struct p11Token_t) + sizeof(struct starcosPrivateData), 1);

	if (ptoken == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	ptoken->slot = slot;
	ptoken->freeObjectNumber = 1;
	strbpcpy(ptoken->info.manufacturerID, "Giesecke & Devrient", sizeof(ptoken->info.manufacturerID));
	strbpcpy(ptoken->info.model, "3.5 ID ECC C1", sizeof(ptoken->info.model));
	ptoken->info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulMinPinLen = 6;
	ptoken->info.ulMaxPinLen = 16;
	ptoken->info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	ptoken->info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	ptoken->info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	ptoken->info.ulSessionCount = CK_UNAVAILABLE_INFORMATION;

	ptoken->info.flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED;
	ptoken->user = 0xFF;
	ptoken->drv = &starcos_token;

	sc = getPrivateData(ptoken);
	sc->application = STARCOS_DEFAULT;
	sc->selectedApplication = -1;

	strbpcpy(ptoken->info.label, starcosApplications[sc->application].name, sizeof(ptoken->info.label));

	// For QES application check PIN status after C_Sign
	ptoken->checkPINAfterSigning = starcosApplications[sc->application].isQES;

	loadPublicObjects(ptoken);

	rc = checkPINStatus(slot, starcosApplications[sc->application].pinref);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error querying PIN status");
	}

	updatePinStatus(ptoken, rc);

	*token = ptoken;
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
		pInfo->flags = CKF_SIGN;
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
		break;

	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

	FUNC_RETURNS(rv);
}



struct p11TokenDriver starcos_token = {
	"Starcos",
	isCandidate,
	newStarcosToken,
	getMechanismList,
	getMechanismInfo,
	login,
	logout
};
