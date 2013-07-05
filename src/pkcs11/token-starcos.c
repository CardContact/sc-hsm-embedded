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


struct p15PrivateKeyDescription prkd_eSign[] = {

};

struct p15CertificateDescription certd_eSign[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.DS" },                              // Label
		{ (unsigned char[]){ 0x01 }, 1 },           // Id
		{ (unsigned char[]){ 0xC0, 0x01}, 2 }       // efifOrPath
	},
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
		{ "C.CA.DS" },
		{ (unsigned char[]){ 0x11 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x11 }, 2 }
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
		{ "C.ATTRIBUTE.DS" },
		{ (unsigned char[]){ 0x21 }, 1 },
		{ (unsigned char[]){ 0xC0, 0x13 }, 2 }
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
	struct bytestring_s aid;
	struct p15PrivateKeyDescription *privateKeys;
	size_t privateKeysLen;
	struct p15CertificateDescription *certs;
	size_t certsLen;
};


static unsigned char aid_eSign[] = { 0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E };
static unsigned char aid_eUserPKI[] = { 0xA0,0x00,0x00,0x05,0x25,0x65,0x55,0x73,0x65,0x72,0x01 };

struct starcosApplication starcosApplications[] = {
		{
				{ aid_eSign, sizeof(aid_eSign) },
				prkd_eSign,
				sizeof(prkd_eSign) / sizeof(struct p15PrivateKeyDescription),
				certd_eSign,
				sizeof(certd_eSign) / sizeof(struct p15CertificateDescription)
		},
		{
				{ aid_eUserPKI, sizeof(aid_eUserPKI) },
				prkd_eUserPKI,
				sizeof(prkd_eUserPKI) / sizeof(struct p15PrivateKeyDescription),
				certd_eUserPKI,
				sizeof(certd_eUserPKI) / sizeof(struct p15CertificateDescription)
		}
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



static int starcosSelectApplication(struct p11Token_t *token)
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
	unsigned char *spk, *po;
	int rc;

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
	po += asn1Length(&po);

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
#if 0
		sc = getPrivateData(token);
		sc->publickeys[id] = spk;
#endif
	}

//	pObject->tokenid = (int)id;
//	pObject->keysize = p15->keysize;

	addObject(token, pObject, TRUE);
	FUNC_RETURNS(CKR_OK);
}



static int loadObjects(struct p11Token_t *token, int publicObjects)
{
	struct starcosPrivateData *sc;
	struct starcosApplication *appl;
	int rc,i;

	FUNC_CALLED();

	rc = starcosSelectApplication(token);
	if (rc < 0) {
		FUNC_FAILS(rc, "selecting application failed");
	}

	sc = getPrivateData(token);
	appl = &starcosApplications[sc->application];

	if (publicObjects) {
		for (i = 0; i < appl->certsLen; i++) {
			struct p15CertificateDescription *p15 = &appl->certs[i];

			rc = addCertificateObject(token, p15);
			if (rc != CKR_OK) {
#ifdef DEBUG
				debug("addCertificateObject failed with rc=%d\n", rc);
#endif
			}
		}
	} else {

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
static int newStarcosToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	struct p11Token_t *ptoken;
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	ptoken = (struct p11Token_t *)calloc(sizeof(struct p11Token_t) + sizeof(struct starcosPrivateData), 1);

	if (ptoken == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	ptoken->slot = slot;
	ptoken->freeObjectNumber = 1;
	strbpcpy(ptoken->info.label, "STARCOS", sizeof(ptoken->info.label));
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

	sc = getPrivateData(ptoken);
	sc->application = STARCOS_ESIGN;
	sc->selectedApplication = -1;

	loadObjects(ptoken, TRUE);

	*token = ptoken;
	return CKR_OK;
}



struct p11TokenDriver starcos_token = {
	"Starcos",
	isCandidate,
	newStarcosToken
};
