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
		0,                                          // isModifiable
		P15_CT_X509,                                // Certificate type
		{ "C.CH.DS" },                              // Label
		{ (unsigned char *)"\x01", 1 },				// Id
		{ (unsigned char *)"\xC1\x03", 2 }			// efifOrPath
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C.CA.DS" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC1\x04", 2 }
	},
	{
		1,
		0,
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
		0,                                          // isModifiable
		P15_CT_X509,                                // Certificate type
		{ "C.CH.AUT" },                             // Label
		{ (unsigned char *)"\x03", 1 },				// Id
		{ (unsigned char *)"\xC1\x00", 2 }			// efifOrPath
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C.CA.AUT" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC1\x01", 2 }
	},
	{
		1,
		0,
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



static int loadObjects(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;
	int rc,i;

	FUNC_CALLED();

	sc = starcosGetPrivateData(token);

	// The D-Trust card stores certificates in a separate DF
	rc = starcosSwitchApplication(token, &starcosApplications[2]);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "Could not switch to DF.Certs");
	}

	for (i = 0; i < (int)sc->application->certsLen; i++) {
		struct p15CertificateDescription *p15 = &sc->application->certs[i];

		rc = starcosAddCertificateObject(token, p15);
		if (rc != CKR_OK) {
#ifdef DEBUG
			debug("addCertificateObject failed with rc=%d\n", rc);
#endif
		}
	}

	starcosSelectApplication(token);

	for (i = 0; i < (int)sc->application->privateKeysLen; i++) {
		struct p15PrivateKeyDescription *p15 = &sc->application->privateKeys[i];

		rc = starcosAddPrivateKeyObject(token, p15);
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

	rc = allocateToken(&ptoken, sizeof(struct starcosPrivateData));
	if (rc != CKR_OK)
		return rc;

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
	ptoken->info.firmwareVersion.minor = drv->version;

	ptoken->info.flags = CKF_WRITE_PROTECTED|CKF_RNG;
	ptoken->user = INT_CKU_NO_USER;
	ptoken->drv = drv;

	sc = starcosGetPrivateData(ptoken);
	sc->selectedApplication = 0;
	sc->application = application;

	rc = starcosReadICCSN(ptoken);

	if (rc < 0) {
		freeToken(ptoken);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Can't read ICCSN");
	}

	strbpcpy(ptoken->info.label, sc->application->name, sizeof(ptoken->info.label));

	rc = starcosSelectApplication(ptoken);

	if (rc < 0) {
		freeToken(ptoken);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Application not found on token");
	}

	if (sc->application->qESKeyDRec) {
		lc = 0;
		rc = starcosDeterminePinUseCounter(ptoken, sc->application->qESKeyDRec, &ptoken->pinUseCounter, &lc);

		if (rc < 0) {
			freeToken(ptoken);
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error querying PIN key use counter");
		}

		if (lc == 0x23) {
			ptoken->pinChangeRequired = TRUE;
		}

		if (ptoken->pinUseCounter != 1)
			ptoken->info.flags |= CKF_LOGIN_REQUIRED;
	} else {
		ptoken->pinUseCounter = 1;
		ptoken->info.flags |= CKF_LOGIN_REQUIRED;
	}

	rc = loadObjects(ptoken);

	if (rc < 0) {
		freeToken(ptoken);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error loading objects from token");
	}

	rc = starcosCheckPINStatus(slot, sc->application->pinref);

	if (rc < 0) {
		freeToken(ptoken);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error querying PIN status");
	}

	starcosUpdatePinStatus(ptoken, rc);

	if (slot->primarySlot) {
		if (slot->primarySlot->hasFeatureVerifyPINDirect) {
			ptoken->info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
			slot->hasFeatureVerifyPINDirect = slot->primarySlot->hasFeatureVerifyPINDirect;
		}
	} else {
		if (slot->hasFeatureVerifyPINDirect)
			ptoken->info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;
	}

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

	rc = addToken(slot, ptoken);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "addToken() failed");
	}

	*token = ptoken;

	if (slot->supportsVirtualSlots) {
		rc = getVirtualSlot(slot, 0, &vslot);
		if (rc != CKR_OK)
			FUNC_FAILS(rc, "Virtual slot creation failed");

		rc = createDTrustToken(vslot, &ptoken, drv, &starcosApplications[1]);
		if (rc != CKR_OK)
			FUNC_FAILS(rc, "Token creation failed");

		rc = addToken(vslot, ptoken);
		if (rc != CKR_OK)
			FUNC_FAILS(rc, "addToken() failed");
	}

	FUNC_RETURNS(CKR_OK);
}



static int starcos_C_GetMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
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



static int starcos_C_GetMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
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
	token.version = 4;
	token.maxCAPDU = 584;
	token.maxRAPDU = 584;
	token.maxHashBlock = 576;
	token.isCandidate = isCandidate;
	token.newToken = newDTrustToken,
	token.C_GetMechanismList = starcos_C_GetMechanismList;
	token.C_GetMechanismInfo = starcos_C_GetMechanismInfo;

	return &token;
}
