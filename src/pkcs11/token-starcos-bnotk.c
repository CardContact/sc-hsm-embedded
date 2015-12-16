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
 * @file    token-starcos-bnotk.c
 * @author  Andreas Schwier
 * @brief   Token implementation for a Starcos 3.5 ID ECC C1 based card with BNotK profile
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



static unsigned char atr35[]    = { 0x3B,0x9B,0x96,0xC0,0x0A,0x31,0xFE,0x45,0x80,0x67,0x04,0x1E,0xB5,0x01,0x00,0x89,0x4C,0x81,0x05,0x45 };
static unsigned char atr352_1[] = { 0x3B,0xDB,0x96,0xFF,0x81,0x31,0xFE,0x45,0x80,0x67,0x05,0x34,0xB5,0x02,0x01,0xC0,0xA1,0x81,0x05,0x3C };
static unsigned char atr352_2[] = { 0x3B,0xD9,0x96,0xFF,0x81,0x31,0xFE,0x45,0x80,0x31,0xB8,0x73,0x86,0x01,0xC0,0x81,0x05,0x02 };
static unsigned char atr352_3[] = { 0x3B,0xDF,0x96,0xFF,0x81,0x31,0xFE,0x45,0x80,0x5B,0x44,0x45,0x2E,0x42,0x4E,0x4F,0x54,0x4B,0x31,0x31,0x31,0x81,0x05,0xA0 };  /* Multisign */
static unsigned char atr352_4[] = { 0x3B,0xDF,0x96,0xFF,0x81,0x31,0xFE,0x45,0x80,0x5B,0x44,0x45,0x2E,0x42,0x4E,0x4F,0x54,0x4B,0x31,0x30,0x30,0x81,0x05,0xA0 };  /* Stapel100 */



static struct p15PrivateKeyDescription prkd_eSign1[] = {
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



static struct p15PrivateKeyDescription prkd_eSign2[] = {
		{
			P15_KT_RSA,
			{ "C2.CH.DS" },
			1,
			{ (unsigned char *)"\x02", 1 },
			P15_SIGN|P15_NONREPUDIATION,
			2048,
			0x85
		}
};



static struct p15CertificateDescription certd_eSign1[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.DS" },                              // Label
		{ (unsigned char *)"\x01", 1 },				// Id
		{ (unsigned char *)"\xC0\x01", 2 }			// efifOrPath
	},
	{
		1,
		P15_CT_X509,
		{ "C.CA.DS" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC0\x11", 2 }
	},
	{
		0,
		P15_CT_X509_ATTRIBUTE,
		{ "C.ATTRIBUTE.DS" },
		{ (unsigned char *)"\x21", 1 },
		{ (unsigned char *)"\xC0\x13", 2 }
	},
};




static struct p15CertificateDescription certd_eSign2[] = {
	{
		0,
		P15_CT_X509,
		{ "C2.CH.DS" },
		{ (unsigned char *)"\x02", 1 },
		{ (unsigned char *)"\xC0\x02", 2 }
	},
	{
		1,
		P15_CT_X509,
		{ "C2.CA.DS" },
		{ (unsigned char *)"\x12", 1 },
		{ (unsigned char *)"\xC0\x12", 2 }
	},
	{
		0,
		P15_CT_X509_ATTRIBUTE,
		{ "C2.ATTRIBUTE.DS" },
		{ (unsigned char *)"\x22", 1 },
		{ (unsigned char *)"\xC0\x14", 2 }
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
			0x82
		}
};



static struct p15CertificateDescription certd_eUserPKI[] = {
	{
		0,                                          // isCA
		P15_CT_X509,                                // Certificate type
		{ "C.CH.AUT" },                             // Label
		{ (unsigned char *)"\x03", 1 },				// Id
		{ (unsigned char *)"\xC0\x03", 2 }			// efifOrPath
	},
	{
		1,
		P15_CT_X509,
		{ "C.CA.AUT" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC0\x01", 2 }
	}
};



static unsigned char aid_eSign[] = { 0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E };
static unsigned char aid_eUserPKI[] = { 0xA0,0x00,0x00,0x05,0x25,0x65,0x55,0x73,0x65,0x72,0x01 };

static struct starcosApplication starcosApplications[] = {
		{
				"STARCOS.QES1",
				{ aid_eSign, sizeof(aid_eSign) },
				1,
				0x81,
				3,
				prkd_eSign1,
				sizeof(prkd_eSign1) / sizeof(struct p15PrivateKeyDescription),
				certd_eSign1,
				sizeof(certd_eSign1) / sizeof(struct p15CertificateDescription)
		},
		{
				"STARCOS.QES2",
				{ aid_eSign, sizeof(aid_eSign) },
				1,
				0x86,
				6,
				prkd_eSign2,
				sizeof(prkd_eSign2) / sizeof(struct p15PrivateKeyDescription),
				certd_eSign2,
				sizeof(certd_eSign2) / sizeof(struct p15CertificateDescription)
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


extern struct p11Context_t *context;


static int isCandidate(unsigned char *atr, size_t atrLen)
{
	if ((atrLen == sizeof(atr352_1)) && !memcmp(atr, atr352_1, atrLen))
		return 1;

	if ((atrLen == sizeof(atr352_2)) && !memcmp(atr, atr352_2, atrLen))
		return 1;

	if ((atrLen == sizeof(atr352_3)) && !memcmp(atr, atr352_3, atrLen))
		return 1;

	if ((atrLen == sizeof(atr352_4)) && !memcmp(atr, atr352_4, atrLen))
		return 1;

	if ((atrLen == sizeof(atr35)) && !memcmp(atr, atr35, atrLen))
		return 1;

	return 0;
}



struct p11TokenDriver *getBNotKTokenDriver();

/**
 * Create a new BNotK token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
static int newBNotKToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	struct p11Token_t *ptoken;
	struct p11TokenDriver *drv;
	struct p11Slot_t *vslot;
	int rc;

	FUNC_CALLED();

	drv = getBNotKTokenDriver();
	rc = createStarcosToken(slot, &ptoken, drv, &starcosApplications[STARCOS_EUSERPKI]);
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

	rc = createStarcosToken(vslot, &ptoken, drv, &starcosApplications[STARCOS_QES1]);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Token creation failed");

	rc = addToken(vslot, ptoken);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "addToken() failed");


	getVirtualSlot(slot, 1, &vslot);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Virtual slot creation failed");

	rc = createStarcosToken(vslot, &ptoken, drv, &starcosApplications[STARCOS_QES2]);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Token creation failed");

	rc = addToken(vslot, ptoken);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "addToken() failed");

	FUNC_RETURNS(CKR_OK);
}



struct p11TokenDriver *getStarcosTokenDriver();

struct p11TokenDriver *getBNotKTokenDriver()
{
	static struct p11TokenDriver starcos_token;

	starcos_token = *getStarcosTokenDriver();

	starcos_token.name = "3.5ID ECC C1 BNK";
	starcos_token.isCandidate = isCandidate;
	starcos_token.newToken = newBNotKToken;

	return &starcos_token;
}
