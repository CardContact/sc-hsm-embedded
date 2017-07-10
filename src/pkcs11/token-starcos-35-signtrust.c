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
 * @file    token-starcos-signtrust.c
 * @author  Andreas Schwier
 * @brief   Token implementation for a Starcos 3.5 ID ECC C1 based card with Signtrust profile
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



static unsigned char atr352ST[] = { 0x3B,0xDD,0x96,0xFF,0x81,0x31,0xFE,0x45,0x80,0x59,0x53,0x69,0x67,0x6E,0x74,0x72,0x75,0x73,0x74,0x81,0x05,0xA5 };

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
		0,                                          // isModifiable
		P15_CT_X509,                                // Certificate type
		{ "C.CH.DS" },                              // Label
		{ (unsigned char *)"\x01", 1 },				// Id
		{ (unsigned char *)"\xC0\x00", 2 }			// efifOrPath
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C.CA.DS" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC0\x08", 2 }
	},
	{
		0,
		0,
		P15_CT_X509_ATTRIBUTE,
		{ "C.ATTRIBUTE.DS" },
		{ (unsigned char *)"\x21", 1 },
		{ (unsigned char *)"\xC1\x00", 2 }
	},
	{
		0,
		0,
		P15_CT_X509,
		{ "C.RCA.DS" },
		{ (unsigned char *)"\x31", 1 },
		{ (unsigned char *)"\xC0\x0E", 2 }
	}
};




static struct p15CertificateDescription certd_eSign2[] = {
	{
		0,
		0,
		P15_CT_X509,
		{ "C2.CH.DS" },
		{ (unsigned char *)"\x02", 1 },
		{ (unsigned char *)"\xC0\x01", 2 }
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C2.CA.DS" },
		{ (unsigned char *)"\x12", 1 },
		{ (unsigned char *)"\xC0\x09", 2 }
	},
	{
		0,
		0,
		P15_CT_X509_ATTRIBUTE,
		{ "C2.ATTRIBUTE.DS" },
		{ (unsigned char *)"\x22", 1 },
		{ (unsigned char *)"\xC1\x03", 2 }
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
			0x86
		},
		{
			P15_KT_RSA,
			{ "C.CH.ENC" },
			1,
			{ (unsigned char *)"\x04", 1 },
			P15_DECIPHER,
			2048,
			0x93
		}
};



static struct p15CertificateDescription certd_eUserPKI[] = {
	{
		0,                                          // isCA
		0,                                          // isModifiable
		P15_CT_X509,                                // Certificate type
		{ "C.CH.AUT" },                             // Label
		{ (unsigned char *)"\x03", 1 },				// Id
		{ (unsigned char *)"\xC5\x00", 2 }			// efifOrPath
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C.CA.AUT" },
		{ (unsigned char *)"\x11", 1 },
		{ (unsigned char *)"\xC5\x08", 2 }
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C.RCA.AUT" },
		{ (unsigned char *)"\x31", 1 },
		{ (unsigned char *)"\xC5\x0E", 2 }
	},
	{
		0,                                          // isCA
		0,                                          // isModifiable
		P15_CT_X509,                                // Certificate type
		{ "C.CH.ENC" },                             // Label
		{ (unsigned char *)"\x04", 1 },				// Id
		{ (unsigned char *)"\xC2\x00", 2 }			// efifOrPath
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C.CA.ENC" },
		{ (unsigned char *)"\x12", 1 },
		{ (unsigned char *)"\xC2\x08", 2 }
	},
	{
		1,
		0,
		P15_CT_X509,
		{ "C.RCA.ENC" },
		{ (unsigned char *)"\x32", 1 },
		{ (unsigned char *)"\xC2\x0E", 2 }
	}
};



static unsigned char aid_QES[] = { 0xD2,0x76,0x00,0x00,0x66,0x01 };
static unsigned char aid_eUserPKI[] = { 0xA0,0x00,0x00,0x01,0x67,0x45,0x53,0x49,0x47,0x4E };

static struct starcosApplication starcosApplications[] = {
		{
				"STARCOS.QES1",
				{ aid_QES, sizeof(aid_QES) },
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
				{ aid_QES, sizeof(aid_QES) },
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



static int isCandidate(unsigned char *atr, size_t atrLen)
{
	if ((atrLen == sizeof(atr352ST)) && !memcmp(atr, atr352ST, atrLen))
		return 1;

	return 0;
}



struct p11TokenDriver *getSigntrust35TokenDriver();

/**
 * Create a new STARCOS token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
static int newSigntrust35Token(struct p11Slot_t *slot, struct p11Token_t **token)
{
	struct p11Token_t *ptoken;
	struct p11TokenDriver *drv;
	struct p11Slot_t *vslot;
	int rc;

	FUNC_CALLED();

	drv = getSigntrust35TokenDriver();
	rc = createStarcosToken(slot, &ptoken, drv, &starcosApplications[STARCOS_EUSERPKI]);
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
	}

	FUNC_RETURNS(CKR_OK);
}



struct p11TokenDriver *getStarcosTokenDriver();

struct p11TokenDriver *getSigntrust35TokenDriver()
{
	static struct p11TokenDriver starcos_token;

	starcos_token = *getStarcosTokenDriver();

	starcos_token.name = "3.5 ID ECC C1 ST";
	starcos_token.isCandidate = isCandidate;
	starcos_token.newToken = newSigntrust35Token;

	return &starcos_token;
}
