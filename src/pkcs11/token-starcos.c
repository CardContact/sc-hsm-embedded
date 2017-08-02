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
 * @brief   Basic Token implementation for a Starcos card
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



static unsigned char algo_PKCS15[] =           { 0x89, 0x02, 0x13, 0x23 };
static unsigned char algo_PSS_SHA1[] =         { 0x89, 0x03, 0x13, 0x33, 0x10 };
static unsigned char algo_PSS_SHA224[] =       { 0x89, 0x03, 0x13, 0x33, 0x60 };
static unsigned char algo_PSS_SHA256[] =       { 0x89, 0x03, 0x13, 0x33, 0x30 };
static unsigned char algo_PSS_SHA384[] =       { 0x89, 0x03, 0x13, 0x33, 0x40 };
static unsigned char algo_PSS_SHA512[] =       { 0x89, 0x03, 0x13, 0x33, 0x50 };
static unsigned char algo_SHA1[] =             { 0x89, 0x02, 0x14, 0x10 };
static unsigned char algo_SHA224[] =           { 0x89, 0x02, 0x14, 0x60 };
static unsigned char algo_SHA256[] =           { 0x89, 0x02, 0x14, 0x30 };
static unsigned char algo_SHA384[] =           { 0x89, 0x02, 0x14, 0x40 };
static unsigned char algo_SHA512[] =           { 0x89, 0x02, 0x14, 0x50 };
static unsigned char algo_PKCS15_DECRYPT34[] = { 0x89, 0x02, 0x11, 0x30 };
static unsigned char algo_PKCS15_DECRYPT[] =   { 0x89, 0x02, 0x11, 0x31 };
static unsigned char algo_OAEP_DECRYPT[] =     { 0x89, 0x02, 0x11, 0x32 };
static unsigned char algo_ECDSA[] =            { 0x89, 0x02, 0x13, 0x35 };


static const CK_MECHANISM_TYPE p11MechanismList[] = {
		CKM_RSA_PKCS,
		CKM_RSA_PKCS_OAEP,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA224_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA384_RSA_PKCS,
		CKM_SHA512_RSA_PKCS,
		CKM_SHA1_RSA_PKCS_PSS,
		CKM_SHA224_RSA_PKCS_PSS,
		CKM_SHA256_RSA_PKCS_PSS,
		CKM_SHA384_RSA_PKCS_PSS,
		CKM_SHA512_RSA_PKCS_PSS,
		CKM_SC_HSM_PSS_SHA1,
		CKM_SC_HSM_PSS_SHA224,
		CKM_SC_HSM_PSS_SHA256,
		CKM_SC_HSM_PSS_SHA384,
		CKM_SC_HSM_PSS_SHA512,
#ifdef ENABLE_LIBCRYPTO
		CKM_SHA_1,
		CKM_SHA224,
		CKM_SHA256,
		CKM_SHA384,
		CKM_SHA512,
#endif
		CKM_ECDSA
};



struct starcosPrivateData *starcosGetPrivateData(struct p11Token_t *token)
{
	return (struct starcosPrivateData *)(token + 1);
}



void starcosLock(struct p11Token_t *token)
{
	p11LockMutex(token->mutex);
}



void starcosUnlock(struct p11Token_t *token)
{
	p11UnlockMutex(token->mutex);
}



int starcosSwitchApplication(struct p11Token_t *token, struct starcosApplication *application)
{
	int rc, *sa;
	unsigned short SW1SW2;
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = starcosGetPrivateData(token);

	if (token->slot->primarySlot) {
		sa = &(starcosGetPrivateData(getBaseToken(token))->selectedApplication);
	} else {
		sa = &sc->selectedApplication;
	}

	if (application->aidId == *sa) {
#ifdef DEBUG
		debug("Application %d already selected\n", *sa);
#endif
		return 0;
	}

#ifdef DEBUG
		debug("Switch to application %d\n", application->aidId);
#endif

	rc = transmitAPDU(token->slot, 0x00, 0xA4, 0x04, 0x0C,
			(int)application->aid.len, application->aid.val,
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



int starcosSelectApplication(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = starcosGetPrivateData(token);
	FUNC_RETURNS(starcosSwitchApplication(token, sc->application));
}



int starcosReadTLVEF(struct p11Token_t *token, bytestring fid, unsigned char *content, size_t len)
{
	int rc, le, tl, ne, maxapdu;
	size_t ofs;
	unsigned short SW1SW2;
	unsigned char *po;

	FUNC_CALLED();

	// Select EF
	rc = transmitAPDU(token->slot, 0x00, 0xA4, 0x02, 0x0C,
			(int)fid->len, fid->val,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "File not found");
	}

	// Read first block to determine tag and length
	rc = transmitAPDU(token->slot, 0x00, 0xB0, 0x00, 0x00,
			0, NULL,
			0, content, (int)len, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Read EF failed");
	}

	ofs = rc;

	// Restrict the number of bytes in Le to either the maximum APDU size of STARCOS or
	// the maximum APDU size of the reader, if any.
	maxapdu = token->drv->maxRAPDU;
	if (token->slot->maxRAPDU && (token->slot->maxRAPDU < maxapdu))
		maxapdu = token->slot->maxRAPDU;
	maxapdu -= 2;		// Accommodate SW1/SW2

	le = 65536;			// Read all if no certificate found
	if ((*content == 0x30) || (*content == 0x5A)) {
		po = content;
		asn1Tag(&po);
		tl = asn1Length(&po);
		tl += (int)(po - content);
		le = tl - (int)ofs;
	}

	while ((rc > 0) && (ofs < len) && (le > 0)) {
		ne = le;
		// Restrict Ne to the maximum APDU length allowed
		if (((le != 65536) || token->slot->noExtLengthReadAll) && (le > maxapdu))
			ne = maxapdu;

		rc = transmitAPDU(token->slot, 0x00, 0xB0, (unsigned char)(ofs >> 8), (unsigned char)(ofs & 0xFF),
				0, NULL,
				ne, content + ofs, (int)(len - ofs), &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(rc, "transmitAPDU failed");
		}

		if ((SW1SW2 != 0x9000) && (SW1SW2 != 0x6B00) && (SW1SW2 != 0x6282)) {
			FUNC_FAILS(-1, "Read EF failed");
		}
		ofs += rc;
		if (le != 65536)
			le -= rc;
	}

	FUNC_RETURNS((int)ofs);
}



#ifndef bcddigit
	#define bcddigit(x) ((x) >= 10 ? 'A' - 10 + (x) : '0' + (x))
#endif

int starcosReadICCSN(struct p11Token_t *token)
{
	static struct bytestring_s EFICCSN = { (unsigned char *)"\x2F\x02", 2 };
	unsigned char scr[12],*s,*d;
	unsigned short SW1SW2;
	struct starcosPrivateData *sc;
	int rc,*sa;

	FUNC_CALLED();

	// Clear currently selected application indicator
	sc = starcosGetPrivateData(token);

	if (token->slot->primarySlot) {
		sa = &(starcosGetPrivateData(getBaseToken(token))->selectedApplication);
	} else {
		sa = &sc->selectedApplication;
	}

	*sa = 0;

	// Select MF
	rc = transmitAPDU(token->slot, 0x00, 0xA4, 0x00, 0x0C,
			0, NULL,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Could not select MF");
	}

	rc = starcosReadTLVEF(token, &EFICCSN, scr, sizeof(scr));

	if (rc < 0)
		FUNC_FAILS(rc, "Reading EF.SN.ICC");
	
	memset(token->info.serialNumber, ' ', sizeof(token->info.serialNumber));

	s = scr + 4;		// Ignore 5A08 and first two bytes as serial number is only 16 digits while ICCSN is 20 digits
	rc -= 4;
	d = token->info.serialNumber;

	while (rc > 0) {
		*d++ = bcddigit(*s >> 4);
		*d++ = bcddigit(*s & 15);
		s++;
		rc--;
	}

	return 0;
}



int starcosCheckPINStatus(struct p11Slot_t *slot, unsigned char pinref)
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



/**
 * Update internal PIN status based on SW1/SW2 received from token
 */
int starcosUpdatePinStatus(struct p11Token_t *token, int pinstatus)
{
	int rc = CKR_OK;

	token->info.flags &= ~(CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED | CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_TO_BE_CHANGED );

	if (pinstatus != 0x6984) {
		token->info.flags |= CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
	}

	if (token->pinChangeRequired) {
		token->info.flags |= CKF_USER_PIN_TO_BE_CHANGED;
	}

	if ((pinstatus & 0x63C0) == 0x63C0)
		token->pinTriesLeft = pinstatus & 0xF;

	switch(pinstatus) {
	case 0x9000:
		token->pinTriesLeft = 3;
		rc = CKR_OK;
		break;
	case 0x6985:
		token->pinTriesLeft = 3;
		token->info.flags |= CKF_USER_PIN_TO_BE_CHANGED;
		rc = CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case 0x6984:
		token->pinTriesLeft = 3;
		rc = CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case 0x6983:
	case 0x63C0:
		token->pinTriesLeft = 0;
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



int starcosDeterminePinUseCounter(struct p11Token_t *token, unsigned char recref, int *useCounter, int *lifeCycle)
{
	int rc,ucpathlen;
	unsigned short SW1SW2;
	unsigned char rec[256], *p,*fid,*ucpath;
	FUNC_CALLED();

	if (token->info.firmwareVersion.minor >= 5) {
		fid = (unsigned char *)"\x00\x13";		// EF.KEYD
		ucpath = (unsigned char *)"\x30\x7B\xA4\x9F\x22";
		ucpathlen = 4;		// 4 Tags (not bytes)
	} else {
		fid = (unsigned char *)"\x00\x15";		// EF.PWDD
		ucpath = (unsigned char *)"\x30\x7B\x9F\x22";
		ucpathlen = 3;		// 3 Tags (not bytes)
	}

	// Select EF
	rc = transmitAPDU(token->slot, 0x00, 0xA4, 0x02, 0x0C,
			2, fid,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "File not found");
	}

	// Read record, but leave 3 bytes to add encapsulating 30 81 FF later
	rc = transmitAPDU(token->slot, 0x00, 0xB2, recref, 0x04,
			0, NULL,
			0, rec, sizeof(rec) - 3, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Record not found");
	}

	rc = asn1Encap(0x30, rec, rc);
	rc = (int)asn1Validate(rec, rc);

	if (rc > 0) {
		FUNC_FAILS(rc, "ASN.1 structure invalid");
	}

	*useCounter = 0;
	p = asn1Find(rec, ucpath, ucpathlen);

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
	case CKM_SC_HSM_PSS_SHA1:
	case CKM_SC_HSM_PSS_SHA224:
	case CKM_SC_HSM_PSS_SHA256:
	case CKM_SC_HSM_PSS_SHA384:
	case CKM_SC_HSM_PSS_SHA512:
		return pObject->keysize >> 3;
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA:
		return pObject->keysize >> 2;
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
	case CKM_SC_HSM_PSS_SHA1:
		*algotlv = algo_PSS_SHA1;
		break;
	case CKM_SHA224_RSA_PKCS_PSS:
	case CKM_SC_HSM_PSS_SHA224:
		*algotlv = algo_PSS_SHA224;
		break;
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SC_HSM_PSS_SHA256:
		*algotlv = algo_PSS_SHA256;
		break;
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SC_HSM_PSS_SHA384:
		*algotlv = algo_PSS_SHA384;
		break;
	case CKM_SHA512_RSA_PKCS_PSS:
	case CKM_SC_HSM_PSS_SHA512:
		*algotlv = algo_PSS_SHA512;
		break;
	case CKM_ECDSA_SHA1:
	case CKM_ECDSA:
		*algotlv = algo_ECDSA;
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



static int getAlgorithmIdForDecryption(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char **algotlv)
{
	if (token->info.firmwareVersion.minor >= 5) {
		switch(mech) {
		case CKM_RSA_PKCS:
			*algotlv = algo_PKCS15_DECRYPT;
			break;
		case CKM_RSA_PKCS_OAEP:
			*algotlv = algo_OAEP_DECRYPT;
			break;
		default:
			return CKR_MECHANISM_INVALID;
		}
	} else {
		switch(mech) {
		case CKM_RSA_PKCS:
			*algotlv = algo_PKCS15_DECRYPT34;
			break;
		default:
			return CKR_MECHANISM_INVALID;
		}
	}
	return CKR_OK;
}



int starcosDigest(struct p11Token_t *token, CK_MECHANISM_TYPE mech, unsigned char *data, size_t len)
{
	int rc;
	size_t chunk;
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
	rc += (int)(po - algo);

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
		rc = asn1Encap(0x80, scr + 2, (int)len) + 2;

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
			chunk = (len > (size_t)token->drv->maxHashBlock ? (size_t)token->drv->maxHashBlock : len);

			memcpy(scr, data, chunk);
			rc = asn1Encap(0x80, scr, (int)chunk);

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

	if ((mech != CKM_RSA_PKCS) && (mech != CKM_ECDSA) && (mech != CKM_ECDSA_SHA1) &&
		(mech != CKM_SC_HSM_PSS_SHA1) && (mech != CKM_SC_HSM_PSS_SHA224) &&
		(mech != CKM_SC_HSM_PSS_SHA256) && (mech != CKM_SC_HSM_PSS_SHA384)  && (mech != CKM_SC_HSM_PSS_SHA512)) {
		rc = starcosDigest(pObject->token, mech, pData, ulDataLen);
		if (rc != CKR_OK) {
			starcosUnlock(pObject->token);
			FUNC_FAILS(rc, "digesting failed");
		}
		pData = NULL;
		ulDataLen = 0;
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



static int starcos_C_DecryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	unsigned char *algotlv;

	FUNC_CALLED();

	FUNC_RETURNS(getAlgorithmIdForDecryption(pObject->token, mech->mechanism, &algotlv));
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
	starcosLock(pObject->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = starcosSelectApplication(pObject->token);
	if (rc < 0) {
		starcosUnlock(pObject->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "selecting application failed");
	}

	rc = getAlgorithmIdForDecryption(pObject->token, mech, &s);
	if (rc != CKR_OK) {
		starcosUnlock(pObject->token);
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



static int starcos_C_GenerateRandom(struct p11Slot_t *slot, CK_BYTE_PTR rnd, CK_ULONG rndlen)
{
	unsigned short SW1SW2;
	CK_ULONG maxblk;
	int rc;

	FUNC_CALLED();

	maxblk = slot->token->drv->maxRAPDU - 2;		// Maximum block size
	while (rndlen > 0) {
		if (rndlen < maxblk) {
			maxblk = rndlen;
		}
		rc = transmitAPDU(slot, 0x00, 0x84, 0x00, 0x00,
				0, NULL,
				maxblk, rnd, rndlen, &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
		}

		if (SW1SW2 != 0x9000) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "device reported error");
		}
		rndlen -= rc;
		rnd += rc;
	}

	FUNC_RETURNS(CKR_OK);
}



int starcosAddCertificateObject(struct p11Token_t *token, struct p15CertificateDescription *p15)
{
	unsigned char certValue[MAX_CERTIFICATE_SIZE];
	struct p11Object_t *pObject;
	int rc;

	FUNC_CALLED();

	rc = starcosReadTLVEF(token, &p15->efidOrPath, certValue, sizeof(certValue));

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



int starcosAddPrivateKeyObject(struct p11Token_t *token, struct p15PrivateKeyDescription *p15)
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
	template[1].ulValueLen = (CK_ULONG)p15->id.len;

	rc = findMatchingTokenObject(token, template, 2, &p11cert);

	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "Could not find matching certificate");
	}

	useAA = (p15->usage & P15_NONREPUDIATION) && (token->pinUseCounter == 1);

	rc = createPrivateKeyObjectFromP15(p15, p11cert, useAA, &p11prikey);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create private key object");
	}

	p11prikey->C_SignInit = token->drv->C_SignInit;
	p11prikey->C_Sign = token->drv->C_Sign;
	p11prikey->C_DecryptInit = token->drv->C_DecryptInit;
	p11prikey->C_Decrypt = token->drv->C_Decrypt;

	p11prikey->tokenid = p15->keyReference;
	p11prikey->keysize = p15->keysize;

	rc = createPublicKeyObjectFromCertificate(p15, p11cert, &p11pubkey);

	if (rc != CKR_OK) {
		freeObject(p11prikey);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create public key object");
	}

	addObject(token, p11prikey, useAA ? TRUE : FALSE);
	addObject(token, p11pubkey, TRUE);

	FUNC_RETURNS(CKR_OK);
}



static int loadObjects(struct p11Token_t *token)
{
	struct starcosPrivateData *sc;
	int rc,i;

	FUNC_CALLED();

	sc = starcosGetPrivateData(token);

	for (i = 0; i < (int)sc->application->certsLen; i++) {
		struct p15CertificateDescription *p15 = &sc->application->certs[i];

		rc = starcosAddCertificateObject(token, p15);
		if (rc != CKR_OK) {
#ifdef DEBUG
			debug("addCertificateObject failed with rc=%d\n", rc);
#endif
		}
	}

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



int encodeF2B(unsigned char *pin, int pinlen, unsigned char *f2b)
{
	unsigned char *po;
	int i;

	FUNC_CALLED();

	if ((pinlen <= 4) || (pinlen > 14)) {
		FUNC_FAILS(CKR_PIN_LEN_RANGE, "PIN length must be between 4 and 14");
	}

	memset(f2b, 0xFF, 8);
	f2b[0] = 0x20 | pinlen;

	po = f2b + 1;
	for (i = 0; i < pinlen; i++) {
		if ((*pin < '0') || (*pin > '9')) {
			FUNC_FAILS(CKR_PIN_INCORRECT, "PIN must be numeric");
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
static int login(struct p11Slot_t *slot, int userType, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
{
	int rc = CKR_OK;
	unsigned short SW1SW2;
	unsigned char f2b[8];
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	starcosLock(slot->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = starcosSelectApplication(slot->token);
	if (rc < 0) {
		starcosUnlock(slot->token);
		FUNC_FAILS(rc, "selecting application failed");
	}

	sc = starcosGetPrivateData(slot->token);

	if (userType == CKU_SO) {
		rc = encodeF2B(pin, pinlen, sc->sopin);

		if (rc != CKR_OK) {
			starcosUnlock(slot->token);
			FUNC_FAILS(rc, "Could not encode PIN");
		}
	} else {

		if ((slot->token->info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) && !pinlen && !pin) {
#ifdef DEBUG
			debug("Verify PIN using CKF_PROTECTED_AUTHENTICATION_PATH\n");
#endif
			memset(f2b, 0xFF, 8);
			f2b[0] = 0x20;

			rc = transmitVerifyPinAPDU(slot, 0x00, 0x20, 0x00, sc->application->pinref,
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
				starcosUnlock(slot->token);
				FUNC_FAILS(rc, "Could not encode PIN");
			}

			rc = transmitAPDU(slot, 0x00, 0x20, 0x00, sc->application->pinref,
					8, f2b,
					0, NULL, 0, &SW1SW2);
		}


		if (rc < 0) {
			starcosUnlock(slot->token);
			FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
		}

		rc = starcosUpdatePinStatus(slot->token, SW1SW2);

		if (rc != CKR_OK) {
			starcosUnlock(slot->token);
			FUNC_FAILS(rc, "login failed");
		}
	}

	starcosUnlock(slot->token);
	FUNC_RETURNS(CKR_OK);
}



/**
 * Initialize user pin in SO session
 *
 * @param slot      The slot in which the token is inserted
 * @param pin       Pointer to PIN value or NULL if PIN shall be verified using PIN-Pad
 * @param pinLen    The length of the PIN supplied in pin
 * @return          CKR_OK or any other Cryptoki error code
 */
static int initpin(struct p11Slot_t *slot, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
{
	int rc = CKR_OK;
	unsigned short SW1SW2;
	unsigned char data[16], pinref;
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	if (pinlen) {
		rc = encodeF2B(pin, pinlen, data + 8);

		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "Could not encode PIN");
		}
	}

	starcosLock(slot->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = starcosSelectApplication(slot->token);
	if (rc < 0) {
		starcosUnlock(slot->token);
		FUNC_FAILS(rc, "selecting application failed");
	}

	sc = starcosGetPrivateData(slot->token);
	memcpy(data, sc->sopin, sizeof(sc->sopin));
	pinref = sc->application->pinref;

#ifdef DEBUG
	debug("Init PIN using provided PIN value\n");
#endif
	if (pin) {
		rc = transmitAPDU(slot, 0x00, 0x2C, 0x00, pinref,
				sizeof(data), data,
				0, NULL, 0, &SW1SW2);
	} else {
		rc = transmitAPDU(slot, 0x00, 0x2C, 0x01, pinref,
				sizeof(sc->sopin), data,
				0, NULL, 0, &SW1SW2);
	}
	if (rc < 0) {
		starcosUnlock(slot->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 == 0x6982) {
		starcosUnlock(slot->token);
		FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Function not allowed");
	}

	if (SW1SW2 != 0x9000) {
		starcosUnlock(slot->token);
		FUNC_FAILS(CKR_PIN_INCORRECT, "Invalid SO-PIN");
	}

	rc = starcosCheckPINStatus(slot, pinref);

	if (rc < 0) {
		starcosUnlock(slot->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	starcosUpdatePinStatus(slot->token, rc);

	starcosUnlock(slot->token);
	FUNC_RETURNS(CKR_OK);
}



/**
 * Change PIN in User or SO session
 *
 * @param slot      The slot in which the token is inserted
 * @param oldpin    Pointer to PIN value or NULL if PIN shall be verified using PIN-Pad
 * @param oldpinLen The length of the PIN supplied in oldpin
 * @param newpin    Pointer to PIN value or NULL if PIN shall be verified using PIN-Pad
 * @param newpinLen The length of the PIN supplied in newpin
 * @return          CKR_OK or any other Cryptoki error code
 */
static int setpin(struct p11Slot_t *slot, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldpinlen, CK_UTF8CHAR_PTR newpin, CK_ULONG newpinlen)
{
	int rc = CKR_OK;
	unsigned short SW1SW2;
	unsigned char data[16];
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	if (slot->token->user == CKU_SO) {
		FUNC_FAILS(CKR_USER_TYPE_INVALID, "User not logged in");
	}

	rc = encodeF2B(oldpin, oldpinlen, data);

	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "Could not encode OldPIN");
	}

	rc = encodeF2B(newpin, newpinlen, data + 8);

	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "Could not encode NewPIN");
	}

	starcosLock(slot->token);
	if (!slot->token) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	rc = starcosSelectApplication(slot->token);
	if (rc < 0) {
		starcosUnlock(slot->token);
		FUNC_FAILS(rc, "selecting application failed");
	}

	sc = starcosGetPrivateData(slot->token);

#ifdef DEBUG
	debug("Set PIN using provided PIN value\n");
#endif
	rc = transmitAPDU(slot, 0x00, 0x24, 0x00, sc->application->pinref,
		sizeof(data), data,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		starcosUnlock(slot->token);
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (slot->token->user == CKU_SO) {
		if (SW1SW2 != 0x9000) {
			starcosUnlock(slot->token);
			FUNC_FAILS(CKR_PIN_INCORRECT, "Incorrect old SO-PIN");
		}
	} else {
		slot->token->pinChangeRequired = FALSE;
		rc = starcosUpdatePinStatus(slot->token, SW1SW2);
	}

	starcosUnlock(slot->token);
	FUNC_RETURNS(rc);
}



/**
 * Starcos does not support a deauthentication for the User PIN
 *
 * @param slot      The slot in which the token is inserted
 * @return          CKR_OK or any other Cryptoki error code
 */
static int logout(struct p11Slot_t *slot)
{
	struct starcosPrivateData *sc;

	FUNC_CALLED();

	sc = starcosGetPrivateData(slot->token);
	memset(sc->sopin, 0, sizeof(sc->sopin));

	sc->selectedApplication = 0;

	FUNC_RETURNS(CKR_OK);
}



static void freeStarcosToken(struct p11Token_t *token)
{
}



/**
 * Create a new STARCOS token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
int createStarcosToken(struct p11Slot_t *slot, struct p11Token_t **token, struct p11TokenDriver *drv, struct starcosApplication *application)
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
	}

	if (ptoken->pinUseCounter != 1)
		ptoken->info.flags |= CKF_LOGIN_REQUIRED;

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
#ifdef ENABLE_LIBCRYPTO
		pInfo->flags = CKF_HW|CKF_SIGN|CKF_DECRYPT|CKF_VERIFY|CKF_ENCRYPT;
#else
		pInfo->flags = CKF_HW|CKF_SIGN|CKF_DECRYPT;
#endif
		break;
	case CKM_RSA_PKCS_OAEP:
#ifdef ENABLE_LIBCRYPTO
		pInfo->flags = CKF_HW|CKF_DECRYPT|CKF_ENCRYPT;
#else
		pInfo->flags = CKF_HW|CKF_DECRYPT;
#endif
		break;
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
	case CKM_SC_HSM_PSS_SHA1:
	case CKM_SC_HSM_PSS_SHA224:
	case CKM_SC_HSM_PSS_SHA256:
	case CKM_SC_HSM_PSS_SHA384:
	case CKM_SC_HSM_PSS_SHA512:
	case CKM_ECDSA:
#ifdef ENABLE_LIBCRYPTO
		pInfo->flags = CKF_HW|CKF_SIGN|CKF_VERIFY;
#else
		pInfo->flags = CKF_HW|CKF_SIGN;
#endif
		break;

#ifdef ENABLE_LIBCRYPTO
	case CKM_SHA_1:
	case CKM_SHA224:
	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:
		pInfo->flags = CKF_DIGEST;
		break;

#endif
	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

	if (type == CKM_ECDSA) {
		pInfo->ulMinKeySize = 256;
		pInfo->ulMaxKeySize = 256;
	} else if ((type == CKM_SHA_1) || (type == CKM_SHA224) || (type == CKM_SHA256) || (type == CKM_SHA384) || (type == CKM_SHA512)) {
		pInfo->ulMinKeySize = 0;
		pInfo->ulMaxKeySize = 0;
	} else {
		pInfo->ulMinKeySize = 2048;
		pInfo->ulMaxKeySize = 2048;
	}
	FUNC_RETURNS(rv);
}



struct p11TokenDriver *getStarcosTokenDriver()
{
	static struct p11TokenDriver starcos_token = {
		"STARCOS",
		5,
		1920,
		1920,
		// Chunk must be aligned to the hash block size
		// As we support SHA-2 up to 512 we choose 7 * 128 as chunk size
		896,
		NULL,
		NULL,
		freeStarcosToken,
		starcos_C_GetMechanismList,
		starcos_C_GetMechanismInfo,
		login,
		logout,
		initpin,
		setpin,

		starcos_C_DecryptInit,		// int (*C_DecryptInit)  (struct p11Object_t *, CK_MECHANISM_PTR);
		starcos_C_Decrypt,		// int (*C_Decrypt)      (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
		NULL,				// int (*C_DecryptUpdate)(struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
		NULL,				// int (*C_DecryptFinal) (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

		starcos_C_SignInit,		// int (*C_SignInit)     (struct p11Object_t *, CK_MECHANISM_PTR);
		starcos_C_Sign,			// int (*C_Sign)         (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
		NULL,				// int (*C_SignUpdate)   (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG);
		NULL,				// int (*C_SignFinal)    (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

		NULL,				// int (*C_GenerateKeyPair)  (struct p11Slot_t *, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, struct p11Object_t **, struct p11Object_t **);
		NULL,				// int (*C_CreateObject)     (struct p11Slot_t *, CK_ATTRIBUTE_PTR, CK_ULONG ulCount, struct p11Object_t **);

		NULL,				// int (*destroyObject)       (struct p11Slot_t *, struct p11Object_t *);
		NULL,				// int (*C_SetAttributeValue)(struct p11Slot_t *, struct p11Object_t *, CK_ATTRIBUTE_PTR, CK_ULONG);
		starcos_C_GenerateRandom	// int (*C_GenerateRandom)   (struct p11Slot_t *, CK_BYTE_PTR , CK_ULONG );
	};



	return &starcos_token;
}
