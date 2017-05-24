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
 * @file    token-sc-hsm.c
 * @author  Andreas Schwier
 * @brief   Token implementation for a SmartCard-HSM
 */

#include <string.h>
#include <ctype.h>

#include "token-sc-hsm.h"

#include <pkcs11/slot.h>
#include <pkcs11/object.h>
#include <pkcs11/token.h>
#include <pkcs11/certificateobject.h>
#include <pkcs11/privatekeyobject.h>
#include <pkcs11/publickeyobject.h>
#include <pkcs11/strbpcpy.h>
#include <pkcs11/asn1.h>
#include <pkcs11/pkcs15.h>
#include <pkcs11/cvc.h>
#include <pkcs11/debug.h>



static unsigned char aid[] = { 0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01 };

static unsigned char atrJCOP41[] = { 0x3B,0xF8,0x13,0x00,0x00,0x81,0x31,0xFE,0x45,0x4A,0x43,0x4F,0x50,0x76,0x32,0x34,0x31,0xB7 };
static unsigned char atrHSM[]    = { 0x3B,0xFE,0x18,0x00,0x00,0x81,0x31,0xFE,0x45,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0xFA };
static unsigned char atrHSMCL[]  = { 0x3B,0x8E,0x80,0x01,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0x18 };

static struct bytestring_s defaultAlgorithmRSA = { (unsigned char *)"\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02", 10 };
static struct bytestring_s defaultAlgorithmEC = { (unsigned char *)"\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03", 10 };
static struct bytestring_s defaultCHR = { (unsigned char *)"UTDUMMY00000", 12 };
static struct bytestring_s defaultPublicExponent = { (unsigned char *)"\x01\x00\x01", 3 };



static const CK_MECHANISM_TYPE p11MechanismList[] = {
		CKM_RSA_X_509,
		CKM_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA1_RSA_PKCS_PSS,
		CKM_SHA256_RSA_PKCS_PSS,
		CKM_ECDSA,
		CKM_ECDSA_SHA1
};



static struct token_sc_hsm *getPrivateData(struct p11Token_t *token)
{
	return (struct token_sc_hsm *)(token + 1);
}



static int isCandidate(unsigned char *atr, size_t atrLen)
{
	if ((atrLen == sizeof(atrJCOP41)) && !memcmp(atr, atrJCOP41, atrLen))
		return 1;

	if ((atrLen == sizeof(atrHSM)) && !memcmp(atr, atrHSM, atrLen))
		return 1;

	if ((atrLen == sizeof(atrHSMCL)) && !memcmp(atr, atrHSMCL, atrLen))
		return 1;

	return 0;
}



static int checkPINStatus(struct p11Slot_t *slot)
{
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x00, 0x20, 0x00, 0x81,
			0, NULL,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	FUNC_RETURNS(SW1SW2);
}



static int selectApplet(struct p11Slot_t *slot)
{
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x00, 0xA4, 0x04, 0x0C,
			sizeof(aid), aid,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Token is not a SmartCard-HSM");
	}

	FUNC_RETURNS(CKR_OK);
}



static int enumerateObjects(struct p11Slot_t *slot, unsigned char *filelist, size_t len)
{
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x80, 0x58, 0x00, 0x00,
			0, NULL,
			65536, filelist, len, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Token did not enumerate objects");
	}

	FUNC_RETURNS(rc);
}



static int readEF(struct p11Slot_t *slot, unsigned short fid, unsigned char *content, size_t len)
{
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x00, 0xB1, fid >> 8, fid & 0xFF,
			4, (unsigned char*)"\x54\x02\x00\x00",
			65536, content, len, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Read EF failed");
	}

	FUNC_RETURNS(rc);
}



static int writeEF(struct p11Slot_t *slot, unsigned short fid, unsigned char *content, size_t len)
{
	int rc,maxblk, blen, ofs;
	unsigned short SW1SW2;
	unsigned char buff[MAX_CAPDU],*p;

	FUNC_CALLED();

	maxblk = slot->maxCAPDU - 15;			// Maximum block size
	ofs = 0;

	while (len > 0) {
		blen = len > maxblk ? maxblk : len;

		p = buff;

		*p++ = 0x54;
		*p++ = 0x02;
		*p++ = ofs >> 8;
		*p++ = ofs & 0xFF;
		*p++ = 0x53;
		asn1StoreLength(&p, blen);

		memcpy(p, content, blen);
		content += blen;
		len -= blen;
		blen += p - buff;

		rc = transmitAPDU(slot, 0x00, 0xD7, fid >> 8, fid & 0xFF,
				blen, buff,
				0, NULL, 0, &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(rc, "transmitAPDU failed");
		}

		if (SW1SW2 != 0x9000) {
			FUNC_FAILS(-1, "Write EF failed");
		}
	}

	FUNC_RETURNS(rc);
}



static int getSignatureSize(CK_MECHANISM_TYPE mech, struct p11Object_t *pObject)
{
	switch(mech) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
		return pObject->keysize >> 3;
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
		return pObject->keysize >> 2;
	default:
		return -1;
	}
}



static int getAlgorithmIdForSigning(CK_MECHANISM_TYPE mech)
{
	switch(mech) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
		return ALGO_RSA_RAW;
	case CKM_SHA1_RSA_PKCS:
		return ALGO_RSA_PKCS1_SHA1;
	case CKM_SHA256_RSA_PKCS:
		return ALGO_RSA_PKCS1_SHA256;
	case CKM_SHA1_RSA_PKCS_PSS:
		return ALGO_RSA_PSS_SHA1;
	case CKM_SHA256_RSA_PKCS_PSS:
		return ALGO_RSA_PSS_SHA256;
	case CKM_ECDSA:
		return ALGO_EC_RAW;
	case CKM_ECDSA_SHA1:
		return ALGO_EC_SHA1;
	default:
		return -1;
	}
}



static int getAlgorithmIdForDecryption(CK_MECHANISM_TYPE mech)
{
	switch(mech) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
		return ALGO_RSA_DECRYPT;
	default:
		return -1;
	}
}



static int decodeECDSASignature(unsigned char *data, int datalen,
								unsigned char *out, int outlen)
{
	int fieldsizebytes, i, r, taglen;
	unsigned char *po, *value;

	FUNC_CALLED();

	r = asn1Validate(data, datalen);

	if (r != 0) {
		FUNC_FAILS(-1, "Signature is not a valid TLV structure");
	}

	// Determine field size from length of signature
	if (datalen <= 58) {			// 192 bit curve = 24 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 24;
	} else if (datalen <= 66) {		// 224 bit curve = 28 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 28;
	} else if (datalen <= 74) {		// 256 bit curve = 32 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 32;
	} else if (datalen <= 90) {		// 320 bit curve = 40 * 2 + 10 byte maximum DER signature
		fieldsizebytes = 40;
	} else {
		fieldsizebytes = 64;
	}

#ifdef DEBUG
	debug("Field size %d, signature buffer size %d\n", fieldsizebytes, outlen);
#endif

	if (outlen < (fieldsizebytes * 2)) {
		FUNC_FAILS(-1, "output too small for EC signature");
	}

	memset(out, 0, outlen);

	po = data;
	if (asn1Tag(&po) != ASN1_SEQUENCE) {
		FUNC_FAILS(-1, "Signature not encapsulated in SEQUENCE");
	}

	r = asn1Length(&po);
	if ((r < 8) || (r > 137)) {
		FUNC_FAILS(-1, "Invalid signature size");
	}

	for (i = 0; i < 2; i++) {
		if (asn1Tag(&po) != ASN1_INTEGER) {
			FUNC_FAILS(-1, "Coordinate not encapsulated in INTEGER");
		}

		taglen = asn1Length(&po);
		value = po;
		po += taglen;

		if (taglen > fieldsizebytes) { /* drop leading 00 if present */
			if (*value != 0x00) {
				FUNC_FAILS(-1, "Invalid value in coordinate");
			}
			value++;
			taglen--;
		}
		memcpy(out + fieldsizebytes * i + fieldsizebytes - taglen , value, taglen);
	}
	FUNC_RETURNS(fieldsizebytes << 1);
}



static int sc_hsm_C_SignInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	int algo;

	FUNC_CALLED();

	algo = getAlgorithmIdForSigning(mech->mechanism);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	FUNC_RETURNS(CKR_OK);
}



static void applyPKCSPadding(unsigned char *di, int dilen, unsigned char *buff, int bufflen)
{
	int i;

	if (dilen + 4 > bufflen) {
		return;
	}

	*buff++ = 0x00;
	*buff++ = 0x01;
	for (i = bufflen - dilen - 3; i > 0; i--) {
		*buff++ = 0xFF;
	}

	*buff++ = 0x00;
	memcpy(buff, di, dilen);
}



static int sc_hsm_C_Sign(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	int rc, algo, signaturelen;
	unsigned short SW1SW2;
	unsigned char scr[256];
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

	algo = getAlgorithmIdForSigning(mech);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	if ((algo == ALGO_EC_RAW) || (algo == ALGO_EC_SHA1)) {
		rc = transmitAPDU(pObject->token->slot, 0x80, 0x68, (unsigned char)pObject->tokenid, (unsigned char)algo,
				ulDataLen, pData,
				0, scr, sizeof(scr), &SW1SW2);
	} else {
		if (mech == CKM_RSA_PKCS) {
			if (signaturelen > sizeof(scr)) {
				FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "Signature length is larger than buffer");
			}
			applyPKCSPadding(pData, ulDataLen, scr, signaturelen);
			rc = transmitAPDU(pObject->token->slot, 0x80, 0x68, (unsigned char)pObject->tokenid, (unsigned char)algo,
				signaturelen, scr,
				0, pSignature, *pulSignatureLen, &SW1SW2);
		} else {
			rc = transmitAPDU(pObject->token->slot, 0x80, 0x68, (unsigned char)pObject->tokenid, (unsigned char)algo,
				ulDataLen, pData,
				0, pSignature, *pulSignatureLen, &SW1SW2);
		}
	}

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Signature operation failed");
	}

	if ((algo == ALGO_EC_RAW) || (algo == ALGO_EC_SHA1)) {
		rc = decodeECDSASignature(scr, rc, pSignature, *pulSignatureLen);
		if (rc < 0) {
			FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
		}
	}

	*pulSignatureLen = rc;
	FUNC_RETURNS(CKR_OK);
}



static int sc_hsm_C_DecryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
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



static int sc_hsm_C_Decrypt(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
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
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Decryption operation failed");
	}

	if (mech == CKM_RSA_X_509) {
		if (rc > *pulDataLen) {
			*pulDataLen = rc;
			FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
		}
		*pulDataLen = rc;
		memcpy(pData, scr, rc);
	} else {
		rc = stripPKCS15Padding(scr, rc, pData, pulDataLen);
		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "Invalid PKCS#1 padding");
		}
	}

	FUNC_RETURNS(CKR_OK);
}



static int encodeGAKP(bytebuffer bb, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, int *keysize)
{
	int rc;
	CK_ULONG keybits;
	struct bytestring_s publicKeyAlgorithm;
	struct bytestring_s oid;
	struct bytestring_s publicExponent;
	struct ec_curve *curve;
	unsigned char scr[2];

	FUNC_CALLED();

	bbClear(bb);
	asn1AppendBytes(bb, 0x5F29, (unsigned char *)"\x00", 1);

	rc = findAttributeInTemplate(CKA_INNER_CAR, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x42, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	}

	int ofs = bbGetLength(bb);

	rc = findAttributeInTemplate(CKA_PUBLIC_KEY_ALGORITHM, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		publicKeyAlgorithm.val = pPublicKeyTemplate[rc].pValue;
		publicKeyAlgorithm.len = pPublicKeyTemplate[rc].ulValueLen;
	} else {
		if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
			publicKeyAlgorithm = defaultAlgorithmEC;
		} else {
			publicKeyAlgorithm = defaultAlgorithmRSA;
		}
	}
	asn1Append(bb, 0x06, &publicKeyAlgorithm);

	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
		rc = findAttributeInTemplate(CKA_EC_PARAMS, pPublicKeyTemplate, ulPublicKeyAttributeCount);
		if (rc < 0) {
			FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "Missing CKA_EC_PARAMS in public key template");
		}

		if ((pPublicKeyTemplate[rc].ulValueLen < 2) || asn1Validate(pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen)) {
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_EC_PARAMS not valid ASN");
		}

		if (*(unsigned char *)pPublicKeyTemplate[rc].pValue != 0x06) {
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_EC_PARAMS not an object identifier");
		}

		oid.val = pPublicKeyTemplate[rc].pValue + 2;
		oid.len = pPublicKeyTemplate[rc].ulValueLen - 2;

		curve = cvcGetCurveForOID(&oid);

		if (curve == NULL) {
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_EC_PARAMS contains unknown curve OID");
		}

		asn1Append(bb, 0x81, &curve->prime);
		asn1Append(bb, 0x82, &curve->coefficientA);
		asn1Append(bb, 0x83, &curve->coefficientB);
		asn1Append(bb, 0x84, &curve->basePointG);
		asn1Append(bb, 0x85, &curve->order);
		asn1Append(bb, 0x87, &curve->coFactor);

		keybits = curve->prime.len << 3;
	} else {
		rc = findAttributeInTemplate(CKA_MODULUS_BITS, pPublicKeyTemplate, ulPublicKeyAttributeCount);
		if (rc < 0) {
			FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "Missing CKA_MODULUS_BITS in public key template");
		}
		if (pPublicKeyTemplate[rc].ulValueLen != sizeof(CK_ULONG)) {
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_MODULUS_BITS not an CK_ULONG");
		}
		keybits = *(CK_ULONG *)pPublicKeyTemplate[rc].pValue;

		rc = findAttributeInTemplate(CKA_PUBLIC_EXPONENT, pPublicKeyTemplate, ulPublicKeyAttributeCount);
		if (rc < 0) {
			publicExponent = defaultPublicExponent;
		} else {
			publicExponent.val = pPublicKeyTemplate[rc].pValue;
			publicExponent.len = pPublicKeyTemplate[rc].ulValueLen;
		}

		asn1Append(bb, 0x82, &publicExponent);
		scr[0] = keybits >> 8;
		scr[1] = keybits & 0xFF;
		asn1AppendBytes(bb, 0x02, scr, 2);
	}

	asn1EncapBuffer(0x7F49, bb, ofs);

	rc = findAttributeInTemplate(CKA_CHR, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x5F20, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	} else {
		asn1Append(bb, 0x5F20, &defaultCHR);
	}

	rc = findAttributeInTemplate(CKA_OUTER_CAR, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x45, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_KEY_USE_COUNTER, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x90, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_ALGORITHM_LIST, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x91, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	}

	if (bbHasFailed(bb)) {
		FUNC_FAILS(CKR_DEVICE_MEMORY, "Buffer to encode GAKP buffer too small");
	}

	*keysize = (int)keybits;
	FUNC_RETURNS(CKR_OK);
}



/**
 * Determine a free key identifier by enumerating all files and locating a free id in the range CC01-CCFF
 */
static int determineFreeKeyId(struct p11Slot_t *slot) {
	unsigned char filelist[MAX_FILES * 2];
	int listlen,i,id;

	FUNC_CALLED();

	listlen = enumerateObjects(slot, filelist, sizeof(filelist));
	if (listlen < 0) {
		FUNC_FAILS(listlen, "enumerateObjects failed");
	}

	for (id = 1; id <= 255; id++) {
		for (i = 0; i < listlen; i += 2) {
			if ((filelist[i] == KEY_PREFIX) && (filelist[i + 1] == id)) {
				break;
			}
		}
		if (i >= listlen) {
			break;
		}
	}

	FUNC_RETURNS(id <= 255 ? id : -1);
}



/**
 * Generate EC or RSA key pair
 */
static int sc_hsm_C_GenerateKeyPair(
		struct p11Slot_t *slot,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		CK_ULONG ulPublicKeyAttributeCount,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG ulPrivateKeyAttributeCount,
		CK_OBJECT_HANDLE_PTR phPublicKey,
		CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	unsigned char buff[512];
	struct bytebuffer_s bb = { buff, 0, sizeof(buff) };
	struct p15PrivateKeyDescription *p15key = NULL;
	unsigned short SW1SW2;
	int rc,id,keysize;

	FUNC_CALLED();

	if ((pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) && (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN)) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism is neither CKM_EC_KEY_PAIR_GEN nor CKM_RSA_PKCS_KEY_PAIR_GEN");
	}

	rc = encodeGAKP(&bb, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, &keysize);

	id = determineFreeKeyId(slot);

	rc = transmitAPDU(slot, 0x00, 0x46, id, 0x00,
			bbGetLength(&bb), buff,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Signature operation failed");
	}

	p15key = calloc(1, sizeof(struct p15PrivateKeyDescription));
	if (p15key == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	p15key->keytype = pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN ? P15_KEYTYPE_ECC : P15_KEYTYPE_RSA;
	p15key->keyReference = id;
	p15key->keysize = keysize;

	rc = findAttributeInTemplate(CKA_SIGN, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pPrivateKeyTemplate[rc].pValue) {
		p15key->usage |= P15_SIGN;
	}

	rc = findAttributeInTemplate(CKA_SIGN_RECOVER, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pPrivateKeyTemplate[rc].pValue) {
		p15key->usage |= P15_SIGNRECOVER;
	}

	rc = findAttributeInTemplate(CKA_DECRYPT, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pPrivateKeyTemplate[rc].pValue) {
		p15key->usage |= P15_DECIPHER;
	}

	rc = findAttributeInTemplate(CKA_DERIVE, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pPrivateKeyTemplate[rc].pValue) {
		p15key->usage |= P15_DERIVE;
	}

	rc = findAttributeInTemplate(CKA_LABEL, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if (rc >= 0) {
		p15key->coa.label = calloc(1, pPrivateKeyTemplate[rc].ulValueLen + 1);
		if (p15key->coa.label == NULL) {
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}
		memcpy(p15key->coa.label, pPrivateKeyTemplate[rc].pValue, pPrivateKeyTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_ID, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if (rc >= 0) {
		p15key->id.val = calloc(1, pPrivateKeyTemplate[rc].ulValueLen);
		if (p15key->id.val == NULL) {
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}
		memcpy(p15key->id.val, pPrivateKeyTemplate[rc].pValue, pPrivateKeyTemplate[rc].ulValueLen);
	}

	rc = encodePrivateKeyDescription(&bb, p15key);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Encoding PRKD failed");
	}

	rc = writeEF(slot, (PRKD_PREFIX << 8) | id, bb.val, bb.len);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Writing PRKD failed");
	}

	FUNC_RETURNS(rc);
}



static int addEECertificateAndKeyObjects(struct p11Token_t *token, unsigned char id)
{
	unsigned char certValue[MAX_CERTIFICATE_SIZE];
	struct p11Object_t *p11cert, *p11pubkey, *p11prikey;
	struct p15PrivateKeyDescription *p15key = NULL;
	struct p15CertificateDescription p15cert;
	unsigned char prkd[MAX_P15_SIZE];
	int rc;

	FUNC_CALLED();

	rc = readEF(token->slot, (PRKD_PREFIX << 8) | id, prkd, sizeof(prkd));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading private key description");
	}

	rc = decodePrivateKeyDescription(prkd, rc, &p15key);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error decoding private key description");
	}

	rc = readEF(token->slot, (EE_CERTIFICATE_PREFIX << 8) | id, certValue, sizeof(certValue));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate");
	}

	// A SmartCard-HSM does not store a separate P15 certificate description. Copy from key description
	memset(&p15cert, 0, sizeof(p15cert));
	p15cert.certtype = P15_CT_X509;
	p15cert.coa = p15key->coa;
	p15cert.id = p15key->id;
	p15cert.isCA = 0;

	rc = createCertificateObjectFromP15(&p15cert, certValue, rc, &p11cert);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create P11 certificate object");
	}

	p11cert->tokenid = (int)id;

	addObject(token, p11cert, TRUE);

	// As a side effect p11cert->keysize is updated with the key size determined from the public key
	rc = createPublicKeyObjectFromCertificate(p15key, p11cert, &p11pubkey);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create public key object");
	}

	addObject(token, p11pubkey, TRUE);

	rc = createPrivateKeyObjectFromP15(p15key, p11cert, FALSE, &p11prikey);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create private key object");
	}

	p11prikey->C_SignInit = sc_hsm_C_SignInit;
	p11prikey->C_Sign = sc_hsm_C_Sign;
	p11prikey->C_DecryptInit = sc_hsm_C_DecryptInit;
	p11prikey->C_Decrypt = sc_hsm_C_Decrypt;

	p11prikey->tokenid = (int)id;
	p11prikey->keysize = p11cert->keysize;

	addObject(token, p11prikey, FALSE);

	freePrivateKeyDescription(&p15key);
	FUNC_RETURNS(CKR_OK);
}



static int addCACertificateObject(struct p11Token_t *token, unsigned char id)
{
	unsigned char certValue[MAX_CERTIFICATE_SIZE];
	struct p11Object_t *p11cert;
	struct p15CertificateDescription *p15cert;
	unsigned char cd[MAX_P15_SIZE];
	int rc;

	FUNC_CALLED();

	rc = readEF(token->slot, (CD_PREFIX << 8) | id, cd, sizeof(cd));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate description");
	}

	rc = decodeCertificateDescription(cd, rc, &p15cert);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error decoding certificate description");
	}

	rc = readEF(token->slot, (CA_CERTIFICATE_PREFIX << 8) | id, certValue, sizeof(certValue));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate");
	}

	p15cert->isCA = 1;
	rc = createCertificateObjectFromP15(p15cert, certValue, rc, &p11cert);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create P11 certificate object");
	}

	p11cert->tokenid = (int)id;

	addObject(token, p11cert, TRUE);

	freeCertificateDescription(&p15cert);
	FUNC_RETURNS(CKR_OK);
}



static int sc_hsm_loadObjects(struct p11Token_t *token)
{
	unsigned char filelist[MAX_FILES * 2];
	struct p11Slot_t *slot = token->slot;
	int rc,listlen,i,id,prefix;

	FUNC_CALLED();

	rc = enumerateObjects(slot, filelist, sizeof(filelist));
	if (rc < 0) {
		FUNC_FAILS(rc, "enumerateObjects failed");
	}

	listlen = rc;
	for (i = 0; i < listlen; i += 2) {
		prefix = filelist[i];
		id = filelist[i + 1];

		switch(prefix) {
		case KEY_PREFIX:
			if (id != 0) {				// Skip Device Authentication Key
				rc = addEECertificateAndKeyObjects(token, id);
				if (rc != CKR_OK) {
#ifdef DEBUG
					debug("addEECertificateAndKeyObjects failed with rc=%d\n", rc);
#endif
				}
			}
			break;
		case CA_CERTIFICATE_PREFIX:
			rc = addCACertificateObject(token, id);
			if (rc != CKR_OK) {
#ifdef DEBUG
				debug("addCACertificateAndKeyObjects failed with rc=%d\n", rc);
#endif
			}
			break;
		}
	}

	FUNC_RETURNS(CKR_OK);
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



/**
 * Encode SO-PIN from 16 hexadecimal characters into BCD encoding
 */
static int parseSOPIN(unsigned char *pin, unsigned char *encodedPIN)
{
	unsigned char *p, c;
	int i;

	p = encodedPIN;
	for (i = 0; i < 16; i++, pin++) {
		if (!(i & 1)) {
			*p = 0;
		}
		c = toupper(*pin);
		if (!isxdigit(c))
			return -1;
		*p = (*p << 4) | ((c >= '0') && (c <= '9') ? c - '0' : c - 'A');
		if (i & 1) {
			p++;
		}
	}

	return 0;
}



/**
 * Perform PIN verification and make private objects visible
 *
 * @param slot      The slot in which the token is inserted
 * @param userType  One of CKU_SO, CKU_CONTEXT_SPECIFIC or CKU_USER
 * @param pin       Pointer to PIN value or NULL if PIN shall be verified using PIN-Pad
 * @param pinLen    The length of the PIN supplied in pin
 * @return          CKR_OK or any other Cryptoki error code
 */
static int sc_hsm_login(struct p11Slot_t *slot, int userType, unsigned char *pin, int pinlen)
{
	int rc = CKR_OK;
	unsigned short SW1SW2;
	struct token_sc_hsm *sc;

	FUNC_CALLED();

	if (userType == CKU_SO) {
		sc = getPrivateData(slot->token);

		if (pinlen != 16) {
			FUNC_FAILS(CKR_PIN_LEN_RANGE, "SO-PIN must be 16 characters long");
		}
		if (parseSOPIN(pin, sc->sopin) < 0) {
			FUNC_FAILS(CKR_ARGUMENTS_BAD, "SO-PIN must contain only hexadecimal characters");
		}
	} else {

		if ((slot->token->info.flags & CKF_PROTECTED_AUTHENTICATION_PATH) && !pinlen && !pin) {
#ifdef DEBUG
			debug("Verify PIN using CKF_PROTECTED_AUTHENTICATION_PATH\n");
#endif
			rc = transmitVerifyPinAPDU(slot, 0x00, 0x20, 0x00, 0x81,
					0, NULL,
					&SW1SW2,
					PIN_SYSTEM_UNIT_BYTES + PIN_POSITION_0 + PIN_LEFT_JUSTIFICATION + PIN_FORMAT_ASCII, /* bmFormatString */
					0x06, 0x0F, /* Minimum and maximum length of PIN */
					0x00, /* bmPINBlockString: no inserted PIN length, no PIN block size*/
					0x00 /* bmPINLengthFormat: no PIN length insertion - set to all zeros */
					);
		} else {
#ifdef DEBUG
			debug("Verify PIN using provided PIN value\n");
#endif
			rc = transmitAPDU(slot, 0x00, 0x20, 0x00, 0x81,
				pinlen, pin,
				0, NULL, 0, &SW1SW2);
		}

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
		}

		rc = updatePinStatus(slot->token, SW1SW2);

		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "sc_hsm_login failed");
		}
	}

	FUNC_RETURNS(rc);
}



/**
 * Reselect applet in order to reset authentication state
 *
 * @param slot      The slot in which the token is inserted
 * @return          CKR_OK or any other Cryptoki error code
 */
static int sc_hsm_logout(struct p11Slot_t *slot)
{
	int rc;
	struct token_sc_hsm *sc;

	FUNC_CALLED();

	sc = getPrivateData(slot->token);
	memset(sc->sopin, 0, sizeof(sc->sopin));

	rc = selectApplet(slot);
	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "applet selection failed");
	}

	rc = checkPINStatus(slot);
	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "checkPINStatus failed");
	}

	updatePinStatus(slot->token, rc);

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
static int sc_hsm_initpin(struct p11Slot_t *slot, unsigned char *pin, int pinlen)
{
	int rc = CKR_OK;
	unsigned short SW1SW2;
	unsigned char data[24];
	struct token_sc_hsm *sc;

	FUNC_CALLED();

	if ((pinlen < 0) || (pinlen > 16)) {
		FUNC_FAILS(CKR_PIN_LEN_RANGE, "PIN must not exceed 16 characters");
	}

	sc = getPrivateData(slot->token);
	memcpy(data, sc->sopin, sizeof(sc->sopin));
	if (pin != NULL)
		memcpy(data + sizeof(sc->sopin), pin, pinlen);

#ifdef DEBUG
	debug("Init PIN using provided PIN value\n");
#endif
	rc = transmitAPDU(slot, 0x00, 0x2C, pinlen ? 0x00 : 0x01, 0x81,
		pinlen + sizeof(sc->sopin), data,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(CKR_PIN_INCORRECT, "Invalid SO-PIN");
	}

	rc = checkPINStatus(slot);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	updatePinStatus(slot->token, rc);

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
static int sc_hsm_setpin(struct p11Slot_t *slot, unsigned char *oldpin, int oldpinlen, unsigned char *newpin, int newpinlen)
{
	int rc = CKR_OK, len;
	unsigned short SW1SW2;
	unsigned char data[32], p2;

	FUNC_CALLED();

	if (slot->token->user == CKU_SO) {
		if (oldpinlen != 16) {
			FUNC_FAILS(CKR_PIN_LEN_RANGE, "Old PIN must be 16 characters");
		}

		if (newpinlen != 16) {
			FUNC_FAILS(CKR_PIN_LEN_RANGE, "New PIN must be 16 characters");
		}

		if (parseSOPIN(oldpin, data) < 0) {
			FUNC_FAILS(CKR_ARGUMENTS_BAD, "Old SO-PIN must contain only hexadecimal characters");
		}

		if (parseSOPIN(newpin, data + 8) < 0) {
			FUNC_FAILS(CKR_ARGUMENTS_BAD, "New SO-PIN must contain only hexadecimal characters");
		}

		len = 16;
		p2 = 0x88;
	} else {
		if ((oldpinlen < 0) || (oldpinlen > 16)) {
			FUNC_FAILS(CKR_PIN_LEN_RANGE, "Old PIN must not exceed 16 characters");
		}

		if ((newpinlen < 0) || (newpinlen > 16)) {
			FUNC_FAILS(CKR_PIN_LEN_RANGE, "New PIN must not exceed 16 characters");
		}

		memcpy(data, oldpin, oldpinlen);
		memcpy(data + oldpinlen, newpin, newpinlen);
		len = oldpinlen + newpinlen;
		p2 = 0x81;
	}

#ifdef DEBUG
	debug("Set PIN using provided PIN value\n");
#endif
	rc = transmitAPDU(slot, 0x00, 0x24, 0x00, p2,
		len, data,
		0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	if (slot->token->user == CKU_SO) {
		if (SW1SW2 != 0x9000) {
			FUNC_FAILS(CKR_PIN_INCORRECT, "Incorrect old SO-PIN");
		}
	} else {
		rc = updatePinStatus(slot->token, SW1SW2);
	}

	FUNC_RETURNS(rc);
}



struct p11TokenDriver *getSmartCardHSMTokenDriver();

/**
 * Create a new SmartCard-HSM token if token detection and initialization is successful
 *
 * @param slot      The slot in which a token was detected
 * @param token     Pointer to pointer updated with newly created token structure
 * @return          CKR_OK or any other Cryptoki error code
 */
int newSmartCardHSMToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	struct p11Token_t *ptoken;
	int rc, pinstatus;

	FUNC_CALLED();

	rc = checkPINStatus(slot);
	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "checkPINStatus failed");
	}

	if (rc != 0x9000) {
		rc = selectApplet(slot);
		if (rc < 0) {
			FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "applet selection failed");
		}

		rc = checkPINStatus(slot);
		if (rc < 0) {
			FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "checkPINStatus failed");
		}
	}
	pinstatus = rc;

	ptoken = (struct p11Token_t *)calloc(sizeof(struct p11Token_t) + sizeof(struct token_sc_hsm), 1);

	if (ptoken == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	ptoken->slot = slot;
	ptoken->freeObjectNumber = 1;
	strbpcpy(ptoken->info.label, "SmartCard-HSM", sizeof(ptoken->info.label));
	strbpcpy(ptoken->info.manufacturerID, "CardContact (www.cardcontact.de)", sizeof(ptoken->info.manufacturerID));
	strbpcpy(ptoken->info.model, "SmartCard-HSM", sizeof(ptoken->info.model));
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

	if (slot->hasFeatureVerifyPINDirect)
		ptoken->info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;

	ptoken->user = INT_CKU_NO_USER;
	ptoken->drv = getSmartCardHSMTokenDriver();

	updatePinStatus(ptoken, pinstatus);

	sc_hsm_loadObjects(ptoken);

	rc = addToken(slot, ptoken);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "addToken() failed");
	}

	*token = ptoken;
	return CKR_OK;
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
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
		pInfo->flags = CKF_SIGN;
		pInfo->flags |= CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_GENERATE_KEY_PAIR;	// Quick fix for Peter Gutmann's cryptlib
		pInfo->ulMinKeySize = 1024;
		pInfo->ulMaxKeySize = 2048;
		break;

	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
		pInfo->flags = CKF_SIGN;
		pInfo->flags |= CKF_HW|CKF_VERIFY|CKF_GENERATE_KEY_PAIR; // Quick fix for Peter Gutmann's cryptlib
		pInfo->ulMinKeySize = 192;
		pInfo->ulMaxKeySize = 320;
		break;

	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

	FUNC_RETURNS(rv);

}



struct p11TokenDriver *getSmartCardHSMTokenDriver()
{
	static struct p11TokenDriver sc_hsm_token = {
		"SmartCard-HSM",
		1,
		MAX_EXT_APDU_LENGTH,
		MAX_EXT_APDU_LENGTH,
		0,
		isCandidate,
		newSmartCardHSMToken,
		NULL,
		getMechanismList,
		getMechanismInfo,
		sc_hsm_login,
		sc_hsm_logout,
		sc_hsm_initpin,
		sc_hsm_setpin,

		sc_hsm_C_DecryptInit,	// int (*C_DecryptInit)  (struct p11Object_t *, CK_MECHANISM_PTR);
		sc_hsm_C_Decrypt,		// int (*C_Decrypt)      (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
		NULL,					// int (*C_DecryptUpdate)(struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
		NULL,					// int (*C_DecryptFinal) (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

		sc_hsm_C_SignInit,		// int (*C_SignInit)     (struct p11Object_t *, CK_MECHANISM_PTR);
		sc_hsm_C_Sign,			// int (*C_Sign)         (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
		NULL,					// int (*C_SignUpdate)   (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG);
		NULL,					// int (*C_SignFinal)    (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

		sc_hsm_C_GenerateKeyPair
	};

	return &sc_hsm_token;
}
