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

#include <common/asn1.h>
#include <common/cvc.h>
#include <common/pkcs15.h>
#include <common/debug.h>

#include <pkcs11/slot.h>
#include <pkcs11/object.h>
#include <pkcs11/token.h>
#include <pkcs11/certificateobject.h>
#include <pkcs11/privatekeyobject.h>
#include <pkcs11/publickeyobject.h>
#include <pkcs11/secretkeyobject.h>
#include <pkcs11/strbpcpy.h>
#include <pkcs11/crypto.h>



static unsigned char aid[] = { 0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01 };

static unsigned char atrJCOP41[] = { 0x3B,0xF8,0x13,0x00,0x00,0x81,0x31,0xFE,0x45,0x4A,0x43,0x4F,0x50,0x76,0x32,0x34,0x31,0xB7 };
static unsigned char atrHSM[]    = { 0x3B,0xFE,0x18,0x00,0x00,0x81,0x31,0xFE,0x45,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0xFA };
static unsigned char atrHSMCL[]  = { 0x3B,0x8E,0x80,0x01,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0x18 };
static unsigned char atrJCOP3[]  = { 0x3B,0xDE,0x18,0xFF,0x81,0x91,0xFE,0x1F,0xC3,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0x1C };
static unsigned char atrJCOP3F[] = { 0x3B,0xDE,0x96,0xFF,0x81,0x91,0xFE,0x1F,0xC3,0x80,0x31,0x81,0x54,0x48,0x53,0x4D,0x31,0x73,0x80,0x21,0x40,0x81,0x07,0x92 };


static struct bytestring_s defaultAlgorithmRSA = { (unsigned char *)"\x04\x00\x7F\x00\x07\x02\x02\x02\x01\x02", 10 };
static struct bytestring_s defaultAlgorithmEC = { (unsigned char *)"\x04\x00\x7F\x00\x07\x02\x02\x02\x02\x03", 10 };
static struct bytestring_s defaultCHR = { (unsigned char *)"UTDUMMY00000", 12 };
static struct bytestring_s defaultPublicExponent = { (unsigned char *)"\x01\x00\x01", 3 };
static struct bytestring_s defaultAESAlgorithms = { (unsigned char *)"\x10\x11\x18\x99", 4 };



static const CK_MECHANISM_TYPE p11MechanismList[] = {
		CKM_RSA_X_509,
		CKM_RSA_PKCS,
		CKM_RSA_PKCS_PSS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA1_RSA_PKCS_PSS,
		CKM_SHA256_RSA_PKCS_PSS,
		CKM_ECDSA,
		CKM_ECDSA_SHA1,
		CKM_AES_CBC,
		CKM_AES_CMAC,
#ifdef ENABLE_LIBCRYPTO
		CKM_RSA_PKCS_OAEP,
		CKM_SHA_1,
		CKM_SHA224,
		CKM_SHA256,
		CKM_SHA384,
		CKM_SHA512,
#endif
		CKM_EC_KEY_PAIR_GEN,
		CKM_RSA_PKCS_KEY_PAIR_GEN,
		CKM_AES_KEY_GEN,
		CKM_SC_HSM_PSS_SHA1,
		CKM_SC_HSM_PSS_SHA256,
		CKM_SC_HSM_ECDSA_SHA224,
		CKM_SC_HSM_ECDSA_SHA256
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

	if ((atrLen == sizeof(atrJCOP3)) && !memcmp(atr, atrJCOP3, atrLen))
		return 1;

	if ((atrLen == sizeof(atrJCOP3F)) && !memcmp(atr, atrJCOP3F, atrLen))
		return 1;

	return 0;
}



static int checkPINStatus(struct p11Slot_t *slot, unsigned char ref)
{
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x00, 0x20, 0x00, ref,
			0, NULL,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	FUNC_RETURNS(SW1SW2);
}



static int selectApplet(struct p11Slot_t *slot, unsigned char *tag85, size_t *tag85len)
{
	int rc;
	unsigned short SW1SW2;
	unsigned char scr[256], *po;
	FUNC_CALLED();

	rc = transmitAPDU(slot, 0x00, 0xA4, 0x04, 0x04,
			sizeof(aid), aid,
			0, scr, sizeof(scr), &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Token is not a SmartCard-HSM");
	}

	if (tag85 != NULL) {
		po = asn1Find(scr, (unsigned char*)"\x62\x85", 2);
		if ((po != NULL) && (*(po + 1) <= *tag85len)) {
			*tag85len = *(po + 1);
			memcpy(tag85, po + 2, *tag85len);
		}
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
			65536, filelist, (int)len, &SW1SW2);

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
	int rc,blk,rlen;
	unsigned short SW1SW2;
	unsigned char t54[] = { 0x54, 0x02, 0x00, 0x00 };

	FUNC_CALLED();

	blk = 65536;
	rlen = 0;

	if (slot->noExtLengthReadAll) {
		blk = slot->maxRAPDU - 2;
		if (blk > (int)len) {
			blk = (int)len;
		}
	}
	do	{
		t54[2] = rlen >> 8;
		t54[3] = rlen & 0xFF;

		rc = transmitAPDU(slot, 0x00, 0xB1, fid >> 8, fid & 0xFF,
				sizeof(t54), t54,
				blk, content, (int)len, &SW1SW2);

		if (rc < 0) {
			FUNC_FAILS(rc, "transmitAPDU failed");
		}

		if ((SW1SW2 != 0x9000) && (SW1SW2 != 0x6282)) {
			FUNC_FAILS(-1, "Read EF failed");
		}

		rlen += rc;

		if ((rc == 0) || (blk == 65536) || (SW1SW2 == 0x6282)) {
			FUNC_RETURNS(rlen);
		}

		content += rc;
		len -= rc;

		if (blk > (int)len) {
			blk = (int)len;
		}
	} while ((rc > 0) && (len > 0));

	FUNC_RETURNS(rlen);
}



static int writeEF(struct p11Slot_t *slot, unsigned short fid, unsigned char *content, size_t len)
{
	int rc, blen, ofs;
	size_t maxblk;
	unsigned short SW1SW2;
	unsigned char buff[MAX_CAPDU],*p;

	FUNC_CALLED();

	maxblk = slot->token->drv->maxCAPDU;	// Limit defined by token
	if ((int)maxblk > slot->maxCAPDU) {
		maxblk = slot->maxCAPDU;			// Limit defined by slot
	}

	maxblk -= 15;			// Maximum block size
	ofs = 0;
	rc = CKR_OK;

	while (len > 0) {
		blen = (int)(len > maxblk ? maxblk : len);

		p = buff;

		*p++ = 0x54;
		*p++ = 0x02;
		*p++ = ofs >> 8;
		*p++ = ofs & 0xFF;
		*p++ = 0x53;
		asn1StoreLength(&p, blen);

		memcpy(p, content, blen);
		content += blen;
		ofs += blen;
		len -= blen;
		blen += (int)(p - buff);

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



static int deleteEF(struct p11Slot_t *slot, unsigned short fid)
{
	int rc;
	unsigned char scr[2];
	unsigned short SW1SW2;
	FUNC_CALLED();

	scr[0] = fid >> 8;
	scr[1] = fid & 0xFF;

	rc = transmitAPDU(slot, 0x00, 0xE4, 0x02, 0x00,
			2, scr,
			0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(rc, "transmitAPDU failed");
	}

	if (SW1SW2 != 0x9000) {
		FUNC_FAILS(-1, "Delete EF failed");
	}

	FUNC_RETURNS(CKR_OK);
}



static int getSignatureSize(CK_MECHANISM_TYPE mech, struct p11Object_t *pObject)
{
	switch(mech) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_SC_HSM_PSS_SHA1:
	case CKM_SC_HSM_PSS_SHA256:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SHA384_RSA_PKCS_PSS:
	case CKM_SHA512_RSA_PKCS_PSS:
		return (pObject->keysize + 7) >> 3;
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_SC_HSM_ECDSA_SHA224:
	case CKM_SC_HSM_ECDSA_SHA256:
		return (pObject->keysize + 7) >> 2 & ~1;
	case CKM_AES_CMAC:
		return 16;
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
	case CKM_SHA384_RSA_PKCS_PSS:
		return ALGO_RSA_PSS_SHA384;
	case CKM_SHA512_RSA_PKCS_PSS:
		return ALGO_RSA_PSS_SHA512;
	case CKM_ECDSA:
		return ALGO_EC_RAW;
	case CKM_ECDSA_SHA1:
		return ALGO_EC_SHA1;
	case CKM_SC_HSM_ECDSA_SHA224:
		return ALGO_EC_SHA224;
	case CKM_SC_HSM_ECDSA_SHA256:
		return ALGO_EC_SHA256;
	case CKM_RSA_PKCS_PSS:
	case CKM_SC_HSM_PSS_SHA1:
	case CKM_SC_HSM_PSS_SHA256:
		return ALGO_RSA_PSS;
	case CKM_AES_CMAC:
		return ALGO_AES_CMAC;
	default:
		return -1;
	}
}



static int getAlgorithmIdForEncryption(CK_MECHANISM_TYPE mech)
{
	switch(mech) {
	case CKM_AES_CBC:
		return ALGO_AES_CBC_ENCRYPT;
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
#ifdef ENABLE_LIBCRYPTO
	case CKM_RSA_PKCS_OAEP:
		return ALGO_RSA_DECRYPT;
#endif
	case CKM_AES_CBC:
		return ALGO_AES_CBC_DECRYPT;
	default:
		return -1;
	}
}



static int decodeECDSASignature(int fieldsizebytes, unsigned char *data, int datalen,
								unsigned char *out, int outlen)
{
	int i, r, taglen;
	unsigned char *po, *value;

	FUNC_CALLED();

	r = (int)asn1Validate(data, datalen);

	if (r != 0) {
		FUNC_FAILS(-1, "Signature is not a valid TLV structure");
	}

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



static CK_RV sc_hsm_C_SignInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	int algo;

	FUNC_CALLED();

	algo = getAlgorithmIdForSigning(mech->mechanism);
	if (algo < 0) {
#ifdef DEBUG
		debug("Mechanism %lx unknown\n", mech->mechanism);
#endif
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



static CK_RV sc_hsm_C_Sign(struct p11Object_t *pObject, CK_MECHANISM_PTR mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	int rc, algo, signaturelen;
	unsigned short SW1SW2;
	unsigned char scr[512];
	FUNC_CALLED();

	rc = getSignatureSize(mech->mechanism, pObject);
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

	algo = getAlgorithmIdForSigning(mech->mechanism);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	if ((mech->mechanism == CKM_SC_HSM_PSS_SHA1) && ulDataLen != 20) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Input for CKM_SC_HSM_PSS_SHA1 must be 20 bytes long");
	}

	if ((mech->mechanism == CKM_SC_HSM_PSS_SHA256) && ulDataLen != 32) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Input for CKM_SC_HSM_PSS_SHA256 must be 32 bytes long");
	}

	if ((algo == ALGO_EC_RAW) || (algo == ALGO_EC_SHA1) || (algo == ALGO_EC_SHA224) || (algo == ALGO_EC_SHA256)) {
		rc = transmitAPDU(pObject->token->slot, 0x80, 0x68, (unsigned char)pObject->tokenid, (unsigned char)algo,
				ulDataLen, pData,
				0, scr, sizeof(scr), &SW1SW2);
	} else if (algo == ALGO_AES_CMAC) {
		rc = transmitAPDU(pObject->token->slot, 0x80, 0x78, (unsigned char)pObject->tokenid, (unsigned char)algo,
				ulDataLen, pData,
				0, pSignature, *pulSignatureLen, &SW1SW2);
	} else {
		if (mech->mechanism == CKM_RSA_PKCS) {
			if (signaturelen > sizeof(scr)) {
				FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "Signature length is larger than buffer");
			}
			applyPKCSPadding(pData, ulDataLen, scr, signaturelen);
			rc = transmitAPDU(pObject->token->slot, 0x80, 0x68, (unsigned char)pObject->tokenid, (unsigned char)algo,
				signaturelen, scr,
				0x10000, pSignature, *pulSignatureLen, &SW1SW2);
		} else {
			rc = transmitAPDU(pObject->token->slot, 0x80, 0x68, (unsigned char)pObject->tokenid, (unsigned char)algo,
				ulDataLen, pData,
				0x10000, pSignature, *pulSignatureLen, &SW1SW2);
		}
	}

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	switch(SW1SW2) {
	case 0x9000:
		break;
	case 0x6984:
		FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Key user counter expired");
		break;
	case 0x6A81:
		FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Decryption operation not allowed for key");
		break;
	case 0x6982:
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
		break;
	default:
		FUNC_FAILS(CKR_DEVICE_ERROR, "Signature operation failed");
		break;
	}

	if ((algo == ALGO_EC_RAW) || (algo == ALGO_EC_SHA1) || (algo == ALGO_EC_SHA224) || (algo == ALGO_EC_SHA256)) {
		rc = decodeECDSASignature((pObject->keysize + 7) >> 3, scr, rc, pSignature, *pulSignatureLen);
		if (rc < 0) {
			FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
		}
	}

	*pulSignatureLen = rc;
	FUNC_RETURNS(CKR_OK);
}



static CK_RV sc_hsm_C_EncryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	int algo;

	FUNC_CALLED();

	algo = getAlgorithmIdForEncryption(mech->mechanism);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	if ((algo == ALGO_AES_CBC_ENCRYPT) && mech->ulParameterLen && ((mech->ulParameterLen != 16) || (mech->pParameter == NULL))) {
		FUNC_FAILS(CKR_MECHANISM_PARAM_INVALID, "IV must be 16 bytes");
	}

	FUNC_RETURNS(CKR_OK);
}



static CK_RV sc_hsm_C_DecryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	int algo;

	FUNC_CALLED();

	algo = getAlgorithmIdForDecryption(mech->mechanism);
	if (algo < 0) {
#ifdef DEBUG
		debug("Mechanism %lx unknown\n", mech->mechanism);
#endif
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	if ((algo == ALGO_AES_CBC_DECRYPT) && mech->ulParameterLen && ((mech->ulParameterLen != 16) || (mech->pParameter == NULL))) {
		FUNC_FAILS(CKR_MECHANISM_PARAM_INVALID, "IV must be 16 bytes");
	}

	FUNC_RETURNS(CKR_OK);
}



static void xor(CK_BYTE_PTR buff1, CK_BYTE_PTR buff2, int len)
{
	while(len-- > 0) {
		*buff1++ ^= *buff2++;
	}
}



static CK_RV sc_hsm_C_Encrypt(struct p11Object_t *pObject, CK_MECHANISM_PTR mech, CK_BYTE_PTR pData, CK_ULONG pulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR ulEncryptedDataLen)
{
	int rc, algo;
	unsigned short SW1SW2;
	unsigned char scr[2048];

	FUNC_CALLED();

	if (pEncryptedData == NULL) {
		*ulEncryptedDataLen = pulDataLen;
		FUNC_RETURNS(CKR_OK);
	}

	algo = getAlgorithmIdForEncryption(mech->mechanism);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	if (mech->ulParameterLen && (algo == ALGO_AES_CBC_ENCRYPT)) {
		if (pulDataLen > sizeof(scr)) {
			FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Input too large");
		}

		if (pulDataLen < 16) {
			FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Input too short");
		}

		if (pulDataLen &0x0F) {
			FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Input not a multiple of 16");
		}

		memcpy(scr, pData, pulDataLen);
		xor(scr, (CK_BYTE_PTR)mech->pParameter, (int)mech->ulParameterLen);

		rc = transmitAPDU(pObject->token->slot, 0x80, 0x78, (unsigned char)pObject->tokenid, (unsigned char)algo,
				pulDataLen, scr,
				0, scr, sizeof(scr), &SW1SW2);
	} else {
		rc = transmitAPDU(pObject->token->slot, 0x80, 0x78, (unsigned char)pObject->tokenid, (unsigned char)algo,
				pulDataLen, pData,
				0, scr, sizeof(scr), &SW1SW2);
	}

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	switch(SW1SW2) {
	case 0x9000:
		break;
	case 0x6A81:
		FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Encryption operation not allowed for key");
		break;
	case 0x6982:
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
		break;
	case 0x6A80:
		FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Encryption operation failed");
		break;
	default:
		FUNC_FAILS(CKR_DEVICE_ERROR, "Encryption operation failed");
		break;
	}

	if (rc > (int)*ulEncryptedDataLen) {
		*ulEncryptedDataLen = rc;
		memset(scr, 0, sizeof(scr));
		FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
	}
	*ulEncryptedDataLen = rc;
	memcpy(pEncryptedData, scr, rc);

	memset(scr, 0, sizeof(scr));

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

	if (len > (int)*pulDataLen) {
		return CKR_BUFFER_TOO_SMALL;
	}

	memcpy(pData, scr, len);
	*pulDataLen = len;

	return CKR_OK;
}



static CK_RV sc_hsm_C_Decrypt(struct p11Object_t *pObject, CK_MECHANISM_PTR mech, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	int rc, algo, ins;
	unsigned short SW1SW2;
	unsigned char scr[2048];

	FUNC_CALLED();

	if (pData == NULL) {
		if (mech->mechanism == CKM_AES_CBC) {
			*pulDataLen = ulEncryptedDataLen;
		} else {
			*pulDataLen = (pObject->keysize + 7) >> 3;
		}
		FUNC_RETURNS(CKR_OK);
	}

	algo = getAlgorithmIdForDecryption(mech->mechanism);
	if (algo < 0) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	if (mech->mechanism == CKM_AES_CBC) {
		ins = 0x78;
	} else {
		ins = 0x62;
	}

	rc = transmitAPDU(pObject->token->slot, 0x80, ins, (unsigned char)pObject->tokenid, (unsigned char)algo,
			ulEncryptedDataLen, pEncryptedData,
			0, scr, sizeof(scr), &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
	}

	switch(SW1SW2) {
	case 0x9000:
		break;
	case 0x6984:
		FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Key user counter expired");
		break;
	case 0x6A81:
		FUNC_FAILS(CKR_KEY_FUNCTION_NOT_PERMITTED, "Decryption operation not allowed for key");
		break;
	case 0x6982:
		FUNC_FAILS(CKR_USER_NOT_LOGGED_IN, "User not logged in");
		break;
	case 0x6A80:
		FUNC_FAILS(CKR_ENCRYPTED_DATA_INVALID, "Decryption operation failed");
		break;
	default:
		FUNC_FAILS(CKR_DEVICE_ERROR, "Decryption operation failed");
		break;
	}

	if ((mech->mechanism == CKM_RSA_X_509)
			|| (mech->mechanism == CKM_AES_CBC)) {
		if (rc > (int)*pulDataLen) {
			*pulDataLen = rc;
			FUNC_FAILS(CKR_BUFFER_TOO_SMALL, "supplied buffer too small");
		}

		if (mech->ulParameterLen && (algo == ALGO_AES_CBC_DECRYPT)) {
			xor(scr, (CK_BYTE_PTR)mech->pParameter, (int)mech->ulParameterLen);
		}

		*pulDataLen = rc;
		memcpy(pData, scr, rc);
	} else if (mech->mechanism == CKM_RSA_PKCS) {
		rc = stripPKCS15Padding(scr, rc, pData, pulDataLen);
		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "Invalid PKCS#1 padding");
		}
	} else {
#ifdef ENABLE_LIBCRYPTO
		rc = stripOAEPPadding(scr, rc, pData, pulDataLen);
		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "Invalid OAEP padding");
		}
#endif
	}

	memset(scr, 0, sizeof(scr));

	FUNC_RETURNS(CKR_OK);
}



static int sc_hsm_C_GenerateRandom(struct p11Slot_t *slot, CK_BYTE_PTR rnd, CK_ULONG rndlen)
{
	unsigned short SW1SW2;
	size_t maxblk;
	int rc;

	FUNC_CALLED();

	maxblk = 1024;			// Maximum block size

	if ((int)maxblk + 2 > slot->maxRAPDU) {
		maxblk = slot->maxRAPDU - 2;
	}
	while (rndlen > 0) {
		if (rndlen < maxblk) {
			maxblk = rndlen;
		}
		rc = transmitAPDU(slot, 0x00, 0x84, 0x00, 0x00,
				0, NULL,
				(int)maxblk, rnd, rndlen, &SW1SW2);

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



static int encodeGSK(bytebuffer bb, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulKeyAttributeCount)
{
	int rc;
	CK_ULONG kuc;
	unsigned char scr[4];
	FUNC_CALLED();

	bbClear(bb);

	rc = findAttributeInTemplate(CKA_SC_HSM_ALGORITHM_LIST, pTemplate, ulKeyAttributeCount);
	if (rc >= 0) {
		if (pTemplate[rc].pValue == NULL || pTemplate[rc].ulValueLen > 16) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_ALGORITHM_LIST must not be longer that 16 bytes");
		}
		asn1AppendBytes(bb, 0x91, pTemplate[rc].pValue, pTemplate[rc].ulValueLen);
	} else {
		asn1AppendBytes(bb, 0x91, defaultAESAlgorithms.val, defaultAESAlgorithms.len);
	}

	rc = findAttributeInTemplate(CKA_SC_HSM_KEY_USE_COUNTER, pTemplate, ulKeyAttributeCount);
	if (rc >= 0) {
		if (pTemplate[rc].pValue == NULL || pTemplate[rc].ulValueLen != sizeof(CK_ULONG)) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_KEY_USE_COUNTER must be CK_ULONG");
		}
		kuc = *(CK_ULONG *)pTemplate[rc].pValue;

		if ((kuc < 1) || (kuc > 0xFFFFFFFF)) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_KEY_USE_COUNTER is not in the range between 1 and 2^32");
		}

		scr[0] = (unsigned char)((kuc >> 24) & 0xFF);
		scr[1] = (unsigned char)((kuc >> 16) & 0xFF);
		scr[2] = (unsigned char)((kuc >>  8) & 0xFF);
		scr[3] = (unsigned char)( kuc & 0xFF);
		asn1AppendBytes(bb, 0x90, scr, 4);
	}

	rc = findAttributeInTemplate(CKA_SC_HSM_KEY_DOMAIN, pTemplate, ulKeyAttributeCount);
	if (rc >= 0) {
		if (pTemplate[rc].pValue == NULL || pTemplate[rc].ulValueLen != 1) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_KEY_DOMAIN must be a single CK_BYTE");
		}
		asn1AppendBytes(bb, 0x92, pTemplate[rc].pValue, pTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_SC_HSM_WRAPPING_KEY_ID, pTemplate, ulKeyAttributeCount);
	if (rc >= 0) {
		if (pTemplate[rc].pValue == NULL || pTemplate[rc].ulValueLen != 1) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_WRAPPING_KEY_ID must be a single CK_BYTE");
		}
		asn1AppendBytes(bb, 0x93, pTemplate[rc].pValue, pTemplate[rc].ulValueLen);
	}

	if (bbHasFailed(bb)) {
		FUNC_FAILS(CKR_DEVICE_MEMORY, "Buffer to encode GSK buffer too small");
	}

	FUNC_RETURNS(CKR_OK);
}



static int encodeGAKP(bytebuffer bb, struct p11Token_t *token, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pPublicKeyTemplate, CK_ULONG ulPublicKeyAttributeCount, int *keysize)
{
	int rc,pos,ofs;
	CK_ULONG keybits,kuc;
	struct bytestring_s publicKeyAlgorithm;
	struct bytestring_s oid;
	struct bytestring_s publicExponent;
	struct ec_curve *curve, crve;
	unsigned char scr[4];

	FUNC_CALLED();

	bbClear(bb);
	asn1AppendBytes(bb, 0x5F29, (unsigned char *)"\x00", 1);

	rc = findAttributeInTemplate(CKA_CVC_INNER_CAR, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x42, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	} else {
		if (token->info.firmwareVersion.major < 2) {
			asn1Append(bb, 0x42, &defaultCHR);
		}
	}

	ofs = (int)bbGetLength(bb);

	rc = findAttributeInTemplate(CKA_SC_HSM_PUBLIC_KEY_ALGORITHM, pPublicKeyTemplate, ulPublicKeyAttributeCount);
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
		pos = findAttributeInTemplate(CKA_EC_PARAMS, pPublicKeyTemplate, ulPublicKeyAttributeCount);
		if (pos < 0) {
			FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "Missing CKA_EC_PARAMS in public key template");
		}

		if ((pPublicKeyTemplate[pos].ulValueLen < 2) || asn1Validate(pPublicKeyTemplate[pos].pValue, pPublicKeyTemplate[pos].ulValueLen)) {
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_EC_PARAMS not valid ASN");
		}

		if (*(unsigned char *)pPublicKeyTemplate[pos].pValue == 0x06) {
			oid.val = (unsigned char *)pPublicKeyTemplate[pos].pValue + 2;
			oid.len = pPublicKeyTemplate[pos].ulValueLen - 2;

			curve = cvcGetCurveForOID(&oid);

			if (curve == NULL) {
				FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_EC_PARAMS contains unknown curve OID");
			}
		} else if (*(unsigned char *)pPublicKeyTemplate[pos].pValue == 0x30) {
			rc = cvcDetermineCurveFromECParam((unsigned char *)pPublicKeyTemplate[pos].pValue, pPublicKeyTemplate[pos].ulValueLen, &crve);
			if (rc < 0) {
				FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "Explicit parameter in CKA_EC_PARAMS invalid");
			}
			curve = &crve;
		} else {
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_EC_PARAMS not a curve object identifier or explicit domain parameter");
		}

		asn1Append(bb, 0x81, &curve->prime);
		asn1Append(bb, 0x82, &curve->coefficientA);
		asn1Append(bb, 0x83, &curve->coefficientB);
		asn1Append(bb, 0x84, &curve->basePointG);
		asn1Append(bb, 0x85, &curve->order);
		asn1Append(bb, 0x87, &curve->coFactor);

		keybits = (int)(curve->prime.len << 3);
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
		scr[0] = (unsigned char)(keybits >> 8);
		scr[1] = (unsigned char)(keybits & 0xFF);
		asn1AppendBytes(bb, 0x02, scr, 2);
	}

	asn1EncapBuffer(0x7F49, bb, ofs);

	rc = findAttributeInTemplate(CKA_CVC_CHR, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x5F20, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	} else {
		asn1Append(bb, 0x5F20, &defaultCHR);
	}

	rc = findAttributeInTemplate(CKA_CVC_OUTER_CAR, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		asn1AppendBytes(bb, 0x45, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_SC_HSM_KEY_USE_COUNTER, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		if (pPublicKeyTemplate[rc].pValue == NULL || pPublicKeyTemplate[rc].ulValueLen != sizeof(CK_ULONG)) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_KEY_USE_COUNTER must be CK_ULONG");
		}
		kuc = *(CK_ULONG *)pPublicKeyTemplate[rc].pValue;

		if ((kuc < 1) || (kuc > 0xFFFFFFFF)) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_KEY_USE_COUNTER is not in the range between 1 and 2^32");
		}

		scr[0] = (unsigned char)((kuc >> 24) & 0xFF);
		scr[1] = (unsigned char)((kuc >> 16) & 0xFF);
		scr[2] = (unsigned char)((kuc >>  8) & 0xFF);
		scr[3] = (unsigned char)( kuc & 0xFF);
		asn1AppendBytes(bb, 0x90, scr, 4);
	}

	rc = findAttributeInTemplate(CKA_SC_HSM_ALGORITHM_LIST, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		if (pPublicKeyTemplate[rc].pValue == NULL || pPublicKeyTemplate[rc].ulValueLen > 16) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_ALGORITHM_LIST must not be longer that 16 bytes");
		}
		asn1AppendBytes(bb, 0x91, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_SC_HSM_KEY_DOMAIN, pPublicKeyTemplate, ulPublicKeyAttributeCount);
	if (rc >= 0) {
		if (pPublicKeyTemplate[rc].pValue == NULL || pPublicKeyTemplate[rc].ulValueLen != 1) {
			FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_SC_HSM_KEY_DOMAIN must be a single CK_BYTE");
		}
		asn1AppendBytes(bb, 0x92, pPublicKeyTemplate[rc].pValue, pPublicKeyTemplate[rc].ulValueLen);
	}

	if (bbHasFailed(bb)) {
		FUNC_FAILS(CKR_DEVICE_MEMORY, "Buffer to encode GAKP buffer too small");
	}

	*keysize = (int)keybits;
	FUNC_RETURNS(CKR_OK);
}



static int decodeLabel(struct p11Token_t *token)
{
	int rc, len;
	unsigned char ciainfo[256], *po;

	FUNC_CALLED();

	rc = readEF(token->slot, 0x2F03, ciainfo, sizeof(ciainfo));

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading CIAInfo");

	rc = (int)asn1Validate(ciainfo, rc);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not decode CVC request");

	po = asn1Find(ciainfo, (unsigned char *)"\x30\x80", 2);

	if (po == NULL)
		FUNC_FAILS(CKR_DEVICE_ERROR, "label not found");

	memset(token->info.label, ' ', sizeof(token->info.label));
	asn1Tag(&po);
	len = asn1Length(&po);

	if (len > sizeof(token->info.label))
		len = sizeof(token->info.label);

	memcpy(token->info.label, po, len);

	FUNC_RETURNS(CKR_OK);
}



static int decodeDevAutCert(struct p11Token_t *token)
{
	int rc, len, certlen;
	unsigned char cert[MAX_CERTIFICATE_SIZE];
	struct p15CertificateDescription p15;
	struct p11Object_t *p11cert;
	struct p11Attribute_t *attribute;
	unsigned char *po;

	FUNC_CALLED();

	len = readEF(token->slot, 0x2F02, cert, sizeof(cert));

	if (len < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading C.DevAut");
	}

	memset(&p15, 0, sizeof(p15));
	p15.certtype = P15_CT_CVC;
	p15.coa.label = "C.DevAut";
	p15.isModifiable = 0;

	rc = createCertificateObjectFromP15(&p15, cert, len, &p11cert);
	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "Problem adding C.DevAut");
	}
	addObject(token, p11cert, TRUE);

	findAttribute(p11cert, CKA_CVC_CHR, &attribute);

	po = cert;
	asn1Tag(&po);
	certlen = asn1Length(&po);
	certlen += (int)(po - cert);

	if (certlen < len) {		// Add device issuer CA certificate
		p15.certtype = P15_CT_CVC;
		p15.coa.label = "C.DICA";
		p15.isCA = TRUE;
		rc = createCertificateObjectFromP15(&p15, cert + certlen, len - certlen, &p11cert);
		if (rc != CKR_OK) {
			FUNC_FAILS(rc, "Problem adding C.DICA");
		}
		addObject(token, p11cert, TRUE);
	}

	memset(token->info.serialNumber, ' ', sizeof(token->info.serialNumber));
	len = attribute->attrData.ulValueLen - 5;
	if (len > sizeof(token->info.serialNumber))
		len = sizeof(token->info.serialNumber);

	memcpy(token->info.serialNumber, attribute->attrData.pValue, len);

	FUNC_RETURNS(CKR_OK);
}



/**
 * Determine a free key identifier by enumerating all files and locating a free id in the range CC01-CCFF
 */
static int determineFreeKeyId(struct p11Slot_t *slot, unsigned char prefix) {
	unsigned char filelist[MAX_FILES * 2];
	int listlen,i,id;

	FUNC_CALLED();

	listlen = enumerateObjects(slot, filelist, sizeof(filelist));
	if (listlen < 0) {
		FUNC_FAILS(listlen, "enumerateObjects failed");
	}

	for (id = 1; id <= 255; id++) {
		for (i = 0; i < listlen; i += 2) {
			if ((filelist[i] == prefix) && (filelist[i + 1] == id)) {
				break;
			}
		}
		if (i >= listlen) {
			break;
		}
	}

	FUNC_RETURNS(id <= 255 ? id : -1);
}



static CK_RV sc_hsm_C_DeriveSymmetricKey(
		struct p11Object_t *pObject,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		struct p11Object_t **pKey);

static CK_RV sc_hsm_C_DeriveKey(
		struct p11Object_t *pObject,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		struct p11Object_t **pKey);

static int addEECertificateAndKeyObjects(struct p11Token_t *token, unsigned char id, struct p11Object_t **priKey, struct p11Object_t **pubKey, struct p11Object_t **cert)
{
	unsigned char certValue[MAX_CERTIFICATE_SIZE];
	struct p11Object_t *p11cert = NULL, *p11pubkey = NULL, *p11prikey;
	struct p15PrivateKeyDescription *p15key = NULL;
	struct p15SecretKeyDescription *p15skey = NULL;
	struct p15CertificateDescription p15cert;
	unsigned char prkd[MAX_P15_SIZE];
	int rc, certLen;

	FUNC_CALLED();

	rc = readEF(token->slot, (PRKD_PREFIX << 8) | id, prkd, sizeof(prkd));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading private key description");
	}

	if (prkd[0] == P15_KEYTYPE_AES) {
		rc = decodeSecretKeyDescription(prkd, rc, &p15skey);

		if (rc != CKR_OK) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error decoding secret key description");
		}

		rc = createSecretKeyObjectFromP15(p15skey, &p11prikey);

		if (rc != CKR_OK) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create secret key object");
		}

		freeSecretKeyDescription(&p15skey);

		p11prikey->C_EncryptInit = sc_hsm_C_EncryptInit;
		p11prikey->C_Encrypt = sc_hsm_C_Encrypt;
		p11prikey->C_DeriveKey = sc_hsm_C_DeriveSymmetricKey;
	} else {
		rc = decodePrivateKeyDescription(prkd, rc, &p15key);

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error decoding private key description");
		}

		rc = readEF(token->slot, (EE_CERTIFICATE_PREFIX << 8) | id, certValue, sizeof(certValue));

		if (rc > 0) {
			certLen = rc;

			if ((certValue[0] != 0x30) && (certValue[0] != 0x7F) && (certValue[0] != 0x67))
				FUNC_FAILS(CKR_DEVICE_ERROR, "Unknown certificate type");

			if (certValue[0] == 0x30) {		// X.509 certificate
				// A SmartCard-HSM does not store a separate P15 certificate description. Copy from key description
				memset(&p15cert, 0, sizeof(p15cert));
				p15cert.certtype = P15_CT_X509;
				p15cert.coa = p15key->coa;
				p15cert.id = p15key->id;
				p15cert.isCA = 0;
				p15cert.isModifiable = 1;

				rc = createCertificateObjectFromP15(&p15cert, certValue, certLen, &p11cert);

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
			} else {
				if (certValue[0] == 0x7F) {		// CVC Certificate
					memset(&p15cert, 0, sizeof(p15cert));
					p15cert.certtype = P15_CT_CVC;
					p15cert.coa = p15key->coa;
					p15cert.id = p15key->id;
					p15cert.isCA = 0;
					p15cert.isModifiable = 1;

					rc = createCertificateObjectFromP15(&p15cert, certValue, certLen, &p11cert);

					if (rc != CKR_OK) {
						FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create P11 certificate object");
					}

					p11cert->tokenid = (int)id;

					addObject(token, p11cert, TRUE);

					if (rc != CKR_OK) {
						FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create private key object");
					}
				}

				if ((certValue[0] == 0x7F) || (certValue[0] == 0x67)) {		// CVC Request or Certificate
					rc = createPublicKeyObjectFromCVC(p15key, certValue, certLen, &p11pubkey);

					if (rc != CKR_OK) {
						FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create public key object");
					}

					addObject(token, p11pubkey, TRUE);

					rc = createPrivateKeyObjectFromP15AndPublicKey(p15key, p11pubkey, FALSE, &p11prikey);

					if (rc != CKR_OK) {
						FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create private key object");
					}
				}
			}
		} else {
			rc = createPrivateKeyObjectFromP15(p15key, NULL, FALSE, &p11prikey);

			if (rc != CKR_OK) {
				FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create private key object");
			}
		}

		freePrivateKeyDescription(&p15key);

		p11prikey->C_DeriveKey = sc_hsm_C_DeriveKey;
	}

	p11prikey->C_SignInit = sc_hsm_C_SignInit;
	p11prikey->C_Sign = sc_hsm_C_Sign;
	p11prikey->C_DecryptInit = sc_hsm_C_DecryptInit;
	p11prikey->C_Decrypt = sc_hsm_C_Decrypt;

	p11prikey->tokenid = (int)id;

	addObject(token, p11prikey, FALSE);

	if (priKey != NULL)
		*priKey = p11prikey;

	if ((pubKey != NULL) && (p11pubkey != NULL))
		*pubKey = p11pubkey;

	if ((p11cert != NULL) && (cert != NULL))
		*cert = p11cert;

	FUNC_RETURNS(CKR_OK);
}



static int addCACertificateObject(struct p11Token_t *token, unsigned char id)
{
	unsigned char certValue[MAX_CERTIFICATE_SIZE];
	struct p11Object_t *p11cert;
	struct p15CertificateDescription *p15cert;
	unsigned char cd[MAX_P15_SIZE];
	unsigned short fid;
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

	fid = (CA_CERTIFICATE_PREFIX << 8) | id;
	rc = readEF(token->slot, fid, certValue, sizeof(certValue));

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate");
	}

	p15cert->isCA = 1;
	p15cert->isModifiable = 1;

	rc = createCertificateObjectFromP15(p15cert, certValue, rc, &p11cert);

	if (rc != CKR_OK) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not create P11 certificate object");
	}

	p11cert->tokenid = (int)fid;

	addObject(token, p11cert, TRUE);

	freeCertificateDescription(&p15cert);
	FUNC_RETURNS(CKR_OK);
}



static int createCertDescription(struct p11Slot_t *slot,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		unsigned char *id,
		size_t idlen,
		struct p15CertificateDescription *p15cert)
{
	int rc, idf;

	FUNC_CALLED();

	rc = findAttributeInTemplate(CKA_LABEL, pTemplate, ulCount);
	if (rc >= 0) {
		p15cert->coa.label = calloc(1, pTemplate[rc].ulValueLen + 1);
		if (p15cert->coa.label == NULL)
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");

		memcpy(p15cert->coa.label, pTemplate[rc].pValue, pTemplate[rc].ulValueLen);
	}

	idf = determineFreeKeyId(slot, CD_PREFIX);

	if (idf < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Determine free id failed");

	p15cert->efidOrPath.len = 2;
	p15cert->efidOrPath.val = calloc(1, 2);
	if (p15cert->efidOrPath.val == NULL)
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");

	p15cert->efidOrPath.val[0] = CA_CERTIFICATE_PREFIX;
	p15cert->efidOrPath.val[1] = idf;

	if (id == NULL) {
		id = p15cert->efidOrPath.val;
		idlen = p15cert->efidOrPath.len;
	}

	p15cert->id.len = idlen;
	p15cert->id.val = calloc(1, idlen);
	if (p15cert->id.val == NULL)
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");

	memcpy(p15cert->id.val, id, idlen);

	FUNC_RETURNS(CKR_OK);
}



static int createSecretKeyDescription(
		struct p11Slot_t *slot,
		CK_ATTRIBUTE_PTR pSecretKeyTemplate,
		CK_ULONG ulSecretKeyAttributeCount,
		int id,
		int keysize)
{
	int rc, len;
	unsigned char buff[512], *po;
	struct bytebuffer_s bb = { buff, 0, sizeof(buff) };
	struct p15SecretKeyDescription *p15key = NULL;

	p15key = calloc(1, sizeof(struct p15SecretKeyDescription));
	if (p15key == NULL)
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");


	p15key->keytype = P15_KEYTYPE_AES;
	p15key->keyReference = id;
	p15key->keysize = keysize;

	rc = findAttributeInTemplate(CKA_SIGN, pSecretKeyTemplate, ulSecretKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pSecretKeyTemplate[rc].pValue) {
		p15key->usage |= P15_SIGN;
	}

	rc = findAttributeInTemplate(CKA_ENCRYPT, pSecretKeyTemplate, ulSecretKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pSecretKeyTemplate[rc].pValue) {
		p15key->usage |= P15_ENCIPHER;
	}

	rc = findAttributeInTemplate(CKA_DECRYPT, pSecretKeyTemplate, ulSecretKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pSecretKeyTemplate[rc].pValue) {
		p15key->usage |= P15_DECIPHER;
	}

	rc = findAttributeInTemplate(CKA_DERIVE, pSecretKeyTemplate, ulSecretKeyAttributeCount);
	if ((rc >= 0) && *(unsigned char *)pSecretKeyTemplate[rc].pValue) {
		p15key->usage |= P15_DERIVE;
	}

	rc = findAttributeInTemplate(CKA_LABEL, pSecretKeyTemplate, ulSecretKeyAttributeCount);
	if (rc >= 0) {
		p15key->coa.label = calloc(1, pSecretKeyTemplate[rc].ulValueLen + 1);
		if (p15key->coa.label == NULL) {
			freeSecretKeyDescription(&p15key);
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}
		memcpy(p15key->coa.label, pSecretKeyTemplate[rc].pValue, pSecretKeyTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_ID, pSecretKeyTemplate, ulSecretKeyAttributeCount);
	if (rc >= 0) {
		po = pSecretKeyTemplate[rc].pValue;
		len = pSecretKeyTemplate[rc].ulValueLen;
	} else {
		buff[0] = id;
		po = buff;
		len = 1;
	}
	p15key->id.val = calloc(1, len);
	if (p15key->id.val == NULL) {
		freeSecretKeyDescription(&p15key);
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}
	memcpy(p15key->id.val, po, len);
	p15key->id.len = len;

	rc = encodeSecretKeyDescription(&bb, p15key);

	freeSecretKeyDescription(&p15key);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Encoding SKD failed");

	rc = writeEF(slot, (PRKD_PREFIX << 8) | id, bb.val, bb.len);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Writing SKD failed");

	FUNC_RETURNS(CKR_OK);
}



static int createPrivateKeyDescription(
		struct p11Slot_t *slot,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		CK_ULONG ulPrivateKeyAttributeCount,
		int id,
		int keysize)
{
	int rc, len;
	unsigned char buff[512], *po;
	struct bytebuffer_s bb = { buff, 0, sizeof(buff) };
	struct p15PrivateKeyDescription *p15key = NULL;

	p15key = calloc(1, sizeof(struct p15PrivateKeyDescription));
	if (p15key == NULL)
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");

	if ((pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) ||
		(pMechanism->mechanism == CKM_SC_HSM_EC_DERIVE)) {
		p15key->keytype = P15_KEYTYPE_ECC;
	} else {
		p15key->keytype = P15_KEYTYPE_RSA;
	}
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
			freePrivateKeyDescription(&p15key);
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}
		memcpy(p15key->coa.label, pPrivateKeyTemplate[rc].pValue, pPrivateKeyTemplate[rc].ulValueLen);
	}

	rc = findAttributeInTemplate(CKA_ID, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if (rc >= 0) {
		po = pPrivateKeyTemplate[rc].pValue;
		len = pPrivateKeyTemplate[rc].ulValueLen;
	} else {
		buff[0] = id;
		po = buff;
		len = 1;
	}
	p15key->id.val = calloc(1, len);
	if (p15key->id.val == NULL) {
		freePrivateKeyDescription(&p15key);
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}
	memcpy(p15key->id.val, po, len);
	p15key->id.len = len;

	rc = encodePrivateKeyDescription(&bb, p15key);

	freePrivateKeyDescription(&p15key);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Encoding PRKD failed");

	rc = writeEF(slot, (PRKD_PREFIX << 8) | id, bb.val, bb.len);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Writing PRKD failed");

	FUNC_RETURNS(CKR_OK);
}



static CK_RV sc_hsm_C_DeriveSymmetricKey(
		struct p11Object_t *pObject,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		struct p11Object_t **pKey)
{
	int rc;
	unsigned short SW1SW2;
	unsigned char *pDerivationParam;
	unsigned char derivedKeyValue[32];
	struct p11Object_t *derivedKey;
	CK_ATTRIBUTE kva = { CKA_VALUE, &derivedKeyValue, sizeof(derivedKeyValue) };

	if (pMechanism->mechanism != CKM_SC_HSM_SP80056C_DERIVE) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism must be CKM_SC_HSM_SP80056C_DERIVE");
	}

	pDerivationParam = malloc(pMechanism->ulParameterLen);
	memcpy(pDerivationParam, pMechanism->pParameter, pMechanism->ulParameterLen);

	rc = transmitAPDU(pObject->token->slot, 0x80, 0x78, (unsigned char)pObject->tokenid, 0x99,
			pMechanism->ulParameterLen, pDerivationParam, 0, derivedKeyValue, sizeof(derivedKeyValue), &SW1SW2);

	free(pDerivationParam);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");

	if (SW1SW2 != 0x9000)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Key derivation failed");

	derivedKey = calloc(sizeof(struct p11Object_t), 1);

	if (derivedKey == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	rc = findAttributeInTemplate(CKA_VALUE, pTemplate, ulAttributeCount);


	rc = createSecretKeyObject(pTemplate, ulAttributeCount, derivedKey);
	if (rc != CKR_OK) {
		free(derivedKey);
		FUNC_FAILS(rc, "Could not create secret key object");
	}

	rc = addAttribute(derivedKey, &kva);
	if (rc != CKR_OK) {
		free(derivedKey);
		FUNC_FAILS(rc, "Could not create secret key object");
	}

	*pKey = derivedKey;

	FUNC_RETURNS(rc);
}



static CK_RV sc_hsm_C_DeriveKey(
		struct p11Object_t *pObject,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulAttributeCount,
		struct p11Object_t **pKey)
{

	int rc, id, len, idpos;
	unsigned short SW1SW2;
	unsigned char *pDerivationParam;
	struct p11Object_t *key;

	if (pMechanism->mechanism != CKM_SC_HSM_EC_DERIVE) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism must be CKM_SC_HSM_EC_DERIVE");
	}

	idpos = findAttributeInTemplate(CKA_ID, pTemplate, ulAttributeCount);
	if (idpos >= 0) {
		rc = validateAttribute(&pTemplate[idpos], 0);
		if (rc != CKR_OK)
			FUNC_FAILS(rc, "CKA_ID");

		rc = findMatchingTokenObjectById(pObject->token->slot->token, CKO_PRIVATE_KEY, pTemplate[idpos].pValue, pTemplate[idpos].ulValueLen, &key);
		if (rc == CKR_OK)
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "A private key with that CKA_ID does already exist");

		rc = findMatchingTokenObjectById(pObject->token->slot->token, CKO_SECRET_KEY, pTemplate[idpos].pValue, pTemplate[idpos].ulValueLen, &key);
		if (rc == CKR_OK)
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "A secret key with that CKA_ID does already exist");
	}

	id = determineFreeKeyId(pObject->token->slot, KEY_PREFIX);

	if (id < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Determine free id failed");

	len = pMechanism->ulParameterLen + 1;
	pDerivationParam = malloc(len);
	pDerivationParam[0] = ALGO_EC_DERIVE;
	memcpy(pDerivationParam + 1, pMechanism->pParameter, pMechanism->ulParameterLen);

	rc = transmitAPDU(pObject->token->slot, 0x80, 0x76, (unsigned char)pObject->tokenid, id,
			len, pDerivationParam, 0, NULL, 0, &SW1SW2);

	free(pDerivationParam);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");

	if (SW1SW2 != 0x9000)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Key derivation failed");

	createPrivateKeyDescription(pObject->token->slot, pMechanism, pTemplate, ulAttributeCount, id, pObject->keysize);

	rc = addEECertificateAndKeyObjects(pObject->token->slot->token, id, &key, NULL, NULL);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Could not create secret key object");

	*pKey = key;

	FUNC_RETURNS(rc);
}



static int sc_hsm_C_CreateObject(
		struct p11Slot_t *slot,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		struct p11Object_t **pp11o)
{
	int pos, rc, vallen, idlen;
	unsigned short fid, certfid;
	CK_CERTIFICATE_TYPE ct;
	CK_ATTRIBUTE idattr = { CKA_ID, NULL, 0 };
	unsigned char *val, *po, *id;
	struct p11Object_t *p11Key, *p11o;
	struct p15CertificateDescription *p15cert;
	unsigned char buff[512];
	struct bytebuffer_s bb = { buff, 0, sizeof(buff) };

	pos = findAttributeInTemplate(CKA_CLASS, pTemplate, ulCount);
	if (pos == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_CLASS not found in template");

	rc = validateAttribute(&pTemplate[pos], sizeof(CK_OBJECT_CLASS));
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "CKA_CLASS");

	if (*(CK_OBJECT_CLASS *)pTemplate[pos].pValue != CKO_CERTIFICATE)
		FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_CLASS must be CKO_CERTIFICATE");


	pos = findAttributeInTemplate(CKA_CERTIFICATE_TYPE, pTemplate, ulCount);
	if (pos == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_CERTIFICATE_TYPE not found in template");

	rc = validateAttribute(&pTemplate[pos], sizeof(CK_CERTIFICATE_TYPE));
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "CKA_CERTIFICATE_TYPE");

	ct = *(CK_CERTIFICATE_TYPE *)pTemplate[pos].pValue;
	if ((ct != CKC_CVC_TR3110) && (ct != CKC_X_509))
		FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_CERTIFICATE_TYPE");


	pos = findAttributeInTemplate(CKA_VALUE, pTemplate, ulCount);
	if (pos == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_VALUE not found in template");

	rc = validateAttribute(&pTemplate[pos], 0);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "CKA_VALUE");

	val = (unsigned char *)pTemplate[pos].pValue;
	vallen = pTemplate[pos].ulValueLen;

	if (asn1Validate(val, vallen)) {
		FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_VALUE does not seem to be a TLV structure");
	}

	po = val;
	rc = asn1Tag(&po);
	if ((ct == CKC_CVC_TR3110) && (rc != 0x7F21))
		FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_VALUE does not seem to contain a CVC");

	if ((ct == CKC_X_509) && (rc != 0x30))
		FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_VALUE does not seem to be a X.509 certificate");

	id = NULL;
	p11Key = NULL;
	p11o = NULL;
	idlen = 0;

	pos = findAttributeInTemplate(CKA_ID, pTemplate, ulCount);
	if (pos >= 0) {
		id = (unsigned char *)pTemplate[pos].pValue;
		idlen = pTemplate[pos].ulValueLen;

		rc = findMatchingTokenObjectById(slot->token, CKO_PRIVATE_KEY, id, idlen, &p11Key);
#ifdef DEBUG
		if (rc != CKR_OK) {
			debug("No private key found with matching CKA_ID");
		}
#endif

		// See if we already have a certificate object for that ID
		findMatchingTokenObjectById(slot->token, CKO_CERTIFICATE, id, idlen, &p11o);
	}

	if (p11Key != NULL) {
		certfid = p11Key->tokenid;
		rc = writeEF(slot, (EE_CERTIFICATE_PREFIX << 8) | p11Key->tokenid, val, vallen);
		if (rc < 0)
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error writing certificate");
	} else {
		p15cert = calloc(1, sizeof(struct p15CertificateDescription));
		if (p15cert == NULL)
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");

		p15cert->certtype = ct == CKC_X_509 ? P15_CT_X509 : P15_CT_CVC;

		rc = createCertDescription(slot, pTemplate, ulCount, id, idlen, p15cert);
		if (rc < 0)
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error creating certificate description");

		rc = encodeCertificateDescription(&bb, p15cert);
		certfid = p15cert->efidOrPath.val[0] << 8 | p15cert->efidOrPath.val[1];
		freeCertificateDescription(&p15cert);

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error encoding certificate description");
		}

		rc = writeEF(slot, certfid, val, vallen);
		if (rc < 0)
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error writing certificate");

		fid = (CD_PREFIX << 8) | (certfid & 0xFF);
		rc = writeEF(slot, fid , bb.val, bb.len);
		if (rc < 0)
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error writing certificate description");
	}

	if (p11o != NULL) {
		removeTokenObject(slot->token, p11o->handle, TRUE);
	}

	p11o = calloc(sizeof(struct p11Object_t), 1);

	if (p11o == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	rc = createCertificateObject(pTemplate, ulCount, p11o);

	if (rc != CKR_OK) {
		free(p11o);
		FUNC_FAILS(rc, "Could not create certificate object");
	}

	if ((id == NULL) && (p11Key == NULL)) {		// CA certificate without CKA_ID
		buff[0] = certfid >> 8;
		buff[1] = certfid & 0XFF;
		idattr.pValue = buff;
		idattr.ulValueLen = 2;
		addAttribute(p11o, &idattr);
	}

	p11o->tokenid = (int)certfid;

	if (ct == CKC_X_509) {
		rc = populateIssuerSubjectSerial(p11o);
	} else {
		rc = populateCVCAttributes(p11o);
	}

	if (rc != CKR_OK) {
#ifdef DEBUG
		debug("Populating additional attributes failed\n");
#endif
	}

	addObject(slot->token, p11o, TRUE);

	*pp11o = p11o;

	FUNC_RETURNS(CKR_OK);
}



/**
 * Generate AES key
 */
static int sc_hsm_C_GenerateKey(
		struct p11Slot_t *slot,
		CK_MECHANISM_PTR pMechanism,
		CK_ATTRIBUTE_PTR pTemplate,
		CK_ULONG ulCount,
		struct p11Object_t **phKey)
{
	unsigned char buff[128];
	struct bytebuffer_s bb = { buff, 0, sizeof(buff) };
	int rc, idpos, id, algo, length;
	unsigned short SW1SW2;
	struct p11Object_t *priKey;

	FUNC_CALLED();

	if (pMechanism->mechanism != CKM_AES_KEY_GEN) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism not supported");
	}

	rc = findAttributeInTemplate(CKA_VALUE_LEN, pTemplate, ulCount);
	if (rc < 0) {
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_VALUE_LEN not found in template");
	}
	length = *(CK_ULONG *)pTemplate[rc].pValue;

	switch(length) {
	case 16:
		algo = 0xB0;
		break;
	case 24:
		algo = 0xB1;
		break;
	case 32:
		algo = 0xB2;
		break;
	default:
		FUNC_FAILS(CKR_TEMPLATE_INCONSISTENT, "CKA_VALUE_LEN must be either 16, 24 or 32");
	}

	rc = encodeGSK(&bb, pTemplate, ulCount);
	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Encoding GAKP failed");

	idpos = findAttributeInTemplate(CKA_ID, pTemplate, ulCount);
	if (idpos >= 0) {
		rc = validateAttribute(&pTemplate[idpos], 0);
		if (rc != CKR_OK)
			FUNC_FAILS(rc, "CKA_ID");

		rc = findMatchingTokenObjectById(slot->token, CKO_PRIVATE_KEY, pTemplate[idpos].pValue, pTemplate[idpos].ulValueLen, &priKey);
		if (rc == CKR_OK)
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "A key with that CKA_ID does already exist");

		id = *(CK_BYTE *)pTemplate[idpos].pValue;
	} else {
		id = determineFreeKeyId(slot, KEY_PREFIX);
	}

	if (id < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Determine free id failed");

	rc = transmitAPDU(slot, 0x00, 0x48, id, algo,
			(int)bbGetLength(&bb), buff,
			0, NULL, 0, &SW1SW2);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");

	if (SW1SW2 != 0x9000)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Generate Symmetric Key operation failed");

	createSecretKeyDescription(slot, pTemplate, ulCount, id, length * 8);

	rc = addEECertificateAndKeyObjects(slot->token, id, &priKey, NULL, NULL);

	*phKey = priKey;

	FUNC_RETURNS(rc);
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
		struct p11Object_t **phPublicKey,
		struct p11Object_t **phPrivateKey)
{
	unsigned char buff[512];
	struct bytebuffer_s bb = { buff, 0, sizeof(buff) };
	struct p11Object_t *priKey, *pubKey;
	unsigned short SW1SW2;
	int rc,id,keysize,idpos;

	FUNC_CALLED();

	if ((pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) && (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN)) {
		FUNC_FAILS(CKR_MECHANISM_INVALID, "Mechanism is neither CKM_EC_KEY_PAIR_GEN nor CKM_RSA_PKCS_KEY_PAIR_GEN");
	}

	idpos = findAttributeInTemplate(CKA_ID, pPrivateKeyTemplate, ulPrivateKeyAttributeCount);
	if (idpos >= 0) {
		rc = validateAttribute(&pPrivateKeyTemplate[idpos], 0);
		if (rc != CKR_OK)
			FUNC_FAILS(rc, "CKA_ID");

		rc = findMatchingTokenObjectById(slot->token, CKO_PRIVATE_KEY, pPrivateKeyTemplate[idpos].pValue, pPrivateKeyTemplate[idpos].ulValueLen, &priKey);
		if (rc == CKR_OK)
			FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "A private key with that CKA_ID does already exist");
	}

	rc = encodeGAKP(&bb, slot->token, pMechanism, pPublicKeyTemplate, ulPublicKeyAttributeCount, &keysize);

	if (rc != CKR_OK)
		FUNC_FAILS(rc, "Encoding GAKP failed");

	id = determineFreeKeyId(slot, KEY_PREFIX);

	if (id < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Determine free id failed");

	rc = transmitAPDU(slot, 0x00, 0x46, id, 0x00,
			(int)bbGetLength(&bb), buff,
			0, NULL, 0, &SW1SW2);

	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");

	if (SW1SW2 != 0x9000)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Signature operation failed");

	createPrivateKeyDescription(slot,pMechanism, pPrivateKeyTemplate, ulPrivateKeyAttributeCount, id, keysize);

	rc = addEECertificateAndKeyObjects(slot->token, id, &priKey, &pubKey, NULL);

	*phPublicKey = pubKey;
	*phPrivateKey = priKey;

	FUNC_RETURNS(rc);
}



static int sc_hsm_C_SetAttributeValue(struct p11Slot_t *slot, struct p11Object_t *pObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct p11Attribute_t *attribute;
	unsigned char desc[MAX_P15_SIZE];
	struct bytebuffer_s bb = { desc, 0, sizeof(desc) };
	unsigned short fid;
	struct p15PrivateKeyDescription *p15key = NULL;
	struct p15CertificateDescription *p15cert = NULL;
	struct p11Object_t *p11;
	int rc, i;

	FUNC_CALLED();

	rc = findAttribute(pObject, CKA_CLASS, &attribute);
	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Attribute CKA_CLASS not found. Data corrupted");


	switch(*(CK_OBJECT_CLASS *)attribute->attrData.pValue) {
	case CKO_PRIVATE_KEY:
		fid = (PRKD_PREFIX << 8) | pObject->tokenid;

		rc = readEF(slot, fid, desc, sizeof(desc));

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading private key description");
		}

		rc = decodePrivateKeyDescription(desc, rc, &p15key);

		if (rc < 0) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Error decoding private key description");
		}

		for (i = 0; i < (int)ulCount; i++) {
			switch(pTemplate[i].type) {
			case CKA_ID:
				rc = findMatchingTokenObjectById(slot->token, CKO_PRIVATE_KEY, pTemplate[i].pValue, pTemplate[i].ulValueLen, &p11);
				if ((rc == CKR_OK) && (p11 != pObject)) {
					freePrivateKeyDescription(&p15key);
					FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_ID does already exist");
				}

				if (p15key->id.val) {
					free(p15key->id.val);
				}
				p15key->id.val = calloc(1, pTemplate[i].ulValueLen);
				if (p15key->id.val == NULL) {
					freePrivateKeyDescription(&p15key);
					FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
				}
				memcpy(p15key->id.val, pTemplate[i].pValue, pTemplate[i].ulValueLen);
				p15key->id.len = pTemplate[i].ulValueLen;
				break;
			case CKA_LABEL:
				if (p15key->coa.label) {
					free(p15key->coa.label);
				}
				p15key->coa.label = calloc(1, pTemplate[i].ulValueLen + 1);
				if (p15key->coa.label == NULL) {
					freePrivateKeyDescription(&p15key);
					FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
				}
				memcpy(p15key->coa.label, pTemplate[i].pValue, pTemplate[i].ulValueLen);
				break;
			}
		}

		rc = encodePrivateKeyDescription(&bb, p15key);

		freePrivateKeyDescription(&p15key);

		if (rc < 0)
			FUNC_FAILS(CKR_DEVICE_ERROR, "Encoding PRKD failed");

		rc = writeEF(slot, fid, bb.val, bb.len);

		if (rc < 0)
			FUNC_FAILS(CKR_DEVICE_ERROR, "Writing PRKD failed");

		break;
	case CKO_CERTIFICATE:
		if (pObject->tokenid >= 0x100) {
			fid = (CD_PREFIX << 8) | (pObject->tokenid & 0xFF);

			rc = readEF(slot, fid, desc, sizeof(desc));

			if (rc < 0) {
				FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate description");
			}

			rc = decodeCertificateDescription(desc, rc, &p15cert);

			if (rc < 0) {
				FUNC_FAILS(CKR_DEVICE_ERROR, "Error decoding certificate description");
			}

			for (i = 0; i < (int)ulCount; i++) {
				switch(pTemplate[i].type) {
				case CKA_ID:
					rc = findMatchingTokenObjectById(slot->token, CKO_CERTIFICATE, pTemplate[i].pValue, pTemplate[i].ulValueLen, &p11);
					if ((rc == CKR_OK) && (p11 != pObject)) {
						freeCertificateDescription(&p15cert);
						FUNC_FAILS(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_ID does already exist");
					}

					if (p15cert->id.val) {
						free(p15cert->id.val);
					}
					p15cert->id.val = calloc(1, pTemplate[i].ulValueLen);
					if (p15cert->id.val == NULL) {
						freeCertificateDescription(&p15cert);
						FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
					}
					memcpy(p15cert->id.val, pTemplate[i].pValue, pTemplate[i].ulValueLen);
					p15cert->id.len = pTemplate[i].ulValueLen;
					break;
				case CKA_LABEL:
					if (p15cert->coa.label) {
						free(p15cert->coa.label);
					}
					p15cert->coa.label = calloc(1, pTemplate[i].ulValueLen + 1);
					if (p15cert->coa.label == NULL) {
						freeCertificateDescription(&p15cert);
						FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
					}
					memcpy(p15cert->coa.label, pTemplate[i].pValue, pTemplate[i].ulValueLen);
					break;
				}
			}

			rc = encodeCertificateDescription(&bb, p15cert);

			freeCertificateDescription(&p15cert);

			if (rc < 0)
				FUNC_FAILS(CKR_DEVICE_ERROR, "Encoding CD failed");

			rc = writeEF(slot, fid, bb.val, bb.len);

			if (rc < 0)
				FUNC_FAILS(CKR_DEVICE_ERROR, "Writing CD failed");
		}
		break;
	}

	FUNC_RETURNS(CKR_OK);
}



static int sc_hsm_destroyObject(struct p11Slot_t *slot, struct p11Object_t *pObject)
{
	struct p11Attribute_t *attribute;
	unsigned short fid,fid2;
	int rc;

	FUNC_CALLED();

	rc = findAttribute(pObject, CKA_CLASS, &attribute);
	if (rc < 0)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Attribute CKA_CLASS not found. Data corrupted");


	switch(*(CK_OBJECT_CLASS *)attribute->attrData.pValue) {
	case CKO_PRIVATE_KEY:
	case CKO_SECRET_KEY:
		fid = (KEY_PREFIX << 8) | pObject->tokenid;
		rc = deleteEF(slot, fid);
		if (rc < 0)
			FUNC_FAILS(CKR_DEVICE_ERROR, "Deleting key failed");

		fid = (PRKD_PREFIX << 8) | pObject->tokenid;
		deleteEF(slot, fid);
		// May fail

		fid = (EE_CERTIFICATE_PREFIX << 8) | pObject->tokenid;
		deleteEF(slot, fid);
		break;
	case CKO_CERTIFICATE:
		fid = pObject->tokenid;
		if (fid > 0) {
			if (fid < 0x100) {
				fid |= EE_CERTIFICATE_PREFIX << 8;
			} else {
				fid2 = (CD_PREFIX << 8) | (fid & 0xFF);
				rc = deleteEF(slot, fid2);
				if (rc < 0)
					FUNC_FAILS(CKR_DEVICE_ERROR, "Deleting certificate description failed");
			}
			rc = deleteEF(slot, fid);
			if (rc < 0)
				FUNC_FAILS(CKR_DEVICE_ERROR, "Deleting certificate failed");
		}
		break;
	}

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
				rc = addEECertificateAndKeyObjects(token, id, NULL, NULL, NULL);
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

	token->info.flags &= ~(CKF_USER_PIN_INITIALIZED | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED | CKF_USER_PIN_COUNT_LOW);

	if (pinstatus != 0x6A88) {
		token->info.flags |= CKF_USER_PIN_INITIALIZED;
	}

	if ((pinstatus & 0x63C0) == 0x63C0)
		token->pinTriesLeft = pinstatus & 0xF;

	switch(pinstatus) {
	case 0x9000:
		token->pinTriesLeft = 3;
		rc = CKR_OK;
		break;
	case 0x6984:
		token->pinTriesLeft = 3;
		token->info.flags |= CKF_USER_PIN_TO_BE_CHANGED;
		rc = CKR_USER_PIN_NOT_INITIALIZED;
		break;
	case 0x6983:
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
	case 0x6A80:
		rc = CKR_PIN_LEN_RANGE;
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
static int sc_hsm_login(struct p11Slot_t *slot, int userType, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
{
	int rc = CKR_OK, retry;
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
		retry = 2;			// Retry PIN verification if applet selection was lost
		while (retry--) {
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
				if (pinlen > 16) {
					FUNC_FAILS(CKR_PIN_LEN_RANGE, "transmitAPDU failed");
				}

				rc = transmitAPDU(slot, 0x00, 0x20, 0x00, 0x81,
					pinlen, pin,
					0, NULL, 0, &SW1SW2);
			}

			if (rc < 0) {
				FUNC_FAILS(CKR_DEVICE_ERROR, "transmitAPDU failed");
			}

			// Reselect applet is selection was lost, e.g. due to reconnect in minidriver
			if ((SW1SW2 == 0x6E00) || (SW1SW2 == 0x6D00)) {
				rc = selectApplet(slot, NULL, NULL);
				if (rc < 0) {
					FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "applet selection failed");
				}

				continue;
			}
			break;
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

	rc = selectApplet(slot, NULL, NULL);
	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "applet selection failed");
	}

	rc = checkPINStatus(slot, 0x81);
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
static int sc_hsm_initpin(struct p11Slot_t *slot, CK_UTF8CHAR_PTR pin, CK_ULONG pinlen)
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

	rc = checkPINStatus(slot, 0x81);

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
static int sc_hsm_setpin(struct p11Slot_t *slot, CK_UTF8CHAR_PTR oldpin, CK_ULONG oldpinlen, CK_UTF8CHAR_PTR newpin, CK_ULONG newpinlen)
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
	int rc, pinstatus, isinitialized;
	size_t tag85len;
	unsigned char tag85[10];

	FUNC_CALLED();

	rc = checkPINStatus(slot, 0x81);
	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "checkPINStatus failed");
	}

	tag85len = 0;
	if (rc != 0x9000) {
		tag85len = sizeof(tag85);
		rc = selectApplet(slot, tag85, &tag85len);

		if (rc < 0) {
			FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "applet selection failed");
		}

		rc = checkPINStatus(slot, 0x81);
		if (rc < 0) {
			FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "checkPINStatus failed");
		}
	}
	pinstatus = rc;

	isinitialized = 1;
	if ((pinstatus == 0x6984) || (pinstatus == 0x6A88)) {
		rc = checkPINStatus(slot, 0x88);
		if (rc < 0) {
			FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "checkPINStatus failed");
		}
		if (rc == 0x6A88)
			isinitialized = 0;
	}

	rc = allocateToken(&ptoken, sizeof(struct token_sc_hsm));
	if (rc != CKR_OK)
		return rc;

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

	if (tag85len > 0) {
		ptoken->info.firmwareVersion.major = tag85[tag85len - 2];
		ptoken->info.firmwareVersion.minor = tag85[tag85len - 1];

		if (tag85len > 2) {
			ptoken->info.hardwareVersion.major = tag85[tag85len - 3];
		} else {
			ptoken->info.hardwareVersion.major = 2;
		}
	} else {
		ptoken->info.firmwareVersion.major = 3;		// Assume 3.0 as default
		ptoken->info.firmwareVersion.minor = 0;
	}

	ptoken->info.flags = CKF_LOGIN_REQUIRED|CKF_RNG;

	if (slot->hasFeatureVerifyPINDirect)
		ptoken->info.flags |= CKF_PROTECTED_AUTHENTICATION_PATH;

	ptoken->user = INT_CKU_NO_USER;
	ptoken->drv = getSmartCardHSMTokenDriver();

	updatePinStatus(ptoken, pinstatus);

	if (isinitialized) {
		ptoken->info.flags |= CKF_TOKEN_INITIALIZED;
	}

	decodeLabel(ptoken);

#ifdef CVC
	rc = decodeDevAutCert(ptoken);
	if (rc != CKR_OK) {
		freeToken(ptoken);
		FUNC_FAILS(rc, "addToken() failed");
	}
#endif

	rc = sc_hsm_loadObjects(ptoken);
	if (rc != CKR_OK) {
		freeToken(ptoken);
		FUNC_FAILS(rc, "addToken() failed");
	}


	rc = addToken(slot, ptoken);
	if (rc != CKR_OK) {
		freeToken(ptoken);
		FUNC_FAILS(rc, "addToken() failed");
	}

	*token = ptoken;
	return CKR_OK;
}



static int sc_hsm_C_GetMechanismList(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
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



static int sc_hsm_C_GetMechanismInfo(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv = CKR_OK;

	FUNC_CALLED();

	switch (type) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SC_HSM_PSS_SHA1:
	case CKM_SC_HSM_PSS_SHA256:
#ifdef ENABLE_LIBCRYPTO
	case CKM_RSA_PKCS_OAEP:
#endif

		pInfo->ulMinKeySize = 1024;
		pInfo->ulMaxKeySize = 4096;
		break;

	case CKM_EC_KEY_PAIR_GEN:
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_SC_HSM_ECDSA_SHA224:
	case CKM_SC_HSM_ECDSA_SHA256:
		pInfo->ulMinKeySize = 192;
		pInfo->ulMaxKeySize = 521;
		break;

	case CKM_AES_KEY_GEN:
	case CKM_AES_CBC:
	case CKM_AES_CMAC:
		pInfo->ulMinKeySize = 16;
		pInfo->ulMaxKeySize = 32;
		break;

#ifdef ENABLE_LIBCRYPTO
	case CKM_SHA_1:
	case CKM_SHA224:
	case CKM_SHA256:
	case CKM_SHA384:
	case CKM_SHA512:
		pInfo->ulMinKeySize = 0;
		pInfo->ulMaxKeySize = 0;
		break;

#endif
	default:
		rv = CKR_MECHANISM_INVALID;
		break;
	}

	switch (type) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		pInfo->flags = CKF_HW|CKF_GENERATE_KEY_PAIR;
		break;
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
#ifdef ENABLE_LIBCRYPTO
		pInfo->flags = CKF_HW|CKF_SIGN|CKF_DECRYPT|CKF_VERIFY|CKF_ENCRYPT;
#else
		pInfo->flags = CKF_HW|CKF_SIGN|CKF_DECRYPT;
#endif
		break;
#ifdef ENABLE_LIBCRYPTO
	case CKM_RSA_PKCS_OAEP:
		pInfo->flags = CKF_HW|CKF_DECRYPT|CKF_ENCRYPT;
		break;
#endif
	case CKM_RSA_PKCS_PSS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS_PSS:
	case CKM_SHA256_RSA_PKCS_PSS:
	case CKM_SC_HSM_PSS_SHA1:
	case CKM_SC_HSM_PSS_SHA256:
#ifdef ENABLE_LIBCRYPTO
		pInfo->flags = CKF_HW|CKF_SIGN|CKF_VERIFY;
#else
		pInfo->flags = CKF_HW|CKF_SIGN;
#endif
		break;

	case CKM_EC_KEY_PAIR_GEN:
		pInfo->flags = CKF_HW|CKF_GENERATE_KEY_PAIR;
		break;
	case CKM_ECDSA:
	case CKM_ECDSA_SHA1:
	case CKM_SC_HSM_ECDSA_SHA224:
	case CKM_SC_HSM_ECDSA_SHA256:
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
	case CKM_AES_KEY_GEN:
		pInfo->flags = CKF_HW|CKF_GENERATE;
		break;
	case CKM_AES_CBC:
		pInfo->flags = CKF_HW|CKF_DECRYPT|CKF_ENCRYPT;
		break;
	case CKM_AES_CMAC:
		pInfo->flags = CKF_HW|CKF_SIGN;
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
		sc_hsm_C_GetMechanismList,
		sc_hsm_C_GetMechanismInfo,
		sc_hsm_login,
		sc_hsm_logout,
		sc_hsm_initpin,
		sc_hsm_setpin,

		NULL,
		NULL,
		NULL,
		NULL,

		NULL,
		NULL,
		NULL,
		NULL,

		sc_hsm_C_GenerateKey,
		sc_hsm_C_GenerateKeyPair,	// int (*C_GenerateKeyPair)  (struct p11Slot_t *, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, struct p11Object_t **, struct p11Object_t **);
		sc_hsm_C_CreateObject,		// int (*C_CreateObject)     (struct p11Slot_t *, CK_ATTRIBUTE_PTR, CK_ULONG ulCount, struct p11Object_t **);
		sc_hsm_destroyObject,		// int (*destroyObject)       (struct p11Slot_t *, struct p11Object_t *);
		sc_hsm_C_SetAttributeValue,	// int (*C_SetAttributeValue)(struct p11Slot_t *, struct p11Object_t *, CK_ATTRIBUTE_PTR, CK_ULONG);
		sc_hsm_C_GenerateRandom		// int (*C_GenerateRandom)   (struct p11Slot_t *, CK_BYTE_PTR , CK_ULONG );
	};

	return &sc_hsm_token;
}
