/**
 * SmartCard-HSM Ultra-Light Library
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
 * @file sc-hsm-ultralite.c
 * @author Christoph Brunhuber
 * @brief Functions for RSA-2k signing of SHA-256
 *                  ECDSA-prime256 signing of SHA-256
 *                  Card Devices, Version 1.0
 */

#define LITTLE_ENDIAN
#define USE_PRINTF

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "sc-hsm-ultralite.h"

#ifdef USE_PRINTF
#include <stdio.h>
#else
#define printf no_printf
void no_printf(const char *format, ...) {}
#endif

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ************************ Template Helper Functions ****************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/

/* Warning: case sensitive */
static int FindLabel(const char *label, const uint8* buf, int len)
{
	int val, ix = 0;

#define ReturnIfTagIsNot(tag1, tag2)\
	if (ix >= len || buf[ix] != tag1 && buf[ix] != tag2)\
		return 0;\
	if (++ix >= len)\
		return 0;\
	val = buf[ix++];\
	if (val >= 0x80)\
		ix += 1 + (val & 0x7f); /* skip over length bytes */

/* SEQUENCE or CONT [0] */
	ReturnIfTagIsNot(0x30, 0xa0);
/*   SEQUENCE */
	ReturnIfTagIsNot(0x30, 0x30);
/*     UTF8String */
	ReturnIfTagIsNot(0x0c, 0x0c);
	if (val >= 0x80)
		return 0;  /* assume length < 128 */
	val += ix; /* end of UTF8String */
	if (val > len)
		return 0;
	/* compare passed label with label of file */
	while (ix < val && *label) {
		if (*label++ != buf[ix++]) /* case sensitive */
			return 0;
	}
	return ix == val && *label == 0;

#undef ReturnIfTagIsNot
}

static int FindFid(uint8 hi, uint8 lo, const uint8* buf, int len)
{
	int i;
	for (i = 0; i < len; i += 2) {
		if (buf[i] == hi && buf[i + 1] == lo)
			return i;
	}
	return -1;
}

/*
	Files on the SmartCard-HSM are addressed by a 16 bit unsigned integers,
	where the upper 8 bits (hi) indicate the type of file and the lower 8 bits the name.
	In most cases 2 filegroup are associated (data and descriptor).
	lo is the binding between the 2 files.
	private keys:
	0xCC00 | lo .. private key (never readable)
	0xC400 | lo .. private key descriptor

	PKCS11 PIN protected data
	0xCD00 | lo .. data
	0xC900 | lo .. data descriptor.

	GetFids returns the key fid in pKeyFid and the template fid id in pTemplateFid.
	Because the template preparation is performed via PKCS11 the association between
	the key and the template is the label (you cannot specify the elementary file id
	with PKCS11, the ids are managed internally by the PKCS11 library).
	E.g.: We have a key "sign0" with fid 0xCC03 for the private data and 0xC403 for the descriptor.
	To find a key for a given label: enumerate through all 0xCCii files and open the associatet
	0xC4ii descriptor file. Check if it has the proper label ("sign0").
	If found: enumerate through all 0xCDjj files and open the associated 0xC9jj descriptor file.
	Check if it has the proper label.
	In case of success we have found a template associates with a key.
	The templates could be also used with PKCS11 withou a crypto library.
	The approach here is much simpler, you do not even need a PKCS11 library, here it is managed
	on a lower level, but specific to the SC-HSM (CardContact) card.
*/
static int GetFids(int ctn, const char *label, uint16 *pKeyFid, uint16 *pTemplateFid)
{
	uint8 list[2 * 128];
	uint16 sw1sw2;
	int rc, i;
	*pKeyFid = 0;
	*pTemplateFid = 0;
	/* - SmartCard-HSM: ENUMERATE OBJECTS */
	rc = SC_ProcessAPDU(
		ctn, 0, 0x00,0x58,0x00,0x00,
		0, 0,
		list, sizeof(list),
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000 && sw1sw2 != 0x6282)
		return ERR_APDU;
	/* find key file id */
	for (i = 0; i < rc; i += 2) {
		if (list[i] == 0xCC && FindFid(0xC4, list[i + 1], list, rc) >= 0) {
			uint8 buf[256];
			int rc = SC_ReadFile(ctn, 0xC400 | list[i + 1], 0, buf, sizeof(buf));
			if (rc > 0 && FindLabel(label, buf, rc)) {
				*pKeyFid = 0xCC00 | list[i + 1];
				break;
			}
		}
	}
	if (*pKeyFid == 0) {
		printf("key '%s' not found\n", label);
		return ERR_KEY;
	}
	/* find template file id */
	for (i = 0; i < rc; i += 2) {
		if (list[i] == 0xCD && FindFid(0xC9, list[i + 1], list, rc) >= 0) {
			uint8 buf[256];
			int rc = SC_ReadFile(ctn, 0xC900 | list[i + 1], 0, buf, sizeof(buf));
			if (rc > 0 && FindLabel(label, buf, rc)) {
				*pTemplateFid = 0xCD00 | list[i + 1];
				break;
			}
		}
	}
	if (*pTemplateFid == 0) {
		printf("template '%s' not found\n", label);
		return ERR_TEMPLATE;
	}
	return 0;
}

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ************************** Template  Functions ********************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/

typedef struct {
	uint8 Version;
	uint8 HeaderLength;
	uint16 HashLen;
	uint16 CertIdOff; /* unique cert id, 32 uint8 length */
	uint16 SignedAttributesOff;
	uint16 SignedAttributesLen;
	uint16 SigningTimeOff;
	uint16 MessageDigestOff;
	uint16 SignatureOff;
	uint16 SignatureSize;
	uint16 CMSLen;
/* up to here from file */
	uint16 KeyFid;
	uint16 TemplateFid;
	int Ctn;
	uint8 *pCms;
	char Label[1]; /* space for the 0 terminator, need calloc(1, sizeof(Template_t) + strlen(label)) */
} Template_t;

static Template_t *This; /* current template (singleton) */

#define TEMPLATE_VERSION (0)
#define TEMPLATE_HEADER_LENGTH (20)

static int LoadTemplate(int ctn, const char *label)
{
	uint8 *pCms;
	int rc, end, off, labelLen;
	if (label == 0)
		return ERR_INVALID;
	labelLen = strlen(label);
	This = (Template_t*)calloc(1, sizeof(Template_t) + labelLen);
	if (This == 0)
		return ERR_MEMORY;
	This->Ctn = ctn;
	memcpy(This->Label, label, labelLen + 1); /* include 0 terminator */
	rc = GetFids(ctn, label, &This->KeyFid, &This->TemplateFid);
	if (rc < 0)
		goto error;
	/* read template header */
	rc = SC_ReadFile(ctn, This->TemplateFid, 0, (uint8*)This, TEMPLATE_HEADER_LENGTH);
	if (rc < 0)
		goto error;
	if (rc != TEMPLATE_HEADER_LENGTH) {
		rc = ERR_TEMPLATE;
		goto error;
	}
	if (This->Version != TEMPLATE_VERSION || This->HeaderLength != TEMPLATE_HEADER_LENGTH) {
		rc = ERR_VERSION;
		goto error;
	}
#ifdef LITTLE_ENDIAN
#define swap(field) { uint8 tmp = This->field >> 8; This->field = This->field << 8 | tmp; }
	swap(HashLen)
	swap(CertIdOff)
	swap(SignedAttributesOff)
	swap(SignedAttributesLen)
	swap(SigningTimeOff)
	swap(MessageDigestOff)
	swap(SignatureOff)
	swap(SignatureSize)
	swap(CMSLen)
#undef swap
#endif
	/*
		Sanity checks
	*/
	if (This->HashLen != 32) {
		printf("currently only SHA256 supported\n");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(0 < This->SignedAttributesOff && This->SignedAttributesOff + This->SignedAttributesLen < This->SignatureOff)) {
		printf("signed attributes offset/length invalid\n");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(This->SignedAttributesOff < This->SigningTimeOff
		&& This->SigningTimeOff + 13 <= This->SignedAttributesOff + This->SignedAttributesLen)) {
		printf("signing time offset invalid\n");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(This->SignedAttributesOff < This->MessageDigestOff
		&& This->MessageDigestOff + This->HashLen <= This->SignedAttributesOff + This->SignedAttributesLen)) {
		printf("MessageDigest-Offset missing or invalid\n");
		rc = ERR_SANITY;
		goto error;
	}
	if (!(0 < This->SignatureOff && This->SignatureOff + This->SignatureSize <= This->CMSLen)) {
		printf("Signature-Offset missing or invalid\n");
		rc = ERR_SANITY;
		goto error;
	}
	This->pCms = (uint8*)calloc(1, This->CMSLen);
	if (This->pCms == 0) {
		rc = ERR_MEMORY;
		goto error;
	}
	/* read template body in MAX_OUT_IN bytes portions */
	off = TEMPLATE_HEADER_LENGTH;
	end = off + This->CMSLen;
	pCms = This->pCms;
	while (off < end) {
		int len = end - off;
		if (len > MAX_OUT_IN)
			len = MAX_OUT_IN;
		rc = SC_ReadFile(ctn, This->TemplateFid, off, pCms, len);
		if (rc != len) {
			rc = ERR_TEMPLATE;
			goto error;
		}
		off += len;
		pCms += len;
	}
	return 0;
error:
	if (This->pCms)
		free(This->pCms);
	free(This);
	This = 0;
	return rc;
}

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ************************** Signature Functions ********************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/

static int PatchSignedAttributes(
	const uint8 *hash, int hashLen,
	uint8 *hashToSign, int hashToSignLen)
{
	time_t now;
	struct tm t;
	char signingTime[16];
	uint8 oldTag;
	sha256_context ctx;
	/* patch signing time */
	time(&now);
	t = *gmtime(&now);
	if (!(2013 - 1900 <= t.tm_year && t.tm_year < 2050 - 1900))
		return ERR_TIME;
	sprintf(signingTime,
			"%02d%02d%02d%02d%02d%02dZ",
			t.tm_year - 100, 1 + t.tm_mon, t.tm_mday,
			t.tm_hour, t.tm_min, t.tm_sec);
	memcpy(This->pCms + This->SigningTimeOff, signingTime, 13);
	/* patch MessageDigest */
	memcpy(This->pCms + This->MessageDigestOff, hash, hashLen);
	/* calculate hash of signed attributes */
	oldTag = This->pCms[This->SignedAttributesOff]; /* save old tag */
	This->pCms[This->SignedAttributesOff] = 0x31; /* change from CONT [0] to SET tag */
	/* todo additional support of at least SHA1 */
	sha256_starts(&ctx);
	sha256_update(&ctx, This->pCms + This->SignedAttributesOff, This->SignedAttributesLen);
	sha256_finish(&ctx, hashToSign);
	This->pCms[This->SignedAttributesOff] = oldTag; /* restore CONT [0] */
	return 0;
}

static int PatchRSATemplate(const uint8 *hash, int hashLen)
{
	/*
	const ASN1 headers to build the asn1 enclosed hash:

		SEQUENCE
			SEQUENCE
				OID of hash
				NULL
			OCTETSTRING hash
	*/
	static const uint8 encSHA256[] =
		"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20";
#if 0
	static const uint8 encSHA1[] =
		"\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14";
	static const uint8 encSHA384[] =
		"\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30";
	static const uint8 encSHA512[] =
		"\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40";
#endif
	int ix, encLen;
	const uint8 *enc;
	uint8 *sig;
	int rc;
	uint8 hashToSign[32];
	rc = PatchSignedAttributes(hash, hashLen, hashToSign, sizeof(hashToSign));
	if (rc < 0)
		return rc;
	switch (hashLen) {
	case 32:          /* SHA-256 */
		enc = encSHA256;
		encLen = sizeof(encSHA256) - 1;
		break;
#if 0
	case 20:          /* SHA1 */
		enc = encSHA1;
		encLen = sizeof(encSHA1) - 1;
		break;
	case 48:          /* SHA-384 */
		enc = encSHA384;
		encLen = sizeof(encSHA384) - 1;
		break;
	case 64:          /* SHA-512 */
		enc = encSHA512;
		encLen = sizeof(encSHA512) - 1;
		break;
#endif
	default:
		return ERR_HASH;
	}
	/*
		Build 0x00, 0x01, 0xff, ... , 0xff, 0x00, asn1-enclosed-hash.
		The total size must match exactly the RSA modulus size (RSA2k: 2048 bits == 256 bytes).
		Use space of p->Signature !!!
	*/
	sig = This->pCms + This->SignatureOff;
	ix = This->SignatureSize;
	memcpy(sig + (ix -= hashLen), hashToSign, hashLen);
	memcpy(sig + (ix -= encLen), enc, encLen);
	sig[ix -= 1] = 0;
	memset(sig + 2, -1, ix - 2);
	sig[1] = 1;
	sig[0] = 0;
	return SC_Sign(This->Ctn, 0x20, (uint8)This->KeyFid, sig, This->SignatureSize, sig, This->SignatureSize);
}

static int PatchECDSATemplate(const uint8 *hash, int hashLen)
{
	int rc;
	uint8 hashToSign[32];
	uint8 *sig;
	rc = PatchSignedAttributes(hash, hashLen, hashToSign, sizeof(hashToSign));
	if (rc < 0)
		return rc;
	rc = SC_Sign(This->Ctn, 0x70, (uint8)This->KeyFid, hashToSign, hashLen, This->pCms + This->SignatureOff, This->SignatureSize);
	if (rc < 0)
		return rc;
	/*
		Expand to fixed length.
		Expanding is used to obtain a fixed length signature. A fixed length
		signature is convenient for signing with a template (otherwise all
		previous nodes need to be adjusted and probably moved).
		An ASN.1 INTEGER is signed. If we want to encode an unsigned integer
		(like in almost all cases of cryptography) and the highest bit is set
		a leading 0 must be added. An additional leading 0 violates the DER but
		not the BER encoding. A ECDSA signature needs not to be DER encoded because
		it is never hashed or bitwise compared.

		ASN.1 encoding of DSA and ECDSA signature: (total length ... 70, 71 or 72)
		SEQUENCE // length: ... 68, 69 or 70)
			r INTEGER // length: ... 32 or 33 if MSBit set
			s INTEGER // length: ... 32 or 33 if MSBit set

		expanded ASN.1 encoding: (total length 72)
		0x00=00: 0x30 0x46 //  SEQUENCE of length 0x46 (== 70)
		0x02=02: 0x02 0x21 // r INTEGER of length 0x21 (== 33)
		0x25=37: 0x02 0x21 // s INTEGER of length 0x21 (== 33)
		0x48=72:
	*/
	sig = This->pCms + This->SignatureOff;
	if ((57 <= rc && rc <= 72) && sig[0] == 0x30) {
		int ri = 2 + 2;          /*  index of r data */
		int rl = sig[ri - 1];    /* length of r data */
		int si = 2 + 2 + rl + 2; /*  index of s data */
		int sl = sig[si - 1];    /* length of s data */
		if (rl > 33 || sl > 33)
			return ERR_INVALID; /* should never happen */
		/* due to inplace moving we must start with s */
		memmove(sig + 72 - sl, sig + si, sl); /* move data of s to end  */
		memset(sig + 37 + 2, 0, 33 - sl);     /* set leading zeros of s */
		sig[38] = 33;                         /* set length of s        */
		sig[37] = 0x02;                       /* set INTEGER tag        */
		memmove(sig + 37 - rl, sig + ri, rl); /* move data of r         */
		memset(sig + 2 + 2, 0, 33 - rl);      /* set leading zeros of r */
		sig[ 3] = 33;                         /* set length of r        */
		sig[ 2] = 0x02;                       /* set INTEGER tag        */
		sig[ 1] = 70;                         /* set lenth of SEQUENCE  */
		/* sig[0] = 0x30; */
		return 72;
	}
	return rc;
}

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 *******************************************************************************
 **************************** public Functions *********************************
 *******************************************************************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/
/*
 *  Signature of specified hash
 *
 *  pin         : smartcard pin
 *  label       : key and template label
 *  hash        : Hash to be signed
 *  hashLen     : Length of hash (20, 32, 48 or 64)
 *  ppCms       : returns the CMS data in *ppCms
 *
 *  Returns : CMS size or error if <= 0
 */
int EXPORT_FUNC sign_hash(const char *pin, const char *label, const uint8 *hash, int hashLen, const uint8 **ppCms)
{
	int rc;

	*ppCms = 0;

	if (This) { /* try to reuse template */
		if (strcmp(This->Label, label)) {
			release_template();
		} else {
			uint8 certId[32];
			rc = SC_ReadFile(This->Ctn, This->TemplateFid, TEMPLATE_HEADER_LENGTH + This->CertIdOff, certId, sizeof(certId));
			if (rc != sizeof(certId) || memcmp(certId, This->pCms + This->CertIdOff, sizeof(certId)))
				release_template(); /* do not reuse, but release rescources */
		}
	}
	if (This == 0) {
		int ctn = SC_Open(pin);
		if (ctn < 0)
			return ctn;
		rc = LoadTemplate(ctn, label);
		if (rc < 0) {
			SC_Close(ctn);
			return rc;
		}
	}
	if (This->SignatureSize == 256) /* RSA */
		rc = PatchRSATemplate(hash, hashLen);
	else if (This->SignatureSize == 72)
		rc = PatchECDSATemplate(hash, hashLen);
	else
		rc = ERR_TEMPLATE;
	if (rc == 72 || rc == 256) {
		*ppCms = This->pCms;
		return This->CMSLen;
	}
	/* error case */
	release_template();
	return rc < 0 ? rc : ERR_KEY_SIZE;
}

void EXPORT_FUNC release_template()
{
	if (This == 0)
		return;
	SC_Close(This->Ctn);
	free(This->pCms);
	free(This);
	This = 0;
}
