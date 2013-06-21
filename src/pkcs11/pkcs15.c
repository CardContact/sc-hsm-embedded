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
 * @file    pkcs15.c
 * @author  Andreas Schwier
 * @brief   Decoder for PKCS#15 private key, certificate and data objects
 */

#include <stdlib.h>
#include <string.h>
#include <pkcs11/asn1.h>

#include "pkcs15.h"



static int decodeCommonObjectAttributes(unsigned char *coa, int coalen, struct p15CommonObjectAttributes *p15)
{
	int tag,len;
	unsigned char *po;
	char *label;

	po = coa;
	tag = asn1Tag(&po);

	if (tag == ASN1_UTF8String) {
		len = asn1Length(&po);
		label = calloc(len + 1, 1);
		if (label == NULL) {
			return -1;
		}
		memcpy(label, po, len);
		p15->label = label;
	}

	return 0;
}



static int decodeCommonKeyAttributes(unsigned char *cka, int ckalen, struct p15PrivateKeyDescription *p15)
{
	int tag,len;
	unsigned char *po, *obj, *id;

	po = obj = cka;
	tag = asn1Tag(&po);
	len = asn1Length(&po);

	if ((tag != ASN1_OCTET_STRING) || (len <= 0)) {
		return -1;
	}

	id = calloc(len, 1);
	if (id == NULL) {
		return -1;
	}
	memcpy(id, po, len);
	p15->id = id;
	p15->idlen = len;

	po += len;

	if ((po - cka) >= ckalen) {
		return 0;
	}

	obj = po;
	tag = asn1Tag(&po);
	len = asn1Length(&po);

	if ((tag != ASN1_BIT_STRING) || (len <= 1)) {
		return -1;
	}

	asn1DecodeFlags(po + 1, len - 1, &p15->usage);
	return 0;
}



static int decodeKeyAttributes(unsigned char *ka, int kalen, struct p15PrivateKeyDescription *p15)
{
	int tag,len;
	unsigned char *po, *obj;

	po = obj = ka;
	tag = asn1Tag(&po);
	len = asn1Length(&po);

	if ((tag != ASN1_SEQUENCE) || (len <= 0)) {
		return -1;
	}

	po += len;

	if ((po - ka) >= kalen) {
		return 0;
	}

	obj = po;
	tag = asn1Tag(&po);
	len = asn1Length(&po);

	if ((tag == ASN1_INTEGER) && (len > 0)) {
		if (asn1DecodeInteger(po, len, &p15->keysize) < 0) {
			return -1;
		}
	} else {
		p15->keysize = 2048;		// Save default for key size
	}
	return 0;
}



static int decodePrivateKeyAttributes(unsigned char *prkd, int prkdlen, struct p15PrivateKeyDescription *p15)
{
	int rc,tag,len;
	unsigned char *po, *obj;

	if (prkdlen <= 0) {				// Nothing to decode
		return 0;
	}

	po = obj = prkd;

	tag = asn1Tag(&po);
	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	len = asn1Length(&po);

	rc = decodeCommonObjectAttributes(po, len, &p15->coa);
	if (rc < 0) {
		return rc;
	}

	po += len;

	if ((po - prkd) >= prkdlen) {
		return 0;
	}

	obj = po;
	tag = asn1Tag(&po);
	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	len = asn1Length(&po);

	rc = decodeCommonKeyAttributes(po, len, p15);
	if (rc < 0) {
		return rc;
	}

	po += len;

	if ((po - prkd) >= prkdlen) {
		return 0;
	}

	obj = po;
	tag = asn1Tag(&po);
	if (tag == 0xA0) {
		len = asn1Length(&po);
		po += len;

		if ((po - prkd) >= prkdlen) {
			return 0;
		}
		obj = po;
		tag = asn1Tag(&po);
	}

	len = asn1Length(&po);
	if ((tag != 0xA1) || (len <= 0)) {
		return -1;
	}

	tag = asn1Tag(&po);
	len = asn1Length(&po);

	if ((tag != ASN1_SEQUENCE) || (len <= 0)) {
		return -1;
	}

	rc = decodeKeyAttributes(po, len, p15);
	if (rc < 0) {
		return rc;
	}

	return 0;
}



/**
 * Decode a TLV encoded PKCS#15 private key description into a structure
 *
 * The caller must use freePrivateKeyDescription() to free the allocated structure
 *
 * @param prkd      The first byte of the encoded structure
 * @param prkdlen   The length of the encoded structure
 * @param p15       Pointer to pointer updated with the newly allocated structure
 * @return          0 if successfull, -1 for structural errors
 */
int decodePrivateKeyDescription(unsigned char *prkd, size_t prkdlen, struct p15PrivateKeyDescription **p15)
{
	int rc,tag,len;
	unsigned char *po;

	rc = asn1Validate(prkd, prkdlen);

	if (rc != 0) {
		return -1;
	}

	*p15 = calloc(1, sizeof(struct p15PrivateKeyDescription));
	if (*p15 == NULL) {
		return -1;
	}

	po = prkd;

	tag = asn1Tag(&po);
	len = asn1Length(&po);

	if ((tag != ASN1_SEQUENCE) && (tag != 0xA0)) {
		return -1;
	}

	(*p15)->keytype = (int)tag;
	rc = decodePrivateKeyAttributes(po, len, *p15);

	return rc;
}



static void freeCommonObjectAttributes(struct p15CommonObjectAttributes *coa)
{
	if (coa->label != NULL) {
		free(coa->label);
		coa->label = NULL;
	}
}



/**
 * Free structure allocated in decodePrivateKeyDescription()
 *
 * @param p15       Pointer to pointer to structure. Pointer is cleared with NULL
 */
void freePrivateKeyDescription(struct p15PrivateKeyDescription **p15)
{
	if (*p15 != NULL) {
		freeCommonObjectAttributes(&(*p15)->coa);
		if ((*p15)->id) {
			free((*p15)->id);
			(*p15)->id = NULL;
		}
		free(*p15);
	}
	*p15 = NULL;
}
