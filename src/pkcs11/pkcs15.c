/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2004. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  ---------
 */

/**
 * @file    pkcs15.c
 * @author  Andreas Schwier (ASC)
 * @brief   Decoder for PKCS#15 private key, certificate and data objects
 */

#include <stdlib.h>
#include <string.h>
#include <pkcs11/asn1.h>

#include "pkcs15.h"



static int decodeCommonObjectAttributes(unsigned char *coa, int coalen, struct p15CommonObjectAttributes *p15)
{
	int rc,tag,len;
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
	int rc,tag,len;
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
	int rc,tag,len;
	unsigned char *po, *obj;
	char *label;

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



void freeCommonObjectAttributes(struct p15CommonObjectAttributes *coa)
{
	if (coa->label != NULL) {
		free(coa->label);
		coa->label = NULL;
	}
}



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
