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



static int decodeCommonObjectAttributes(unsigned char *prkd, size_t prkdlen, struct p15PrivateKeyDescription *p15)
{
	int rc,tag,len;
	unsigned char *po;
	char *label;

	po = prkd;
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



static int decodeRSAPrivateKeyDescription(unsigned char *prkd, size_t prkdlen, struct p15PrivateKeyDescription *p15)
{
	int rc,tag,len;
	unsigned char *po;

	po = prkd;

	tag = asn1Tag(&po);
	len = asn1Length(&po);

	rc = decodeCommonObjectAttributes(po, len, p15);
	if (rc < 0) {
		return rc;
	}

	po += len;

	return 0;
}



static int decodeECPrivateKeyDescription(unsigned char *prkd, size_t prkdlen, struct p15PrivateKeyDescription *p15)
{
	int rc,tag,len;
	unsigned char *po;

	po = prkd;

	tag = asn1Tag(&po);
	len = asn1Length(&po);

	rc = decodeCommonObjectAttributes(po, len, p15);
	if (rc < 0) {
		return rc;
	}

	po += len;

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

	(*p15)->keytype = (int)tag;
	switch(tag) {
	case ASN1_SEQUENCE:
		rc = decodeRSAPrivateKeyDescription(po, len, *p15);
		break;
	case 0xA0:
		rc = decodeECPrivateKeyDescription(po, len, *p15);
		break;
	default:
		return -1;
	}
	return 0;
}



void freePrivateKeyDescription(struct p15PrivateKeyDescription **p15)
{
	if (*p15 != NULL) {
		if ((*p15)->label != NULL) {
			free((*p15)->label);
			(*p15)->label = NULL;
		}
		free(*p15);
	}
	*p15 = NULL;
}
