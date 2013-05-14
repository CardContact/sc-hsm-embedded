/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2003. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  --------- 
 *
 * The Smart Card Development Platform (SCDP) provides a basic framework to
 * implement smartcard aware applications.
 *
 * Abstract :       Functions for secret key object management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

/**
 * \file    certificateobject.c
 * \author  Frank Thater (fth)
 * \brief   Functions for certificate management
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pkcs11/object.h>
#include <pkcs11/certificateobject.h>
#include <pkcs11/asn1.h>

#ifdef DEBUG
#include <pkcs11/debug.h>

extern int dumpAttributeList(struct p11Object_t *pObject);

#endif

static struct attributesForObject_t attributesCertificateObject[NEEDED_ATTRIBUTES_CERTIFICATEOBJECT] = {
		{{CKA_CERTIFICATE_TYPE, NULL, 0}, FALSE},
		{{CKA_ID, NULL, 0}, FALSE},
		{{CKA_VALUE, NULL, 0}, FALSE}
};



/**
 *  Constructor for the certificate object
 */
int createCertificateObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	unsigned int i;
	int index, rc;

	rc = createStorageObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	for (i = 0; i < NEEDED_ATTRIBUTES_CERTIFICATEOBJECT; i++) {

		index = findAttributeInTemplate(attributesCertificateObject[i].attribute.type, pTemplate, ulCount);

		if (index == -1) { /* The attribute is not present - is it optional? */

			if (attributesCertificateObject[i].optional) {

				addAttribute(pObject, &attributesCertificateObject[i].attribute);

			} else { /* the attribute is not optional */

				removeAllAttributes(pObject);
				memset(pObject, 0x00, sizeof(*pObject));
				return CKR_TEMPLATE_INCOMPLETE;

			}

		} else {
			addAttribute(pObject, &pTemplate[index]);
		}
	}

#ifdef DEBUG
	dumpAttributeList(pObject);
#endif

	return 0;
}



/**
 * Populate the attribute CKA_ISSUER, CKA_SUBJECT and CKA_SERIAL from certificate
 */
int populateIssuerSubjectSerial(struct p11Object_t *pObject)
{
	CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
	struct p11Attribute_t *pattr;
	int tag, length, buflen;
	unsigned char *value, *cursor, *obj;

	attr.type = CKA_VALUE;
	if (findAttribute(pObject, &attr, &pattr) < 0) {
		return -1;
	}

	cursor = pattr->attrData.pValue;
	buflen = pattr->attrData.ulValueLen;

	if (asn1Validate(cursor, buflen)) {
		return -1;
	}

	// Outer SEQUENCE
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	cursor = value;
	buflen = length;

	// TBS SEQUENCE
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	cursor = value;
	buflen = length;

	obj = cursor;
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag == 0xA0) {				// Skip optional cert type
		obj = cursor;
		if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
			return -1;
		}
	}

	if (tag != ASN1_INTEGER) {
		return -1;
	}

	attr.type = CKA_SERIAL_NUMBER;
	attr.pValue = obj;
	attr.ulValueLen = cursor - obj;

	addAttribute(pObject, &attr);

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Skip SignatureAlgorithm
		return -1;
	}

	obj = cursor;
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Decode Issuer
		return -1;
	}

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	attr.type = CKA_ISSUER;
	attr.pValue = obj;
	attr.ulValueLen = cursor - obj;

	addAttribute(pObject, &attr);

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Skip validity dates
		return -1;
	}

	obj = cursor;
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Decode Subject
		return -1;
	}

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	attr.type = CKA_SUBJECT;
	attr.pValue = obj;
	attr.ulValueLen = cursor - obj;

	addAttribute(pObject, &attr);

	return 0;
}
