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
 * @file    certificateobject.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for certificate objects
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

static struct attributesForObject_t attributesCertificateObject[] = {
		{{CKA_CERTIFICATE_TYPE, NULL, 0}, MANDATORY},
		{{CKA_ID, NULL, 0}, OPTIONAL},
		{{CKA_VALUE, NULL, 0}, MANDATORY},
		{{0, NULL, 0}, DEFAULT }
};



/**
 *  Constructor for the certificate object
 */
int createCertificateObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	int rc;

	rc = createStorageObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	rc = copyObjectAttributes(pTemplate, ulCount, pObject, attributesCertificateObject);

#ifdef DEBUG
	dumpAttributeList(pObject);
#endif

	return rc;
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



int getSubjectPublicKeyInfo(struct p11Object_t *pObject, unsigned char **spki)
{
	CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
	struct p11Attribute_t *pattr;
	int tag, length, buflen;
	unsigned char *value, *cursor;

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

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag == 0xA0) {				// Skip optional cert type
		if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
			return -1;
		}
	}

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Skip SignatureAlgorithm
		return -1;
	}

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Skip Issuer
		return -1;
	}

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Skip validity dates
		return -1;
	}

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Skip Subject
		return -1;
	}

	*spki =cursor;

	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {	// Skip SubjectPublicKeyInfo
		return -1;
	}

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	return 0;
}



int decodeModulusExponentFromSPKI(unsigned char *spki,
                                 CK_ATTRIBUTE_PTR modulus,
                                 CK_ATTRIBUTE_PTR exponent)
{
	int tag, length, buflen;
	unsigned char *value, *cursor;

	cursor = spki;				// spk is ASN.1 validated before, not need to check again

	// subjectPublicKeyInfo
	tag = asn1Tag(&cursor);

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	buflen = asn1Length(&cursor);

	// algorithm
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	// subjectPublicKey
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_BIT_STRING) {
		return -1;
	}

	if (length < 6) {
		return -1;
	}

	cursor = value + 1;
	buflen = length - 1;

	if (asn1Validate(cursor, buflen) != 0) {
		return -1;
	}

	// Outer SEQUENCE
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	cursor = value;
	buflen = length;

	// Modulus
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_INTEGER) {
		return -1;
	}

	if (*value == 0) {
		value++;
		length--;
	}

	modulus->type = CKA_MODULUS;
	modulus->pValue = value;
	modulus->ulValueLen = length;

	// Exponent
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_INTEGER) {
		return -1;
	}

	exponent->type = CKA_PUBLIC_EXPONENT;
	exponent->pValue = value;
	exponent->ulValueLen = length;

	return 0;
}



int decodeECParamsFromSPKI(unsigned char *spki,
                           CK_ATTRIBUTE_PTR ecparams)
{
	int tag, length, buflen;
	unsigned char *value, *cursor;

	cursor = spki;				// spk is ASN.1 validated before, not need to check again

	// subjectPublicKeyInfo
	tag = asn1Tag(&cursor);

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	buflen = asn1Length(&cursor);

	// algorithm
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	cursor = value;
	buflen = length;

	// algorithm
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_OBJECT_IDENTIFIER) {
		return -1;
	}

	ecparams->type = CKA_EC_PARAMS;
	ecparams->pValue = cursor;

	// parameters
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	ecparams->ulValueLen = cursor - (unsigned char *)ecparams->pValue;

	return 0;
}



int decodeECPointFromSPKI(unsigned char *spki,
                                 CK_ATTRIBUTE_PTR point)
{
	int tag, length, buflen;
	unsigned char *value, *cursor;
	static unsigned char encappuk[83];

	cursor = spki;				// spk is ASN.1 validated before, not need to check again

	// subjectPublicKeyInfo
	tag = asn1Tag(&cursor);

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	buflen = asn1Length(&cursor);

	// algorithm
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_SEQUENCE) {
		return -1;
	}

	// subjectPublicKey
	if (!asn1Next(&cursor, &buflen, &tag, &length, &value)) {
		return -1;
	}

	if (tag != ASN1_BIT_STRING) {
		return -1;
	}

	if ((length < 6) || (length > 82)) {
		return -1;
	}

	encappuk[0] = ASN1_OCTET_STRING;
	encappuk[1] = length - 1;
	memcpy(encappuk + 2, value + 1, length - 1);
	point->type = CKA_EC_POINT;
	point->pValue = encappuk;
	point->ulValueLen = length + 1;

	return 0;
}



int createCertificateObjectFromP15(struct p15CertificateDescription *p15, unsigned char *cert, size_t certlen, struct p11Object_t **pObject)
{
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
			{ CKA_TOKEN, &true, sizeof(true) },
			{ CKA_PRIVATE, &false, sizeof(false) },
			{ CKA_LABEL, NULL, 0 },
			{ CKA_ID, NULL, 0 },
			{ CKA_VALUE, NULL, 0 }
	};
	struct p11Object_t *p11o;
	unsigned char *po;
	int rc, len;

	FUNC_CALLED();

	if ((*cert != ASN1_SEQUENCE) || (certlen < 5)) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error not a certificate");
	}

	po = cert;
	asn1Tag(&po);
	len = asn1Length(&po);
	po += len;

	if ((po - cert) > certlen) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Certificate corrupted");
	}

	template[6].pValue = cert;
	template[6].ulValueLen = po - cert;

	certType = (p15->certtype == P15_CT_X509) ? CKC_X_509 : CKC_X_509_ATTR_CERT;

	if (p15->coa.label) {
		template[4].pValue = p15->coa.label;
		template[4].ulValueLen = strlen(template[4].pValue);
	}

	if (p15->id.len) {
		template[5].pValue = p15->id.val;
		template[5].ulValueLen = p15->id.len;
	}

	p11o = calloc(sizeof(struct p11Object_t), 1);

	if (p11o == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	rc = createCertificateObject(template, 7, p11o);

	if (rc != CKR_OK) {
		free(p11o);
		FUNC_FAILS(rc, "Could not create certificate key object");
	}

	rc = populateIssuerSubjectSerial(p11o);

	if (rc != CKR_OK) {
#ifdef DEBUG
		debug("populateIssuerSubjectSerial() failed\n");
#endif
	}

	*pObject = p11o;

	FUNC_RETURNS(CKR_OK);
}

