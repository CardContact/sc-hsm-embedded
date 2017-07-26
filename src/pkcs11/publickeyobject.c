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
 * @file    publickeyobject.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for public key management
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pkcs11/object.h>
#include <pkcs11/publickeyobject.h>
#include <pkcs11/certificateobject.h>
#include <pkcs11/crypto.h>
#include <common/pkcs15.h>

#include <common/cvc.h>
#include <common/asn1.h>

#ifdef DEBUG
#include <common/debug.h>

extern int dumpAttributeList(struct p11Object_t *pObject);

#endif

extern CK_BBOOL ckFalse;

static struct attributesForObject_t attributesPublicKeyObject[] = {
		{{CKA_SUBJECT, NULL, 0}, AC_DEFAULT},
		{{CKA_ENCRYPT, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
		{{CKA_VERIFY, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
		{{CKA_VERIFY_RECOVER, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
		{{CKA_WRAP, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
		{{CKA_TRUSTED, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
		{{CKA_WRAP_TEMPLATE, 0, 0}, AC_OPTIONAL},
		{{CKA_MODULUS, 0, 0}, AC_OPTIONAL},
		{{CKA_MODULUS_BITS, 0, 0}, AC_OPTIONAL},
		{{CKA_PUBLIC_EXPONENT, 0, 0}, AC_OPTIONAL},
		{{CKA_EC_PARAMS, 0, 0}, AC_OPTIONAL},
		{{CKA_EC_POINT, 0, 0}, AC_OPTIONAL},
		{{CKA_CVC_REQUEST, 0, 0 }, AC_OPTIONAL},
		{{0, NULL, 0}, AC_DEFAULT }
};


/**
 *  Constructor for the public key object
 */
int createPublicKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	int rc;

	rc = createKeyObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	rc = copyObjectAttributes(pTemplate, ulCount, pObject, attributesPublicKeyObject);

#ifdef ENABLE_LIBCRYPTO
	pObject->C_VerifyInit = cryptoVerifyInit;
	pObject->C_Verify = cryptoVerify;
	pObject->C_EncryptInit = cryptoEncryptInit;
	pObject->C_Encrypt = cryptoEncrypt;
#endif

#ifdef DEBUG
	dumpAttributeList(pObject);
#endif

	return rc;
}



int createPublicKeyObjectFromCertificate(struct p15PrivateKeyDescription *p15, struct p11Object_t *cert, struct p11Object_t **pObject)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_UTF8CHAR label[10];
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_ULONG modulus_bits = 2048;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_TOKEN, &true, sizeof(true) },
			{ CKA_PRIVATE, &false, sizeof(false) },
			{ CKA_LABEL, label, sizeof(label) - 1 },
			{ CKA_ID, NULL, 0 },
			{ CKA_LOCAL, &true, sizeof(true) },
			{ CKA_ENCRYPT, &true, sizeof(true) },
			{ CKA_VERIFY, &true, sizeof(true) },
			{ CKA_VERIFY_RECOVER, &true, sizeof(true) },
			{ CKA_WRAP, &false, sizeof(false) },
			{ CKA_TRUSTED, &false, sizeof(false) },
			{ 0, NULL, 0 },
			{ 0, NULL, 0 },
			{ 0, NULL, 0 }
	};
	struct p11Object_t *p11o;
	unsigned char *spki;
	int rc, attributes;

	FUNC_CALLED();

	if (p15->coa.label) {
		template[4].pValue = p15->coa.label;
		template[4].ulValueLen = (CK_ULONG)strlen(template[4].pValue);
	}

	if (p15->id.len) {
		template[5].pValue = p15->id.val;
		template[5].ulValueLen = (CK_ULONG)p15->id.len;
	}

	rc = getSubjectPublicKeyInfo(cert, &spki);

	if (rc != CKR_OK){
		FUNC_FAILS(rc, "Could not create public key in certificate");
	}

	p11o = calloc(sizeof(struct p11Object_t), 1);

	if (p11o == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	attributes = sizeof(template) / sizeof(CK_ATTRIBUTE) - 3;

	switch(p15->keytype) {
	case P15_KEYTYPE_RSA:
		keyType = CKK_RSA;
		if (decodeModulusExponentFromSPKI(spki, &template[attributes], &template[attributes + 1])) {
			free(p11o);
			FUNC_FAILS(CKR_KEY_TYPE_INCONSISTENT, "Can't decode modulus - Private key type does not match public key type in certificate");
		}
		cert->keysize = template[attributes].ulValueLen << 3;

		attributes += 2;
		modulus_bits = cert->keysize;
		template[attributes].type = CKA_MODULUS_BITS;
		template[attributes].ulValueLen = sizeof(modulus_bits);
		template[attributes].pValue = &modulus_bits;
		attributes++;
		break;
	case P15_KEYTYPE_ECC:
		keyType = CKK_ECDSA;
		if (decodeECParamsFromSPKI(spki, &template[attributes])) {
			free(p11o);
			FUNC_FAILS(CKR_KEY_TYPE_INCONSISTENT, "Can't decode EC parameter - Private key type does not match public key type in certificate");
		}
		attributes++;
		if (decodeECPointFromSPKI(spki, &template[attributes])) {
			free(p11o);
			FUNC_FAILS(CKR_KEY_TYPE_INCONSISTENT, "Private key type does not match public key type in certificate");
		}
		cert->keysize = (template[attributes].ulValueLen - 3) << 2;
		attributes++;
		break;
	default:
		free(p11o);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Unknown key type in PRKD");
	}

	rc = createPublicKeyObject(template, attributes, p11o);

	if (rc != CKR_OK) {
		free(p11o);
		FUNC_FAILS(rc, "Could not create public key object");
	}

	*pObject = p11o;

	FUNC_RETURNS(CKR_OK);
}



int createPublicKeyObjectFromCVC(struct p15PrivateKeyDescription *p15, unsigned char *cert, size_t certlen, struct p11Object_t **pObject)
{
	CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_ULONG modulus_bits;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_TOKEN, &true, sizeof(true) },
			{ CKA_PRIVATE, &false, sizeof(false) },
			{ CKA_LABEL, NULL, 0 },
			{ CKA_ID, NULL, 0 },
			{ CKA_LOCAL, &true, sizeof(true) },
			{ CKA_ENCRYPT, &true, sizeof(true) },
			{ CKA_VERIFY, &true, sizeof(true) },
			{ CKA_VERIFY_RECOVER, &true, sizeof(true) },
			{ CKA_WRAP, &false, sizeof(false) },
			{ CKA_TRUSTED, &false, sizeof(false) },
			{ CKA_CVC_REQUEST, NULL, 0 },
			{ 0, NULL, 0 },
			{ 0, NULL, 0 },
			{ 0, NULL, 0 }
	};
	struct p11Object_t *p11o;
	struct cvc cvc;
	unsigned char screcparam[20];		// 06 Len OID
	struct bytebuffer_s ecparam = { screcparam, 0, sizeof(screcparam)};
	unsigned char screcpuk[140];			// 04 Len X||Y
	struct bytebuffer_s ecpuk = { screcpuk, 0, sizeof(screcpuk)};
	bytestring oid;
	int rc, attributes;

	FUNC_CALLED();

	rc = cvcDecode(cert, certlen, &cvc);

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not decode CVC request");
	}

	template[12].pValue = cert;
	template[12].ulValueLen = rc;

	if (p15->coa.label) {
		template[4].pValue = p15->coa.label;
		template[4].ulValueLen = (CK_ULONG)strlen(template[4].pValue);
	}

	if (p15->id.len) {
		template[5].pValue = p15->id.val;
		template[5].ulValueLen = (CK_ULONG)p15->id.len;
	}

	p11o = calloc(sizeof(struct p11Object_t), 1);

	if (p11o == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	attributes = sizeof(template) / sizeof(CK_ATTRIBUTE) - 3;

	switch(p15->keytype) {
	case P15_KEYTYPE_RSA:
		keyType = CKK_RSA;

		template[attributes].type = CKA_MODULUS;
		template[attributes].pValue = cvc.primeOrModulus.val;
		template[attributes].ulValueLen = (CK_ULONG)cvc.primeOrModulus.len;
		attributes++;

		modulus_bits = (CK_ULONG)(cvc.primeOrModulus.len << 3);
		template[attributes].type = CKA_MODULUS_BITS;
		template[attributes].pValue = &modulus_bits;
		template[attributes].ulValueLen = sizeof(modulus_bits);
		attributes++;

		template[attributes].type = CKA_PUBLIC_EXPONENT;
		template[attributes].pValue = cvc.coefficientAorExponent.val;
		template[attributes].ulValueLen = (CK_ULONG)cvc.coefficientAorExponent.len;
		attributes++;
		break;
	case P15_KEYTYPE_ECC:
		keyType = CKK_ECDSA;
		if (cvcDetermineCurveOID(&cvc, &oid)) {
#ifdef DEBUG
			debug("Can't determine EC curve oid from domain parameter\n");
#endif
		} else {
			asn1Append(&ecparam, ASN1_OBJECT_IDENTIFIER, oid);
			template[attributes].type = CKA_EC_PARAMS;
			template[attributes].pValue = ecparam.val;
			template[attributes].ulValueLen = (CK_ULONG)ecparam.len;
			attributes++;
		}

		asn1Append(&ecpuk, ASN1_OCTET_STRING, &cvc.publicPoint);
		template[attributes].type = CKA_EC_POINT;
		template[attributes].pValue = ecpuk.val;
		template[attributes].ulValueLen = (CK_ULONG)ecpuk.len;
		attributes++;
		break;
	default:
		free(p11o);
		FUNC_FAILS(CKR_DEVICE_ERROR, "Unknown key type in PRKD");
	}

	rc = createPublicKeyObject(template, attributes, p11o);

	if (rc != CKR_OK) {
		free(p11o);
		FUNC_FAILS(rc, "Could not create public key object");
	}

	p11o->keysize =  (CK_ULONG)(cvc.primeOrModulus.len << 3);
	*pObject = p11o;

	FUNC_RETURNS(CKR_OK);
}
