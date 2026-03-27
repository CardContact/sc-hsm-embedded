/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2019, CardContact Systems GmbH, Minden, Germany
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
 * @file    secretkeyobject.c
 * @author  Leif Erik Wagner
 * @brief   Functions for secret key management
 */

#include <pkcs11/p11generic.h>
#include <pkcs11/object.h>
#include <common/pkcs15.h>

#ifdef DEBUG
#include <common/debug.h>

extern int dumpAttributeList(struct p11Object_t *pObject);

#endif

extern CK_BBOOL ckFalse;



static struct attributesForObject_t attributesSecretKeyObject[] = {
	{{CKA_VALUE_LEN, 0, 0}, AC_OPTIONAL},
	{{CKA_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_ENCRYPT, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_DECRYPT, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_SIGN, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_VERIFY, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_WRAP, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_UNWRAP, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_ALWAYS_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_NEVER_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_WRAP_WITH_TRUSTED, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_TRUSTED, &ckFalse, sizeof(CK_BBOOL)}, AC_DEFAULT},
	{{CKA_WRAP_TEMPLATE, 0, 0}, AC_DEFAULT},
	{{CKA_UNWRAP_TEMPLATE, 0, 0}, AC_DEFAULT},
	{{0, NULL, 0}, AC_DEFAULT }
};



/**
 *  Constructor for the secret key object
 */
int createSecretKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject) {
	int rc;

	rc = createKeyObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	rc = copyObjectAttributes(pTemplate, ulCount, pObject, attributesSecretKeyObject);

#ifdef DEBUG
	dumpAttributeList(pObject);
#endif

	return rc;
}



int createSecretKeyObjectFromP15(struct p15SecretKeyDescription *p15, struct p11Object_t **pObject) {
	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE keyType = CKK_AES;
	CK_MECHANISM_TYPE genMechType = CKM_AES_KEY_GEN;
	CK_ULONG keylen = 0;
	CK_BBOOL ck_true = CK_TRUE;
	CK_BBOOL ck_false = CK_FALSE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_TOKEN, &ck_true, sizeof(ck_true) },
			{ CKA_PRIVATE, &ck_true, sizeof(ck_true) },
			{ CKA_LABEL, NULL, 0 },
			{ CKA_ID, NULL, 0 },
			{ CKA_LOCAL, &ck_true, sizeof(ck_true) },
			{ CKA_KEY_GEN_MECHANISM, &genMechType, sizeof(genMechType) },
			{ CKA_VALUE_LEN, &keylen, sizeof(keylen) },
			{ CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
			{ CKA_ENCRYPT, &ck_true, sizeof(ck_true) },
			{ CKA_DECRYPT, &ck_true, sizeof(ck_true) },
			{ CKA_SIGN, &ck_true, sizeof(ck_true) },
			{ CKA_VERIFY, &ck_true, sizeof(ck_true) },
			{ CKA_WRAP, &ck_false, sizeof(ck_false) },
			{ CKA_UNWRAP, &ck_false, sizeof(ck_false) },
			{ CKA_DERIVE, &ck_false, sizeof(ck_false) },
			{ CKA_EXTRACTABLE, &ck_false, sizeof(ck_false) },
			{ CKA_ALWAYS_SENSITIVE, &ck_true, sizeof(ck_true) },
			{ CKA_NEVER_EXTRACTABLE, &ck_true, sizeof(ck_true) }
	};
	struct p11Object_t *p11o;
	int rc, attributes;

	FUNC_CALLED();

	p11o = calloc(sizeof(struct p11Object_t), 1);

	if (p11o == NULL) {
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
	}

	if (p15->coa.label) {
		template[4].pValue = p15->coa.label;
		template[4].ulValueLen = (CK_ULONG)strlen(template[4].pValue);
	}

	if (p15->id.val) {
		template[5].pValue = p15->id.val;
		template[5].ulValueLen = (CK_ULONG)p15->id.len;
	}

	keylen = p15->keysize >> 3;

	template[10].pValue = p15->usage & P15_ENCIPHER ? &ck_true : &ck_false;
	template[11].pValue = p15->usage & P15_DECIPHER ? &ck_true : &ck_false;
	template[12].pValue = p15->usage & P15_SIGN ? &ck_true : &ck_false;
	template[13].pValue = p15->usage & P15_VERIFY ? &ck_true : &ck_false;
	template[14].pValue = p15->usage & P15_KEYENCIPHER ? &ck_true : &ck_false;
	template[15].pValue = p15->usage & P15_KEYDECIPHER ? &ck_true : &ck_false;
	template[16].pValue = p15->usage & P15_DERIVE ? &ck_true : &ck_false;

	attributes = sizeof(template) / sizeof(CK_ATTRIBUTE);

	rc = createSecretKeyObject(template, attributes, p11o);

	if (rc != CKR_OK) {
		free(p11o);
		FUNC_FAILS(rc, "Could not create secret key object");
	}

	*pObject = p11o;

	p11o->keysize = p15->keysize;

	FUNC_RETURNS(CKR_OK);
}

