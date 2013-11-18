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
 * @file    privatekeyobject.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for private key management
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pkcs11/object.h>
#include <pkcs11/privatekeyobject.h>

#ifdef DEBUG
#include <pkcs11/debug.h>

extern int dumpAttributeList(struct p11Object_t *pObject);

#endif

extern CK_BBOOL ckFalse;

static struct attributesForObject_t attributesPrivateKeyObject[] = {
		{{CKA_SUBJECT, 0, 0}, DEFAULT},
		{{CKA_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_DECRYPT, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_SIGN, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_SIGN_RECOVER, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_UNWRAP, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_ALWAYS_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_NEVER_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_WRAP_WITH_TRUSTED, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_UNWRAP_TEMPLATE, 0, 0}, DEFAULT},
		{{CKA_ALWAYS_AUTHENTICATE, &ckFalse, sizeof(CK_BBOOL)}, DEFAULT},
		{{CKA_MODULUS, 0, 0}, OPTIONAL},
		{{CKA_PUBLIC_EXPONENT, 0, 0}, OPTIONAL},
		{{CKA_EC_PARAMS, 0, 0}, OPTIONAL},
		{{0, NULL, 0}, DEFAULT }
};


/**
 *  Constructor for the private key object
 */
int createPrivateKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	int rc;

	rc = createKeyObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	rc = copyObjectAttributes(pTemplate, ulCount, pObject, attributesPrivateKeyObject);

#ifdef DEBUG
	dumpAttributeList(pObject);
#endif

	return rc;
}
