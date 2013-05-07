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
 * Abstract :       Functions for private key object management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

/**
 * \file    certificateobject.c
 * \author  Frank Thater (fth)
 * \brief   Functions for private key management
 *
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


static struct attributesForObject_t attributesPrivateKeyObject[NEEDED_ATTRIBUTES_PRIVATEKEYOBJECT] = {
		{{CKA_SUBJECT, 0, 0}, TRUE},
		{{CKA_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_DECRYPT, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_SIGN, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_SIGN_RECOVER, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_UNWRAP, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_ALWAYS_SENSITIVE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_NEVER_EXTRACTABLE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_WRAP_WITH_TRUSTED, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_UNWRAP_TEMPLATE, 0, 0}, TRUE},
		{{CKA_ALWAYS_AUTHENTICATE, &ckFalse, sizeof(CK_BBOOL)}, TRUE}
};


/**
 *  Constructor for the private key object
 */
int createPrivateKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	unsigned int i;
	int index, rc;

	rc = createKeyObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	for (i = 0; i < NEEDED_ATTRIBUTES_PRIVATEKEYOBJECT; i++) {

		index = findAttributeInTemplate(attributesPrivateKeyObject[i].attribute.type, pTemplate, ulCount);

		if (index == -1) { /* The attribute is not present - is it optional? */

			if (attributesPrivateKeyObject[i].optional) {

				addAttribute(pObject, &attributesPrivateKeyObject[i].attribute);

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
