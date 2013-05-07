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
 * Abstract :       Functions for data object management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

/**
 * \file    dataobject.c
 * \author  Frank Thater (fth)
 * \brief   Functions for data object management
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <memory.h>
#include <pkcs11/object.h>
#include <pkcs11/dataobject.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

extern int dumpAttributeList(struct p11Object_t *pObject);

/**
 *  Constructor for the data object
 */

int createDataObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	unsigned int i;
	int index, rc;

	rc = createStorageObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	for (i = 0; i < NEEDED_ATTRIBUTES_DATAOBJECT; i++) {

		index = findAttributeInTemplate(attributesDataObject[i].attribute.type, pTemplate, ulCount);

		if (index == -1) { /* The attribute is not present - is it optional? */

			if (attributesDataObject[i].optional) {

				addAttribute(pObject, &attributesDataObject[i].attribute);

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
