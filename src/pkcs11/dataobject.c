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
 * @file    dataobject.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for data object management
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

#define NEEDED_ATTRIBUTES_DATAOBJECT   3

static struct attributesForObject_t attributesDataObject[] = {
		{{CKA_APPLICATION, 0, 0}, TRUE},
		{{CKA_OBJECT_ID, NULL, 0}, TRUE},
		{{CKA_VALUE, NULL, 0}, FALSE}
};



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
