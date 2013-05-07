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

#ifndef ___DATAOBJECT_H_INC___
#define ___DATAOBJECT_H_INC___


#include <pkcs11/p11generic.h>
#include <pkcs11/cryptoki.h>
#include <pkcs11/session.h>
#include <pkcs11/object.h>

#define NEEDED_ATTRIBUTES_DATAOBJECT   3

static struct attributesForObject_t attributesDataObject[] = {
		{{CKA_APPLICATION, 0, 0}, TRUE},
		{{CKA_OBJECT_ID, NULL, 0}, TRUE},
		{{CKA_VALUE, NULL, 0}, FALSE}
};

int createDataObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *object);

#endif /* ___DATAOBJECT_H_INC___ */
