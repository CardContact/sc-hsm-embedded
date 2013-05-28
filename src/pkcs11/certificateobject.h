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

#ifndef ___CERTIFICATEOBJECT_H_INC___
#define ___CERTIFICATEOBJECT_H_INC___


#include <pkcs11/p11generic.h>
#include <pkcs11/session.h>
#include <pkcs11/cryptoki.h>
#include <pkcs11/object.h>

#define NEEDED_ATTRIBUTES_CERTIFICATEOBJECT   3

int createCertificateObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *object);
int populateIssuerSubjectSerial(struct p11Object_t *pObject);
int getSubjectPublicKeyInfo(struct p11Object_t *pObject, unsigned char **spki);
int decodeModulusExponentFromSPK(unsigned char *spk, CK_ATTRIBUTE_PTR modulus, CK_ATTRIBUTE_PTR exponent);

#endif /* ___SECRETKEYOBJECT_H_INC___ */
