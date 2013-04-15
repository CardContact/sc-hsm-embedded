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
 * \file    secretkeyobject.c
 * \author  Frank Thater (fth)
 * \brief   Functions for secret key object management
 *
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pkcs11/object.h>
#include <pkcs11/secretkeyobject.h>

#ifdef DEBUG
#include <pkcs11/debug.h>

extern int dumpAttributeList(struct p11Object_t *pObject);

#endif

/**
 *  Constructor for the secret key object
 */

int createSecretKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)

{
    unsigned int i;
    int index, rc;

    rc = createKeyObject(pTemplate, ulCount, pObject);

    if (rc) {
        return rc;
    }
    
    for (i = 0; i < NEEDED_ATTRIBUTES_SECRETKEYOBJECT; i++) {

        index = findAttributeInTemplate(attributesSecretKeyObject[i].attribute.type, pTemplate, ulCount);
    
        if (index == -1) { /* The attribute is not present - is it optional? */
            
            if (attributesSecretKeyObject[i].optional) {
            
                addAttribute(pObject, &attributesSecretKeyObject[i].attribute);
            
            } else { /* the attribute is not optional */

#ifdef DEBUG
                debug("[createSecretKeyObject] Error creating secret key object - the following attribute is not present!");
                dumpAttribute(&(attributesSecretKeyObject[i].attribute));
#endif
  
                removeAllAttributes(pObject);
                memset(pObject, 0x00, sizeof(*pObject));
                return CKR_TEMPLATE_INCOMPLETE;
            
            }
        
        } else {

            /* The object is a sensitive object */
            if ((pTemplate[index].type == CKA_SENSITIVE) &&
                (*(CK_BBOOL *)pTemplate[index].pValue == CK_TRUE)) {
                pObject->sensitiveObj = TRUE;
            }
        
            addAttribute(pObject, &pTemplate[index]);   
        }
    }

    /* Set the function pointers for the cryptographic functions */
    pObject->C_EncryptInit = secretKeyEncryptInit;
    pObject->C_Encrypt = secretKeyEncrypt;
    pObject->C_EncryptUpdate = secretKeyEncryptUpdate;
    pObject->C_EncryptFinal = secretKeyEncryptFinal;

#ifdef DEBUG
    debug("[createSecretKeyObject] Secret key object successfully created!\n");
#endif

    return 0;
}


int secretKeyEncryptInit(CK_MECHANISM_PTR pMechanism)

{
    return CKR_OK;
}


int secretKeyEncrypt(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)

{
    return CKR_OK;
}


int secretKeyEncryptUpdate(CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)

{
    return CKR_OK;
}


int secretKeyEncryptFinal(CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)

{
    return CKR_OK;
}
