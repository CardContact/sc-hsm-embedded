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
 * @file    object.h
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for object management
 */

#ifndef ___OBJECT_H_INC___
#define ___OBJECT_H_INC___


#include <pkcs11/p11generic.h>
#include <pkcs11/session.h>
#include <pkcs11/cryptoki.h>

/**
 * Internal structure to store information about an attribute.
 *
 */

struct p11Attribute_t {

    CK_ATTRIBUTE attrData;          /**< The attribute data                   */
    
    struct p11Attribute_t *next;    /**< Pointer to next attribute            */
};



struct p11Token_t;				// Forward declaration

/**
 * Internal structure to store common attributes of an object.
 *
 * This structure is used to manage the handle and the type of an object.
 *
 */

struct p11Object_t {

    CK_OBJECT_HANDLE handle;
    int dirtyFlag;
    int publicObj;
    int tokenObj;
    int sensitiveObj;

    int tokenid;
    int keysize;

    struct p11Token_t *token;

    int (*C_EncryptInit)  (struct p11Object_t *, CK_MECHANISM_PTR);
    int (*C_Encrypt)      (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    int (*C_EncryptUpdate)(struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    int (*C_EncryptFinal) (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

    int (*C_DecryptInit)  (struct p11Object_t *, CK_MECHANISM_PTR);
    int (*C_Decrypt)      (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    int (*C_DecryptUpdate)(struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    int (*C_DecryptFinal) (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

    int (*C_SignInit)     (struct p11Object_t *, CK_MECHANISM_PTR);
    int (*C_Sign)         (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
    int (*C_SignUpdate)   (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG);
    int (*C_SignFinal)    (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

    struct p11Attribute_t *attrList;    /**< The list of attributes              */
    struct p11Object_t *next;       /**< Pointer to next object              */

};

static CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
static CK_MECHANISM_TYPE ckMechType = CK_UNAVAILABLE_INFORMATION;

struct attributesForObject_t {
    CK_ATTRIBUTE        attribute;  /* The attribute and its default value */
    CK_BBOOL            optional;   /* Indicator - is the attribute optional (true or false) */
};

#define NEEDED_ATTRIBUTES_OBJECT             1

static struct attributesForObject_t attributesObject[NEEDED_ATTRIBUTES_OBJECT] = {
    {{CKA_CLASS, 0, 0}, FALSE}
};

#define NEEDED_ATTRIBUTES_STORAGEOBJECT      4

static struct attributesForObject_t attributesStorageObject[NEEDED_ATTRIBUTES_STORAGEOBJECT] = {
    {{CKA_TOKEN, 0, 0}, FALSE},
    {{CKA_PRIVATE, 0, 0}, FALSE},
    {{CKA_MODIFIABLE, &ckTrue, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_LABEL, NULL, 0}, TRUE}
};                                           

#define NEEDED_ATTRIBUTES_KEYOBJECT          7

static struct attributesForObject_t attributesKeyObject[NEEDED_ATTRIBUTES_KEYOBJECT] = {
    {{CKA_KEY_TYPE, 0, 0}, FALSE},
    {{CKA_ID, NULL, 0}, TRUE},
    {{CKA_START_DATE, NULL, 0}, TRUE},
    {{CKA_END_DATE, NULL, 0}, TRUE},
    {{CKA_DERIVE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_LOCAL, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
    {{CKA_KEY_GEN_MECHANISM, &ckMechType, sizeof(CK_MECHANISM_TYPE)}, TRUE}
};

#ifdef DEBUG
struct id2name_t {
    unsigned long       id;
    char                *name;
    unsigned long       attr;
};

char *id2name(struct id2name_t *p, unsigned long id, unsigned long *attr);
#endif

int addAttribute(struct p11Object_t *object, CK_ATTRIBUTE_PTR pTemplate);

int findAttribute(struct p11Object_t *object, CK_ATTRIBUTE_PTR attributeTemplate, struct p11Attribute_t **attribute);

int findAttributeInTemplate(CK_ATTRIBUTE_TYPE attributeType, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

int removeAttribute(struct p11Object_t *object, CK_ATTRIBUTE_PTR attributeTemplate);

int removeAllAttributes(struct p11Object_t *object);

int createObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *object);

int createStorageObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *object);

int createKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *object);

int serializeObject(struct p11Object_t *pObject, unsigned char **pBuffer, unsigned int *bufLength);

void dumpAttribute(CK_ATTRIBUTE_PTR attr);

#endif /* ___OBJECT_H_INC___ */
