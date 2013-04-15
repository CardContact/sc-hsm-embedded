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
 * Abstract :       <Short description of what is done with this file>
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

#include <stdlib.h>
#include <fcntl.h>      
#include <sys/types.h>
#include <sys/stat.h>

#ifdef WIN32
#include <io.h>
#endif

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>
#include <pkcs11/slot.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/token.h>

extern struct p11Context_t *context;

/*  C_EncryptInit initializes an encryption operation. */

CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{   
    int rv;
    struct p11Object_t *pObject;
    struct p11Slot_t *pSlot;
    struct p11Session_t *pSession;

    rv = findSessionByHandle(context->sessionPool, hSession, &pSession);
    
    if (rv < 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pSession->activeObjectHandle != -1) {
        return CKR_OPERATION_ACTIVE;
    }
           
    rv = findSlot(context->slotPool, pSession->slotID, &pSlot);

    if (pSlot == NULL) {
        return CKR_GENERAL_ERROR;
    }

    rv = findObject(pSlot->token, hKey, &pObject, FALSE);

    if (rv < 0) {
        return CKR_GENERAL_ERROR;
    }

    if (pObject->C_EncryptInit != NULL) {
        rv = pObject->C_EncryptInit(pMechanism);
    } else {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    if (!rv) {
        pSession->activeObjectHandle = pObject->handle;
        rv = CKR_OK;
    }

    return rv;
}


/*  C_Encrypt encrypts single-part data. */

CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG_PTR pulEncryptedDataLen
)
{   
    int rv;
    struct p11Object_t *pObject;
    struct p11Slot_t *pSlot;
    struct p11Session_t *pSession;

    rv = findSessionByHandle(context->sessionPool, hSession, &pSession);
    
    if (rv < 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (pSession->activeObjectHandle == -1) {
        return CKR_GENERAL_ERROR;
    }

    rv = findSlot(context->slotPool, pSession->slotID, &pSlot);

    if (pSlot == NULL) {
        return CKR_GENERAL_ERROR;
    }

    rv = findObject(pSlot->token, pSession->activeObjectHandle, &pObject, FALSE);

    if (rv < 0) {
        return CKR_GENERAL_ERROR;
    }

    if (pObject->C_Encrypt != NULL) {
        rv = pObject->C_Encrypt(pData, ulDataLen, pEncryptedData, pulEncryptedDataLen);
    } else {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return rv;
}


/*  C_EncryptUpdate continues a multiple-part encryption operation, 
    processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen
)
{
    int rv;
    struct p11Object_t *pObject;
    struct p11Slot_t *pSlot;
    struct p11Session_t *pSession;

    rv = findSessionByHandle(context->sessionPool, hSession, &pSession);
    
    if (rv < 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (pSession->activeObjectHandle == -1) {
        return CKR_GENERAL_ERROR;
    }

    rv = findSlot(context->slotPool, pSession->slotID, &pSlot);

    if (pSlot == NULL) {
        return CKR_GENERAL_ERROR;
    }

    rv = findObject(pSlot->token, pSession->activeObjectHandle, &pObject, FALSE);

    if (rv < 0) {
        return CKR_GENERAL_ERROR;
    }

    if (pObject->C_EncryptUpdate != NULL) {
        rv = pObject->C_EncryptUpdate(pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
    } else {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return rv;
}


/*  C_EncryptFinal finishes a multiple-part encryption operation. */

CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastEncryptedPart,
    CK_ULONG_PTR pulLastEncryptedPartLen
)
{
    int rv;
    struct p11Object_t *pObject;
    struct p11Slot_t *pSlot;
    struct p11Session_t *pSession;

    rv = findSessionByHandle(context->sessionPool, hSession, &pSession);
    
    if (rv < 0) {
        return CKR_SESSION_HANDLE_INVALID;
    }
    
    if (pSession->activeObjectHandle == -1) {
        return CKR_GENERAL_ERROR;
    }

    rv = findSlot(context->slotPool, pSession->slotID, &pSlot);

    if (pSlot == NULL) {
        return CKR_GENERAL_ERROR;
    }

    rv = findObject(pSlot->token, pSession->activeObjectHandle, &pObject, FALSE);

    if (rv < 0) {
        return CKR_GENERAL_ERROR;
    }

    if (pObject->C_EncryptFinal != NULL) {
        rv = pObject->C_EncryptFinal(pLastEncryptedPart, pulLastEncryptedPartLen);
    } else {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    if (!rv) {
        pSession->activeObjectHandle = -1;
        rv = CKR_OK;
    }

    return rv;
}


/*  C_DecryptInit initializes a decryption operation. */

CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_Decrypt decrypts encrypted data in a single part. */

CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedData,
    CK_ULONG ulEncryptedDataLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DecryptUpdate continues a multiple-part decryption operation, 
    processing another encrypted data part. */

CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DecryptFinal finishes a multiple-part decryption operation. */

CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pLastPart,
    CK_ULONG_PTR pulLastPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DigestInit initializes a message-digesting operation. */

CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_Digest digests data in a single part. */

CK_DECLARE_FUNCTION(CK_RV, C_Digest)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DigestUpdate continues a multiple-part message-digesting operation, 
    processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DigestKey continues a multiple-part message-digesting operation by 
    digesting the value of a secret key. */

CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)(
    CK_SESSION_HANDLE hSession,
    CK_OBJECT_HANDLE hKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DigestFinal finishes a multiple-part message-digesting operation. */

CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pDigest,
    CK_ULONG_PTR pulDigestLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_SignInit initializes a signature operation, 
    here the signature is an appendix to the data. */

CK_DECLARE_FUNCTION(CK_RV, C_SignInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_Sign signs data in a single part, where the signature is an appendix to the data. */

CK_DECLARE_FUNCTION(CK_RV, C_Sign)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_SignUpdate continues a multiple-part signature operation, 
    processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_SignFinal finishes a multiple-part signature operation. */

CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_SignRecoverInit initializes a signature operation, where the data 
    can be recovered from the signature. */

CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_SignRecover signs data in a single operation, where the data can be 
    recovered from the signature. */

CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG_PTR pulSignatureLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_VerifyInit initializes a verification operation, where the signature is 
    an appendix to the data. */

CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_Verify verifies a signature in a single-part operation, where the signature 
    is an appendix to the data. */

CK_DECLARE_FUNCTION(CK_RV, C_Verify)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pData,
    CK_ULONG ulDataLen,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_VerifyUpdate continues a multiple-part verification operation, 
    processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_VerifyFinal finishes a multiple-part verification operation, 
    checking the signature. */

CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_VerifyRecoverInit initializes a signature verification operation, 
    where the data is recovered from the signature. */

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_VerifyRecover verifies a signature in a single-part operation, 
    where the data is recovered from the signature. */

CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSignature,
    CK_ULONG ulSignatureLen,
    CK_BYTE_PTR pData,
    CK_ULONG_PTR pulDataLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DigestEncryptUpdate continues multiple-part digest and encryption 
    operations, processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DecryptDigestUpdate continues a multiple-part combined decryption and 
    digest operation, processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_SignEncryptUpdate continues a multiple-part combined signature and 
    encryption operation, processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_SignEncryptUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pPart,
    CK_ULONG ulPartLen,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG_PTR pulEncryptedPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DecryptVerifyUpdate continues a multiple-part combined decryption and verification
    operation, processing another data part. */

CK_DECLARE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pEncryptedPart,
    CK_ULONG ulEncryptedPartLen,
    CK_BYTE_PTR pPart,
    CK_ULONG_PTR pulPartLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_GenerateKey generates a secret key or set of domain parameters, 
    creating a new object. */

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_GenerateKeyPair generates a public/private key pair, creating new key objects. */

CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_ATTRIBUTE_PTR pPublicKeyTemplate,
    CK_ULONG ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
    CK_ULONG ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR phPublicKey,
    CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_WrapKey wraps (i.e., encrypts) a private or secret key. */

CK_DECLARE_FUNCTION(CK_RV, C_WrapKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hWrappingKey,
    CK_OBJECT_HANDLE hKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG_PTR pulWrappedKeyLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_UnwrapKey unwraps (i.e. decrypts) a wrapped key, creating a new private key 
    or secret key object. */

CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hUnwrappingKey,
    CK_BYTE_PTR pWrappedKey,
    CK_ULONG ulWrappedKeyLen,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_DeriveKey derives a key from a base key, creating a new key object. */

CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)(
    CK_SESSION_HANDLE hSession,
    CK_MECHANISM_PTR pMechanism,
    CK_OBJECT_HANDLE hBaseKey,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulAttributeCount,
    CK_OBJECT_HANDLE_PTR phKey
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_SeedRandom mixes additional seed material into the token�s random number generator. */

CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pSeed,
    CK_ULONG ulSeedLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_GenerateRandom generates random or pseudo-random data. */

CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)(
    CK_SESSION_HANDLE hSession,
    CK_BYTE_PTR pRandomData,
    CK_ULONG ulRandomLen
)
{
    CK_RV rv = CKR_FUNCTION_NOT_SUPPORTED;

    return rv;
}


/*  C_GetFunctionStatus obtained the status of a function
    running in parallel with an application. Now legacy! */

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)(
    CK_SESSION_HANDLE hSession
)
{
    return CKR_FUNCTION_NOT_PARALLEL;
}


/*  C_CancelFunction cancelled a function running in parallel
    with an application. Now legacy! */

CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)(
    CK_SESSION_HANDLE hSession
)
{
    return CKR_FUNCTION_NOT_PARALLEL; 
}
