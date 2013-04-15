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


#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>

#ifdef WIN32
#include <direct.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#endif

#ifndef _O_RDONLY
#define _O_RDONLY O_RDONLY
#endif

#ifndef _O_TEXT
#define _O_TEXT 0
#endif

#ifndef _MAX_PATH
#define _MAX_PATH FILENAME_MAX
#endif

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/session.h>
#include <pkcs11/object.h>

#include <pkcs11/strbpcpy.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

/* 
 * Set up the global context structure.
 * 
 */

struct p11Context_t *context = NULL;


/*
 * Initialize the PKCS#11 function list. 
 *
 */

CK_FUNCTION_LIST pkcs11_function_list = {
	{ 2, 20 },
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
    C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
    C_CancelFunction,
	C_WaitForSlotEvent
};


/**
 * C_Initialize initializes the Cryptoki library. 
 *
 */

CK_DECLARE_FUNCTION(CK_RV, C_Initialize)
(
   CK_VOID_PTR   pInitArgs  /* if this is not NULL_PTR, it gets
                            * cast to CK_C_INITIALIZE_ARGS_PTR
                            * and dereferenced */
)
{
    int rv = CKR_OK;
    int fh;
    unsigned char scr[_MAX_PATH], *p;
    int len;
    
    /* Make sure the cryptoki has not been initialized */
    if (context != NULL) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
     
    context = (struct p11Context_t *) malloc (sizeof(struct p11Context_t));

    if (context == NULL) {
        return CKR_HOST_MEMORY;
    }

    memset(context, 0x00,sizeof(struct p11Context_t));

    context->debugFileHandle = NULL;      /* no debug */
  
#ifdef DEBUG
    rv = initDebug(context);
    if (rv < 0) {
        free(context);
        context = NULL;
        return CKR_GENERAL_ERROR;    
    }
#endif

    strcpy(context->slotDirectory, "token");

    context->sessionPool = (struct p11SessionPool_t *) malloc(sizeof(struct p11SessionPool_t));
    
    if (context->sessionPool == NULL) {
        free(context);
        context = NULL;
        return CKR_HOST_MEMORY;
    }

    context->slotPool = (struct p11SlotPool_t *) malloc(sizeof(struct p11SlotPool_t));

    if (context->slotPool == NULL) {
        free(context->sessionPool);
        free(context);
        context = NULL;
        return CKR_HOST_MEMORY;
    }

    rv = initSessionPool(context->sessionPool);    
    
    if (rv != CKR_OK) {
#ifdef DEBUG
        debug("[C_Initialize] Error initializing session pool ...\n");  
#endif 
        free(context->sessionPool);
        free(context->slotPool);
        free(context);
        context = NULL;
        return rv;
    }

    rv = initSlotPool(context->slotPool);
    
    if (rv != CKR_OK) {
#ifdef DEBUG
        printf("[C_Initialize] Error initializing slot pool ...\n");  
#endif 
        free(context->sessionPool);
        free(context->slotPool);
        free(context);
        context = NULL;
        return rv;
    }

#ifdef DEBUG
    debug("[C_Initialize] Cryptoki is up ...\n");
#endif

    return CKR_OK;

}


/** 
 * C_Finalize indicates that an application is done with the
 * Cryptoki library. 
 *
 */

CK_DECLARE_FUNCTION(CK_RV, C_Finalize)
(
     CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
)
{    
    CK_RV rv = CKR_OK;

    if (context != NULL) {

        terminateSessionPool(context->sessionPool);
        free(context->sessionPool);

        terminateSlotPool(context->slotPool);
        free(context->slotPool);

#ifdef DEBUG
        termDebug(context);        
#endif
                
        free(context);    
    }

    context = NULL;

    return rv;
}


/**
 * C_GetInfo returns general information about Cryptoki. 
 *
 * @param pInfo     Pointer to structure for the information.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK         </TD>
 *                   <TD>Success</TD>
 *                   </TR>
 *                   </TABLE></P>
 */

CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)
(
     CK_INFO_PTR   pInfo  /* location that receives information */
)
{
    CK_RV rv = CKR_OK;

    if (pInfo == NULL) {
        return CKR_HOST_MEMORY;
    }

    memset(pInfo, 0, sizeof(CK_INFO));
	
    pInfo->cryptokiVersion.major = 2;
	pInfo->cryptokiVersion.minor = 20;
	
    strbpcpy(pInfo->manufacturerID,
		  "CardContact (www.cardcontact.de)",
		  sizeof(pInfo->manufacturerID));
	strbpcpy(pInfo->libraryDescription,
		  "PKCS#11 Framework",
		  sizeof(pInfo->libraryDescription));
	pInfo->libraryVersion.major = 0;
	pInfo->libraryVersion.minor = 1;

    return rv;
}


/**
 * C_GetFunctionList returns the function list. 
 *
 */

CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)
(
    CK_FUNCTION_LIST_PTR_PTR ppFunctionList  /* receives pointer to
                                              * function list       */
)
{
    CK_RV rv = CKR_OK;

    *ppFunctionList = &pkcs11_function_list;

    return rv;
}
