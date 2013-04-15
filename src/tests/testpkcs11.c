/*
 * Unittest for utility functions
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkcs11/cryptoki.h>

struct id2name_t {
    unsigned long       id;
    char                *name;
    unsigned long       attr;
};

struct id2name_t p11CKRName[] = {
{ CKR_CANCEL                            , "CKR_CANCEL", 0 },
{ CKR_HOST_MEMORY                       , "CKR_HOST_MEMORY", 0 },
{ CKR_SLOT_ID_INVALID                   , "CKR_SLOT_ID_INVALID", 0 },
{ CKR_GENERAL_ERROR                     , "CKR_GENERAL_ERROR", 0 },
{ CKR_FUNCTION_FAILED                   , "CKR_FUNCTION_FAILED", 0 },
{ CKR_ARGUMENTS_BAD                     , "CKR_ARGUMENTS_BAD", 0 },
{ CKR_NO_EVENT                          , "CKR_NO_EVENT", 0 },
{ CKR_NEED_TO_CREATE_THREADS            , "CKR_NEED_TO_CREATE_THREADS", 0 },
{ CKR_CANT_LOCK                         , "CKR_CANT_LOCK", 0 },
{ CKR_ATTRIBUTE_READ_ONLY               , "CKR_ATTRIBUTE_READ_ONLY", 0 },
{ CKR_ATTRIBUTE_SENSITIVE               , "CKR_ATTRIBUTE_SENSITIVE", 0 },
{ CKR_ATTRIBUTE_TYPE_INVALID            , "CKR_ATTRIBUTE_TYPE_INVALID", 0 },
{ CKR_ATTRIBUTE_VALUE_INVALID           , "CKR_ATTRIBUTE_VALUE_INVALID", 0 },
{ CKR_DATA_INVALID                      , "CKR_DATA_INVALID", 0 },
{ CKR_DATA_LEN_RANGE                    , "CKR_DATA_LEN_RANGE", 0 },
{ CKR_DEVICE_ERROR                      , "CKR_DEVICE_ERROR", 0 },
{ CKR_DEVICE_MEMORY                     , "CKR_DEVICE_MEMORY", 0 },
{ CKR_DEVICE_REMOVED                    , "CKR_DEVICE_REMOVED", 0 },
{ CKR_ENCRYPTED_DATA_INVALID            , "CKR_ENCRYPTED_DATA_INVALID", 0 },
{ CKR_ENCRYPTED_DATA_LEN_RANGE          , "CKR_ENCRYPTED_DATA_LEN_RANGE", 0 },
{ CKR_FUNCTION_CANCELED                 , "CKR_FUNCTION_CANCELED", 0 },
{ CKR_FUNCTION_NOT_PARALLEL             , "CKR_FUNCTION_NOT_PARALLEL", 0 },
{ CKR_FUNCTION_NOT_SUPPORTED            , "CKR_FUNCTION_NOT_SUPPORTED", 0 },
{ CKR_KEY_HANDLE_INVALID                , "CKR_KEY_HANDLE_INVALID", 0 },
{ CKR_KEY_SIZE_RANGE                    , "CKR_KEY_SIZE_RANGE", 0 },
{ CKR_KEY_TYPE_INCONSISTENT             , "CKR_KEY_TYPE_INCONSISTENT", 0 },
{ CKR_KEY_NOT_NEEDED                    , "CKR_KEY_NOT_NEEDED", 0 },
{ CKR_KEY_CHANGED                       , "CKR_KEY_CHANGED", 0 },
{ CKR_KEY_NEEDED                        , "CKR_KEY_NEEDED", 0 },
{ CKR_KEY_INDIGESTIBLE                  , "CKR_KEY_INDIGESTIBLE", 0 },
{ CKR_KEY_FUNCTION_NOT_PERMITTED        , "CKR_KEY_FUNCTION_NOT_PERMITTED", 0 },
{ CKR_KEY_NOT_WRAPPABLE                 , "CKR_KEY_NOT_WRAPPABLE", 0 },
{ CKR_KEY_UNEXTRACTABLE                 , "CKR_KEY_UNEXTRACTABLE", 0 },
{ CKR_MECHANISM_INVALID                 , "CKR_MECHANISM_INVALID", 0 },
{ CKR_MECHANISM_PARAM_INVALID           , "CKR_MECHANISM_PARAM_INVALID", 0 },
{ CKR_OBJECT_HANDLE_INVALID             , "CKR_OBJECT_HANDLE_INVALID", 0 },
{ CKR_OPERATION_ACTIVE                  , "CKR_OPERATION_ACTIVE", 0 },
{ CKR_OPERATION_NOT_INITIALIZED         , "CKR_OPERATION_NOT_INITIALIZED", 0 },
{ CKR_PIN_INCORRECT                     , "CKR_PIN_INCORRECT", 0 },
{ CKR_PIN_INVALID                       , "CKR_PIN_INVALID", 0 },
{ CKR_PIN_LEN_RANGE                     , "CKR_PIN_LEN_RANGE", 0 },
{ CKR_PIN_EXPIRED                       , "CKR_PIN_EXPIRED", 0 },
{ CKR_PIN_LOCKED                        , "CKR_PIN_LOCKED", 0 },
{ CKR_SESSION_CLOSED                    , "CKR_SESSION_CLOSED", 0 },
{ CKR_SESSION_COUNT                     , "CKR_SESSION_COUNT", 0 },
{ CKR_SESSION_HANDLE_INVALID            , "CKR_SESSION_HANDLE_INVALID", 0 },
{ CKR_SESSION_PARALLEL_NOT_SUPPORTED    , "CKR_SESSION_PARALLEL_NOT_SUPPORTED", 0 },
{ CKR_SESSION_READ_ONLY                 , "CKR_SESSION_READ_ONLY", 0 },
{ CKR_SESSION_EXISTS                    , "CKR_SESSION_EXISTS", 0 },
{ CKR_SESSION_READ_ONLY_EXISTS          , "CKR_SESSION_READ_ONLY_EXISTS", 0 },
{ CKR_SESSION_READ_WRITE_SO_EXISTS      , "CKR_SESSION_READ_WRITE_SO_EXISTS", 0 },
{ CKR_SIGNATURE_INVALID                 , "CKR_SIGNATURE_INVALID", 0 },
{ CKR_SIGNATURE_LEN_RANGE               , "CKR_SIGNATURE_LEN_RANGE", 0 },
{ CKR_TEMPLATE_INCOMPLETE               , "CKR_TEMPLATE_INCOMPLETE", 0 },
{ CKR_TEMPLATE_INCONSISTENT             , "CKR_TEMPLATE_INCONSISTENT", 0 },
{ CKR_TOKEN_NOT_PRESENT                 , "CKR_TOKEN_NOT_PRESENT", 0 },
{ CKR_TOKEN_NOT_RECOGNIZED              , "CKR_TOKEN_NOT_RECOGNIZED", 0 },
{ CKR_TOKEN_WRITE_PROTECTED             , "CKR_TOKEN_WRITE_PROTECTED", 0 },
{ CKR_UNWRAPPING_KEY_HANDLE_INVALID     , "CKR_UNWRAPPING_KEY_HANDLE_INVALID", 0 },
{ CKR_UNWRAPPING_KEY_SIZE_RANGE         , "CKR_UNWRAPPING_KEY_SIZE_RANGE", 0 },
{ CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  , "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT", 0 },
{ CKR_USER_ALREADY_LOGGED_IN            , "CKR_USER_ALREADY_LOGGED_IN", 0 },
{ CKR_USER_NOT_LOGGED_IN                , "CKR_USER_NOT_LOGGED_IN", 0 },
{ CKR_USER_PIN_NOT_INITIALIZED          , "CKR_USER_PIN_NOT_INITIALIZED", 0 },
{ CKR_USER_TYPE_INVALID                 , "CKR_USER_TYPE_INVALID", 0 },
{ CKR_USER_ANOTHER_ALREADY_LOGGED_IN    , "CKR_USER_ANOTHER_ALREADY_LOGGED_IN", 0 },
{ CKR_USER_TOO_MANY_TYPES               , "CKR_USER_TOO_MANY_TYPES", 0 },
{ CKR_WRAPPED_KEY_INVALID               , "CKR_WRAPPED_KEY_INVALID", 0 },
{ CKR_WRAPPED_KEY_LEN_RANGE             , "CKR_WRAPPED_KEY_LEN_RANGE", 0 },
{ CKR_WRAPPING_KEY_HANDLE_INVALID       , "CKR_WRAPPING_KEY_HANDLE_INVALID", 0 },
{ CKR_WRAPPING_KEY_SIZE_RANGE           , "CKR_WRAPPING_KEY_SIZE_RANGE", 0 },
{ CKR_WRAPPING_KEY_TYPE_INCONSISTENT    , "CKR_WRAPPING_KEY_TYPE_INCONSISTENT", 0 },
{ CKR_RANDOM_SEED_NOT_SUPPORTED         , "CKR_RANDOM_SEED_NOT_SUPPORTED", 0 },
{ CKR_RANDOM_NO_RNG                     , "CKR_RANDOM_NO_RNG", 0 },
{ CKR_DOMAIN_PARAMS_INVALID             , "CKR_DOMAIN_PARAMS_INVALID", 0 },
{ CKR_BUFFER_TOO_SMALL                  , "CKR_BUFFER_TOO_SMALL", 0 },
{ CKR_SAVED_STATE_INVALID               , "CKR_SAVED_STATE_INVALID", 0 },
{ CKR_INFORMATION_SENSITIVE             , "CKR_INFORMATION_SENSITIVE", 0 },
{ CKR_STATE_UNSAVEABLE                  , "CKR_STATE_UNSAVEABLE", 0 },
{ CKR_CRYPTOKI_NOT_INITIALIZED          , "CKR_CRYPTOKI_NOT_INITIALIZED", 0 },
{ CKR_CRYPTOKI_ALREADY_INITIALIZED      , "CKR_CRYPTOKI_ALREADY_INITIALIZED", 0 },
{ CKR_MUTEX_BAD                         , "CKR_MUTEX_BAD", 0 },
{ CKR_MUTEX_NOT_LOCKED                  , "CKR_MUTEX_NOT_LOCKED", 0 },
{ CKR_OK			                    , "CKR_OK", 0 }
};


char *id2name(struct id2name_t *p, unsigned long id, unsigned long *attr)

{
    static char scr[40];

    if (attr)
        *attr = 0;

    if (id & 0x80000000) {
        sprintf(scr, "Vendor defined 0x%lx", id);
    } else {
        while (p->name && (p->id != id)) {
            p++;
        }

        if (p->name) {
            strcpy(scr, p->name);
            if (attr)
                *attr = p->attr;
        } else {
            sprintf(scr, "*** Undefined 0x%lx ***", id);
        }
    }
    return scr;
}


void main(int argc, char *argv[])

{
    int i;
    CK_RV rc;
    CK_LONG slots;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID_PTR slotlist;
    CK_SLOT_ID slotid;
    CK_SLOT_INFO slotinfo;
    CK_TOKEN_INFO tokeninfo;
    CK_UTF8CHAR pin[] = "1111";
    CK_ULONG pinlen = 4;
    CK_UTF8CHAR label[] = "MyFirstToken";
    CK_BBOOL cktrue = CK_TRUE, ckfalse = CK_FALSE;
    CK_OBJECT_HANDLE objhandle;
    CK_ATTRIBUTE attr[6];
    long keytype, objclass;
    char buff[256];
    CK_UTF8CHAR objlabel[] = "sampleobj";
    char *value = "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";
    CK_FUNCTION_LIST_PTR p11;

    printf("PKCS11 unittest running.\n");

    printf("Calling C_GetFunctionList ");

    C_GetFunctionList(&p11);

    printf("Calling C_Initialize ");

    rc = p11->C_Initialize(NULL);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
    	exit(-1);
    }

    printf("Calling C_GetSlotList ");

    rc = p11->C_GetSlotList(FALSE, NULL, &slots);

    if (rc != CKR_OK) {
    	printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");
    	exit(-1);
    }

    slotlist = (CK_SLOT_ID_PTR) malloc(sizeof(CK_SLOT_ID) * slots);

    rc = p11->C_GetSlotList(FALSE, slotlist, &slots);
    printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
    	exit(-1);
    }

    i = 0;

    while (i < slots) {
    	slotid = *(slotlist + i);

    	printf("Calling C_GetSlotInfo for slot %i ", slotid);

    	rc = p11->C_GetSlotInfo(slotid, &slotinfo);
    	printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    	if (rc != CKR_OK) {
    		printf("Error getting slot information from cryptoki. slotid = %l, rc = %l = %s\n", slotid, rc, id2name(p11CKRName, rc, NULL));
    	    free(slotlist);
    	    exit(-1);
    	}

    	printf("Slot manufacturer: %s\n", slotinfo.manufacturerID);
    	printf("Slot description: %s\n", slotinfo.slotDescription);

        printf("Calling C_GetTokenInfo ");

        rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
      	printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : rc == CKR_TOKEN_NOT_PRESENT ? "No token" : "Failed");

        if (rc != CKR_OK && rc != CKR_TOKEN_NOT_PRESENT) {
            printf("Error getting token information from cryptoki. slotid = %l, rc = %l = %s\n", slotid, rc, id2name(p11CKRName, rc, NULL));
        	free(slotlist);
        	exit(-1);
        }

        if (rc == CKR_OK) {
        	printf("Token label: %s\n", tokeninfo.label);
        }

        i++;
    }

    // Grab the first slot and create a token
    slotid = *(slotlist);
    free(slotlist);

    printf("Calling C_InitToken ");

    rc = p11->C_InitToken(slotid, pin, pinlen, label);
    printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
    	printf("Error getting slot information from cryptoki. slotid = %l, rc = %l = %s\n", slotid, rc, id2name(p11CKRName, rc, NULL));
        exit(-1);
    }

    printf("Calling C_OpenSession ");

    rc = p11->C_OpenSession(slotid, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &session);
    printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
    	exit(-1);
    }

    printf("Calling C_Login SO ");

    rc = p11->C_Login(session, CKU_SO, pin, pinlen);
    printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
      	exit(-1);
    }

    printf("Calling C_InitPIN ");

    rc = p11->C_InitPIN(session, pin, pinlen);
    printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
    	exit(-1);
    }

    printf("Calling C_Logout ");

    rc = p11->C_Logout(session);
    printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
        exit(-1);
    }

    printf("Calling C_GetTokenInfo ");

    rc = p11->C_GetTokenInfo(slotid, &tokeninfo);
    printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : rc == CKR_TOKEN_NOT_PRESENT ? "No token" : "Failed");

    if (rc != CKR_OK) {
    	printf("Error getting token information from cryptoki. slotid = %l, rc = %l = %s\n", slotid, rc, id2name(p11CKRName, rc, NULL));
        exit(-1);
    }

   	printf("Token label: %s\n", tokeninfo.label);

   	printf("Calling C_Login User ");

	rc = p11->C_Login(session, CKU_USER, pin, pinlen);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

	if (rc != CKR_OK) {
		exit(-1);
	}

	memset(attr, 0, sizeof(attr));

	objclass = CKO_SECRET_KEY;
	attr[0].type = CKA_CLASS;
	attr[0].ulValueLen = sizeof(objclass);
	attr[0].pValue = &objclass;

	attr[1].type = CKA_TOKEN;
	attr[1].ulValueLen = sizeof(cktrue);
	attr[1].pValue = &cktrue;

	attr[2].type = CKA_PRIVATE;
	attr[2].ulValueLen = sizeof(cktrue);
	attr[2].pValue = &cktrue;

	attr[3].type = CKA_LABEL;
	attr[3].ulValueLen = strlen(objlabel);
	attr[3].pValue = objlabel;

	keytype = CKK_DES2;
	attr[4].type = CKA_KEY_TYPE;
	attr[4].ulValueLen = sizeof(keytype);
	attr[4].pValue = &keytype;

	attr[5].type = CKA_VALUE;
	attr[5].ulValueLen = 16;
	attr[5].pValue = value;

	printf("Calling C_CreateObject ");

    rc = p11->C_CreateObject(session, attr, 6, &objhandle);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

	if (rc != CKR_OK) {
		exit(-1);
	}

    printf("Calling C_Finalize ");

    rc = p11->C_Finalize(NULL);
	printf("- %s : %s\n", id2name(p11CKRName, rc, 0), rc == CKR_OK ? "Passed" : "Failed");

    if (rc != CKR_OK) {
    	exit(-1);
    }

    printf("Unittest finished.\n");
    exit(0);
}
