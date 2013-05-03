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
 * Abstract :       Functions for token management in a specific slot
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

/**
 * \file    slot.c
 * \author  Andreas Schwier (ASC)
 * \brief   SmartCard-HSM functions
 *
 */

#include <string.h>
#include "token-sc-hsm.h"

#include <pkcs11/object.h>
#include <pkcs11/certificateobject.h>


static unsigned char aid[] = { 0xE8,0x2B,0x06,0x01,0x04,0x01,0x81,0xC3,0x1F,0x02,0x01 };


token_sc_hsm_t *getPrivateData(struct p11Token_t *token) {
	return (token_sc_hsm_t *)(token + 1);
}



static int checkPINStatus(struct p11Slot_t *slot) {
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

    rc = transmitAPDU(slot, 0x00, 0x20, 0x00, 0x81,
                     0, NULL,
                     0, NULL, 0, &SW1SW2);

    if (rc < 0) {
    	FUNC_FAILS(rc, "transmitAPDU failed");
    }

    FUNC_RETURNS(SW1SW2);
}



static int selectApplet(struct p11Slot_t *slot) {
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

    rc = transmitAPDU(slot, 0x00, 0xA4, 0x04, 0x0C,
                     sizeof(aid), aid,
                     0, NULL, 0, &SW1SW2);

    if (rc < 0) {
    	FUNC_FAILS(rc, "transmitAPDU failed");
    }

    if (SW1SW2 != 0x9000) {
    	FUNC_FAILS(-1, "Token is not a SmartCard-HSM");
    }

    FUNC_RETURNS(CKR_OK);
}



static int enumerateObjects(struct p11Slot_t *slot, unsigned char *filelist, size_t len) {
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

    rc = transmitAPDU(slot, 0x80, 0x58, 0x00, 0x00,
                     0, NULL,
                     65536, filelist, len, &SW1SW2);

    if (rc < 0) {
    	FUNC_FAILS(rc, "transmitAPDU failed");
    }

    if (SW1SW2 != 0x9000) {
    	FUNC_FAILS(-1, "Token did not enumerate objects");
    }

    FUNC_RETURNS(rc);
}



static int readEF(struct p11Slot_t *slot, unsigned short fid, unsigned char *content, size_t len) {
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

    rc = transmitAPDU(slot, 0x00, 0xB1, fid >> 8, fid & 0xFF,
    				 4, (unsigned char*)"\x54\x02\x00\x00",
                     65536, content, len, &SW1SW2);

    if (rc < 0) {
    	FUNC_FAILS(rc, "transmitAPDU failed");
    }

    if (SW1SW2 != 0x9000) {
    	FUNC_FAILS(-1, "Read EF failed");
    }

    FUNC_RETURNS(rc);
}



static int addCertificateObject(struct p11Token_t *token, unsigned char id) {
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_UTF8CHAR label[10];
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_BYTE certValue[MAX_CERTIFICATE_SIZE];
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_CERTIFICATE_TYPE, &certType, sizeof(certType) },
			{ CKA_TOKEN, &true, sizeof(true) },
			{ CKA_PRIVATE, &false, sizeof(false) },
			{ CKA_LABEL, label, sizeof(label) - 1 },
			{ CKA_ID, &id, sizeof(id) },
			{ CKA_VALUE, certValue, sizeof(certValue) }
	};
	struct p11Object_t *pObject;
	int rc;

	FUNC_CALLED();

	rc = readEF(token->slot, (EE_CERTIFICATE_PREFIX << 8) | id, certValue, sizeof(certValue));

	if (rc < 0) {
    	FUNC_FAILS(CKR_DEVICE_ERROR, "Error reading certificate");
	}
	template[6].ulValueLen = rc;

    pObject = calloc(sizeof(struct p11Object_t), 1);

    if (pObject == NULL) {
    	FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
    }

    // ToDo: Fill CKA_LABEL from PKCS15 structure
    sprintf(label, "Cert#%d", id);
    template[4].ulValueLen = strlen(label);

    // ToDo: Fill CKA_ID from PKCS15 structure or set based on key id
	rc = createCertificateObject(template, 7, pObject);

	if (rc != CKR_OK) {
		free(pObject);
		FUNC_FAILS(rc, "Could not create certificate key object");
	}

	pObject->tokenid = (int)id;
	addObject(token, pObject, TRUE);
    FUNC_RETURNS(CKR_OK);
}



static int sc_hsm_C_SignInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech) {
	FUNC_CALLED();
    FUNC_RETURNS(CKR_OK);
}



static int sc_hsm_C_Sign(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen) {
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	if (pSignature == NULL) {
		*pulSignatureLen = 256;
	    FUNC_RETURNS(CKR_OK);
	}

    rc = transmitAPDU(pObject->token->slot, 0x80, 0x68, (unsigned char)pObject->tokenid, 0xA0,
                     ulDataLen, pData,
                     0, pSignature, *pulSignatureLen, &SW1SW2);

    if (rc < 0) {
    	FUNC_FAILS(rc, "transmitAPDU failed");
    }

    if (SW1SW2 != 0x9000) {
    	FUNC_FAILS(-1, "Signature operation failed");
    }

    *pulSignatureLen = rc;
    FUNC_RETURNS(CKR_OK);
}



static int addPrivateKeyObject(struct p11Token_t *token, unsigned char id) {
	CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_UTF8CHAR label[10];
	CK_MECHANISM_TYPE genMechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
	CK_BBOOL true = CK_TRUE;
	CK_BBOOL false = CK_FALSE;
	CK_ATTRIBUTE template[] = {
			{ CKA_CLASS, &class, sizeof(class) },
			{ CKA_KEY_TYPE, &keyType, sizeof(keyType) },
			{ CKA_TOKEN, &true, sizeof(true) },
			{ CKA_PRIVATE, &true, sizeof(true) },
			{ CKA_LABEL, label, sizeof(label) - 1 },
			{ CKA_ID, &id, sizeof(id) },
			{ CKA_LOCAL, &true, sizeof(true) },
			{ CKA_KEY_GEN_MECHANISM, &genMechType, sizeof(genMechType) },
			{ CKA_SENSITIVE, &true, sizeof(true) },
			{ CKA_DECRYPT, &true, sizeof(true) },
			{ CKA_SIGN, &true, sizeof(true) },
			{ CKA_SIGN_RECOVER, &true, sizeof(true) },
			{ CKA_UNWRAP, &false, sizeof(false) },
			{ CKA_EXTRACTABLE, &false, sizeof(false) },
			{ CKA_ALWAYS_SENSITIVE, &true, sizeof(true) },
			{ CKA_NEVER_EXTRACTABLE, &true, sizeof(true) }
	};
	struct p11Object_t *pObject;
	int rc;

	FUNC_CALLED();

    pObject = calloc(sizeof(struct p11Object_t), 1);

    if (pObject == NULL) {
    	FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
    }

    // ToDo: Fill CKA_LABEL from PKCS15 structure
    sprintf(label, "Key#%d", id);
    template[4].ulValueLen = strlen(label);

    // ToDo: Fill CKA_ID from PKCS15 structure or set based on key id
    // ToDo: Set CKA_EXTRACTABLE based on KCV

	rc = createPrivateKeyObject(template, sizeof(template) / sizeof(CK_ATTRIBUTE), pObject);

	if (rc != CKR_OK) {
		free(pObject);
		FUNC_FAILS(rc, "Could not create private key object");
	}

	pObject->C_SignInit = sc_hsm_C_SignInit;
	pObject->C_Sign = sc_hsm_C_Sign;

	pObject->tokenid = (int)id;
	addObject(token, pObject, FALSE);
    FUNC_RETURNS(CKR_OK);
}



int sc_hsm_loadObjects(struct p11Token_t *token, int publicObjects) {
	unsigned char filelist[MAX_FILES * 2];
	struct p11Slot_t *slot = token->slot;
	int rc,listlen,i,id,prefix;

	FUNC_CALLED();

	rc = enumerateObjects(slot, filelist, sizeof(filelist));
    if (rc < 0) {
    	FUNC_FAILS(rc, "enumerateObjects failed");
    }

    listlen = rc;
    for (i = 0; i < listlen; i += 2) {
    	prefix = filelist[i];
    	id = filelist[i + 1];

    	if (publicObjects) {
    		switch(prefix) {
    		case EE_CERTIFICATE_PREFIX:
    			if (id != 0) {				// Skip Device Authentication Key
    				rc = addCertificateObject(token, id);
    				if (rc != CKR_OK) {
    					FUNC_FAILS(rc, "addCertificateObject failed");
    				}
    			}
    			break;
    		}
    	} else {
    		switch(prefix) {
    		case KEY_PREFIX:
    			if (id != 0) {				// Skip Device Authentication Key
    				rc = addPrivateKeyObject(token, id);
    				if (rc != CKR_OK) {
    					FUNC_FAILS(rc, "addPrivateKeyObject failed");
    				}
    			}
    			break;
    		}
    	}
    }
    FUNC_RETURNS(CKR_OK);
}



static int updatePinStatus(struct p11Token_t *token, int pinstatus) {
	int rc = CKR_OK;

	token->info.flags &= ~(CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED);

   	if (pinstatus != 0x6984) {
   	   	token->info.flags |= CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
   	}

   	switch(pinstatus) {
   	case 0x9000:
   		rc = CKR_OK;
   		break;
   	case 0x6984:
   	   	rc = CKR_USER_PIN_NOT_INITIALIZED;
   		break;
   	case 0x6983:
   	   	token->info.flags |= CKF_USER_PIN_LOCKED;
   	   	rc = CKR_PIN_LOCKED;
   		break;
   	case 0x63C1:
   	   	token->info.flags |= CKF_USER_PIN_FINAL_TRY;
   	   	rc = CKR_PIN_INCORRECT;
   		break;
   	default:
   	   	rc = CKR_PIN_INCORRECT;
   	}
   	return rc;
}



int sc_hsm_login(struct p11Slot_t *slot, int userType, unsigned char *pin, int pinlen) {
	int rc;
	unsigned short SW1SW2;
	FUNC_CALLED();

	if (userType != CKU_USER) {
		FUNC_FAILS(CKR_FUNCTION_NOT_SUPPORTED, "sc_hsm_login with other than user PIN not possible");
	}

    rc = transmitAPDU(slot, 0x00, 0x20, 0x00, 0x081,
    				 pinlen, pin,
                     0, NULL, 0, &SW1SW2);

    if (rc < 0) {
    	FUNC_FAILS(rc, "transmitAPDU failed");
    }

    rc = updatePinStatus(slot->token, SW1SW2);

    if (rc != CKR_OK) {
		FUNC_FAILS(rc, "sc_hsm_login failed");
    }

    sc_hsm_loadObjects(slot->token, FALSE);
    FUNC_RETURNS(rc);
}



struct p11Token_t *newSmartCardHSMToken(struct p11Slot_t *slot) {
	struct p11Token_t *ptoken;
	token_sc_hsm_t *sc;
	int rc, pinstatus;

	FUNC_CALLED();

	rc = checkPINStatus(slot);
	if (rc < 0) {
		FUNC_FAILS(NULL, "checkPINStatus failed");
	}

	if ((rc != 0x9000) && ((rc && 0xFF00) != 0x6300) && ((rc && 0xFF00) != 0x6900) ) {
		rc = selectApplet(slot);
		if (rc < 0) {
			FUNC_FAILS(NULL, "applet selection failed");
		}

		rc = checkPINStatus(slot);
		if (rc < 0) {
			FUNC_FAILS(NULL, "checkPINStatus failed");
		}
	}
	pinstatus = rc;

   	ptoken = (struct p11Token_t *)calloc(sizeof(struct p11Token_t) + sizeof(token_sc_hsm_t), 1);

   	if (ptoken == NULL) {
   		return NULL;
   	}

   	ptoken->slot = slot;
   	strbpcpy(ptoken->info.label, "SC-HSM", sizeof(ptoken->info.label));
   	strbpcpy(ptoken->info.manufacturerID, "CardContact", sizeof(ptoken->info.manufacturerID));
   	strbpcpy(ptoken->info.model, "SmartCard-HSM", sizeof(ptoken->info.model));

   	ptoken->info.flags = CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED;

   	updatePinStatus(ptoken, pinstatus);

   	sc = getPrivateData(ptoken);

   	sc_hsm_loadObjects(ptoken, TRUE);

   	return ptoken;
}
