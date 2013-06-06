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
 * \file    token-sc-hsm.h
 * \author  Andreas Schwier (ASC)
 * \brief   SmartCard-HSM functions
 *
 */

#ifndef ___TOKEN_SC_HSM_H_INC___
#define ___TOKEN_SC_HSM_H_INC___

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>

#define MAX_ATR					40
#define MAX_EXT_APDU_LENGTH		1014
#define MAX_FILES				128
#define MAX_CERTIFICATE_SIZE	4096
#define MAX_P15_SIZE			1024

#define PRKD_PREFIX				0xC4		/* Hi byte in file identifier for PKCS#15 PRKD objects */
#define CD_PREFIX				0xC8		/* Hi byte in file identifier for PKCS#15 CD objects */
#define DCOD_PREFIX				0xC9		/* Hi byte in file identifier for PKCS#15 DCOD objects */
#define CA_CERTIFICATE_PREFIX	0xCA		/* Hi byte in file identifier for CA certificates */
#define KEY_PREFIX				0xCC		/* Hi byte in file identifier for key objects */
#define PROT_DATA_PREFIX		0xCD		/* Hi byte in file identifier for PIN protected data objects */
#define EE_CERTIFICATE_PREFIX	0xCE		/* Hi byte in file identifier for EE certificates */
#define DATA_PREFIX				0xCF		/* Hi byte in file identifier for readable data objects */

#define ALGO_RSA_RAW			0x20		/* RSA signature with external padding */
#define ALGO_RSA_DECRYPT		0x21		/* RSA decrypt */
#define ALGO_RSA_PKCS1			0x30		/* RSA signature with DigestInfo input and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA1		0x31		/* RSA signature with SHA-1 hash and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA256	0x33		/* RSA signature with SHA-256 hash and PKCS#1 V1.5 padding */

#define ALGO_RSA_PSS_SHA1		0x41		/* RSA signature with SHA-1 hash and PKCS#1 PSS padding */
#define ALGO_RSA_PSS_SHA256		0x43		/* RSA signature with SHA-256 hash and PKCS#1 PSS padding */

#define ALGO_EC_RAW				0x70		/* ECDSA signature with hash input */
#define ALGO_EC_SHA1			0x71		/* ECDSA signature with SHA-1 hash */
#define ALGO_EC_SHA224			0x72		/* ECDSA signature with SHA-224 hash */
#define ALGO_EC_SHA256			0x73		/* ECDSA signature with SHA-256 hash */
#define ALGO_EC_DH				0x80		/* ECDH key derivation */

#define ID_USER_PIN				0x81		/* User PIN identifier */
#define ID_SO_PIN				0x88		/* Security officer PIN identifier */

typedef struct token_sc_hsm {
	unsigned char *publickeys[256];
} token_sc_hsm_t;

int newSmartCardHSMToken(struct p11Slot_t *slot, struct p11Token_t **token);
int sc_hsm_loadObjects(struct p11Token_t *token, int publicObjects);
int sc_hsm_login(struct p11Slot_t *slot, int userType, unsigned char *pin, int pinlen);
int sc_hsm_logout(struct p11Slot_t *slot);

#endif /* ___TOKEN_SC_HSM_H_INC___ */
