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
 * @file    token-sc-hsm.h
 * @author  Andreas Schwier
 * @brief   Token implementation for a SmartCard-HSM
 */

#ifndef ___TOKEN_SC_HSM_H_INC___
#define ___TOKEN_SC_HSM_H_INC___

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>

#define MAX_ATR			40
#define MAX_EXT_APDU_LENGTH	1014
#define MAX_FILES		128
#define MAX_P15_SIZE		1024

#define PRKD_PREFIX		0xC4		/* Hi byte in file identifier for PKCS#15 PRKD objects */
#define CD_PREFIX		0xC8		/* Hi byte in file identifier for PKCS#15 CD objects */
#define DCOD_PREFIX		0xC9		/* Hi byte in file identifier for PKCS#15 DCOD objects */
#define CA_CERTIFICATE_PREFIX	0xCA		/* Hi byte in file identifier for CA certificates */
#define KEY_PREFIX		0xCC		/* Hi byte in file identifier for key objects */
#define PROT_DATA_PREFIX	0xCD		/* Hi byte in file identifier for PIN protected data objects */
#define EE_CERTIFICATE_PREFIX	0xCE		/* Hi byte in file identifier for EE certificates */
#define DATA_PREFIX		0xCF		/* Hi byte in file identifier for readable data objects */

#define ALGO_RSA_RAW		0x20		/* RSA signature with external padding */
#define ALGO_RSA_DECRYPT	0x21		/* RSA decrypt */
#define ALGO_RSA_PKCS1		0x30		/* RSA signature with DigestInfo input and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA1	0x31		/* RSA signature with SHA-1 hash and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA256	0x33		/* RSA signature with SHA-256 hash and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA384	0x34		/* RSA signature with SHA-384 hash and PKCS#1 V1.5 padding */
#define ALGO_RSA_PKCS1_SHA512	0x35		/* RSA signature with SHA-512 hash and PKCS#1 V1.5 padding */

#define ALGO_RSA_PSS		0x40		/* RSA signature with PKCS#1 PSS padding (External Hash) */
#define ALGO_RSA_PSS_SHA1	0x41		/* RSA signature with SHA-1 hash and PKCS#1 PSS padding */
#define ALGO_RSA_PSS_SHA256	0x43		/* RSA signature with SHA-256 hash and PKCS#1 PSS padding */
#define ALGO_RSA_PSS_SHA384	0x44		/* RSA signature with SHA-384 hash and PKCS#1 PSS padding */
#define ALGO_RSA_PSS_SHA512	0x45		/* RSA signature with SHA-512 hash and PKCS#1 PSS padding */

#define ALGO_EC_RAW		0x70		/* ECDSA signature with hash input */
#define ALGO_EC_SHA1		0x71		/* ECDSA signature with SHA-1 hash */
#define ALGO_EC_SHA224		0x72		/* ECDSA signature with SHA-224 hash */
#define ALGO_EC_SHA256		0x73		/* ECDSA signature with SHA-256 hash */
#define ALGO_EC_DH		0x80		/* ECDH key derivation */

#define ALGO_EC_DERIVE		0x98		/* Derive EC key from EC key */

#define ALGO_AES_CBC_ENCRYPT	0x10
#define ALGO_AES_CBC_DECRYPT	0x11
#define ALGO_AES_CMAC		0x18

#define ID_USER_PIN		0x81		/* User PIN identifier */
#define ID_SO_PIN		0x88		/* Security officer PIN identifier */

struct token_sc_hsm {
	unsigned char sopin[8];
};

struct p11TokenDriver *sc_hsm_getDriver();

#endif /* ___TOKEN_SC_HSM_H_INC___ */
