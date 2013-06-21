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
 * @file    pkcs15.h
 * @author  Andreas Schwier
 * @brief   Decoder for PKCS#15 private key, certificate and data objects
 */

/* Prevent from including twice ------------------------------------------- */

#ifndef __PKCS15_H__
#define __PKCS15_H__

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

#define P15_KEYTYPE_RSA     0x30
#define P15_KEYTYPE_ECC     0xA0

#define P15_ENCIPHER        0x80000000
#define P15_DECIPHER        0x40000000
#define P15_SIGN            0x20000000
#define P15_SIGNRECOVER     0x10000000
#define P15_KEYENCIPHER     0x08000000
#define P15_KEYDECIPHER     0x04000000
#define P15_VERIFY          0x02000000
#define P15_VERIFYRECOVER   0x01000000
#define P15_DERIVE          0x00800000
#define P15_NONREPUDIATION  0x00400000

/**
 * CommonObjectAttribute as defined by PKCS#15
 */
struct p15CommonObjectAttributes {
	char            *label;             /**< The label        */
};

/**
 * Private key description as defined by PKCS#15
 */
struct p15PrivateKeyDescription {
	int             keytype;            /**< the keytype encoded as the tag value */
	struct p15CommonObjectAttributes
	                coa;                /**< CommonObjectAttributes               */
	size_t          idlen;              /**< Length of key id                     */
	unsigned char   *id;                /**< The key id as visible at PKCS#11     */
	unsigned long   usage;              /**< Key usage flags                      */
	int             keysize;            /**< Key size in bits                     */
};

int decodePrivateKeyDescription(unsigned char *prkd, size_t prkdlen, struct p15PrivateKeyDescription **p15);
void freePrivateKeyDescription(struct p15PrivateKeyDescription **p15);


/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif
