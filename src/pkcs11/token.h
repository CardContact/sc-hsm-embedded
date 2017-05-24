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
 * @file    token.h
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for token authentication and token management
 */

#ifndef ___TOKEN_H_INC___
#define ___TOKEN_H_INC___

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>

/*
 * Define human readable constants for
 *	bmFormatString
 * according to USB CCID Spec Rev. 1.1
 */

#define PIN_FORMAT_BINARY	0x00
#define PIN_FORMAT_BCD		0x01
#define PIN_FORMAT_ASCII	0x02

#define PIN_SYSTEM_UNIT_BITS	0x00
#define PIN_SYSTEM_UNIT_BYTES	0x80

#define PIN_LEFT_JUSTIFICATION		0x00
#define PIN_RIGHT_JUSTIFICATION		0x04

#define PIN_POSITION_0		(0x00 << 3)
#define PIN_POSITION_1		(0x01 << 3)
#define PIN_POSITION_2		(0x02 << 3)
#define PIN_POSITION_3		(0x03 << 3)
#define PIN_POSITION_4		(0x04 << 3)
#define PIN_POSITION_5		(0x05 << 3)
#define PIN_POSITION_6		(0x06 << 3)
#define PIN_POSITION_7		(0x07 << 3)
#define PIN_POSITION_8		(0x08 << 3)
#define PIN_POSITION_9		(0x09 << 3)
#define PIN_POSITION_10		(0x0A << 3)
#define PIN_POSITION_11		(0x0B << 3)
#define PIN_POSITION_12		(0x0C << 3)
#define PIN_POSITION_13		(0x0D << 3)
#define PIN_POSITION_14		(0x0E << 3)
#define PIN_POSITION_15		(0x0F << 3)

#define MAX_CERTIFICATE_SIZE	4096
#define MAX_CAPDU				4096
#define MAX_RAPDU				4096

int newToken(struct p11Slot_t *slot, unsigned char *atr, size_t atrlen, struct p11Token_t **token);
void freeToken(struct p11Token_t *token);
int logIn(struct p11Slot_t *slot, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
int logOut(struct p11Slot_t *slot);
int initPIN(struct p11Slot_t *slot, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen);
int setPIN(struct p11Slot_t *slot, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldPinLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewPinLen);
int addObject(struct p11Token_t *token, struct p11Object_t *object, int publicObject);
int findObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, struct p11Object_t **object, int publicObject);
int findMatchingTokenObject(struct p11Token_t *token, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t **pObject);
int removeTokenObject(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject);
int removeObjectLeavingAttributes(struct p11Token_t *token, CK_OBJECT_HANDLE handle, int publicObject);
int saveObjects(struct p11Slot_t *slot, struct p11Token_t *token, int publicObject);
int destroyObject(struct p11Slot_t *slot, struct p11Token_t *token, struct p11Object_t *object);
int synchronizeToken(struct p11Slot_t *slot, struct p11Token_t *token);
struct p11Token_t *getBaseToken(struct p11Token_t *token);

#endif /* ___TOKEN_H_INC___ */
