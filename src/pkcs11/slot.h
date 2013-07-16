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
 * @file    slot.h
 * @author  Frank Thater, Andreas Schwier
 * @brief   API exposed by slot implementation
 */

#ifndef ___SLOT_H_INC___
#define ___SLOT_H_INC___

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>

int addToken(struct p11Slot_t *slot, struct p11Token_t *token);

int removeToken(struct p11Slot_t *slot);

int encodeCommandAPDU(
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		size_t Nc, unsigned char *OutData, int Ne,
		unsigned char *apdu, size_t apdu_len);

int transmitAPDU(struct p11Slot_t *slot,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2);

int transmitVerifyPinAPDU(struct p11Slot_t *slot,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		unsigned short *SW1SW2,
		unsigned char pinformat, unsigned char minpinsize, unsigned char maxpinsize,
		unsigned char pinblockstring, unsigned char pinlengthformat);

int getToken(struct p11Slot_t *slot, struct p11Token_t **token);

int findSlotObject(struct p11Slot_t *slot, CK_OBJECT_HANDLE handle, struct p11Object_t **object, int publicObject);

int updateSlots(struct p11SlotPool_t *pool);

int closeSlot(struct p11Slot_t *slot);

int addToken(struct p11Slot_t *slot, struct p11Token_t *token);

int removeToken(struct p11Slot_t *slot);

#endif /* ___SLOT_H_INC___ */
