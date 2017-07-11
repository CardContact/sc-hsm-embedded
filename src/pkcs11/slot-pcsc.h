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
 * @file    slot-pcsc.c
 * @author  Frank Thater
 * @brief   Slot implementation for PC/SC reader
 */

#ifndef ___SLOT_PCSC_H___
#define ___SLOT_PCSC_H___

#ifndef CTAPI

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/strbpcpy.h>

#ifdef _WIN32
#include <winscard.h>
#else
#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#else
#include <pcsclite.h>
#include <winscard.h>
#endif /* __APPLE__ */
#endif

#ifndef SCARD_CTL_CODE
#define SCARD_CTL_CODE(code) (0x42000000 + (code))
#endif

#define FEATURE_VERIFY_PIN_START 			0x01
#define FEATURE_VERIFY_PIN_FINIS			0x02
#define FEATURE_MODIFY_PIN_START			0x03
#define FEATURE_MODIFY_PIN_FINISH			0x04
#define FEATURE_GET_KEY_PRESSED				0x05
#define FEATURE_VERIFY_PIN_DIRECT			0x06
#define FEATURE_MODIFY_PIN_DIRECT			0x07
#define FEATURE_MCT_READER_DIRECT			0x08
#define FEATURE_MCT_UNIVERSAL				0x09
#define FEATURE_IFD_PIN_PROPERTIES			0x0A
#define FEATURE_ABORT						0x0B
#define FEATURE_SET_SPE_MESSAGE				0x0C
#define FEATURE_VERIFY_PIN_DIRECT_APP_ID	0x0D
#define FEATURE_MODIFY_PIN_DIRECT_APP_ID	0x0E
#define FEATURE_WRITE_DISPLAY				0x0F
#define FEATURE_GET_KEY						0x10
#define FEATURE_IFD_DISPLAY_PROPERTIES		0x11
#define FEATURE_GET_TLV_PROPERTIES			0x12
#define FEATURE_CCID_ESC_COMMAND			0x13

#pragma pack(1)
typedef struct {
	unsigned char bTimeOut;					/* Timeout is seconds (00 means use default timeout) */
	unsigned char bTimeOut2; 					/* Timeout in seconds after first key stroke */
	unsigned char bmFormatString; 				/* Formatting options */
	unsigned char bmPINBlockString; 			/* bits 7-4 bit size of PIN length in APDU, bits 3-0 PIN block size in bytes after justification and formatting */
	unsigned char bmPINLengthFormat; 			/* bits 7-5 RFU, bit 4 set if system units are bytes, clear if system units are bits, bits 3-0 PIN length position in system units */
	unsigned short wPINMaxExtraDigit; 			/* 0xXXYY where XX is minimum PIN size in digits and YY is maximum PIN size in digits */
	unsigned char bEntryValidationCondition; 	/* Conditions under which PIN entry should be considered complete */
	unsigned char bNumberMessage; 				/* Number of messages to display for PIN verification */
	unsigned short wLangID;					/* Language for messages */
	unsigned char bMsgIndex; 					/* Message index (should be 00) */
	unsigned char bTeoPrologue[3]; 			/* T=1 block prologue field to use (should be all zeros) */
	unsigned int ulDataLength; 				/* Length of Data to be sent to the ICC */
	unsigned char abData[128]; 				/* Data to send to the ICC */
} PIN_VERIFY_DIRECT_STRUCTURE_t;
#pragma pack()

#ifdef DEBUG
char* pcsc_error_to_string(const LONG error);
char* pcsc_feature_to_string(const WORD feature);
#endif

int transmitVerifyPinAPDUviaPCSC(struct p11Slot_t *slot,
	unsigned char pinformat, unsigned char minpinsize, unsigned char maxpinsize,
	unsigned char pinblockstring, unsigned char pinlengthformat,
	unsigned char *capdu, size_t capdu_len,
	unsigned char *rapdu, size_t rapdu_len);
int transmitAPDUviaPCSC(struct p11Slot_t *slot,
	unsigned char *capdu, size_t capdu_len,
	unsigned char *rapdu, size_t rapdu_len);
int getPCSCToken(struct p11Slot_t *slot, struct p11Token_t **token);
int checkForNewPCSCToken(struct p11Slot_t *slot);
int lockPCSCSlot(struct p11Slot_t *slot);
int unlockPCSCSlot(struct p11Slot_t *slot);
int updatePCSCSlots(struct p11SlotPool_t *pool);
int waitForPCSCEvent(struct p11SlotPool_t *pool, int timeout);
int closePCSCSlot(struct p11Slot_t *slot);

#endif

#endif
