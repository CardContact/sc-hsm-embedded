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
 * @file    slot.c
 * @author  Frank Thater
 * @brief   Slot implementation dispatching for PC/SC or CT-API reader
 */

#include <string.h>

#include <common/memset_s.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/session.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

#ifdef CTAPI
#include "slot-ctapi.h"
#else
#include "slot-pcsc.h"
#endif



extern struct p11Context_t *context;



/**
 * addToken adds a token to the specified slot.
 *
 * @param slot       Pointer to slot structure.
 * @param token      Pointer to token structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_FUNCTION_FAILED                    </TD>
 *                   <TD>There is already a token in the slot   </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int addToken(struct p11Slot_t *slot, struct p11Token_t *token)
{
	if (slot->token != NULL) {
		return CKR_FUNCTION_FAILED;
	}

	if (slot->removedToken) {
		freeToken(slot->removedToken);
		slot->removedToken = NULL;
	}

	slot->token = token;                     /* Add token to slot                */
	slot->info.flags |= CKF_TOKEN_PRESENT;   /* indicate the presence of a token */

	return CKR_OK;
}



/**
 * removeToken removes a token from the specified slot.
 *
 * @param slot       Pointer to slot structure.
 *
 * @return
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_FUNCTION_FAILED                    </TD>
 *                   <TD>There is no token in the slot          </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int removeToken(struct p11Slot_t *slot)
{
	int i;

	if (slot->token == NULL) {
		return CKR_FUNCTION_FAILED;
	}

	if (!slot->primarySlot) {
		// Remove token from associated virtual slots
		for (i = 0; i < sizeof(slot->virtualSlots) / sizeof(slot->virtualSlots[0]); i++) {
			if (slot->virtualSlots[i]) {
				removeToken(slot->virtualSlots[i]);
			}
		}
	}

	if (slot->removedToken) {
		freeToken(slot->removedToken);
		slot->removedToken = NULL;
	}

	// A removed token and associated sessions are not immediately released from memory
	// to give running threads a change to complete token operations.
	slot->removedToken = slot->token;
	slot->token = NULL;
	slot->info.flags &= ~CKF_TOKEN_PRESENT;

	// Final close with resource deallocation is done from freeToken().
	tokenRemovedForSessionsOnSlot(&context->sessionPool, slot->id);

	return CKR_OK;
}



/**
 * Encode APDU using either short or extended notation
 *
 * @param CLA the instruction class
 * @param INS the instruction code
 * @param P1 the first parameter
 * @param P2 the second parameter
 * @param Nc number of outgoing bytes
 * @param OutData outgoing command data
 * @param Ne number of bytes expected from card,
 *           -1 for none,
 *           0 for all in short mode,
 *           > 255 in extended mode,
 *           >= 65536 all in extended mode
 * @param apdu buffer receiving the encoded APDU
 * @param apdu_len length of provided buffer
 * @return -1 for error or the length of the encoded APDU otherwise
 */
int encodeCommandAPDU(
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		size_t Nc, unsigned char *OutData, int Ne,
		unsigned char *apdu, size_t apdu_len)
{
	unsigned char *po;

	FUNC_CALLED();

	if (apdu == NULL)
		FUNC_FAILS(-1, "Output buffer not defined");

	if (Nc + 9 > apdu_len)
		FUNC_FAILS(-1, "Nc larger than output buffer");

	if (Nc && (OutData == NULL))
		FUNC_FAILS(-1, "OutData not defined for Nc > 0");

	apdu[0] = CLA;
	apdu[1] = INS;
	apdu[2] = P1;
	apdu[3] = P2;
	po = apdu + 4;

	if (OutData && Nc) {
		if ((Nc <= 255) && (Ne <= 255)) {		// Case 3s or 4s
			*po++ = (unsigned char)Nc;
		} else {
			*po++ = 0;							// Case 3e or 3e
			*po++ = (unsigned char)(Nc >> 8);
			*po++ = (unsigned char)(Nc & 0xFF);
		}
		memcpy(po, OutData, Nc);
		po += Nc;
	}

	if (Ne >= 0) {								// Case 2 or 4
		if ((Ne <= 255) && (Nc <= 255)) {		// Case 2s or 4s
			*po++ = (unsigned char)Ne;
		} else {
			if (Ne >= 65536)					// Request all for extended APDU
				Ne = 0;

			if (!OutData)						// Case 4e
				*po++ = 0;

			*po++ = (unsigned char)(Ne >> 8);
			*po++ = (unsigned char)(Ne & 0xFF);
		}
	}

	FUNC_RETURNS(po - apdu);
}



/*
 *  Process an ISO 7816 APDU with the underlying terminal hardware.
 *
 *  CLA     : Class byte of instruction
 *  INS     : Instruction byte
 *  P1      : Parameter P1
 *  P2      : Parameter P2
 *  OutLen  : Length of outgoing data (Lc)
 *  OutData : Outgoing data or NULL if none
 *  InLen   : Length of incoming data (Le)
 *  InData  : Input buffer for incoming data
 *  InSize  : buffer size
 *  SW1SW2  : Address of short integer to receive SW1SW2
 *
 *  Returns : < 0 Error > 0 Bytes read
 */
int transmitAPDU(struct p11Slot_t *slot,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2)
{
	int rc;
	unsigned char apdu[MAX_CAPDU];
#ifdef DEBUG
	char scr[MAX_CAPDU + 128];
	char *po;
#endif

	if (slot->primarySlot)
		slot = slot->primarySlot;

#ifdef DEBUG
	sprintf(scr, "C-APDU: %02X %02X %02X %02X ", CLA, INS, P1, P2);
	po = strchr(scr, '\0');

	if (OutLen && OutData) {
		sprintf(po, "Lc=%02X(%d) ", OutLen, OutLen);
		po = strchr(scr, '\0');

		if (INS != 0x20 && INS != 0x24 && INS != 0x2C) {
			if (OutLen > 2048) {
				decodeBCDString(OutData, 2048, po);
				strcat(po, "..");
			} else {
				decodeBCDString(OutData, OutLen, po);
			}
		} else {
			strcat(po, "***Sensitive***");
		}
		po = strchr(scr, '\0');
		strcpy(po, " ");
		po++;
	}

	if (InData && InSize)
		sprintf(po, "Le=%02X(%d)", InLen, InLen);

	debug("%s\n", scr);
	memset_s(scr, sizeof(scr), 0, sizeof(scr));
#endif

	rc = encodeCommandAPDU(CLA, INS, P1, P2,
			OutLen, OutData, InData ? InLen : -1,
			apdu, sizeof(apdu));

	if (rc < 0) {
		memset_s(apdu, sizeof(apdu), 0, sizeof(apdu));
		FUNC_FAILS(rc, "Encoding APDU failed");
	}

#ifdef CTAPI
	rc = transmitAPDUviaCTAPI(slot, 0,
			apdu, rc,
			apdu, sizeof(apdu));
#else
	rc = transmitAPDUviaPCSC(slot,
			apdu, rc,
			apdu, sizeof(apdu));
#endif

	if (rc >= 2) {
		*SW1SW2 = (apdu[rc - 2] << 8) | apdu[rc - 1];
		rc -= 2;

		if (InData && InSize) {
			if (rc > InSize) {		// Never return more than caller allocated a buffer for
				rc = InSize;
			}
			memcpy(InData, apdu, rc);
		}
	} else {
		rc = -1;
	}

#ifdef DEBUG
	if (rc > 0 && InData) {
		sprintf(scr, "R-APDU: Lr=%02X(%d) ", rc, rc);
		po = strchr(scr, '\0');
		if (rc > 2048) {
			decodeBCDString(InData, 2048, po);
			strcat(scr, "..");
		} else {
			decodeBCDString(InData, rc, po);
		}

		po = strchr(scr, '\0');
		sprintf(po, " SW1/SW2=%04X", *SW1SW2);
	} else
		sprintf(scr, "R-APDU: rc=%d SW1/SW2=%04X", rc, *SW1SW2);

	debug("%s\n", scr);
#endif
	memset_s(apdu, sizeof(apdu), 0, sizeof(apdu));
	return rc;
}



int transmitVerifyPinAPDU(struct p11Slot_t *slot,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData, unsigned short *SW1SW2,
		unsigned char pinformat, unsigned char minpinsize, unsigned char maxpinsize,
		unsigned char pinblockstring, unsigned char pinlengthformat)
{
	int rc;
	unsigned char apdu[MAX_CAPDU];
#ifdef DEBUG
	char scr[MAX_CAPDU + 128];
#endif

	if (slot->primarySlot)
		slot = slot->primarySlot;

#ifdef DEBUG
	sprintf(scr, "C-APDU: %02X %02X %02X %02X ", CLA, INS, P1, P2);

	debug("%s\n", scr);
#endif

	rc = encodeCommandAPDU(CLA, INS, P1, P2,
			OutLen, OutData, -1,
			apdu, sizeof(apdu));

	if (rc < 0)
		FUNC_FAILS(rc, "Encoding APDU failed");

#ifdef CTAPI
	/*
	 * Not implemented yet
	 */
	rc = -1;

#else
	rc = transmitVerifyPinAPDUviaPCSC(slot,
			pinformat, minpinsize, maxpinsize,
			pinblockstring, pinlengthformat,
			apdu, rc,
			apdu, sizeof(apdu));
#endif

	if (rc >= 2) {
		*SW1SW2 = (apdu[rc - 2] << 8) | apdu[rc - 1];
		rc -= 2;
	}

#ifdef DEBUG
	sprintf(scr, "R-APDU: rc=%d SW1/SW2=%04X", rc, *SW1SW2);
	debug("%s\n", scr);
#endif
	return rc;
}



void appendStr(CK_UTF8CHAR_PTR dest, int destlen, char *str)
{
	int i = destlen;

	while ((i > 0) && (dest[i - 1] == ' '))
		i--;

	strncpy((char *)dest + i, str, destlen - i);
}



int getVirtualSlot(struct p11Slot_t *slot, int index, struct p11Slot_t **vslot)
{
	struct p11Slot_t *newslot;
	char postfix[3];

	FUNC_CALLED();

	if ((index < 0) || (index > sizeof(slot->virtualSlots) / sizeof(*slot->virtualSlots)))
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Index must not exceed size of virtual slot list");

	if (slot->primarySlot)
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Slot is a virtual slot");

	if (slot->virtualSlots[index]) {
		*vslot = slot->virtualSlots[index];
		FUNC_RETURNS(CKR_OK);
	}

	newslot = (struct p11Slot_t *) calloc(1, sizeof(struct p11Slot_t));

	if (newslot == NULL)
		FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");

	*newslot = *slot;
	newslot->token = NULL;
	newslot->next = NULL;
	newslot->primarySlot = slot;

	/* If we already have a pre-allocated slot id, then assign the next id value */
	if (slot->id != 0)
		newslot->id = slot->id + index + 1;

	slot->virtualSlots[index] = newslot;

	postfix[0] = '.';
	postfix[1] = '2' + index;
	postfix[2] = 0;

	appendStr(newslot->info.slotDescription, sizeof(slot->info.slotDescription), postfix);

	addSlot(&context->slotPool, newslot);

	*vslot = newslot;
	FUNC_RETURNS(CKR_OK);
}



int getToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	FUNC_CALLED();

	*token = slot->token;

	FUNC_RETURNS(slot->token ? CKR_OK : CKR_TOKEN_NOT_PRESENT);
}



int getValidatedToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	int rc;
	struct p11Slot_t *pslot;

	FUNC_CALLED();

	// Checking for new or removed token is always performed on the
	// primary slot
	pslot = slot;
	if (pslot->primarySlot)
		pslot = pslot->primarySlot;

	p11LockMutex(context->mutex);

#ifdef CTAPI
	rc = getCTAPIToken(pslot, token);
#else
	rc = getPCSCToken(pslot, token);
#endif

	p11UnlockMutex(context->mutex);

	if (rc != CKR_OK)
		return rc;

	return getToken(slot, token);
}



/**
 * Gain exclusive access to the token in the slot, preventing other processes to access the token
 */
int lockSlot(struct p11Slot_t *slot)
{
	struct p11Slot_t *pslot;
	int rc;

	pslot = slot;
	if (pslot->primarySlot)
		pslot = pslot->primarySlot;

#ifdef CTAPI
	rc = 0;
#else
	rc = lockPCSCSlot(pslot);
#endif
	return rc;
}



/**
 * Release exclusive access to the token in the slot
 */
int unlockSlot(struct p11Slot_t *slot)
{
	struct p11Slot_t *pslot;
	int rc;

	pslot = slot;
	if (pslot->primarySlot)
		pslot = pslot->primarySlot;

#ifdef CTAPI
	rc = 0;
#else
	rc = unlockPCSCSlot(pslot);
#endif
	return rc;
}



int findSlotObject(struct p11Slot_t *slot, CK_OBJECT_HANDLE handle, struct p11Object_t **object, int publicObject)
{
	int rc;
	struct p11Token_t *token;

	rc = getToken(slot, &token);
	if (rc != CKR_OK) {
		return rc;
	}

	rc = findObject(token, handle, object, publicObject);

	return rc < 0 ? CKR_OBJECT_HANDLE_INVALID : CKR_OK;
}



int findSlotKey(struct p11Slot_t *slot, CK_OBJECT_HANDLE handle, struct p11Object_t **object)
{
	int rc;

	// Look in private object list
	rc = findSlotObject(slot, handle, object, 0);

	if (rc == CKR_OBJECT_HANDLE_INVALID)
		// Look also in public object list for keys with CKA_ALWAYS_AUTHENTICATE
		rc = findSlotObject(slot, handle, object, 1);

	return rc == CKR_OBJECT_HANDLE_INVALID ? CKR_KEY_HANDLE_INVALID : rc;
}



int updateSlots(struct p11SlotPool_t *pool)
{
	int rc;

	FUNC_CALLED();

#ifdef CTAPI
	rc = updateCTAPISlots(pool);
#else
	rc = updatePCSCSlots(pool);
#endif

	FUNC_RETURNS(rc);
}



int closeSlot(struct p11Slot_t *slot)
{
	int rc;

	FUNC_CALLED();

	if (slot->primarySlot)
		FUNC_RETURNS(CKR_OK);

#ifdef CTAPI
	rc = closeCTAPISlot(slot);
#else
	rc = closePCSCSlot(slot);
#endif

	FUNC_RETURNS(rc);
}
