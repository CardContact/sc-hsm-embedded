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

#include <pkcs11/p11generic.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

#define CTAPI			// Only CTAPI supported so far
#include <pkcs11/slot-ctapi.h>



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
	if (slot->token == NULL) {
		return CKR_FUNCTION_FAILED;
	}

	slot->info.flags &= ~CKF_TOKEN_PRESENT;
	freeToken(slot);

	return CKR_TOKEN_NOT_PRESENT;
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
	unsigned char apdu[4098];
#ifdef DEBUG
	char scr[4196], *po;

	sprintf(scr, "C-APDU: %02X %02X %02X %02X ", CLA, INS, P1, P2);
	po = strchr(scr, '\0');

	if (OutLen && OutData) {
		sprintf(po, "Lc=%02X(%d) ", OutLen, OutLen);
		po = strchr(scr, '\0');
		if (OutLen > 2048) {
			decodeBCDString(OutData, 2048, po);
			strcat(po, "..");
		} else {
			decodeBCDString(OutData, OutLen, po);
		}
		po = strchr(scr, '\0');
		strcpy(po, " ");
		po++;
	}

	if (InData && InSize)
		sprintf(po, "Le=%02X(%d)", InLen, InLen);

	debug("%s\n", scr);
#endif

	rc = encodeCommandAPDU(CLA, INS, P1, P2,
			OutLen, OutData, InData ? InLen : -1,
			apdu, sizeof(apdu));

	if (rc < 0)
		FUNC_FAILS(rc, "Encoding APDU failed");

#ifdef CTAPI
	rc = transmitAPDUviaCTAPI(slot, 0,
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
	if (rc > 0) {
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
	return rc;
}



int getToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	int rc;
	FUNC_CALLED();

#ifdef CTAPI
	rc = getCTAPIToken(slot, token);
#else
	rc = getPCSCToken(slot, token);
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

	return rc < 0 ? CKR_GENERAL_ERROR : CKR_OK;
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

#ifdef CTAPI
	rc = closeCTAPISlot(slot);
#else
	rc = closePCSCSlot(slot);
#endif

	FUNC_RETURNS(rc);
}
