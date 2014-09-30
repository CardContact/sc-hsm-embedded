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
 * @file    slot-ctapi.c
 * @author  Andreas Schwier
 * @brief   Slot implementation for CT-API reader
 */

#ifdef CTAPI

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot-ctapi.h>

#include <pkcs11/strbpcpy.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

#include <ctccid/ctapi.h>

extern struct p11Context_t *context;

#define MAX_READERS 8
static unsigned short numberOfReaders = 0;



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
int transmitAPDUwithCTAPI(struct p11Slot_t *slot, int todad,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2)
{
	int rc;
	unsigned char apdu[MAX_APDULEN];

	FUNC_CALLED();

	rc = encodeCommandAPDU(CLA, INS, P1, P2,
			OutLen, OutData, InData ? InLen : -1,
			apdu, sizeof(apdu));

	if (rc < 0)
		FUNC_FAILS(rc, "Encoding APDU failed");

	rc = transmitAPDUviaCTAPI(slot, todad,
			apdu, rc,
			apdu, sizeof(apdu));

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

	FUNC_RETURNS(rc);
}



/**
 * Transmit APDU using CT-API
 *
 * @param slot the slot to use for communication
 * @param capdu the command APDU
 * @param capdu_len the length of the command APDU
 * @param rapdu the response APDU
 * @param rapdu_len the length of the response APDU
 * @return -1 for error or length of received response APDU
 */
int transmitAPDUviaCTAPI(struct p11Slot_t *slot, int todad,
	unsigned char *capdu, size_t capdu_len,
	unsigned char *rapdu, size_t rapdu_len)
{
	int rc;
	unsigned short lenr;
	unsigned char dad, sad;

	FUNC_CALLED();

	sad  = HOST;
	dad  = todad;
	lenr = rapdu_len;

	rc = CT_data(slot->ctn, &dad, &sad, capdu_len, capdu, &lenr, rapdu);

	if (rc < 0)
		FUNC_FAILS(rc, "CT_data failed");

	FUNC_RETURNS(lenr);
}



/**
 * checkForNewCTAPIToken looks into a specific slot for a token.
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
 *                   <TD>CKR_HOST_MEMORY                        </TD>
 *                   <TD>Error getting memory (malloc)          </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_GENERAL_ERROR                      </TD>
 *                   <TD>Error opening slot directory           </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
static int checkForNewCTAPIToken(struct p11Slot_t *slot)
{
	struct p11Token_t *ptoken;
	unsigned char rsp[260];
	int rc;
	unsigned short SW1SW2;

	FUNC_CALLED();

	if (slot->closed) {
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	}

	// GET STATUS
	rc = transmitAPDUwithCTAPI(slot, 1, 0x20, 0x13, 0x01, 0x80, 0, NULL, 0, rsp, sizeof(rsp), &SW1SW2);

	if (rc == ERR_CT) {
		closeSlot(slot);
	}

	if (rc < 0) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "GET_STATUS failed");
	}

	if ((SW1SW2 != 0x9000) || (rc < 3) || (rsp[0] != 0x80) || (rsp[1] == 0) || (rsp[1] > rc - 2)) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "GET_STATUS returned invalid response");
	}

	if (!(rsp[2] & 0x01)) {	// No Card in reader
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	}

	rc = transmitAPDUwithCTAPI(slot, 1, 0x20, 0x12, 0x01, 0x01, 0, NULL, 0, rsp, sizeof(rsp), &SW1SW2);

	if (rc < 0) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "REQUEST ICC failed");
	}

	if (SW1SW2 != 0x9001) {
		FUNC_FAILS(CKR_TOKEN_NOT_RECOGNIZED, "Reset failed");
	}

	rc = newToken(slot, rsp, rc, &ptoken);

	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "newToken failed()");
	}

	FUNC_RETURNS(CKR_OK);
}



/**
 * checkForRemovedCTAPIToken looks into a specific slot for a removed token.
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
 *                   <TD>CKR_HOST_MEMORY                        </TD>
 *                   <TD>Error getting memory (malloc)          </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_GENERAL_ERROR                      </TD>
 *                   <TD>Error opening slot directory           </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
static int checkForRemovedCTAPIToken(struct p11Slot_t *slot)
{
	unsigned char rsp[260];
	int rc;
	unsigned short SW1SW2;

	FUNC_CALLED();

	rc = transmitAPDUwithCTAPI(slot, 1, 0x20, 0x13, 0x01, 0x80, 0, NULL, 0, rsp, sizeof(rsp), &SW1SW2);

	if (rc == ERR_CT) {					// Reader or USB-Device removed
		removeToken(slot);
		closeSlot(slot);
	}

	if (rc < 0) {
		FUNC_FAILS(CKR_GENERAL_ERROR, "GET_STATUS failed");
	}

	if ((SW1SW2 != 0x9000) || (rc < 3) || (rsp[0] != 0x80) || (rsp[1] == 0) || (rsp[1] > rc - 2)) {
		FUNC_FAILS(CKR_GENERAL_ERROR, "GET_STATUS returned invalid response");
	}

	if (rsp[2] & 0x01) {	// Token still in reader
		FUNC_RETURNS(CKR_OK);
	}

	rc = removeToken(slot);
	if (rc != CKR_OK) {
		FUNC_RETURNS(rc);
	}

	// Check if a new token was inserted in the meantime
	rc = checkForNewCTAPIToken(slot);

	if (rc == CKR_TOKEN_NOT_PRESENT) {
		FUNC_RETURNS(CKR_DEVICE_REMOVED);
	}

	FUNC_RETURNS(rc);
}



int getCTAPIToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	int rc;
	FUNC_CALLED();

	if (slot->token) {
		rc = checkForRemovedCTAPIToken(slot);
	} else {
		rc = checkForNewCTAPIToken(slot);
	}

	*token = slot->token;
	return rc;
}



int updateCTAPISlots(struct p11SlotPool_t *pool)
{
	struct p11Slot_t *slot;
	unsigned short ctn;
	char scr[20];
	int rc;

	FUNC_CALLED();

	slot = pool->list;
	while (slot) {
		if (slot->closed) {
			ctn = slot->ctn;
			rc = CT_init(ctn, ctn);

			if (rc != OK) {
#ifdef DEBUG
				debug("CT_init returns %d\n", rc);
#endif
			} else {
				slot->closed = FALSE;
			}
		}
		slot = slot->next;
	}

	while (numberOfReaders < MAX_READERS) {
		ctn = numberOfReaders;

		rc = CT_init(ctn, ctn);

		if (rc != OK) {
#ifdef DEBUG
			debug("CT_init returns %d\n", rc);
#endif
			break;
		}

		slot = (struct p11Slot_t *) calloc(1, sizeof(struct p11Slot_t));

		if (slot == NULL) {
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}

		sprintf(scr, "CT-API Port %d", ctn);
		slot->ctn = ctn;
		strbpcpy(slot->info.slotDescription,
				scr,
				sizeof(slot->info.slotDescription));

		strbpcpy(slot->info.manufacturerID,
				"CardContact",
				sizeof(slot->info.manufacturerID));

		slot->info.hardwareVersion.minor = 0;
		slot->info.hardwareVersion.major = 0;

		slot->info.firmwareVersion.minor = VERSION_MAJOR;
		slot->info.firmwareVersion.major = VERSION_MINOR;

		slot->info.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
		addSlot(&context->slotPool, slot);
		numberOfReaders++;

		checkForNewCTAPIToken(slot);
	}

	FUNC_RETURNS(CKR_OK);
}



int closeCTAPISlot(struct p11Slot_t *slot)
{
	int rc;

	FUNC_CALLED();

	rc = CT_close(slot->ctn);

	if (rc != OK) {
#ifdef DEBUG
		debug("CT_close returns %d\n", rc);
#endif
	}

	slot->closed = TRUE;

	FUNC_RETURNS(CKR_OK);
}

#endif
