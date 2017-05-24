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

#ifndef CTAPI

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <assert.h>

#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot-pcsc.h>
#include <pkcs11/strbpcpy.h>
#include <pkcs11/crc32.h>

#ifdef DEBUG
#include <pkcs11/debug.h>
#endif

#ifdef _WIN32
#include <winscard.h>
#define  MAX_READERNAME   128
#else
#include <unistd.h>
#ifdef __APPLE__
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#else
#include <pcsclite.h>
#include <winscard.h>
#endif /* __APPLE__ */
#endif /* _WIN32 */

extern struct p11Context_t *context;

static SCARDCONTEXT globalContext = 0;
static int slotCounter = 0;

#ifdef DEBUG

char* pcsc_error_to_string(const LONG error) {
	static char strError[75];

	switch (error) {
		case SCARD_S_SUCCESS:
			(void) strncpy(strError, "Command successful.", sizeof(strError));
			break;
		case SCARD_F_INTERNAL_ERROR:
			(void) strncpy(strError, "Internal error.", sizeof(strError));
			break;
		case SCARD_E_CANCELLED:
			(void) strncpy(strError, "Command cancelled.", sizeof(strError));
			break;
		case SCARD_E_INVALID_HANDLE:
			(void) strncpy(strError, "Invalid handle.", sizeof(strError));
			break;
		case SCARD_E_INVALID_PARAMETER:
			(void) strncpy(strError, "Invalid parameter given.", sizeof(strError));
			break;
		case SCARD_E_INVALID_TARGET:
			(void) strncpy(strError, "Invalid target given.", sizeof(strError));
			break;
		case SCARD_E_NO_MEMORY:
			(void) strncpy(strError, "Not enough memory.", sizeof(strError));
			break;
		case SCARD_F_WAITED_TOO_LONG:
			(void) strncpy(strError, "Waited too long.", sizeof(strError));
			break;
		case SCARD_E_INSUFFICIENT_BUFFER:
			(void) strncpy(strError, "Insufficient buffer.", sizeof(strError));
			break;
		case SCARD_E_UNKNOWN_READER:
			(void) strncpy(strError, "Unknown reader specified.", sizeof(strError));
			break;
		case SCARD_E_TIMEOUT:
			(void) strncpy(strError, "Command timeout.", sizeof(strError));
			break;
		case SCARD_E_SHARING_VIOLATION:
			(void) strncpy(strError, "Sharing violation.", sizeof(strError));
			break;
		case SCARD_E_NO_SMARTCARD:
			(void) strncpy(strError, "No smart card inserted.", sizeof(strError));
			break;
		case SCARD_E_UNKNOWN_CARD:
			(void) strncpy(strError, "Unknown card.", sizeof(strError));
			break;
		case SCARD_E_CANT_DISPOSE:
			(void) strncpy(strError, "Cannot dispose handle.", sizeof(strError));
			break;
		case SCARD_E_PROTO_MISMATCH:
			(void) strncpy(strError, "Card protocol mismatch.", sizeof(strError));
			break;
		case SCARD_E_NOT_READY:
			(void) strncpy(strError, "Subsystem not ready.", sizeof(strError));
			break;
		case SCARD_E_INVALID_VALUE:
			(void) strncpy(strError, "Invalid value given.", sizeof(strError));
			break;
		case SCARD_E_SYSTEM_CANCELLED:
			(void) strncpy(strError, "System cancelled.", sizeof(strError));
			break;
		case SCARD_F_COMM_ERROR:
			(void) strncpy(strError, "RPC transport error.", sizeof(strError));
			break;
		case SCARD_F_UNKNOWN_ERROR:
			(void) strncpy(strError, "Unknown error.", sizeof(strError));
			break;
		case SCARD_E_INVALID_ATR:
			(void) strncpy(strError, "Invalid ATR.", sizeof(strError));
			break;
		case SCARD_E_NOT_TRANSACTED:
			(void) strncpy(strError, "Transaction failed.", sizeof(strError));
			break;
		case SCARD_E_READER_UNAVAILABLE:
			(void) strncpy(strError, "Reader is unavailable.", sizeof(strError));
			break;
		case SCARD_E_PCI_TOO_SMALL:
			(void) strncpy(strError, "PCI struct too small.", sizeof(strError));
			break;
		case SCARD_E_READER_UNSUPPORTED:
			(void) strncpy(strError, "Reader is unsupported.", sizeof(strError));
			break;
		case SCARD_E_DUPLICATE_READER:
			(void) strncpy(strError, "Reader already exists.", sizeof(strError));
			break;
		case SCARD_E_CARD_UNSUPPORTED:
			(void) strncpy(strError, "Card is unsupported.", sizeof(strError));
			break;
		case SCARD_E_NO_SERVICE:
			(void) strncpy(strError, "Service not available.", sizeof(strError));
			break;
		case SCARD_E_SERVICE_STOPPED:
			(void) strncpy(strError, "Service was stopped.", sizeof(strError));
			break;
		case SCARD_E_NO_READERS_AVAILABLE:
			(void) strncpy(strError, "Cannot find a smart card reader.", sizeof(strError));
			break;
		case SCARD_W_UNSUPPORTED_CARD:
			(void) strncpy(strError, "Card is not supported.", sizeof(strError));
			break;
		case SCARD_W_UNRESPONSIVE_CARD:
			(void) strncpy(strError, "Card is unresponsive.", sizeof(strError));
			break;
		case SCARD_W_UNPOWERED_CARD:
			(void) strncpy(strError, "Card is unpowered.", sizeof(strError));
			break;
		case SCARD_W_RESET_CARD:
			(void) strncpy(strError, "Card was reset.", sizeof(strError));
			break;
		case SCARD_W_REMOVED_CARD:
			(void) strncpy(strError, "Card was removed.", sizeof(strError));
			break;
		case SCARD_E_UNSUPPORTED_FEATURE:
			(void) strncpy(strError, "Feature not supported.", sizeof(strError));
			break;
	};

	/* add a null byte */
	strError[sizeof(strError) - 1] = '\0';

	return strError;
}



char* pcsc_feature_to_string(const WORD feature) {
	static char strFeature[75];

	switch (feature) {
		case FEATURE_VERIFY_PIN_START:
			(void) strncpy(strFeature, "VERIFY_PIN_START", sizeof(strFeature));
			break;
		case FEATURE_VERIFY_PIN_FINIS:
			(void) strncpy(strFeature, "VERIFY_PIN_FINISH", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_START:
			(void) strncpy(strFeature, "MODIFY_PIN_START", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_FINISH:
			(void) strncpy(strFeature, "MODIFY_PIN_FINISH", sizeof(strFeature));
			break;
		case FEATURE_GET_KEY_PRESSED:
			(void) strncpy(strFeature, "GET_KEY_PRESSED", sizeof(strFeature));
			break;
		case FEATURE_VERIFY_PIN_DIRECT:
			(void) strncpy(strFeature, "VERIFY_PIN_DIRECT", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_DIRECT:
			(void) strncpy(strFeature, "MODIFY_PIN_DIRECT", sizeof(strFeature));
			break;
		case FEATURE_MCT_READER_DIRECT:
			(void) strncpy(strFeature, "MCT_READER_DIRECT", sizeof(strFeature));
			break;
		case FEATURE_MCT_UNIVERSAL:
			(void) strncpy(strFeature, "MCT_UNIVERSAL", sizeof(strFeature));
			break;
		case FEATURE_IFD_PIN_PROPERTIES:
			(void) strncpy(strFeature, "IFD_PIN_PROPERTIES", sizeof(strFeature));
			break;
		case FEATURE_ABORT:
			(void) strncpy(strFeature, "ABORT", sizeof(strFeature));
			break;
		case FEATURE_SET_SPE_MESSAGE:
			(void) strncpy(strFeature, "SET_SPE_MESSAGE", sizeof(strFeature));
			break;
		case FEATURE_VERIFY_PIN_DIRECT_APP_ID:
			(void) strncpy(strFeature, "VERIFY_PIN_DIRECT_APP_ID", sizeof(strFeature));
			break;
		case FEATURE_MODIFY_PIN_DIRECT_APP_ID:
			(void) strncpy(strFeature, "MODIFY_PIN_DIRECT_APP_ID", sizeof(strFeature));
			break;
		case FEATURE_WRITE_DISPLAY:
			(void) strncpy(strFeature, "WRITE_DISPLAY", sizeof(strFeature));
			break;
		case FEATURE_GET_KEY:
			(void) strncpy(strFeature, "GET_KEY", sizeof(strFeature));
			break;
		case FEATURE_IFD_DISPLAY_PROPERTIES:
			(void) strncpy(strFeature, "IFD_DISPLAY_PROPERTIES", sizeof(strFeature));
			break;
		case FEATURE_GET_TLV_PROPERTIES:
			(void) strncpy(strFeature, "GET_TLV_PROPERTIES", sizeof(strFeature));
			break;
		case FEATURE_CCID_ESC_COMMAND:
			(void) strncpy(strFeature, "CCID_ESC_COMMAND", sizeof(strFeature));
			break;
		default:
			(void) strncpy(strFeature, "Unknown feature.", sizeof(strFeature));
			break;
	};

	/* add a null byte */
	strFeature[sizeof(strFeature) - 1] = '\0';

	return strFeature;
}
#endif /* DEBUG */



/**
 * Transmit APDU using PC/SC
 *
 * @param slot the slot to use for communication
 * @param capdu the command APDU
 * @param capdu_len the length of the command APDU
 * @param rapdu the response APDU
 * @param rapdu_len the length of the response APDU
 * @return -1 for error or length of received response APDU
 */
int transmitAPDUviaPCSC(struct p11Slot_t *slot,
	unsigned char *capdu, size_t capdu_len,
	unsigned char *rapdu, size_t rapdu_len)
{
	LONG rc;
	DWORD lenr;

	FUNC_CALLED();

	if (!slot->card) {
		FUNC_FAILS(-1, "No card handle");
	}

	lenr = rapdu_len;

	rc = SCardTransmit(slot->card, SCARD_PCI_T1, capdu, capdu_len, NULL, rapdu, &lenr);

#ifdef DEBUG
	debug("SCardTransmit: %s\n", pcsc_error_to_string(rc));
#endif

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(-1, "SCardTransmit failed");
	}

	FUNC_RETURNS(lenr);
}



int transmitVerifyPinAPDUviaPCSC(struct p11Slot_t *slot,
	unsigned char pinformat, unsigned char minpinsize, unsigned char maxpinsize,
	unsigned char pinblockstring, unsigned char pinlengthformat,
	unsigned char *capdu, size_t capdu_len,
	unsigned char *rapdu, size_t rapdu_len)
{
	LONG rc;
	DWORD lenr;
	PIN_VERIFY_DIRECT_STRUCTURE_t verify;

	FUNC_CALLED();

	if (!slot->card) {
		FUNC_FAILS(-1, "No card handle");
	}

	verify.bTimeOut = 0x00;
	verify.bTimeOut2 = 0x00;
	verify.bmFormatString = pinformat;
	verify.bmPINBlockString = pinblockstring;
	verify.bmPINLengthFormat = pinlengthformat;

	verify.wPINMaxExtraDigit = (minpinsize << 8) | maxpinsize;

	/*
	 * Bit 7-3: RFU
	 * Bit   2: Timout occurred
	 * Bit   1: Validation Key pressed
	 * Bit   0: Max size reached
	 */
	verify.bEntryValidationCondition = 0x02;

	verify.bNumberMessage = 0x01;
	verify.wLangID        = 0x0904;
	verify.bMsgIndex      = 0;

	verify.bTeoPrologue[0]= 0;
	verify.bTeoPrologue[1]= 0;
	verify.bTeoPrologue[2]= 0;

	verify.ulDataLength = capdu_len;
	memcpy(verify.abData, capdu, capdu_len);

	lenr = rapdu_len;

	rc = SCardControl(slot->card, slot->hasFeatureVerifyPINDirect, &verify,  18 + capdu_len + 1, rapdu, rapdu_len, &lenr);

#ifdef DEBUG
	debug("SCardControl (VERIFY_PIN_DIRECT): %s\n", pcsc_error_to_string(rc));
#endif

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(-1, "SCardControl failed");
	}

	FUNC_RETURNS(lenr);
}



/**
 * checkForNewPCSCToken looks into a specific slot for a token.
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
static int checkForNewPCSCToken(struct p11Slot_t *slot)
{
	struct p11Token_t *ptoken;
	int rc, i;
	LONG rv;
	DWORD dwActiveProtocol;
	WORD feature;
	DWORD featurecode, lenr, atrlen,readernamelen,state,protocol;
	unsigned char buf[256];
	unsigned char atr[36];
	char *po;

	FUNC_CALLED();

	if (slot->closed) {
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	}

	rv = SCardConnect(slot->context, slot->readername, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &(slot->card), &dwActiveProtocol);

#ifdef DEBUG
	debug("SCardConnect (%i, %s): %s\n", slot->id, slot->readername, pcsc_error_to_string(rv));
#endif

	if (rv == SCARD_E_NO_SMARTCARD || rv == SCARD_W_REMOVED_CARD || rv == SCARD_E_SHARING_VIOLATION) {
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	}

	if (rv != SCARD_S_SUCCESS) {
		closeSlot(slot);
		FUNC_FAILS(CKR_DEVICE_ERROR, pcsc_error_to_string(rv));
	}

	if (!slot->hasFeatureVerifyPINDirect) {
		rv = SCardControl(slot->card, SCARD_CTL_CODE(3400), NULL,0, buf, sizeof(buf), &lenr);

#ifdef DEBUG
		debug("SCardControl (CM_IOCTL_GET_FEATURE_REQUEST): %s\n", pcsc_error_to_string(rv));
#endif

		/* Ignore the feature codes if an error occured */
		if (rv == SCARD_S_SUCCESS) {
			for (i = 0; i < lenr; i += 6) {
				feature = buf[i];
				featurecode = (buf[i + 2] << 24) + (buf[i + 3] << 16) + (buf[i + 4] << 8) + buf[i + 5];
	#ifdef DEBUG
				debug("%s - 0x%08X\n", pcsc_feature_to_string(feature), featurecode);
	#endif
				if (feature == FEATURE_VERIFY_PIN_DIRECT) {
					po = getenv("PKCS11_IGNORE_PINPAD");
	#ifdef DEBUG
					if (po) {
						debug("PKCS11_IGNORE_PINPAD=%s\n", po);
					} else {
						debug("PKCS11_IGNORE_PINPAD not found\n");
					}
	#endif
					if (!po || (*po == '0')) {
	#ifdef DEBUG
						debug("Slot supports feature VERIFY_PIN_DIRECT - setting CKF_PROTECTED_AUTHENTICATION_PATH for token\n");
	#endif
						slot->hasFeatureVerifyPINDirect = featurecode;
					}
				}
			}
		}
	}

	readernamelen = 0;
	atrlen = sizeof(atr);

	rc = SCardStatus(slot->card, NULL, &readernamelen, &state, &protocol, atr, &atrlen);

	if (rc != SCARD_S_SUCCESS) {
		closeSlot(slot);
		FUNC_FAILS(CKR_DEVICE_ERROR, pcsc_error_to_string(rc));
	}

	rc = newToken(slot, atr, atrlen, &ptoken);

	if (rc != CKR_OK) {
		FUNC_FAILS(rc, "newToken() failed");
	}

	FUNC_RETURNS(rc);
}



/**
 * checkForRemovedPCSCToken looks into a specific slot for a removed token.
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
static int checkForRemovedPCSCToken(struct p11Slot_t *slot)
{
	int rc;
	LONG rv;

	FUNC_CALLED();

	if (slot->closed) {
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	}

	if (!slot->card) {
		FUNC_RETURNS(CKR_TOKEN_NOT_PRESENT);
	}

	rv = SCardStatus(slot->card, NULL, 0, 0, 0, 0, 0);

#ifdef DEBUG
	debug("SCardStatus: %s\n", pcsc_error_to_string(rv));
#endif

	if (rv == SCARD_S_SUCCESS) {
		FUNC_RETURNS(CKR_OK);
	} else if ((rv == SCARD_W_REMOVED_CARD) || (rv == SCARD_E_INVALID_HANDLE) || (rv == SCARD_E_READER_UNAVAILABLE)) {
		rc = removeToken(slot);
		if (rc != CKR_OK) {
			FUNC_RETURNS(rc);
		}

		rc = SCardDisconnect(slot->card, SCARD_UNPOWER_CARD);

#ifdef DEBUG
		debug("SCardDisconnect (%i, %s): %s\n", slot->id, slot->readername, pcsc_error_to_string(rc));
#endif

		// Check if a new token was inserted in the meantime
		rc = checkForNewPCSCToken(slot);

		if (rc == CKR_TOKEN_NOT_PRESENT) {
			FUNC_RETURNS(CKR_DEVICE_REMOVED);
		}
	} else {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error getting PC/SC card terminal status");
	}

	FUNC_RETURNS(rc);
}



int getPCSCToken(struct p11Slot_t *slot, struct p11Token_t **token)
{
	int rc;

	FUNC_CALLED();

	if (slot->token) {
		rc = checkForRemovedPCSCToken(slot);
	} else {
		rc = checkForNewPCSCToken(slot);
	}

	*token = slot->token;
	FUNC_RETURNS(rc);
}



int lockPCSCSlot(struct p11Slot_t *slot)
{
	DWORD dwActiveProtocol;
	LONG rv;

	FUNC_CALLED();

	rv = SCardReconnect(slot->card, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD, &dwActiveProtocol);

#ifdef DEBUG
	debug("SCardReconnect (%i, %s): %s\n", slot->id, slot->readername, pcsc_error_to_string(rv));
#endif

	if (rv != SCARD_S_SUCCESS)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not reconnect to card");

	FUNC_RETURNS(CKR_OK);
}



int unlockPCSCSlot(struct p11Slot_t *slot)
{
	DWORD dwActiveProtocol;
	LONG rv;

	FUNC_CALLED();

	rv = SCardReconnect(slot->card, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, SCARD_LEAVE_CARD, &dwActiveProtocol);

#ifdef DEBUG
	debug("SCardReconnect (%i, %s): %s\n", slot->id, slot->readername, pcsc_error_to_string(rv));
#endif

	if (rv != SCARD_S_SUCCESS)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not reconnect to card");

	FUNC_RETURNS(CKR_OK);
}



/**
 * Match an references against a filter expression
 *
 * The following assertions are valid:
 *
 * assert(matchFilter("ABC", "ABC") == 1);
 * assert(matchFilter("ABC", "ABCD") == 0);
 * assert(matchFilter("ABC", "*") == 1);
 * assert(matchFilter("ABC", "A*") == 1);
 * assert(matchFilter("ABC", "B*") == 0);
 * assert(matchFilter("ABC", "???") == 1);
 * assert(matchFilter("ABC", "????") == 0);
 * assert(matchFilter("ABC", "??") == 0);
 * assert(matchFilter("ABC", "?BC") == 1);
 * assert(matchFilter("ABC", "*C") == 1);
 * assert(matchFilter("ABC", "*B*") == 1);
 * assert(matchFilter("ABC", "*C*") == 0);
 */
int matchFilter(char *value, char *filter)
{
	if (!filter)
		return 1;

	while(*value) {
		if ((*value != *filter) && (*filter != '*') && (*filter != '?'))
			return 0;

		if (*filter == '*') {
			filter++;
			value++;

			if (!*filter)		// * is last element
				return 1;

			while(*value && (*value != *filter))
				value++;

			continue;
		}

		value++;
		filter++;
	}

	return *filter ? 0 : 1;
}



int updatePCSCSlots(struct p11SlotPool_t *pool)
{
	struct p11Slot_t *slot,*vslot;
	LPTSTR readers = NULL;
	char *filter, *prealloc;
	DWORD cch = 0;
//	DWORD cch = SCARD_AUTOALLOCATE;
	LPTSTR p;
	LONG rc;
	int match,vslotcnt,i;

	FUNC_CALLED();

	/*
	 * Create a context if not already done
	 */
	if (!globalContext) {

		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &globalContext);

#ifdef DEBUG
		debug("SCardEstablishContext: %s\n", pcsc_error_to_string(rc));
#endif

		if (rc != SCARD_S_SUCCESS) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Could not establish context to PC/SC manager");
		}
	}

	rc = SCardListReaders(globalContext, NULL, NULL, &cch);

#ifdef DEBUG
	debug("SCardListReaders: %s\n", pcsc_error_to_string(rc));
#endif

	if (rc == SCARD_E_NO_READERS_AVAILABLE) {
		FUNC_RETURNS(CKR_OK);
	}

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error listing PC/SC card terminals");
	}

	readers = calloc(cch, 1);

	rc = SCardListReaders(globalContext, NULL, readers, &cch);

#ifdef DEBUG
	debug("SCardListReaders: %s\n", pcsc_error_to_string(rc));
#endif

	if (rc == SCARD_E_NO_READERS_AVAILABLE) {
		FUNC_RETURNS(CKR_OK);
	}

	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Error listing PC/SC card terminals");
	}
	
	filter = getenv("PKCS11_READER_FILTER");
#ifdef DEBUG
	if (filter) {
		debug("Reader filter '%s'\n", filter);
	}
#endif

	/* Determine the total number of readers */
	p = readers;
	while (*p != '\0') {
#ifdef DEBUG
		debug("Found reader '%s'\n", p);
#endif

		/* Check if we already have a slot for the reader */
		slot = pool->list;
		match = FALSE;
		while (slot) {
			if (strncmp(slot->readername, p, strlen(p)) == 0) {
				match = TRUE;
				break;
			}
			slot = slot->next;
		}

		/* Skip the reader as we already have a slot for it */
		if (match) {
			p += strlen(p) + 1;
			slot->closed = FALSE;
			continue;
		}

		if (!matchFilter(p, filter)) {
			p += strlen(p) + 1;
			continue;
		}

		slot = (struct p11Slot_t *) calloc(1, sizeof(struct p11Slot_t));

		if (slot == NULL) {
			free(readers);
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}

		/* If a reader filter is defined, then slot ids for that reader are
		 * derived from the reader name using a CRC32 value. If the token
		 * in the reader allocated virtual slots, then these have incremented
		 * slot ids.
		 *
		 * This is not enabled by default to prevent slot id collisions
		 */
		if (filter)
			slot->id = crc32(0, p, strlen(p));

		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &(slot->context));

#ifdef DEBUG
		debug("SCardEstablishContext: %s\n", pcsc_error_to_string(rc));
#endif

		if (rc != SCARD_S_SUCCESS) {
			free(slot);
			free(readers);
			FUNC_FAILS(CKR_DEVICE_ERROR, "Could not establish context to PC/SC manager");
		}

		slotCounter++;

		strbpcpy(slot->info.slotDescription,
				(char *)p,
				sizeof(slot->info.slotDescription));

		strcpy(slot->readername, (char *)p);

		strbpcpy(slot->info.manufacturerID,
				"CardContact",
				sizeof(slot->info.manufacturerID));

		slot->info.hardwareVersion.minor = 0;
		slot->info.hardwareVersion.major = 0;

		slot->info.firmwareVersion.major = VERSION_MAJOR;
		slot->info.firmwareVersion.minor = VERSION_MINOR;

		slot->info.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;

		slot->maxRAPDU = MAX_RAPDU;
		slot->maxCAPDU = MAX_CAPDU;

		// The REINER SCT readers have an APDU buffer limitation of 1014 bytes
		if (!strncmp((char *)p, "REINER SCT", 10)) {
#ifdef DEBUG
			debug("Detected a REINER SCT reader\n");
#endif
			if (!strncmp((char *)p, "REINER SCT cyberJack ecom_a", 27)) {
#ifdef DEBUG
				debug("Detected a 'REINER SCT cyberJack ecom_a' reader. Limiting use of Le='000000'\n");
#endif
				// Some REINER SCT readers fail if Le='000000' returns more than
				// 1014 bytes.
				slot->noExtLengthReadAll = 1;
			}
			slot->maxRAPDU = 1000;
			slot->maxCAPDU = 1000;
		}

		addSlot(&context->slotPool, slot);

#ifdef DEBUG
		debug("Added slot (%lu, %s) - slot counter is %i\n", slot->id, slot->readername, slotCounter);
#endif

		// The PREALLOCATE option creates two additional virtual slots per card reader.
		// This is required for Firefox/NSS which sets the friendly flag only for slots that are
		// already present during the first C_GetSlotList
		prealloc = getenv("PKCS11_PREALLOCATE_VIRTUAL_SLOTS");
		if (prealloc) {
			vslotcnt = *prealloc;
			if ((vslotcnt == '1') || (vslotcnt == '2')) {
				vslotcnt -= '0';
			} else {
				vslotcnt = 2;
			}
#ifdef DEBUG
			debug("Pre-allocate virtual slots '' %d\n", prealloc, vslotcnt);
#endif
			for (i = 0; i < vslotcnt; i++) {
				getVirtualSlot(slot, i, &vslot);
			}
		}

		checkForNewPCSCToken(slot);

		p += strlen(p) + 1;
	}

	free(readers);

	FUNC_RETURNS(CKR_OK);
}



int closePCSCSlot(struct p11Slot_t *slot)
{
	LONG rc;

	FUNC_CALLED();

#ifdef DEBUG
	debug("Trying to close slot (%i, %s)\n", slot->id, slot->readername);
#endif

	slotCounter--;

	if (slotCounter == 0 && globalContext) {
#ifdef DEBUG
		debug("Releasing global PC/SC context\n");
#endif
		rc = SCardReleaseContext(globalContext);

#ifdef DEBUG
		debug("SCardReleaseContext (%i, %s): %s\n", slot->id, slot->readername, pcsc_error_to_string(rc));
#endif

		globalContext = 0;
	}

	/* No token in slot */
	if (!slot->card) {
		slot->closed = TRUE;
		FUNC_RETURNS(CKR_OK);
	}

	rc = SCardDisconnect(slot->card, SCARD_UNPOWER_CARD);

#ifdef DEBUG
	debug("SCardDisconnect (%i, %s): %s\n", slot->id, slot->readername, pcsc_error_to_string(rc));
	debug("Releasing slot specific PC/SC context - slot counter is %i\n", slotCounter);
#endif

	rc = SCardReleaseContext(slot->context);

#ifdef DEBUG
	debug("SCardReleaseContext (%i, %s): %s\n", slot->id, slot->readername, pcsc_error_to_string(rc));
#endif

	slot->context = 0;
	slot->card = 0;
	slot->closed = TRUE;

	FUNC_RETURNS(CKR_OK);
}

#endif /* CTAPI */
