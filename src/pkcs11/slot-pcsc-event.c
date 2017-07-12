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
 * @file    slot-pcsc-event.c
 * @author  Andreas Schwier
 * @brief   Slot event handling for PC/SC reader
 */

#ifndef CTAPI

#include <pkcs11/slot-pcsc.h>
#include <pkcs11/crc32.h>

#ifdef DEBUG
#include <common/debug.h>
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
static int matchFilter(char *value, char *filter)
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



/**
 * Check for new readers and add to slot pool.
 *
 * Slots are never removed as per PKCS#11 standard.
 *
 * @param pool the pool of already allocated slots
 */
int updatePCSCSlots(struct p11SlotPool_t *pool)
{
	struct p11Slot_t *slot,*vslot;
	LPTSTR readers = NULL;
	char *filter, *prealloc;
	DWORD cch = 0;
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
			if (slot->closed)
				slot->eventOccured = TRUE;
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

		slot->eventOccured = TRUE;

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

		if (context->caller != CALLER_FIREFOX) {
			slot->supportsVirtualSlots = 1;
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

			slot->supportsVirtualSlots = 1;
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



/**
 * Wait for a status change in the PC/SC subsystems, e.g. a card insertion or removal or attach or detach of a card reader
 *
 * @param pool the pool of already allocated slots
 * @param timeout the timeout in milliseconds or 0 for infinite wait
 */
int waitForPCSCEvent(struct p11SlotPool_t *pool, int timeout)
{
	LONG rc;
	SCARD_READERSTATE *rs;
	struct p11Slot_t *slot;
	DWORD readers, i, to;

	FUNC_CALLED();

	if (!globalContext) {

		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &globalContext);

#ifdef DEBUG
		debug("SCardEstablishContext: %s\n", pcsc_error_to_string(rc));
#endif

		if (rc != SCARD_S_SUCCESS) {
			FUNC_FAILS(CKR_DEVICE_ERROR, "Could not establish context to PC/SC manager");
		}
	}

	slot = pool->list;
	readers = 0;
	while (slot) {
		if ((slot->primarySlot == NULL) && !slot->closed)
			readers++;
		slot = slot->next;
	}

#ifndef __APPLE__
	readers++;
#endif

	rs = (SCARD_READERSTATE *)calloc(sizeof(SCARD_READERSTATE), readers);

	slot = pool->list;
	i = 0;
	while (slot) {
		if ((slot->primarySlot == NULL) && !slot->closed) {
			rs[i].szReader = slot->readername;
			rs[i].pvUserData = slot;
			i++;
		}
		slot = slot->next;
	}

#ifndef __APPLE__
	rs[i].szReader = "\\\\?PnP?\\Notification";
	i++;
#endif

	rc = SCardGetStatusChange(globalContext, 0, rs, readers);
	if (rc != SCARD_S_SUCCESS) {
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not query status change");
	}

	for (i = 0; i < readers; i++) {
		rs[i].dwCurrentState = rs[i].dwEventState;
	}

	to = (timeout <= 0 ? INFINITE : timeout);

	rc = SCardGetStatusChange(globalContext, to, rs, readers);

	if (rc == SCARD_E_CANCELLED)
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "Wait for slot event cancelled");

	if (rc == SCARD_E_TIMEOUT)
		FUNC_FAILS(CKR_NO_EVENT, "Timeout before event was detected");

	if (rc != SCARD_S_SUCCESS)
		FUNC_FAILS(CKR_DEVICE_ERROR, "Could not query status change");

	for (i = 0; i < readers; i++) {
		printf("Event for %08lx %08lx %s\n", rs[i].dwCurrentState, rs[i].dwEventState, rs[i].szReader);
		if (rs[i].dwEventState & SCARD_STATE_CHANGED) {
			if (rs[i].pvUserData) {
				slot = (struct p11Slot_t *)rs[i].pvUserData;
				slot->eventOccured = TRUE;
			} else {		// PnP notification
				updatePCSCSlots(pool);
			}
		}
	}

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
		SCardCancel(globalContext);

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
