/**
 * SmartCard-HSM Ultra-Light Library
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
 * @file utils.c
 * @author Christoph Brunhuber
 * @brief Simple abstraction layer for USB devices using libusb or WinSCard
 */

#include <stdio.h>
#include <string.h>

#include "utils.h"
#include "sc-hsm-ultralite.h"

/*******************************************************************************
 *******************************************************************************
 *******************************************************************************
 *********************** SmartCard Helper Functions ****************************
 *******************************************************************************
 *******************************************************************************
 ******************************************************************************/

#ifdef CTAPI /* via libusb */
#include <ctccid/ctapi.h>

static uint16 Ctn;

/* used only for SC_Open */
static int SC_Init()
{
	uint8 dad = 1;   /* Reader */
	uint8 sad = 2;   /* Host   */
	uint8 buf[260];
	uint16 len = sizeof(buf);
	/* - REQUEST ICC */
	int rc = CT_data(Ctn, &dad, &sad, 5, (uint8*)"\x20\x12\x00\x01\x00", &len, buf);
	if (rc < 0 || buf[0] == 0x64 || buf[0] == 0x62)
		return ERR_CARD;
	return buf[len - 1] == 0x00 ? 1 : 2;  /* Memory or processor card ? */
}

#define MAXPORT 2

int SC_Open(const char *pin)
{
	int rc;
	uint16 i;
	/* find 1st available card */
	for (i = 0; i < MAXPORT; i++) {
		if (CT_init(i, i) < 0)
			continue;
		Ctn = i;
		if (SC_Init() < 0) {
			CT_close(i);
			continue;
		}
		break;
	}
	if (Ctn == MAXPORT) {
		printf("no card found\n");
		return ERR_CARD;
	}
	rc = SC_Logon(pin);
	if (rc < 0) {
		printf("Logon error\n");
		CT_close(Ctn);
		return ERR_PIN;
	}
	return 0;
}

int SC_Close()
{
	return CT_close(Ctn);
}

#else /* via PCSC */
#ifndef _WIN32
#include <pcsclite.h>
#endif
#include <winscard.h>

static SCARDCONTEXT hContext;
static SCARDHANDLE hCard;

int SC_Open(const char *pin)
{
	int rc, len, found;
	LPSTR readerNames, readerName;
	DWORD readersLen = SCARD_AUTOALLOCATE;
	if (hContext == 0) {
		rc = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
		if (rc != SCARD_S_SUCCESS)
			return ERR_CARD;
	}
	rc = SCardListReaders(hContext, 0, (LPTSTR)&readerNames, &readersLen);
	if (rc != SCARD_S_SUCCESS) {
		rc = SCardReleaseContext(hContext);
		hContext = 0;
		return ERR_CARD;
	}
	found = 0;
	for (readerName = readerNames; readerName[0] != 0; readerName += len) {
		DWORD proto;
		len = strlen(readerName) + 1;
		rc = SCardConnect(hContext, readerName, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T1, &hCard, &proto);
		if (rc == SCARD_S_SUCCESS) {
			found = 1;
			break;
		}
	}
	SCardFreeMemory(hContext, readerNames);
	if (!found) {
		rc = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		rc = SCardReleaseContext(hContext);
		hContext = 0;
		return ERR_CARD;
	}
	rc = SC_Logon(pin);
	if (rc < 0) {
		printf("Logon error\n");
		rc = SCardDisconnect(hCard, SCARD_LEAVE_CARD);
		rc = SCardReleaseContext(hContext);
		return ERR_PIN;
	}
	return 0;
}

int SC_Close()
{
	return SCardDisconnect(hCard, SCARD_LEAVE_CARD);
}

#endif /* !CTAPI */

int SC_Logon(const char *pin)
{
	uint16 sw1sw2;
	uint8 buf[256];
	int rc, pinLen;
	/* - SmartCard-HSM: SELECT APPLET */
	rc = SC_ProcessAPDU(
		0, 0x00,0xA4,0x04,0x04,
		(uint8*)"\xE8\x2B\x06\x01\x04\x01\x81\xc3\x1f\x02\x01", 11,
		buf, sizeof(buf),
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000)
		return ERR_APDU;

	if (pin == 0)
		return rc;

	pinLen = strlen(pin);
	/* - SmartCard-HSM: VERIFY PIN */
	rc = SC_ProcessAPDU(
		0, 0x00,0x20,0x00,0x81,
		(uint8*)pin, pinLen,
		0, 0,
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000)
		return ERR_APDU;
	return rc;
}

int SC_ReadFile(uint16 fid, int off, uint8 *data, int dataLen)
{
	uint16 sw1sw2;
	int rc;
	uint8 offset[4];
	offset[0] = 0x54;
	offset[1] = 0x02;
	offset[2] = off >> 8;
	offset[3] = off >> 0;
	/* - SmartCard-HSM: READ BINARY */
	rc = SC_ProcessAPDU(
		0, 0x00,
		0xB1,      /* READ BINARY */
		fid >> 8,  /* MSB(fid) */
		fid >> 0,  /* LSB(fid) */
		offset, 4,
		data, dataLen,
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000 && sw1sw2 != 0x6282)
		return ERR_APDU;
	return rc;
}

int SC_Sign(uint8 op, uint8 keyFid,
	uint8 *outBuf, int outLen,
	uint8 *inBuf, int inSize)
{
	uint16 sw1sw2;
	int rc;
	/* - SmartCard-HSM: SIGN */
	rc = SC_ProcessAPDU(
		0, 0x80,
		0x68, /* SIGN */
		keyFid,
		op, /* Plain RSA(0x20) or ECDSA(0x70) signature */
		outBuf, outLen,
		inBuf, inSize,
		&sw1sw2);
	if (rc < 0)
		return rc;
	if (sw1sw2 != 0x9000 && sw1sw2 != 0x6282)
		return ERR_APDU;
	return rc;
}

/*
 *  Process an ISO 7816 APDU with the underlying terminal hardware.
 *
 *  cla     : Class byte of instruction
 *  ins     : Instruction byte
 *  p1      : Parameter P1
 *  p2      : Parameter P2
 *  outData : Outgoing data or NULL if none
 *  outLen  : Length of outgoing data (Lc)
 *  inData  : Input buffer for incoming data
 *  inLen   : Length of incoming data (Le)
 *  sw1sw2  : Address of short integer to receive sw1sw2
 *
 *  Returns : < 0 Error >= 0 Bytes read
 */
int SC_ProcessAPDU(
	int todad,
	uint8 cla, uint8 ins, uint8 p1, uint8 p2,
	uint8 *outData, int outLen,
	uint8 *inData, int inLen,
	uint16 *sw1sw2)
{
	uint8 scr[4 + 3 + 3 + MAX_OUT_IN];
	int rc;
#ifdef CTAPI
	uint16 len;
#else
	DWORD len;
#endif
	uint8 dad, sad;
	uint8 *p;

	/* Reset status word */
	*sw1sw2 = 0x0000;

	if (!scr
		|| 4 + 3 + 3 + outLen > sizeof(scr)    /* worst case: long APDU and in and out */
		|| inLen + 2 > sizeof(scr)             /* need space for sw1sw2 */
		|| !(0 <= inLen  && inLen  <= 0x10000) /* crazy - invalid in length */
		|| !(0 <= outLen && outLen <= 0x10000) /* crazy - invalid out length */
		|| outLen > 0 && !outData              /* no out buffer */
		|| inLen  > 0 && !inData               /* no in buffer */
	)
		return ERR_MEMORY;

	p = scr;
	*p++ = cla;
	*p++ = ins;
	*p++ = p1;
	*p++ = p2;
	if (outLen <= 255 && inLen <= 256) { /* use short APDU */
		if (outLen > 0) {                /* Lc present */
			*p++ = (uint8)outLen;
			memcpy(p, outData, outLen);
			p += outLen;
		}
		if (inLen > 0)                   /* Le present */
			*p++ = (uint8)inLen;         /* (uint8)256 == 0 */
	} else {                             /* use long APDU */
		*p++ = 0;                        /* indicate long APDU */
		if (outLen > 0) {                /* Lc present */
			*p++ = (uint8)(outLen >> 8);
			*p++ = (uint8)(outLen     );
			memcpy(p, outData, outLen);
			p += outLen;
		}
		if (inLen > 0) {                 /* Le present */
			*p++ = (uint8)(inLen >> 8);
			*p++ = (uint8)(inLen     );
		}
	}
	sad = HOST;
	dad = todad;
	len = sizeof(scr);
#ifdef CTAPI
	rc = CT_data(Ctn, &dad, &sad, p - scr, scr, &len, scr);
#else
	rc = SCardTransmit(hCard, SCARD_PCI_T1, scr, p - scr, 0, scr, &len);
#endif
	if (rc < 0)
		return rc;
	if (len < 2) /* sw1sw2 missing? */
		return ERR_INVALID;
	if (len - 2 > inLen) /* never truncate */
		return ERR_INVALID;
	if (scr[len - 2] == 0x6C) /* not enough buffer supplied */
		return ERR_MEMORY;
	rc = len - 2;
	if (inLen > 0)
		memcpy(inData, scr, rc);
	*sw1sw2 = scr[len - 2] << 8 | scr[len - 1];
	return rc;
}
