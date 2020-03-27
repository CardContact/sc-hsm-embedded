/**
 * Mini card service for key generator
 *
 * Copyright (c) 2020, CardContact Systems GmbH, Minden, Germany
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
 * @file sc-hsm-cardservice.c
 * @author Andreas Schwier
 * @brief Minimal card service for key generator
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <ctccid/ctapi.h>

static unsigned char aid[] = { 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01 };
static unsigned char inittemplate[] = {
		0x80,0x02,0x00,0x02,									// Option Transport PIN
		0x81,0x06,0x36,0x35,0x34,0x33,0x32,0x31,				// T-PIN, Offset 6
		0x82,0x08,0x35,0x37,0x36,0x32,0x31,0x38,0x38,0x30,		// SO-PIN, Offset 14
		0x91,0x01,0x03,											// Retry counter 3
		0x97,0x01,0x01 };										// One Key Domain



#ifdef DEBUG
/**
 * Dump the memory pointed to by <mem>
 *
 * @param mem the memory area to dump
 * @param len the length of the memory area
 */
static void dump(unsigned char *mem, int len)
{
	while(len--) {
		printf("%02x ", *mem);
		mem++;
	}

	printf("\n");
}
#endif



/**
 * Process an ISO 7816 APDU with the underlying CT-API terminal hardware.
 *
 * @param ctn the card terminal number
 * @param todad the destination address in the CT-API protocol
 * @param CLA  Class byte of instruction
 * @param INS Instruction byte
 * @param P1 Parameter P1
 * @param P2 Parameter P2
 * @param OutLen Length of outgoing data (Lc)
 * @param OutData Outgoing data or NULL if none
 * @param InLen Length of incoming data (Le)
 * @param InData Input buffer for incoming data
 * @param InSize buffer size
 * @param SW1SW2 Address of short integer to receive SW1SW2
 * @return the number of bytes received, excluding SW1SW2 or < 0 in case of an error
 */
static int processAPDU(int ctn, int todad,
		unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
		int OutLen, unsigned char *OutData,
		int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2)
{
	int rv, rc, r;
	unsigned short lenr;
	unsigned char dad, sad;
	unsigned char scr[MAX_APDULEN], *po;

	/* Reset status word */
	*SW1SW2 = 0x0000;

	scr[0] = CLA;
	scr[1] = INS;
	scr[2] = P1;
	scr[3] = P2;
	po = scr + 4;
	rv = 0;

	if (OutData && OutLen) {
		if ((OutLen <= 255) && (InLen <= 255)) {
			*po++ = (unsigned char)OutLen;
		} else {
			*po++ = 0;
			*po++ = (unsigned char)(OutLen >> 8);
			*po++ = (unsigned char)(OutLen & 0xFF);
		}

		memcpy(po, OutData, OutLen);
		po += OutLen;
	}

	if (InData && InSize) {
		if ((InLen <= 255) && (OutLen <= 255)) {
			*po++ = (unsigned char)InLen;
		} else {
			if (InLen >= 65556) {
				InLen = 0;
			}

			if (!OutData) {
				*po++ = 0;
			}

			*po++ = (unsigned char)(InLen >> 8);
			*po++ = (unsigned char)(InLen & 0xFF);
		}
	}

#ifdef DEBUG
	printf("C: ");
	dump(scr, po - scr);
#endif

	sad = HOST;
	dad = todad;
	lenr = sizeof(scr);

	rc = CT_data(ctn, &dad, &sad, po - scr, scr, &lenr, scr);

	if (rc < 0) {
		memset(scr, 0, sizeof(scr));
		return rc;
	}

#ifdef DEBUG
		printf("R: ");
		dump(scr, lenr);
#endif

	rv = lenr - 2;

	if (rv > InSize) {
		rv = InSize;
	}

	if (InData) {
		memcpy(InData, scr, rv);
	}

	*SW1SW2 = (scr[lenr - 2] << 8) + scr[lenr - 1];

	memset(scr, 0, sizeof(scr));
	return(rv);
}



/**
 * Select the SmartCard-HSM application on the device
 *
 * @param ctn the card terminal number
 * @return < 0 in case of an error
 */
int selectHSM(int ctn)
{
	unsigned char rdata[256];
	unsigned short SW1SW2;
	int rc;

	rc = processAPDU(ctn, 0, 0x00, 0xA4, 0x04, 0x04,
					 sizeof(aid), aid,
					 0, rdata, sizeof(rdata), &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	if (SW1SW2 != 0x9000) {
		return -1;
	}

	return 0;
}



/**
 * Initialize SmartCard-HSM with Transport PIN and one key domain
 *
 * @param ctn the card terminal number
 * @param sopin the Security Officer PIN (SO-PIN)
 * @param sopinlen the length of the SO-PIN (must be 8)
 * @param pin the transport PIN to be set
 * @param pinlen the length of the transport PIN (must be 6)
 * @return < 0 in case of an error
 */
int initializeDevice(int ctn, unsigned char *sopin, int sopinlen, unsigned char *pin, int pinlen)
{
	unsigned short SW1SW2;
	unsigned char cdata[32];
	int rc, len;

	if ((sopin == NULL) || (sopinlen != 8) || (pin == NULL) || (pinlen != 6)) {
		return -1;
	}

	len = sizeof(inittemplate);
	memcpy(cdata, inittemplate, len);
	memcpy(cdata + 6, pin, pinlen);
	memcpy(cdata + 14, sopin, sopinlen);

	rc = processAPDU(ctn, 0, 0x80, 0x50, 0x00, 0x00,
					len, cdata,
					0, NULL, 0, &SW1SW2);

	memset(cdata, 0, sizeof(cdata));

	if (rc < 0) {
		return rc;
	}

	if (SW1SW2 != 0x9000) {
		return -1;
	}

	return 0;
}



/**
 * Query the PIN status
 *
 * @param ctn the card terminal number
 * @return < 0 in case of an error or SW1/SW2
 */
int queryPIN(int ctn)
{
	unsigned short SW1SW2;
	int rc;

	rc = processAPDU(ctn, 0, 0x00, 0x20, 0x00, 0x81,
					0, NULL,
					0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}



/**
 * Verify the User PIN
 *
 * @param ctn the card terminal number
 * @param pin the PIN
 * @param pinlen the length of the PIN
 *
 * @return < 0 in case of an error or SW1/SW2
 */
int verifyPIN(int ctn, unsigned char *pin, int pinlen)
{
	unsigned short SW1SW2;
	int rc;

	if ((pin == NULL) || (pinlen > 16)) {
		return -1;
	}

	rc = processAPDU(ctn, 0, 0x00, 0x20, 0x00, 0x81,
					pinlen, pin,
					0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}



/**
 * Change PIN
 *
 * @param ctn the card terminal number
 * @param oldpin the old PIN
 * @param oldpinlen the length of the old PIN
 * @param newpin the new PIN
 * @param newpinlen the length of the new PIN
 * @return < 0 in case of an error or SW1/SW2
 */
int changePIN(int ctn, unsigned char *oldpin, int oldpinlen, unsigned char *newpin, int newpinlen)
{
	unsigned char cdata[32];
	unsigned short SW1SW2;
	int rc;

	if ((oldpin == NULL) || (oldpinlen > 16) || (newpin == NULL) || (newpinlen > 16)) {
		return -1;
	}

	memcpy(cdata, oldpin, oldpinlen);
	memcpy(cdata + oldpinlen, newpin, newpinlen);

	rc = processAPDU(ctn, 0, 0x00, 0x24, 0x00, 0x81,
					oldpinlen + newpinlen, cdata,
					0, NULL, 0, &SW1SW2);

	memset(cdata, 0, sizeof(cdata));

	if (rc < 0) {
		return rc;
	}

	return SW1SW2;
}



/**
 * Generate AES-128 key as master secret
 *
 * @param ctn the card terminal number
 * @param id the key id on the device
 * @param algo the list of supported algorithms
 * @param algolen the length of the algorithm list
 * @return < 0 in case of an error
 */
int generateSymmetricKey(int ctn, unsigned char id, unsigned char *algo, int algolen)
{
	unsigned short SW1SW2;
	int rc;

	if ((algo == NULL) || (algolen > 16)) {
		return -1;
	}

	rc = processAPDU(ctn, 0, 0x00, 0x48, id, 0xB0,
					algolen, algo,
					0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	if (SW1SW2 != 0x9000) {
		return -1;
	}

	return 0;
}



/**
 * Write key description
 *
 * @param ctn the card terminal number
 * @param id the key id on the device
 * @param desc the PKCS#15 key description
 * @param desclen the length of the key description
 * @return < 0 in case of an error
 */
int writeKeyDescription(int ctn, unsigned char id, unsigned char *desc, int desclen)
{
	unsigned char cdata[256];
	unsigned short SW1SW2;
	int rc;

	if ((desc == NULL) || (desclen > 127)) {
		return -1;
	}

	cdata[0] = 0x54;
	cdata[1] = 0x02;
	cdata[2] = 0x00;
	cdata[3] = 0x00;
	cdata[4] = 0x53;
	cdata[5] = desclen;

	memcpy(cdata + 6, desc, desclen);

	rc = processAPDU(ctn, 0, 0x00, 0xD7, 0xC4, id,
					desclen + 6, cdata,
					0, NULL, 0, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	if (SW1SW2 != 0x9000) {
		return -1;
	}

	return 0;
}



/**
 * Derive a key from the master key
 *
 * @param ctn the card terminal number
 * @param id the key id on the device
 * @param label the derivation parameter (aka label)
 * @param labellen the length of the label
 * @param keybuff a 32 byte key buffer
 * @param keybuff the length of the key buffer
 * @return < 0 in case of an error
 */
int deriveKey(int ctn, unsigned char id, unsigned char *label, int labellen, unsigned char *keybuff, int keybufflen)
{
	unsigned short SW1SW2;
	int rc;

	if ((label == NULL) || (labellen > 127) || (keybuff == NULL) || (keybufflen != 32)) {
		return -1;
	}

	rc = processAPDU(ctn, 0, 0x80, 0x78, id, 0x99,
					labellen, label,
					0, keybuff, keybufflen, &SW1SW2);

	if (rc < 0) {
		return rc;
	}

	if (SW1SW2 != 0x9000) {
		return -1;
	}

	return 0;
}
