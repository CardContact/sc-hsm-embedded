/*
 *  ---------
 * |.**> <**.|  CardContact
 * |*       *|  Software & System Consulting
 * |*       *|  Minden, Germany
 * |.**> <**.|  Copyright (c) 2013. All rights reserved
 *  ---------
 *
 * See file LICENSE for details on licensing
 *
 * Abstract :       Set of utility functions
 *
 * Author :         Frank Thater
 *
 * Last modified:   2013-05-07
 *
 *****************************************************************************/

#include <stdio.h>
#include <string.h>

#include "utils.h"

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
 *  Returns : < 0 Error >= 0 Bytes read

 */
static int ProcessAPDUIntern(
	int ctn, int todad,
	unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
	int OutLen, unsigned char *OutData,
	int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2,
	unsigned char *scr)

{
	int  rv, rc, r, retry;
	unsigned short lenr;
	unsigned char dad, sad;
	unsigned char *po;

	/* Reset status word */
	*SW1SW2 = 0x0000;

	retry = 2;

	while (retry--) {
		scr[0] = CLA;
		scr[1] = INS;
		scr[2] = P1;
		scr[3] = P2;
		po = scr + 4;
		rv = 0;

		if (OutData && OutLen) {
			if (OutLen <= 255 && InLen <= 255) {
				*po++ = (unsigned char)OutLen;
			} else {
				*po++ = 0;
				*po++ = (unsigned char)(OutLen >> 8);
				*po++ = (unsigned char)(OutLen & 0xFF);
			}

			if (OutLen > MAX_APDULEN - (po - scr)) {
				return -1;
			}

			memcpy(po, OutData, OutLen);
			po += OutLen;
		}

		if (InData && InSize) {
			if (InLen <= 255 && OutLen <= 255) {
				*po++ = (unsigned char)InLen;
			} else {
				if (InLen >= 0x10000) {
					if (InLen == 0x10000) {
						InLen = 0;
					} else {
						return -1;
					}
				}

				if (!OutData) {
					*po++ = 0;
				}

				*po++ = (unsigned char)(InLen >> 8);
				*po++ = (unsigned char)(InLen & 0xFF);
			}
		}

		sad  = HOST;
		dad  = todad;
		lenr = MAX_APDULEN;

		rc = CT_data(ctn, &dad, &sad, po - scr, scr, &lenr, scr);

		if (rc < 0) {
			return rc;
		}

		if (scr[lenr - 2] == 0x6C) {
			InLen = scr[lenr - 1];
			continue;
		}

		rv = lenr - 2;

		if (rv > InSize) {
			rv = InSize;
		}

		if (InData) {
			memcpy(InData, scr, rv);
		}

		if (scr[lenr - 2] == 0x9F || scr[lenr - 2] == 0x61) {
			if (InData && InSize) {             /* Get Response             */
				r = ProcessAPDUIntern(
						ctn, todad,
						CLA == 0xE0 || CLA == 0x80 ? 0x00 : CLA, 0xC0, 0, 0,
						0, NULL,
						scr[1], InData + rv, InSize - rv, SW1SW2,
						scr);

				if (r < 0) {
					return r;
				}

				rv += r;
			} else {
				*SW1SW2 = 0x9000;
			}
		} else {
			*SW1SW2 = (scr[lenr - 2] << 8) + scr[lenr - 1];
		}

		break;
	}

	return rv;
}



int ProcessAPDU(
	int ctn, int todad,
	unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
	int OutLen, unsigned char *OutData,
	int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2)

{
	unsigned char scr[MAX_APDULEN];
	return ProcessAPDUIntern(
			   ctn, todad,
			   CLA, INS, P1, P2,
			   OutLen, OutData,
			   InLen, InData, InSize, SW1SW2,
			   scr);
}



/*
 * Dump the memory pointed to by <ptr>
 *
 */
void _Dump(unsigned char *ptr, int len)
{
	int i;

	for (i = 0; i < len; i += 16) {
		int i1 = i + 16;
		int i2 = i1;
		int j;

		if (i1 > len) {
			i1 = len;
		}

		if (i % 16 == 0) {
			printf("\n  %04x: ", (char*)i);
		}

		for (j = i; j < i1; j++) {
			printf("%02x ", ptr[j]);
		}

		for (     ; j < i2; j++) {
			printf("   ");
		}

		printf(" ");

		for (j = i; j < i1; j++) {
			unsigned char ch = ptr[j];

			if (!isprint(ch)) {
				ch = '.';
			}

			putchar(ch);
		}
	}

	printf("\n");
}
