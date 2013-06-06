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
 * Abstract :       Simple abstraction layer for USB devices using libusb
 *
 * Author :         Christoph Brunhuber
 *
 * Last modified:   2013-05-24
 *
 *****************************************************************************/

#include <stdio.h>
#include <string.h>

#include "utils.h"

typedef unsigned char uint8;
typedef unsigned short uint16;

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
 *  SW1SW2  : Address of short integer to receive SW1SW2
 *  scr     : Internal buffer
 *  scrSize : Size of internal buffer (>= 10 + OutLen AND >= InLen + 2 AND < 32768)
 *
 *  Returns : < 0 Error >= 0 Bytes read
 */
int ProcessAPDU(int ctn, int todad,
				uint8 CLA, uint8 INS, uint8 P1, uint8 P2,
				int OutLen, uint8 *OutData,
				int InLen, uint8 *InData, uint16 *SW1SW2, 
				uint8 *scr, int scrLen)
{
	int rv, rc, r, retry;
	uint16 lenr;
	uint8 dad, sad;
	uint8 *po;

	/* Reset status word */
	*SW1SW2 = 0x0000;

	if (!scr
		|| 4 + 3 + 3 + OutLen > scrLen         /* worst case: long APDU and in and out */
		|| InLen + 2 > scrLen                  /* need space for SW1SW2 */
		|| !(0 <= InLen  && InLen  <= 0x10000) /* crazy - invalid in length */
		|| !(0 <= OutLen && OutLen <= 0x10000) /* crazy - invalid out length */
		|| OutLen > 0 && !OutData              /* no out buffer */
		|| InLen  > 0 && !InData               /* no in buffer */
	)
		return ERR_MEMORY;
	
	for (retry = 0; retry < 2; retry++) {
		scr[0] = CLA;
		scr[1] = INS;
		scr[2] = P1;
		scr[3] = P2;
		po = scr + 4;
		if (OutLen <= 255 && InLen <= 256) {
			/*
				use short APDU
			 */
			if (OutLen > 0) {                /* Lc present */
				*po++ = (uint8)OutLen;			
				memcpy(po, OutData, OutLen);
				po += OutLen;
			}
			if (InLen > 0)                   /* Le present */
				*po++ = (uint8)InLen;        /* (uint8)256 == 0 */
		} else {
			/*
				use long APDU
			 */
			*po++ = 0;                       /* indicate long APDU */
			if (OutLen > 0) {                /* Lc present */
				*po++ = (uint8)(OutLen >> 8);
				*po++ = (uint8)(OutLen     );
				memcpy(po, OutData, OutLen);
				po += OutLen;
			}
			if (InLen > 0) {                 /* Le present */
				*po++ = (uint8)(InLen >> 8);
				*po++ = (uint8)(InLen     );
			}

		}

		sad = HOST;
		dad = todad;
		lenr = scrLen;
		rc = CT_data(ctn, &dad, &sad, po - scr, scr, &lenr, scr);
		if (rc < 0)
			return rc;
		if (lenr < 2) /* SW1SW2 missing? */
			return ERR_INVALID;
		if (InLen < lenr - 2) /* never truncate */
			return ERR_INVALID;
		if (scr[lenr - 2] == 0x6C) /* not enough buffer supplied */
			return ERR_MEMORY;

		rv = lenr - 2;
		if (InLen > 0)
			memcpy(InData, scr, rv);

		if (scr[lenr - 2] == 0x9F || scr[lenr - 2] == 0x61) { /* check SW1 */
			if (InLen > 0) { /* Get Response */
				if (scr[lenr - 1] > InLen - rv)
					return ERR_MEMORY;
				if (CLA == 0xE0 || CLA == 0x80)
					CLA = 0;
				r = ProcessAPDU(ctn, todad, CLA, 0xC0, 0, 0,
								0, NULL,
								scr[lenr - 1], InData + rv, SW1SW2,
								scr, scrLen);
				if (r < 0)
					return r;
				rv += r;
			} else { /* TODO: why success */
				*SW1SW2 = 0x9000;
			}
		} else {
			*SW1SW2 = (scr[lenr - 2] << 8) | scr[lenr - 1];
		}

		break;
	}

	return rv;
}




/*
 * Dump the memory pointed to by <ptr>
 *
 */
void Dump(void *_ptr, int len)
{
	uint8 *ptr = (uint8 *)_ptr;
	int i;

#ifdef DEBUG
	static char *MinStack = (char *)-1;
	static char *MaxStack; /* = 0; */
	if (MinStack > (char *)&ptr)
		MinStack = (char *)&ptr;
	if (MaxStack < (char *)&ptr)
		MaxStack = (char *)&ptr;
	printf("Dump(%p, %d) stack used so far: %d", ptr, len, MaxStack - MinStack);
#else
	printf("Dump(%p, %d)", ptr, len);
#endif

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
			uint8 ch = ptr[j];

			if (!isprint(ch)) {
				ch = '.';
			}

			printf("%c", ch);
		}
	}

	printf("\n");
}
