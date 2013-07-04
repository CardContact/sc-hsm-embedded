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
 * @brief Simple abstraction layer for USB devices using libusb
 */

#include <stdio.h>
#include <string.h>

#include "utils.h"

/*
 *  Process an ISO 7816 APDU with the underlying terminal hardware.
 *
 *  cla     : Class byte of instruction
 *  ins     : Instruction byte
 *  p1      : Parameter P1
 *  p2      : Parameter P2
 *  outLen  : Length of outgoing data (Lc)
 *  outData : Outgoing data or NULL if none
 *  inLen   : Length of incoming data (Le)
 *  inData  : Input buffer for incoming data
 *  sw1sw2  : Address of short integer to receive sw1sw2
 *
 *  Returns : < 0 Error >= 0 Bytes read
 */
int ProcessAPDU(int ctn, int todad,
				uint8 cla, uint8 ins, uint8 p1, uint8 p2,
				int outLen, uint8 *outData,
				int inLen, uint8 *inData, uint16 *sw1sw2)
{
	uint8 scr[4 + 3 + 3 + MAX_OUT_IN];
	int rc;
	uint16 len;
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
	if (outLen <= 255 && inLen <= 256) {
		/*
			use short APDU
			*/
		if (outLen > 0) {                /* Lc present */
			*p++ = (uint8)outLen;
			memcpy(p, outData, outLen);
			p += outLen;
		}
		if (inLen > 0)                   /* Le present */
			*p++ = (uint8)inLen;         /* (uint8)256 == 0 */
	} else {
		/*
			use long APDU
			*/
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
	rc = CT_data(ctn, &dad, &sad, p - scr, scr, &len, scr);
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
	*sw1sw2 = (scr[len - 2] << 8) | scr[len - 1];
	return rc;
}
