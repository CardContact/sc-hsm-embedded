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
 * @file utils.h
 * @author Christoph Brunhuber
 * @brief Simple abstraction layer for USB devices using libusb
 */

#ifndef __utils_h__                     /* Prevent from including twice      */
#define __utils_h__

#include "ctccid/scr.h"

#ifdef __cplusplus                      /* Support for C++ compiler          */
extern "C" {
#endif

/* utility functions */

#define MAX_OUT_IN 256

typedef unsigned char uint8;
typedef unsigned short uint16;

int ProcessAPDU(
	int ctn, int todad,
	unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
	int OutLen, unsigned char *OutData,
	int InLen, unsigned char *InData,
	unsigned short *SW1SW2
);

#define SaveToFile(name, ptr, len) {\
	FILE *f = fopen(name, "wb");\
	if (f) {\
		if ((len) > 0)\
			fwrite(ptr, 1, len, f);\
		fclose(f);\
	}\
}

#ifdef __cplusplus
}
#endif

#endif
