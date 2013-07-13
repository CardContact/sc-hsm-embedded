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
 * @brief Simple abstraction layer for USB devices using libusb or WinSCard
 */

#ifndef __utils_h__                     /* Prevent from including twice      */
#define __utils_h__

#ifdef __cplusplus                      /* Support for C++ compiler          */
extern "C" {
#endif

/* utility functions */

#define MAX_OUT_IN 256
typedef unsigned char uint8;
typedef unsigned short uint16;

int SC_Open(const char *pin);
int SC_Close();
int SC_Logon(const char *pin);
int SC_ReadFile(uint16 fid, int off, uint8 *data, int dataLen);
int SC_Sign(uint8 op, uint8 keyFid,
	uint8 *outBuf, int outLen,
	uint8 *inBuf, int inSize);
int SC_ProcessAPDU(
	int todad,
	uint8 cla, uint8 ins, uint8 p1, uint8 p2,
	uint8 *outData, int outLen,
	uint8 *inData, int inLen,
	uint16 *sw1sw2);

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
