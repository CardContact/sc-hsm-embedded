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
 * Author :         Frank Thater
 *
 * Last modified:   2013-05-07
 *
 *****************************************************************************/

#ifndef __utils_h__                     /* Prevent from including twice      */
#define __utils_h__

#include "ctccid/scr.h"

#ifdef __cplusplus                      /* Support for C++ compiler          */
extern "C" {
#endif

/* utility functions */

int ProcessAPDU(
	int ctn, int todad,
	unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
	int OutLen, unsigned char *OutData,
	int InLen, unsigned char *InData,
	unsigned short *SW1SW2,
	unsigned char* scr, int srcSize /* < 32768 */
);

void Dump(void *ptr, int len);

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
