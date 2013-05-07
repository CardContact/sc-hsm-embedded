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

#include "scr.h"

/* utility functions */

int ProcessAPDU(
	int ctn, int todad,
	unsigned char CLA, unsigned char INS, unsigned char P1, unsigned char P2,
	int OutLen, unsigned char *OutData,
	int InLen, unsigned char *InData, int InSize, unsigned short *SW1SW2
);

void _Dump(unsigned char *ptr, int len);

#ifdef WIN32_LEAN_AND_MEAN
#define Dump(ptr, len) { printf(" Dump(func=" __FUNCTION__ ", var=" #ptr ", len=%d):", len); _Dump(ptr, len); }
#else
#define Dump(ptr, len) { _Dump(ptr, len); }
#endif

#endif
