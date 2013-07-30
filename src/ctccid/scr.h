/**
 * CT-API for CCID Driver
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
 * @file scr.h
 * @author Christoph Brunhuber
 * @brief Defines for SCM SCR 3310 reader and SmartCard-HSM
 */

#ifndef _SCR_H_
#define _SCR_H_

#ifdef WIN32
#include <windows.h>
#define usleep(us) Sleep((us) / 1000)
#endif

#include <common/mutex.h>
#include "usb_device.h"

/**
 * Maximum number of readers
 */
#define MAX_READER  8

/**
 * Maximum size of ATR
 */
#define MAX_ATR     34

/**
 * Maximum number of historical bytes
 */
#define HBSIZE      15

typedef struct scr scr_t;

typedef int (*CTModFunc_t) (scr_t *,                   /* specified SCR Data */
							unsigned int,              /* length of command  */
							unsigned char *,           /* command            */
							unsigned int *,            /* length of response */
							unsigned char *);          /* response           */


/**
 * Data structure encapsulating all necessary data elements of the reader interface
 * and the communication protocol
 */
struct scr {

	/** Card terminal number */
	unsigned short ctn;
	/** Port number */
	unsigned short pn;

	/** Card terminal specific mutex */
	MUTEX mutex;

	/** Context structure for USB device */
	struct usb_device	*device;

	/** Last ATR received from the card    */
	unsigned char     ATR[MAX_ATR];
	/** Length of ATR                      */
	unsigned char     LenOfATR;
	/** Number of historical bytes         */
	unsigned char     NumOfHB;
	/** Historical bytes                   */
	unsigned char     HCC[HBSIZE];
	/** Clock rate conversion integer      */
	unsigned char     FI;
	/** Baud rate adjustment integer       */
	unsigned char     DI;
	/** Character waiting time             */
	unsigned char     CWI;
	/** Block waiting time                 */
	unsigned char     BWI;
	/** Extra guard time                   */
	unsigned char     EXTRA_GUARD_TIME;
	/** Maximum length of INF field        */
	unsigned char     IFSC;
	/** Current baudrate                   */
	int               Baud;

	CTModFunc_t       CTModFunc; /* response */

	struct ccidT1     *t1;       /* Context structure for T=1 protocol  */

};


#endif
