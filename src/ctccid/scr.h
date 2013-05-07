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
 * Abstract :       Defines for SCM SCR 3310 reader and SmartCard-HSM
 *
 * Author :         Frank Thater
 *
 * Last modified:   2013-04-22
 *
 *****************************************************************************/

#ifndef _SCR_H_
#define _SCR_H_

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <malloc.h>
#include <stdio.h>
#ifdef _DEBUG
#define DEBUG
#endif
#define usleep(us) Sleep((us) / 1000)
#endif

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

/**
 * Data structure encapsulating all necessary data elements of the reader interface
 * and the communication protocol
 */
typedef struct scr {

	/** Card terminal number */
	unsigned short ctn;
	/** Port number */
	unsigned short pn;

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
	/** Clock rate conversion integer	  */
	unsigned char		FI;
	/** Baud rate adjustment integer      */
	unsigned char		DI;
	/** Character waiting time            */
	unsigned char		CWI;
	/** Block waiting time                 */
	unsigned char		BWI;
	/** Extra guard time                   */
	unsigned char		EXTRA_GUARD_TIME;
	/** Maximum length of INF field        */
	unsigned char     IFSC;
	/** Current baudrate                   */
	int                Baud;

	int               (*CTModFunc)(struct scr *,
								   unsigned int,         /* length of command  */
								   unsigned char *,      /* command            */
								   unsigned int *,       /* length of response */
								   unsigned char *);     /* response           */

	struct ccidT1      *t1;             /** Context structure for T=1 protocol  */

} scr_t;


typedef int (*CTModFunc_t) (scr_t *,        	/* specified SCR Data */
							unsigned int,              /* length of command  */
							unsigned char *,           /* command            */
							unsigned int *,            /* length of response */
							unsigned char *);          /* response           */


#endif
