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

#include "usb_device.h"

#define MAX_READER  8
#define MAX_ATR     34
#define HBSIZE      15
#define FWSIZE      5

typedef struct scr {

    unsigned short ctn;
    unsigned short pn;

    struct usb_device	*device;

    unsigned char     ATR[MAX_ATR];      /* Last ATR received from the card    */
    unsigned char     LenOfATR;          /* Length of ATR                      */
    unsigned char     NumOfHB;           /* Number of HB                       */
    unsigned char     HCC[HBSIZE];       /* History Bytes                      */
    int	                AvailProt;         /* Protocols indicated in ATR         */
    int 		        Protocol;          /* Handler module providing protocol  */
    unsigned char		FI;                /* Clock rate conversion integer	  	 */
    unsigned char		DI;                /* Baud rate adjustement integer      */
    unsigned char		CWI;               /* Char waiting time                  */
    unsigned char		BWI;               /* Block waiting time                 */
    unsigned char		EXTRA_GUARD_TIME;  /* Extra guard time                   */
    unsigned char     IFSC;              /* Maximum length of INF field        */
    int                Baud;              /* Current baudrate                   */

    int               (*CTModFunc)(struct scr *,
                                   unsigned int,         /* length of command  */
                                   unsigned char *,      /* command            */
                                   unsigned int *,       /* length of response */
                                   unsigned char *);     /* response           */

    struct ccidT1      *t1;

} scr_t;


typedef int (*CTModFunc_t) (scr_t *,        	/* specified SCR Data */
                            unsigned int,              /* length of command  */
                            unsigned char *,           /* command            */
                            unsigned int *,            /* length of response */
                            unsigned char *);          /* response           */


#endif
