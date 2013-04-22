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
 * Abstract :       Implementation of T=1 protocol for USB CCID
 *
 * Author :         Frank Thater
 *
 * Last modified:   2013-04-22
 *
 *****************************************************************************/

#ifndef _CCIDT1_H_
#define _CCIDT1_H_

#include "scr.h"
#include "usb_device.h"
#include "ctapi.h"

#define BUFFMAX    261

typedef struct ccidT1 {
    unsigned int    CharWaitTime;        /* Character Wait Time in ETU        */
    unsigned int    BlockWaitTime;       /* Block Wait Time in ETU            */
    long             WorkBWT;             /* Working Block Wait Time in ETU    */
    int              IFSC;                /* Maximum length of INF field       */
    int              RSequenz;            /* Receiver sequence number          */
    int              SSequenz;            /* Transmitter sequence number       */
    unsigned char   Nad;                 /* NAD unsigned char of received block        */
    unsigned char   Pcb;                 /* PCB unsigned char of received blocks       */
    int              InBuffLength;        /* Length of received data block     */
    unsigned char   InBuff[BUFFMAX];     /* Buffer for incoming data          */
} ccidT1_t;

#ifndef TRUE
#define TRUE    1
#define FALSE   0
#endif

#ifndef MAX
#define MAX(x,y)    ((x) > (y) ? (x) : (y))
#define MIN(x,y)    ((x) < (y) ? (x) : (y))
#endif

/* In chipcard communication protocols, the timing is based on ETUs          */
/* One ETU is the number of us it takes to transfer one bit                  */
#define ETU(baud)       (1000000L / (long)MAX(baud,9600))

/* Convert ETU timing into milliseconds                                      */
#define RSD(baud, time) (((1000000L / (long)MAX(baud,9600)) * time) / 1000L)

#define CWT     1920                    /* Timeout between 2 character 200ms */
#define BWT     9600                    /* Timeout between 2 blocks      1s  */
#define BLEN    32                      /* Initial length of block           */
#define RETRY   2                       /* Number of retries                 */

#define RERR_NONE       0x00            /* No error indicated in R-block     */
#define RERR_EDC        0x01            /* EDC error indicated in  R-block   */
#define RERR_OTHER      0x02            /* Other errors in R-block           */
#define RERR_MASK       0x0F            /* Mask to decode errors             */

#define SADMASK         0x07            /* Mask for source id                */
#define DADMASK         0x70            /* Mask for destination id           */

#define NONIBLOCK       0x80            /* Non I Block indicator             */
#define SBLOCK          0x40            /* S Block indicator                 */
#define NRBIT           0x10            /* N(R) indicator                    */
#define NSBIT           0x40            /* N(S) indicator                    */
#define MOREBIT         0x20            /* More bit indicator                */

#define SBLOCKFUNCMASK  0x3F            /* S-block function mask             */
#define RESYNCHREQ      0x00            /* S-block with RESYNCH request      */
#define RESYNCHRES      0x20            /* S-block with RESYNCH response     */
#define IFSREQ          0x01            /* S-block with IFS request          */
#define IFSRES          0x21            /* S-block with IFS response         */
#define ABORTREQ        0x02            /* S-block with ABORT request        */
#define ABORTRES        0x22            /* S-block with ABORT response       */
#define WTXREQ          0x03            /* S-block with WTX request          */
#define WTXRES          0x23            /* S-block with WTX response         */

#define VPPERRRES       0x24            /* S-block with VPPERR response      */

#define CODENAD(sad,dad)    (unsigned char)(((dad & 0x0F) << 4) + (sad & 0x0F))
#define CODESBLOCK(x)       (unsigned char)((x)|NONIBLOCK|SBLOCK)
#define CODERBLOCK(nr,rc)   (unsigned char)(NONIBLOCK|((nr) << 4)|(rc))
#define CODEIBLOCK(ns,mb)   (unsigned char)(((ns) << 6)|((mb) << 5))

#define ISIBLOCK(x)     (!((x) & NONIBLOCK))                    /* I block   */
#define ISRBLOCK(x)     (((x) & NONIBLOCK) && !((x) & SBLOCK))  /* R block   */
#define ISSBLOCK(x)     (((x) & NONIBLOCK) && ((x) & SBLOCK))   /* S block   */
#define NR(x)           (((x) & NRBIT) >> 4)        /* Sequence bit          */
#define NS(x)           (((x) & NSBIT) >> 6)        /* Sequence bit          */
#define RERR(x)         ((x) & RERR_MASK)           /* Error field in R-blck */
#define MORE(x)         (((x) & MOREBIT) >> 5)      /* More data bit         */
#define SBLOCKFUNC(x)   ((x) & SBLOCKFUNCMASK)      /* S-block function      */
#define SAD(x)          ((x) & SADMASK)             /* SAD from NAD unsigned char     */
#define DAD(x)          (((x) & DADMASK) >> 4)      /* DAD from NAD unsigned char     */

#endif







