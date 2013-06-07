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
 * @file ccidT1.h
 * @author Frank Thater, Andreas Schwier
 * @brief Implementation of T=1 protocol for USB CCID
 */

#ifndef _CCIDT1_H_
#define _CCIDT1_H_

#include "scr.h"
#include "ctapi.h"

/**
 * Maximum size of receive buffer
 */
#define BUFFMAX    261

/**
 * Data structure encapsulating all data needed for T=1 protocol
 */
typedef struct ccidT1 {
	/** Character Wait Time in ETU        */
	unsigned int    CharWaitTime;
	/** Block Wait Time in ETU            */
	unsigned int    BlockWaitTime;
	/** Working Block Wait Time in ETU    */
	long             WorkBWT;
	/** Maximum length of INF field       */
	unsigned char   IFSC;
	/** Receiver sequence number          */
	int              RSequenz;
	/** Transmitter sequence number       */
	int              SSequenz;
	/** NAD unsigned char of received block        */
	unsigned char   Nad;
	/** PCB unsigned char of received blocks       */
	unsigned char   Pcb;
	/** Length of received data block     */
	int              InBuffLength;
	/** Buffer for incoming data          */
	unsigned char   InBuff[BUFFMAX];
} ccidT1_t;

/**
 * CRC invalid
 */
#define ERR_EDC     -11

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

#define CODENAD(sad,dad)    (unsigned char)((((dad) & 0x0F) << 4) | (sad & 0x0F))
#define CODESBLOCK(x)       (unsigned char)((x) | NONIBLOCK | SBLOCK)
#define CODERBLOCK(nr,rc)   (unsigned char)(NONIBLOCK | ((nr) << 4) | (rc))
#define CODEIBLOCK(ns,mb)   (unsigned char)(((ns) << 6) | ((mb) << 5))

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







