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
 * @file ccidT1.c
 * @author Frank Thater, Andreas Schwier
 * @brief Implementation of T=1 protocol for USB CCID
 */

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "ccidT1.h"
#include "ccid_usb.h"
#include "ctccid_debug.h"


/**
 * Initialize all T=1 protocol parameter to its default values
 *
 * @param ctx Reader context
 */
void ccidT1InitProtocol(scr_t *ctx)
{
	ctx->t1->BlockWaitTime = 200 + (1 << ctx->BWI) * 100 + 11000 / ctx->Baud;
	ctx->t1->WorkBWT = ctx->t1->BlockWaitTime;
	ctx->t1->IFSC = ctx->IFSC;
	ctx->t1->SSequenz = 0;
	ctx->t1->RSequenz = 0;
}



/**
 * Terminate driver module and release memory
 *
 * @param ctx Reader context
 */
int ccidT1Term (struct scr *ctx)
{
	free(ctx->t1);
	ctx->t1 = NULL;
	ctx->CTModFunc = NULL;
	return 0;
}



#ifdef DEBUG
/**
 * Print the block information of a T=1 transmission block
 *
 * @param Nad Node address
 * @param Pcb PCB of received blocks
 * @param InBuffLength Length of incoming data
 * @param InBuff Incomonf data
 */
void ccidT1BlockInfo(unsigned char Nad, unsigned char Pcb, int InBuffLength, unsigned char *InBuff)
{
	ctccid_debug("SAD:%02d-DAD:%02d\n", SAD(Nad), DAD(Nad));

	if (ISIBLOCK(Pcb)) {
		ctccid_debug("I(%d,%d):\n", NS(Pcb), MORE(Pcb));
		ctccid_dump(InBuff, InBuffLength);
	}

	if (ISRBLOCK(Pcb)) {
		ctccid_debug("R(%d)[%d]\n", NR(Pcb), RERR(Pcb));
	}

	if (ISSBLOCK(Pcb)) {
		switch (SBLOCKFUNC(Pcb)) {
		case RESYNCHREQ :
			ctccid_debug("S(RESYNCH Request)\n");
			break;
		case RESYNCHRES :
			ctccid_debug("S(RESYNCH Response)\n");
			break;
		case IFSREQ :
			ctccid_debug("S(IFS Request:%d)\n",(int)InBuff[0]);
			break;
		case IFSRES :
			ctccid_debug("S(IFS Response:%d)\n",(int)InBuff[0]);
			break;
		case ABORTREQ       :
			ctccid_debug("S(ABORT Request)\n");
			break;
		case ABORTRES       :
			ctccid_debug("S(ABORT Response)\n");
			break;
		case WTXREQ :
			ctccid_debug("S(WTX Request:%d)\n",(int)InBuff[0]);
			break;
		case WTXRES :
			ctccid_debug("S(WTX Response:%d)\n",(int)InBuff[0]);
			break;
		default :
			ctccid_debug("Unknown S(...) Block\n");
			break;
		}
	}
}
#endif



/**
 * Receive a block in T=1 protocol
 *
 * @param ctx Reader context
 * @return 0 on success, -1 or \ref ERR_EDC on error
 */
int ccidT1ReceiveBlock(scr_t *ctx)
{
	int rc = 0;
	unsigned int i, len;
	unsigned char lrc = 0;
	unsigned char buf[BUFFMAX];

	ctx->t1->InBuffLength = -1;

	len = BUFFMAX;
	rc = RDR_to_PC_DataBlock(ctx, &len, buf, NULL, NULL, NULL);

	if (rc < 0) {
		return -1;
	}

#ifdef DEBUG
	ctccid_debug("Received : \n");
	ccidT1BlockInfo(buf[0], buf[1], buf[2], buf + 3);
#endif

	lrc = 0;

	if (len != 0) {
		/* Calculate checksum */
		for (i = 0; i < (len - 1); i++) {
			lrc ^= buf[i];
		}

		if (lrc != buf[len - 1]) {
			return ERR_EDC;
		}
	}

	ctx->t1->Nad = buf[0];
	ctx->t1->Pcb = buf[1];
	ctx->t1->InBuffLength = buf[2];

	if (ctx->t1->InBuffLength > 0) {
		memcpy(ctx->t1->InBuff, buf + 3, ctx->t1->InBuffLength);
	}

	return 0;
}



/**
 * Send a block in T=1 protocol
 *
 * @param ctx Reader context
 * @param Nad Node address
 * @param Pcb PCB address
 * @param Buffer Outgoing buffer
 * @param BuffLen Length of outgoing data
 * @return 0 on success, -1 on error
 */
int ccidT1SendBlock(scr_t *ctx,
					unsigned char Nad,
					unsigned char Pcb,
					unsigned char *Buffer,
					int BuffLen)
{
	int rc, len;
	unsigned char sndbuf[BUFFMAX];
	unsigned char *ptr, lrc;

	if (BuffLen > 254) {
		return -1;
	}

	ptr = sndbuf;
	*ptr++ = Nad;
	*ptr++ = Pcb;
	*ptr++ = (unsigned char)BuffLen;
	memcpy(ptr, Buffer, BuffLen);

	lrc = 0;

	for (len = BuffLen + 3, ptr = sndbuf; len; len--, ptr++) {
		lrc ^= *ptr;
	}

	*ptr = lrc;

	rc = PC_to_RDR_XfrBlock(ctx, BuffLen + 4, sndbuf, 0);

	if (rc < 0) {
		return -1;
	}

#ifdef DEBUG
	ctccid_debug("Sending : \n");
	ccidT1BlockInfo(Nad, Pcb, BuffLen, Buffer);
#endif

	return 0;
}



/**
 * Synchronize sequence counter in both sender and receiver after a transmission error has occurred
 *
 * @param ctx Reader context
 * @param SrcNode Source node
 * @param DestNode Destination node
 * @return 0 on success, -1 on error
 */
int ccidT1Resynch(scr_t *ctx, int SrcNode, int DestNode)
{
	int ret,retry;

	retry = RETRY;

	while (retry--) {
		ret = ccidT1SendBlock(ctx,
							  CODENAD(SrcNode, DestNode),
							  CODESBLOCK(RESYNCHREQ),
							  NULL,0);

		if (ret < 0) {
			return -1;
		}

		ret = ccidT1ReceiveBlock(ctx);

		if (!ret &&
				ISSBLOCK(ctx->t1->Pcb) &&
				(SBLOCKFUNC(ctx->t1->Pcb) == RESYNCHRES)) {
			ccidT1InitProtocol(ctx);
			return 0;
		}
	}

	return -1;
}



/**
 * Abort a sequence of chained transmission blocks
 *
 * @param ctx Reader context
 * @param SrcNode Source node
 * @param DestNode Destination node
 * @return 0 on success, -1 on error
 */
int ccidT1AbortChain(scr_t *ctx, int SrcNode, int DestNode)
{
	int ret,retry;

	retry = RETRY;

	while (retry--) {
		ret = ccidT1SendBlock(ctx,
							  CODENAD(SrcNode, DestNode),
							  CODESBLOCK(ABORTREQ),
							  NULL, 0);

		if (ret < 0) {
			return -1;
		}

		ret = ccidT1ReceiveBlock(ctx);

		if (!ret && ISSBLOCK(ctx->t1->Pcb) && (SBLOCKFUNC(ctx->t1->Pcb) == ABORTRES)) {
			return 0;
		}
	}

	return -1;
}



/**
 * Receive a transmission block and handle all S-block requests
 *
 * @param ctx Reader context
 * @param SrcNode Source node
 * @param DestNode Destination node
 * @return 0 on success, -1 on error
 */
int ccidT1GetBlock(scr_t *ctx, int SrcNode, int DestNode)
{
	int retry,ret;

	retry = RETRY;
	ctx->t1->WorkBWT = ctx->t1->BlockWaitTime;

	while (TRUE) {
		ret = ccidT1ReceiveBlock(ctx);

		if (ret < 0) {
			if (!retry) {
				return -1;
			}

			/* The receiver did not understand our transmission block.             */
			/* Unless the retry counter expires, we send it again                  */

			retry--;
			ret = ccidT1SendBlock(ctx,
								  CODENAD(SrcNode, DestNode),
								  CODERBLOCK(ctx->t1->RSequenz, ret == ERR_EDC ? 1 : 2),
								  NULL,
								  0);

			if (ret < 0) {
				return -1;
			}

			ctx->t1->WorkBWT = ctx->t1->BlockWaitTime;
			continue;
		}

		/* Lets see, if we received a S-block from the other side                */

		if (ISSBLOCK(ctx->t1->Pcb)) {
			switch(SBLOCKFUNC(ctx->t1->Pcb)) {
			case RESYNCHRES :               /* Request to synchronize again      */
				ccidT1InitProtocol(ctx);
				return 1;
				break;

			case IFSREQ :                   /* Request to change the buffer size */
				ccidT1SendBlock(ctx,
								CODENAD(SrcNode, DestNode),
								CODESBLOCK(IFSRES),
								ctx->t1->InBuff,
								1);
				ctx->t1->IFSC = (int)ctx->t1->InBuff[0];

#ifdef DEBUG
				ctccid_debug("New IFSC: %d unsigned chars.\n", ctx->t1->IFSC);
#endif
				break;

			case ABORTREQ :                 /* Request to abort the transmission */
				ccidT1SendBlock(ctx,
								CODENAD(SrcNode, DestNode),
								CODESBLOCK(ABORTRES),
								NULL,
								0);

				ccidT1ReceiveBlock(ctx);
				return -1;
				break;

			case WTXREQ :                   /* Request to extend timeout         */
				ccidT1SendBlock(ctx,
								CODENAD(SrcNode, DestNode),
								CODESBLOCK(WTXRES),
								ctx->t1->InBuff,
								1);
				ctx->t1->WorkBWT = ctx->t1->BlockWaitTime *
								   (int)ctx->t1->InBuff[0];

#ifdef DEBUG
				ctccid_debug("New BWT value %ld ms.\n",ctx->t1->WorkBWT);
#endif
				break;

			default :
				return -1;
			}
		}

		if (ISRBLOCK(ctx->t1->Pcb) || ISIBLOCK(ctx->t1->Pcb)) {
			break;
		}
	}

	return 0;
}



/**
 * Send a block of data using T=1 protocol and handle large block with the chaining mechanism
 *
 * @param ctx Reader context
 * @param HostMode Indicator for host mode
 * @param SrcNode Source node
 * @param DestNode Destination node
 * @param Buffer Outgoing data buffer
 * @param BuffLen Length of outgoing data
 * @return 0 on success, -1 on error
 */
int ccidT1SendData(scr_t *ctx,
				   int HostMode,
				   int SrcNode,
				   int DestNode,
				   unsigned char *Buffer,
				   int BuffLen)
{
	int ret,more,retry,Length,response;

	while (BuffLen) {
		Length = MIN(BuffLen, ctx->t1->IFSC);
		BuffLen -= Length;
		more = BuffLen ? 1 : 0;

		retry = RETRY;
		response = 0;

		while (response <= 0) {
			ret = ccidT1SendBlock(ctx,
								  CODENAD(SrcNode, DestNode),
								  CODEIBLOCK(ctx->t1->SSequenz,more),
								  Buffer,
								  Length);

			if (ret < 0) {
				return -1;
			}

			if (!more && HostMode) {
				ctx->t1->SSequenz = 1 - ctx->t1->SSequenz;
				return 0;
			}

			ret = ccidT1GetBlock(ctx, SrcNode, DestNode);

			if (ret < 0) {                    /* Something went wrong              */
				return ret;
			}

			if (ret > 0) {                     /* Send block again                  */
				continue;
			}

			/* A block can be acknowledged with an I or R-block                    */

			if (ISRBLOCK(ctx->t1->Pcb)) {
				if (NR(ctx->t1->Pcb) == ctx->t1->SSequenz) {
					if (retry--) {
						continue;                   /* Receiver is requesting same block */
					}

					if (ccidT1Resynch(ctx,SrcNode,DestNode)) {
						return -1;
					}

					continue;
				} else if (more) {

					/* In chaining mode, the R-block is used to acknowledge the I-block*/

					response = 1;
					ctx->t1->SSequenz = 1 - ctx->t1->SSequenz;
				} else {
#ifdef DEBUG
					ctccid_debug("Error: Unexpected R-Block.\n");
#endif

					if (ccidT1Resynch(ctx,SrcNode,DestNode)) {
						return -1;
					}
				}
			}

			if (ISIBLOCK(ctx->t1->Pcb)) {    /* Usual response to I-block     */
				if ((NS(ctx->t1->Pcb) != ctx->t1->RSequenz) || more) {
#ifdef DEBUG
					ctccid_debug("Asynchronous I-Block received as response.\n");
#endif

					if (ccidT1Resynch(ctx,SrcNode,DestNode)) {
						return -1;
					}
				} else {
					ctx->t1->SSequenz = 1 - ctx->t1->SSequenz;
					response = 1;
				}
			}
		}

		Buffer += Length;
	}

	return 0;
}



/**
 * Decode a received block into the data buffer passed to the application
 *
 * @param ctx Reader context
 * @param SrcNode Source node
 * @param DestNode Destination node
 * @param Buffer Incoming data buffer
 * @param BuffLen Length of incoming data buffer
 * @return Length of data received
 */
int ccidT1ReceiveData(scr_t *ctx,
					  int SrcNode,
					  int DestNode,
					  unsigned char *Buffer,
					  int BuffLen)
{
	int more,Length,ret;

	Length = 0;

	do  {

		more = MORE(ctx->t1->Pcb);     /* More block following ?            */

		if ((ctx->t1->InBuffLength > BuffLen) || (ctx->t1->InBuffLength == -1)) {
			if (more) {
				ccidT1AbortChain(ctx,SrcNode,DestNode);
			}
			return(ERR_MEMORY);                       /* Out of space in buffer            */
		}

		memcpy(Buffer, ctx->t1->InBuff, ctx->t1->InBuffLength);
		Buffer += ctx->t1->InBuffLength;
		BuffLen -= ctx->t1->InBuffLength;
		Length += ctx->t1->InBuffLength;

		ctx->t1->RSequenz = 1 - ctx->t1->RSequenz;

		if (more) {
			while (TRUE) {
				ret = ccidT1SendBlock(ctx,
									  CODENAD(SrcNode, DestNode),
									  CODERBLOCK(ctx->t1->RSequenz, 0),
									  NULL, 0);

				if (ret < 0) {
					return ret;
				}

				ret = ccidT1GetBlock(ctx, SrcNode, DestNode);

				if (ret < 0) {
					return ret;
				}

				if (ISRBLOCK(ctx->t1->Pcb)) {
					if (NR(ctx->t1->Pcb) != ctx->t1->SSequenz) {

#ifdef DEBUG
						ctccid_debug("Error: Invalid sequenz received in R-Block.\n");
#endif

						if (ccidT1Resynch(ctx,SrcNode,DestNode)) {
							return -1;
						}
					}

					continue;
				}

				break;
			}
		}
	} while (more);

	return Length;
}



/**
 * Transport a data block using T=1 transmission protocol
 *
 * @param ctx Reader context
 * @param SrcNode Source node
 * @param DestNode Destination node
 * @param OBuffer Outgoing data buffer
 * @param OBuffLen Length of outgoig data buffer
 * @param IBuffer Incoming data buffer
 * @param IBuffLen Length of incoming data buffer
 * @return Number of incoming bytes, negative value on error
 */
int ccidT1Transport(scr_t *ctx,
					int SrcNode,
					int DestNode,
					unsigned char *OBuffer,
					int OBuffLen,
					unsigned char *IBuffer,
					int IBuffLen)
{

	int ret;

#ifdef DEBUG
	ctccid_debug("ccidT1SendData called\n");
#endif

	ret = ccidT1SendData(ctx, FALSE, SrcNode, DestNode, OBuffer, OBuffLen);

	if (ret < 0) {
#ifdef DEBUG
		ctccid_debug("ccidT1SendData failed with rc = %i\n", ret);
#endif
		return ret;
	}

	ret = ccidT1ReceiveData(ctx, SrcNode, DestNode, IBuffer, IBuffLen);

#ifdef DEBUG

	if (ret < 0) {
		ctccid_debug("ccidT1ReceiveData failed with rc = %i\n", ret);
	}

#endif

	return ret;
}



/**
 * Process a APDU using T=1 protocol
 * @param ctx Reader context
 * @param lc Length of command APDU
 * @param cmd Command APDU
 * @param lr Length of response APDU
 * @param rsp Response APDU
 * @return 0 on success, -1 on error
 */
int ccidT1Process (struct scr *ctx,
				   unsigned int  lc,
				   unsigned char *cmd,
				   unsigned int  *lr,
				   unsigned char *rsp)
{
	int rc;

	rc = ccidT1Transport(ctx, 0, 0, cmd, lc, rsp, *lr);

	if (rc < 0) {
		return rc;
	}

	*lr = rc;
	return 0;
}



/**
 * Initialize T=1 protocol driver module
 *
 * @param ctx Reader context
 */
int ccidT1Init (struct scr *ctx)
{

	ctx->t1 = calloc(1, sizeof(ccidT1_t));

	ctx->CTModFunc = (CTModFunc_t) ccidT1Process;

	ccidT1InitProtocol(ctx);

	return 0;
}
