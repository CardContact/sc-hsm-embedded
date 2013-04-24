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
 * Author :         Frank Thater, Andreas Schwier
 *
 * Last modified:   2013-04-22
 *
 *****************************************************************************/

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <string.h>

#include "ccidT1.h"
#include "ccid_usb.h"

/*
 * Initialize all T=1 protocol parameter to its default values
 *
 */

void ccidT1InitProtocol(scr_t *ctx) {
    ctx->t1->WorkBWT = ctx->t1->BlockWaitTime;
    ctx->t1->IFSC = 254; /* Fixed IFSC size */
    ctx->t1->SSequenz = 0;
    ctx->t1->RSequenz = 0;
}



/*
 * Terminate driver module and release memory
 *
 */

int ccidT1Term (struct scr *ctx) {
    free(ctx->t1);
    ctx->t1 = NULL;
    ctx->CTModFunc = NULL;
    return 0;
}



#ifdef DEBUG
/*
 * Print the block information of a T=1 transmission block
 *
 */
void ccidT1BlockInfo(unsigned char Nad, unsigned char Pcb, int InBuffLength, unsigned char *InBuff) {
    unsigned char *ptr;
    int cnt;

    printf("SAD:%02d-DAD:%02d  ", SAD(Nad), DAD(Nad));

    if (ISIBLOCK(Pcb)) {
        printf("I(%d,%d):", NS(Pcb), MORE(Pcb));
        ptr = InBuff;
        for (cnt = 0; cnt < InBuffLength; cnt++) {
            printf("%02X ",(int)*ptr);
            ptr++;
        }
        printf("\n");
    }

    if (ISRBLOCK(Pcb))
        printf("R(%d)[%d]\n", NR(Pcb), RERR(Pcb));

    if (ISSBLOCK(Pcb))
        switch (SBLOCKFUNC(Pcb)) {
            case RESYNCHREQ :
                printf("S(RESYNCH Request)\n"); break;
            case RESYNCHRES :
                printf("S(RESYNCH Response)\n"); break;
            case IFSREQ :
                printf("S(IFS Request:%d)\n",(int)InBuff[0]); break;
            case IFSRES :
                printf("S(IFS Response:%d)\n",(int)InBuff[0]); break;
            case ABORTREQ       :
                printf("S(ABORT Request)\n"); break;
            case ABORTRES       :
                printf("S(ABORT Response)\n"); break;
            case WTXREQ :
                printf("S(WTX Request:%d)\n",(int)InBuff[0]); break;
            case WTXRES :
                printf("S(WTX Response:%d)\n",(int)InBuff[0]); break;
            default :
                printf("Unknown S(...) Block\n"); break;
        }
}
#endif



/*
 * Receive a block in T=1 protocol
 *
 */
int ccidT1ReceiveBlock(scr_t *ctx) {
    int rc = 0, i;
    unsigned int len;
    unsigned char lrc = 0;
    unsigned char buf[BUFFMAX];

    ctx->t1->InBuffLength = -1;

    len = BUFFMAX;
    rc = RDR_to_PC_DataBlock(ctx, &len, buf);

    if (rc < 0) {
        return rc;
    }

    lrc = 0;

    if (len != 0) {
    	// Calculate checksum
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



/*
 * Send a block in T=1 protocol
 *
 */
int ccidT1SendBlock(scr_t *ctx,
                   unsigned char Nad,
                   unsigned char Pcb,
                   unsigned char *Buffer,
                   int BuffLen) {
    int rc, len;
    unsigned char sndbuf[BUFFMAX], rcvbuf[BUFFMAX];
    unsigned char *ptr, lrc;

    if (BuffLen > 254) {
        return(-1);
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

    rc = PC_to_RDR_XfrBlock(ctx, BuffLen + 4, sndbuf);

    if (rc < 0) {
        return rc;
    }

#ifdef DEBUG
    printf("Sending : ");
    ccidT1BlockInfo(Nad, Pcb, BuffLen, Buffer);
#endif

    return(0);
}



/*
 * Synchronize sequence counter in both sender and receiver
 * after a transmission error has occured
 *
 */
int ccidT1Resynch(scr_t *ctx, int SrcNode, int DestNode) {
    int ret,retry;

    retry = RETRY;

    while (retry--) {
        ret = ccidT1SendBlock(ctx,
                             CODENAD(SrcNode, DestNode),
                             CODESBLOCK(RESYNCHREQ),
                             NULL,0);

        if (ret < 0)
            return(-1);

        ret = ccidT1ReceiveBlock(ctx);

        if (!ret &&
            ISSBLOCK(ctx->t1->Pcb) &&
            (SBLOCKFUNC(ctx->t1->Pcb) == RESYNCHRES)) {
            ccidT1InitProtocol(ctx);
            return(0);
        }
    }
    return(-1);
}



/*
 * Abort a sequence of chained transmission blocks
 *
 */
int ccidT1AbortChain(scr_t *ctx, int SrcNode, int DestNode) {
    int ret,retry;

    retry = RETRY;

    while (retry--) {
        ret = ccidT1SendBlock(ctx,
                             CODENAD(SrcNode, DestNode),
                             CODESBLOCK(ABORTREQ),
                             NULL, 0);

        if (ret < 0)
            return(-1);

        ret = ccidT1ReceiveBlock(ctx);

        if (!ret && ISSBLOCK(ctx->t1->Pcb) && (SBLOCKFUNC(ctx->t1->Pcb) == ABORTRES))
            return(0);
    }

    return(-1);
}



/*
 * Receive a transmission block and handle all S-block requests
 *
 */
int ccidT1GetBlock(scr_t *ctx, int SrcNode, int DestNode) {
    int retry,ret;

    retry = RETRY;
    ctx->t1->WorkBWT = ctx->t1->BlockWaitTime;

    while (TRUE) {
        ret = ccidT1ReceiveBlock(ctx);

        if (ret < 0) {
            if (!retry)
                return(ret);

            /* The receiver did not understand our transmission block.             */
            /* Unless the retry counter expires, we send it again                  */

            retry--;
            ret = ccidT1SendBlock(ctx,
                                 CODENAD(SrcNode, DestNode),
                                 CODERBLOCK(ctx->t1->RSequenz, ret == ERR_EDC ? 1 : 2),
                                 NULL,
                                 0);

            if (ret < 0)
                return(ret);

            ctx->t1->WorkBWT = ctx->t1->BlockWaitTime;
            continue;
        }

        /* Lets see, if we received a S-block from the other side                */

        if (ISSBLOCK(ctx->t1->Pcb)) {
            switch(SBLOCKFUNC(ctx->t1->Pcb)) {
                case RESYNCHRES :               /* Request to synchronize again      */
                    ccidT1InitProtocol(ctx);
                    return(1);
                    break;

                case IFSREQ :                   /* Request to change the buffer size */
                    ccidT1SendBlock(ctx,
                                   CODENAD(SrcNode, DestNode),
                                   CODESBLOCK(IFSRES),
                                   ctx->t1->InBuff,
                                   1);
                    ctx->t1->IFSC = (int)ctx->t1->InBuff[0];

#ifdef DEBUG
                    printf("New IFSC: %d unsigned chars.\n", ctx->t1->IFSC);
#endif
                    break;

                case ABORTREQ :                 /* Request to abort the transmission */
                    ccidT1SendBlock(ctx,
                                   CODENAD(SrcNode, DestNode),
                                   CODESBLOCK(ABORTRES),
                                   NULL,
                                   0);

                    ccidT1ReceiveBlock(ctx);
                    return(-1);
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
                    printf("New BWT value %ld ms.\n",ctx->t1->WorkBWT);
#endif
                    break;

                default :
                    return(-1);
            }
        }

        if (ISRBLOCK(ctx->t1->Pcb) || ISIBLOCK(ctx->t1->Pcb))
            break;
    }

    return(0);
}



/*
 * Send a block of data using T=1 protocol
 * Handle large block with the chaining mechanism
 *
 */
int ccidT1SendData(scr_t *ctx,
                  int HostMode,
                  int SrcNode,
                  int DestNode,
                  unsigned char *Buffer,
                  int BuffLen) {
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

            if (ret < 0)
                return(ret);


            if (!more & HostMode) {
                ctx->t1->SSequenz = 1 - ctx->t1->SSequenz;
                return(0);
            }

            ret = ccidT1GetBlock(ctx, SrcNode, DestNode);

            if (ret < 0)                      /* Something went wrong              */
                return(ret);

            if (ret > 0)                      /* Send block again                  */
                continue;

            /* A block can be acknowledged with an I or R-block                    */

            if (ISRBLOCK(ctx->t1->Pcb)) {
                if (NR(ctx->t1->Pcb) == ctx->t1->SSequenz) {
                    if (retry--)
                        continue;                   /* Receiver is requesting same block */

                    if (ccidT1Resynch(ctx,SrcNode,DestNode))
                        return(-1);
                    continue;
                } else if (more) {

                    /* In chaining mode, the R-block is used to acknowledge the I-block*/

                    response = 1;
                    ctx->t1->SSequenz = 1 - ctx->t1->SSequenz;
                } else {
#ifdef DEBUG
                    printf("Error: Unexpected R-Block.\n");
#endif
                    if (ccidT1Resynch(ctx,SrcNode,DestNode))
                        return(-1);
                }
            }

            if (ISIBLOCK(ctx->t1->Pcb)) {    /* Usual response to I-block     */
                if ((NS(ctx->t1->Pcb) != ctx->t1->RSequenz) || more) {
#ifdef DEBUG
                    printf("Asynchronous I-Block received as response.\n");
#endif
                    if (ccidT1Resynch(ctx,SrcNode,DestNode))
                        return(-1);
                } else {
                    ctx->t1->SSequenz = 1 - ctx->t1->SSequenz;
                    response = 1;
                }
            }
        }

        Buffer += Length;
    }

    return(0);
}



/*
 * Decode a received block into the data buffer passed to the application
 *
 */
int ccidT1ReceiveData(scr_t *ctx,
                     int SrcNode,
                     int DestNode,
                     unsigned char *Buffer,
                     int BuffLen) {
    int more,Length,ret;

    Length = 0;
    do  {

        if ((ctx->t1->InBuffLength > BuffLen) || (ctx->t1->InBuffLength == -1)) {
            ccidT1AbortChain(ctx,SrcNode,DestNode);
            return(ERR_MEMORY);                       /* Out of space in buffer            */
        }

        memcpy(Buffer, ctx->t1->InBuff, ctx->t1->InBuffLength);
        Buffer += ctx->t1->InBuffLength;
        BuffLen -= ctx->t1->InBuffLength;
        Length += ctx->t1->InBuffLength;

        ctx->t1->RSequenz = 1 - ctx->t1->RSequenz;

        more = MORE(ctx->t1->Pcb);     /* More block following ?            */

        if (more) {
            while (TRUE) {
                ret = ccidT1SendBlock(ctx,
                                     CODENAD(SrcNode, DestNode),
                                     CODERBLOCK(ctx->t1->RSequenz, 0),
                                     NULL, 0);

                ret = ccidT1GetBlock(ctx, SrcNode, DestNode);

                if (ret < 0)
                    return(ret);

                if (ISRBLOCK(ctx->t1->Pcb)) {
                    if (NR(ctx->t1->Pcb) != ctx->t1->SSequenz) {

#ifdef DEBUG
                        printf("Error: Invalid sequenz received in R-Block.\n");
#endif

                        if (ccidT1Resynch(ctx,SrcNode,DestNode))
                            return(-1);
                    }
                    continue;
                }

                break;
            }
        }
    } while (more);

    return(Length);
}



/*
 * Transport a data block using T=1 transmission protocol
 *
 */
int ccidT1Transport(scr_t *ctx,
                   int SrcNode,
                   int DestNode,
                   unsigned char *OBuffer,
                   int OBuffLen,
                   unsigned char *IBuffer,
                   int IBuffLen) {

    int ret;

#ifdef DEBUG
    printf("ccidT1SendData called\n");
#endif

    ret = ccidT1SendData(ctx, FALSE, SrcNode, DestNode, OBuffer, OBuffLen);

    if (ret < 0) {
#ifdef DEBUG
    printf("ccidT1SendData failed with rc = %i\n", ret);
#endif
    	return(ret);
    }

    ret = ccidT1ReceiveData(ctx, SrcNode, DestNode, IBuffer, IBuffLen);

#ifdef DEBUG
    if (ret < 0) {
    	printf("ccidT1ReceiveData failed with rc = %i\n", ret);
    }
#endif

    return(ret);
}



/*
 * Process a APDU using T=1 protocol
 *
 */
int ccidT1Process (struct scr *ctx,
                  unsigned int  lc,
                  unsigned char *cmd,
                  unsigned int  *lr,
                  unsigned char *rsp) {
    int rc;

    rc = ccidT1Transport(ctx, 0, 0, cmd, lc, rsp, *lr);

    if (rc < 0)
        return rc;

    *lr = rc;
    return 0;
}



/*
 * Initialize T=1 protocol driver module
 *
 */
int ccidT1Init (struct scr *ctx) {
    int rc;

    ctx->t1 = malloc(sizeof(ccidT1_t));

    ctx->CTModFunc = (CTModFunc_t) ccidT1Process;

    ccidT1InitProtocol(ctx);

    return 0;
}
