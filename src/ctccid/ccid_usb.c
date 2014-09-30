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
 * @file ccid_usb.c
 * @author Frank Thater
 * @brief Functions for bulks transfers as specified by USB Integrated Circuit(s)
 *        Card Devices, Version 1.0
 */

#include <stdint.h>
#include <string.h>

#ifdef DEBUG
#include <stdio.h>
#include "ctccid_debug.h"
#endif

#include "ccid_usb.h"
#include "scr.h"

int FTable[]  = { 372, 372, 558, 744, 1116, 1488, 1860, -1, -1, 512, 768, 1024, 1536, 2048, -1, -1};
int DTable[]  = { -1, 1, 2, 4, 8, 16, 32, -1, 12, 20, -1, -1, -1, -1, -1, -1};

#ifdef DEBUG

/**
 * Dump the content of a CCID message
 * @param mem Pointer to array holding the message
 * @param len Length of message
 */
void CCIDDump(unsigned char *mem, int len)
{

        switch(mem[0]) {
        case MSG_TYPE_PC_to_RDR_IccPowerOn:
                ctccid_debug("CCID PC_to_RDR_IccPowerOn\n");
                break;
        case MSG_TYPE_PC_to_RDR_IccPowerOff:
                ctccid_debug("CCID PC_to_RDR_IccPowerOff\n");
                break;
        case MSG_TYPE_PC_to_RDR_GetSlotStatus:
                ctccid_debug("CCID PC_to_RDR_GetSlotStatus\n");
                break;
        case MSG_TYPE_PC_to_RDR_XfrBlock        :
                ctccid_debug("CCID PC_to_RDR_XfrBlock\n");
                break;
        case MSG_TYPE_RDR_to_PC_DataBlock:
                ctccid_debug("CCID RDR_to_PC_DataBlock\n");
                break;
        case MSG_TYPE_RDR_to_PC_SlotStatus:
                ctccid_debug("CCID RDR_to_PC_SlotStatus\n");
                break;
        case MSG_TYPE_PC_to_RDR_SetParameters:
                ctccid_debug("CCID PC_to_RDR_SetParameters\n");
                break;
        case MSG_TYPE_RDR_to_PC_Parameters:
                ctccid_debug("CCID RDR_to_PC_Parameters\n");
                break;
        default:
                ctccid_debug("Unknown message type\n");
                break;
        }

        ctccid_dump(mem, len);
}
#endif



/**
 * Power on the ICC in the reader and set the ATR and the communication parameters as specified
 *
 * @param ctx Reader context
 * @return 0 on success, negative value otherwise
 */
int PC_to_RDR_IccPowerOn(scr_t *ctx)
{

        int rc;
        unsigned char msg[10 + MAX_ATR];
        unsigned int atrlen, l = 10 + MAX_ATR;

        memset(msg, 0, 10);
        msg[0] = MSG_TYPE_PC_to_RDR_IccPowerOn;

#ifdef DEBUG
        CCIDDump(msg, 10);
#endif

        rc = USB_Write(ctx->device, 10, msg);

        if (rc < 0) {
                return rc;
        }

        rc = USB_Read(ctx->device, &l, msg);

        if (rc < 0) {
                return rc;
        }

#ifdef DEBUG
        CCIDDump(msg, l);
#endif

        /* check length, message type, slot and sequence number */
        if (l < 10 || msg[0] != MSG_TYPE_RDR_to_PC_DataBlock || msg[5] != 0x00 || msg[6] != 0x00) {
                return -1;
        }

        atrlen = (msg[4] << 24) + (msg[3] << 16) + (msg[2] << 8) + msg[1];

        memset(ctx->ATR, 0, sizeof(ctx->ATR));
        memcpy(ctx->ATR, (msg + 10), atrlen);
        ctx->LenOfATR = atrlen;

        rc = DecodeATRValues(ctx);

        if (rc < 0) {
                return rc;
        }

        rc = PC_to_RDR_SetParameters(ctx);

        if (rc < 0) {
                return rc;
        }

        return 0;
}



/**
 * Calculate the current baudrate depending on the values of F and D
 *
 * @param F Clock rate conversion integer
 * @param D Baud rate adjustment integer
 * @return Calculated baudrate
 */
int DetermineBaudrate(int F, int D)
{
        int br;

        br = 14318000 * D / (F * 4);

        if (MATCH(br, 9600)) {
                br = 9600;
        } else if (MATCH(br, 19200)) {
                br = 19200;
        } else if (MATCH(br, 38400)) {
                br = 38400;
        } else if (MATCH(br, 57600)) {
                br = 57600;
        } else if (MATCH(br, 115200)) {
                br = 115200;
        } else {
                br = -1;
        }

        return br;
}



/**
 * Decode protocol specified ATR values and store them in the reader context
 *
 * @param ctx Reader context
 * @return 0 on success, negative value otherwise
 */
int DecodeATRValues(scr_t *ctx)
{

        int atrp;
        unsigned char i;
        unsigned char temp;
        unsigned char help;

        ctx->FI = 1;
        ctx->DI = 1;

        ctx->IFSC = 32;              /* T=1: information field size TA(i)*/
        ctx->CWI = 13;               /* T=1: Char waiting time indx TB(i)*/
        ctx->BWI = 4;                /* T=1: Block waiting time inx TB(i)*/

        atrp = 0;

        /* Check initial char in ATR */
        temp = ctx->ATR[atrp++];

        if (temp != 0x3B && temp != 0x3F) {
                return -1;
        }

        /* Get T0 */
        temp = ctx->ATR[atrp++];
        ctx->NumOfHB = temp & 0x0F;

        i = 1;

        do {
                help = (temp >> 4);

                if (help & 1) { /* Get TAx                          */
                        if (i == 1) { /* TA(1) present ?                */
                                temp = ctx->ATR[atrp++];
                                ctx->FI = temp >> 4;
                                ctx->DI = temp & 0xF;
                        }

                        if (i > 2) {
                                temp = ctx->ATR[atrp++];
                                ctx->IFSC = temp;
                        }
                }

                if (help & 2) { /* Get TBx                          */
                        temp = ctx->ATR[atrp++];

                        if (i > 2) {
                                ctx->CWI = temp & 0x0F;
                                ctx->BWI = temp >> 4;
                        }
                }

                if (help & 4) { /* Get TCx                          */
                        temp = ctx->ATR[atrp++];

                        if (i == 1) { /* TC(1) present ?                  */
                                ctx->EXTRA_GUARD_TIME = temp;
                        }
                }

                if (help & 8) { /* Get TDx                          */
                        temp = ctx->ATR[atrp++];
                } else {
                        temp = 0;
                }

                i++;

        } while (temp);

        for (i = 0; i < ctx->NumOfHB; i++) {
                ctx->HCC[i] = ctx->ATR[atrp++];
        }

        ctx->Baud = DetermineBaudrate(FTable[ctx->FI], DTable[ctx->DI]);

        return 0;
}



int RDR_APDUTransferMode(scr_t *ctx)
{
	unsigned char const *desc;
	int length, apdu_transfer = 0;

	USB_GetCCIDDescriptor(ctx->device, &desc, &length);

	if (length == 54)
		apdu_transfer = desc[42] & 0x04;

	return apdu_transfer;
}



/**
 * Set communication protocol parameters (guard time, FI, DI, IFSC)
 *
 * @param ctx Reader context
 * @return 0 on success, negative value otherwise
 */
int PC_to_RDR_SetParameters(scr_t *ctx)
{

        unsigned char msg[17];
        int rc;
        unsigned int len = 0;

        /* 61 07 00 00 00 00 0F 01 00 00 18 10 02 45 00 FE 00 */
        memset(msg, 0, 17);
        msg[0] = MSG_TYPE_PC_to_RDR_SetParameters;
        msg[1] = 0x07;
        msg[7] = 0x01;  /* T=1 protocol */
        msg[10] = (ctx->FI << 4) | (ctx->DI & 0x0F); /* FI, DI */
        msg[11] = 0x10; /* CRC, direct convention */
        msg[12] = ctx->EXTRA_GUARD_TIME; /* Extra guard time */
        msg[13] = (ctx->BWI << 4) | (ctx->CWI & 0x0F); /* BWI, CWI */
        msg[14] = 0x00; /* Stopping clock is not allowed */
        msg[15] = ctx->IFSC; /* Negotiated IFSC = 254 bytes */
        msg[16] = 0x00; /* Default value for NAD */

#ifdef DEBUG
        CCIDDump(msg, 17);
#endif

        rc = USB_Write(ctx->device, 17, msg);

        if (rc < 0) {
                return rc;
        }

        len = 17;
        rc = USB_Read(ctx->device, &len, msg);

        if (rc < 0) {
                return rc;
        }

#ifdef DEBUG
        CCIDDump(msg, len);
#endif

        return 0;
}



/**
 * Get the current state of the reader slot
 *
 * @param ctx Reader context
 * @return \ref ICC_PRESENT_AND_INACTIVE, \ref ICC_PRESENT_AND_ACTIVE, \ref NO_ICC_PRESENT or -1 on error
 */
int PC_to_RDR_GetSlotStatus(scr_t *ctx)
{

        unsigned char msg[10];
        unsigned char buf[10];
        unsigned int len = 10, slotstatus;
        int rc;

        memset(msg, 0, 10);
        msg[0] = MSG_TYPE_PC_to_RDR_GetSlotStatus;

#ifdef DEBUG
        CCIDDump(msg, 10);
#endif

        rc = USB_Write(ctx->device, 10, msg);

        if (rc < 0) {
                return rc;
        }

        rc = USB_Read(ctx->device, &len, buf);

        if (rc < 0) {
                return rc;
        }

#ifdef DEBUG
        CCIDDump(buf, len);
#endif

        /* check length, message type, slot and sequence number */
        if (len != 10 || buf[0] != MSG_TYPE_RDR_to_PC_SlotStatus || buf[5] != 0x00 || buf[6] != 0x00) {
                return -1;
        }

        slotstatus = buf[7];

        return (slotstatus & ICC_STATUS_MASK);
}



/**
 * Power off the ICC in the reader
 *
 * @param ctx Reader context
 * @return 0 on success, negative value otherwise
 */
int PC_to_RDR_IccPowerOff(scr_t *ctx)
{

        unsigned char msg[10];
        unsigned char buf[10];
        unsigned int len = 10;
        int rc;

        memset(msg, 0, 10);
        msg[0] = MSG_TYPE_PC_to_RDR_IccPowerOff;

#ifdef DEBUG
        CCIDDump(msg, 10);
#endif

        rc = USB_Write(ctx->device, 10, msg);

        if (rc < 0) {
                return rc;
        }

        rc = USB_Read(ctx->device, &len, buf);

        if (rc < 0) {
                return rc;
        }

#ifdef DEBUG
        CCIDDump(buf, len);
#endif

        /* check length, message type, slot and sequence number */
        if (len != 10 || buf[0] != MSG_TYPE_RDR_to_PC_SlotStatus || buf[5] != 0x00 || buf[6] != 0x00) {
                return -1;
        }

        return 0;
}



/**
 * Exchange data block between PC and reader
 *
 * @param ctx Reader context
 * @param outlen Length of outgoing data
 * @param outbuf Outgoing data buffer
 * @param level of exchanged APDU (0000-first and only block, 0001-first chained command block, 0002-last command block, 0003-intermediate command block, 0010-empty block)
 * @return 0 on success, negative value otherwise
 */
int PC_to_RDR_XfrBlock(scr_t *ctx, unsigned int outlen, unsigned char *outbuf, unsigned char level)
{

        int rc;
        unsigned char msg[10 + BUFFMAX];

        if (outlen > BUFFMAX) {
#ifdef DEBUG
                ctccid_debug("PC_to_RDR_XfrBlock outlen > BUFFMAX\n");
#endif
                return -1;
        }

        memset(msg, 0, 10);
        msg[0] = MSG_TYPE_PC_to_RDR_XfrBlock;
        msg[1] = outlen & 0xFF;
        msg[2] = (outlen >> 8) & 0xFF;
        msg[3] = (outlen >> 16) & 0xFF;
        msg[4] = (outlen >> 24) & 0xFF;
        msg[8] = level & 0xFF,
        msg[9] = (level >> 8) & 0xFF;
        memcpy(msg + 10, outbuf, outlen);

#ifdef DEBUG
        CCIDDump(msg, (10 + outlen));
#endif
        rc = USB_Write(ctx->device, (10 + outlen), msg);

        if (rc < 0) {
                return rc;
        }

        return 0;
}



/**
 * Exchange data block between reader and PC
 *
 * @param ctx Reader context
 * @param inlen Length of data buffer/actual length of incoming data
 * @param inbuf Incoming data buffer
 * @return 0 on success, negative value otherwise
 */
int RDR_to_PC_DataBlock(scr_t *ctx, unsigned int *inlen, unsigned char *inbuf, unsigned char *status, unsigned char *error, unsigned char *chain)
{

        unsigned int l;
        unsigned char msg[10 + BUFFMAX];
        int rc;

        if (*inlen > BUFFMAX) {
#ifdef DEBUG
                ctccid_debug("RDR_to_PC_DataBlock *inlen > BUFFMAX\n");
#endif
                return -1;
        }

        while (1) {
                l = sizeof(msg);
                rc = USB_Read(ctx->device, &l, msg);

                if (rc < 0) {
                        *inlen = 0;
                        return rc;
                }

#ifdef DEBUG
                CCIDDump(msg, l);
#endif

                /* check length, message type, slot and sequence number */
                if (l < 10 || msg[0] != MSG_TYPE_RDR_to_PC_DataBlock || msg[5] != 0x00 || msg[6] != 0x00) {
                        *inlen = 0;
                        return -1;
                }

                if (msg[7] & 0x80) {			// Card requests waiting time extension
                        continue;
                }
                break;
        }

        if (status)
                *status = msg[7];
        if (error)
                *error = msg[8];
        if (chain)
                *chain = msg[9];
#ifdef DEBUG
        memset(inbuf, 0x00, BUFFMAX);
#endif

        *inlen = (l - 10);

        memcpy(inbuf, msg + 10, *inlen);

        return 0;
}
