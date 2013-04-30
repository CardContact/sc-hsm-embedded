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
 * Abstract :       Functions for bulks transfers as specified by USB Integrated Circuit(s)
 * 					Card Devices, Version 1.0
 *
 *
 * Author :         Frank Thater
 *
 * Last modified:   2013-04-22
 *
 *****************************************************************************/

#include <stdint.h>
#include <string.h>

#ifdef DEBUG
#include <stdio.h>
#endif

#include "ccid_usb.h"
#include "scr.h"

int FTable[]  = { 372, 372, 558, 744, 1116, 1488, 1860, -1, -1, 512, 768, 1024, 1536, 2048, -1, -1};
int DTable[]  = { -1, 1, 2, 4, 8, 16, 32, -1, 12, 20, -1, -1, -1, -1, -1, -1};

#ifdef DEBUG
/*
 * Dump the content any type of CCID message
 *
 */
void CCIDDump(unsigned char *mem, int len) {

    switch(mem[0]) {
    case MSG_TYPE_PC_to_RDR_IccPowerOn:
        printf("CCID PC_to_RDR_IccPowerOn\n");
        break;
    case MSG_TYPE_PC_to_RDR_IccPowerOff:
        printf("CCID PC_to_RDR_IccPowerOff\n");
        break;
    case MSG_TYPE_PC_to_RDR_GetSlotStatus:
        printf("CCID PC_to_RDR_GetSlotStatus\n");
        break;
    case MSG_TYPE_PC_to_RDR_XfrBlock	:
        printf("CCID PC_to_RDR_XfrBlock\n");
        break;
    case MSG_TYPE_RDR_to_PC_DataBlock:
        printf("CCID RDR_to_PC_DataBlock\n");
        break;
    case MSG_TYPE_RDR_to_PC_SlotStatus:
        printf("CCID RDR_to_PC_SlotStatus\n");
        break;
    case MSG_TYPE_PC_to_RDR_SetParameters:
        printf("CCID PC_to_RDR_SetParameters\n");
        break;
    case MSG_TYPE_RDR_to_PC_Parameters:
        printf("CCID RDR_to_PC_Parameters\n");
        break;
    default:
        printf("Unknown message type\n");
        break;
    }

    while(len--) {
        printf("%02x ", *mem);
        mem++;
    }

    printf("\n");
}
#endif



int PC_to_RDR_IccPowerOn(scr_t *ctx) {

    int rc;
    unsigned char msg[10 + MAX_ATR];
    unsigned int atrlen, l = 10 + MAX_ATR;

    memset(msg, 0, 10);
    msg[0] = MSG_TYPE_PC_to_RDR_IccPowerOn;

#ifdef DEBUG
    CCIDDump(msg, 10);
#endif

    rc = Write(ctx->device, 10, msg);

    if (rc < 0) {
        return rc;
    }

    rc = Read(ctx->device, &l, msg);

    if (rc < 0) {
        return rc;
    }

#ifdef DEBUG
    CCIDDump(msg, l);
#endif

    if (l < 10 || msg[0] != MSG_TYPE_RDR_to_PC_DataBlock || msg[5] != 0x00 || msg[6] != 0x00) { // wrong length, message type, slot or sequence number
        return -1;
    }

    atrlen = (msg[4] << 24) + (msg[3] << 16) + (msg[2] << 8) + msg[1];

    memset(ctx->ATR, 0, sizeof(ctx->ATR));
    memcpy(ctx->ATR, (msg + 10), atrlen);
    ctx->LenOfATR = atrlen;

    rc = DecodeATR(ctx);

    if (rc < 0) {
        return rc;
    }

    rc = PC_to_RDR_SetParameters(ctx);

    if (rc < 0) {
        return rc;
    }

    return 0;
}



static int DetermineBaudrate(int F, int D) {
    int br;

    br = 14318000 * D / (F * 4);

    if (MATCH(br, 9600)) {
        br = 9600;
    }
    else if (MATCH(br, 19200)) {
        br = 19200;
    }
    else if (MATCH(br, 38400)) {
        br = 38400;
    }
    else if (MATCH(br, 57600)) {
        br = 57600;
    }
    else if (MATCH(br, 115200)) {
        br = 115200;
    }
    else {
        br = -1;
    }

    return br;
}



static int DecodeATR(scr_t *ctx) {

    int atrp,rc;
    int F,Fi;
    unsigned char i;
    unsigned char temp;
    unsigned char help;

    F = Fi = 372;
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



int PC_to_RDR_SetParameters(scr_t *ctx) {

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

    rc = Write(ctx->device, 17, msg);

    if (rc < 0) {
        return rc;
    }

    len = 17;
    rc = Read(ctx->device, &len, msg);

    if (rc < 0) {
        return rc;
    }

#ifdef DEBUG
    CCIDDump(msg, len);
#endif

    return 0;
}



int PC_to_RDR_GetSlotStatus(scr_t *ctx) {

    unsigned char msg[10];
    unsigned char buf[10];
    unsigned int len = 10, rc, slotstatus;

    memset(msg, 0, 10);
    msg[0] = MSG_TYPE_PC_to_RDR_GetSlotStatus;

#ifdef DEBUG
    CCIDDump(msg, 10);
#endif

    rc = Write(ctx->device, 10, msg);

    if (rc < 0) {
        return rc;
    }

    rc = Read(ctx->device, &len, buf);

    if (rc < 0) {
        return rc;
    }

#ifdef DEBUG
    CCIDDump(buf, len);
#endif

    if (len != 10 || buf[0] != MSG_TYPE_RDR_to_PC_SlotStatus || buf[5] != 0x00 || buf[6] != 0x00) { // Wrong length, message type, slot or sequence number
        return -1;
    }

    slotstatus = buf[7];

    return (slotstatus & ICC_STATUS_MASK);
}



int PC_to_RDR_IccPowerOff(scr_t *ctx) {

    unsigned char msg[10];
    unsigned char buf[10];
    unsigned int len = 10, rc, slotstatus;

    memset(msg, 0, 10);
    msg[0] = MSG_TYPE_PC_to_RDR_IccPowerOff;

#ifdef DEBUG
    CCIDDump(msg, 10);
#endif

    rc = Write(ctx->device, 10, msg);

    if (rc < 0) {
        return rc;
    }

    rc = Read(ctx->device, &len, buf);

    if (rc < 0) {
        return rc;
    }

#ifdef DEBUG
    CCIDDump(buf, len);
#endif

    if (len != 10 || buf[0] != MSG_TYPE_RDR_to_PC_SlotStatus || buf[5] != 0x00 || buf[6] != 0x00) { // Wrong length, message type, slot or sequence number
        return -1;
    }

    return 0;
}



int PC_to_RDR_XfrBlock(scr_t *ctx, unsigned int outlen, unsigned char *outbuf) {

    int rc;
    unsigned char msg[10 + outlen];

    memset(msg, 0, 10);
    msg[0] = MSG_TYPE_PC_to_RDR_XfrBlock;
    msg[1] = outlen & 0xFF;
    msg[2] = (outlen >> 8) & 0xFF;
    msg[3] = (outlen >> 16) & 0xFF;
    msg[4] = (outlen >> 24) & 0xFF;

    memcpy(msg + 10, outbuf, outlen);

#ifdef DEBUG
    CCIDDump(msg, (10 + outlen));
#endif
    rc = Write(ctx->device, (10 + outlen), msg);

    if (rc < 0) {
        return rc;
    }

    return 0;
}



int RDR_to_PC_DataBlock(scr_t *ctx, unsigned int *inlen, unsigned char *inbuf) {

    int rc;
    unsigned int l = 10 + *inlen;
    unsigned char msg[10 + *inlen];

    rc = Read(ctx->device, &l, msg);

    if (rc < 0) {
        *inlen = 0;
        return rc;
    }

#ifdef DEBUG
    CCIDDump(msg, l);
#endif

    if (l < 10 || msg[0] != MSG_TYPE_RDR_to_PC_DataBlock || msg[5] != 0x00 || msg[6] != 0x00) { // Wrong length, message type, slot or sequence number
        *inlen = 0;
        return -1;
    }

#ifdef DEBUG
    memset(inbuf, 0x00, 261);
#endif

    *inlen = (l - 10);

    memcpy(inbuf, msg + 10, *inlen);

    return 0;
}
