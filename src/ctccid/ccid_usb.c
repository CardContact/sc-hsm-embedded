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
    default:
        printf("Unknown message type");
        break;
    }

    while(len--) {
        printf("%02x ", *mem);
        mem++;
    }

    printf("\n");
}
#endif



int PC_to_RDR_IccPowerOn(scr_t *ctx, unsigned int *len, unsigned char *buf) {

    int rc;
    unsigned char msg[10];
    unsigned int atrlen;

    memset(msg, 0, 10);
    msg[0] = MSG_TYPE_PC_to_RDR_IccPowerOn;

#ifdef DEBUG
    CCIDDump(msg, 10);
#endif

    rc = Write(ctx->device, 10, msg);

    if (rc < 0) {
        return rc;
    }

    rc = Read(ctx->device, len, buf);

    if (rc < 0) {
        return rc;
    }

#ifdef DEBUG
    CCIDDump(buf, *len);
#endif

    if (*len < 10 || buf[0] != MSG_TYPE_RDR_to_PC_DataBlock || buf[5] != 0x00 || buf[6] != 0x00) { // wrong length, message type, slot or sequence number
        return -1;
    }

    atrlen = (buf[4] << 24) + (buf[3] << 16) + (buf[2] << 8) + buf[1];

    memset(ctx->ATR, 0, sizeof(ctx->ATR));
    memcpy(ctx->ATR, (buf + 10), atrlen);
    ctx->LenOfATR = atrlen;

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



int MaxCCIDMessageLength(scr_t *ctx) {

    /* Message length as indicated in descriptor - CCID header (10 bytes)) */
    return (MaxMessageLength(ctx->device) - 10);
}
