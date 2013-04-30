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
 * Author :         Frank Thater
 *
 * Last modified:   2013-04-22
 *
 *****************************************************************************/

#ifndef _CCID_USB_H_
#define _CCID_USB_H_

#include "scr.h"

#define ERR_ICC_MUTE					0xFE
#define ERR_XFR_OVERRUN					0xFC
#define ERR_HW_ERROR					0xFB

#define MSG_TYPE_PC_to_RDR_SetParameters	0x61
#define MSG_TYPE_PC_to_RDR_IccPowerOn 		0x62
#define MSG_TYPE_PC_to_RDR_IccPowerOff 		0x63
#define MSG_TYPE_PC_to_RDR_GetSlotStatus 	0x65
#define MSG_TYPE_PC_to_RDR_XfrBlock			0x6F
#define MSG_TYPE_RDR_to_PC_DataBlock		0x80
#define MSG_TYPE_RDR_to_PC_SlotStatus		0x81
#define MSG_TYPE_RDR_to_PC_Parameters      0x82

#define ICC_PRESENT_AND_ACTIVE				0x00
#define ICC_PRESENT_AND_INACTIVE			0x01
#define NO_ICC_PRESENT						0x02
#define ICC_STATUS_MASK						0x03

#define MATCH(x,y) ((x >= (y - y / 20)) && (x <= (y + y / 20)))

int PC_to_RDR_IccPowerOn(scr_t *ctx, unsigned int *len, unsigned char *buf);

int PC_to_RDR_IccPowerOff(scr_t *ctx);

int PC_to_RDR_XfrBlock(scr_t *ctx, unsigned int outlen, unsigned char *outbuf);

int RDR_to_PC_DataBlock(scr_t *ctx, unsigned int *inlen, unsigned char *inbuf);

int PC_to_RDR_GetSlotStatus(scr_t *ctx);

static int DetermineBaudrate(int F, int D);

static int DecodeATR(scr_t *ctx);

int PC_to_RDR_SetParameters(scr_t *ctx);

int MaxCCIDMessageLength(scr_t *ctx);

#endif
