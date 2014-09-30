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
 * @file ccid_usb.h
 * @author Frank Thater
 * @brief Functions for bulks transfers as specified by USB Integrated Circuit(s)
 *        Card Devices, Version 1.0
 */

#ifndef _CCID_USB_H_
#define _CCID_USB_H_

#include "scr.h"

/**
 * Maximum size of receive buffer
 */
#define BUFFMAX    261

#define ERR_ICC_MUTE				0xFE
#define ERR_XFR_OVERRUN				0xFC
#define ERR_HW_ERROR				0xFB

#define MSG_TYPE_PC_to_RDR_SetParameters	0x61
#define MSG_TYPE_PC_to_RDR_IccPowerOn		0x62
#define MSG_TYPE_PC_to_RDR_IccPowerOff		0x63
#define MSG_TYPE_PC_to_RDR_GetSlotStatus	0x65
#define MSG_TYPE_PC_to_RDR_XfrBlock			0x6F
#define MSG_TYPE_RDR_to_PC_DataBlock		0x80
#define MSG_TYPE_RDR_to_PC_SlotStatus		0x81
#define MSG_TYPE_RDR_to_PC_Parameters		0x82

#define ICC_PRESENT_AND_ACTIVE		0x00
#define ICC_PRESENT_AND_INACTIVE	0x01
#define NO_ICC_PRESENT				0x02
#define ICC_STATUS_MASK				0x03

#define MATCH(x,y) ((x >= (y - y / 20)) && (x <= (y + y / 20)))

int PC_to_RDR_IccPowerOn(scr_t *ctx);

int PC_to_RDR_IccPowerOff(scr_t *ctx);

int RDR_APDUTransferMode(scr_t *ctx);

int PC_to_RDR_XfrBlock(scr_t *ctx, unsigned int outlen, unsigned char *outbuf, unsigned char level);

int RDR_to_PC_DataBlock(scr_t *ctx, unsigned int *inlen, unsigned char *inbuf, unsigned char *status, unsigned char *error, unsigned char *chain);

int PC_to_RDR_GetSlotStatus(scr_t *ctx);

int DetermineBaudrate(int F, int D);

int DecodeATRValues(scr_t *ctx);

int PC_to_RDR_SetParameters(scr_t *ctx);

#endif
