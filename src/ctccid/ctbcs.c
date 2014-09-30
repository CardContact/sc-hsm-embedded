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
 * @file ctbcs.c
 * @author Frank Thater, Andreas Schwier
 * @brief Defines procedures for CTBCS commands
 */

#include <stdio.h>
#include <string.h>

#include "scr.h"
#include "ctbcs.h"
#include "ctapi.h"
#include "ccid_usb.h"
#include "ctccid_debug.h"

extern int ccidT1Init (struct scr *ctx);
extern int ccidAPDUInit (struct scr *ctx);


/**
 * Set requested response of CT-BCS command
 *
 * @param ctx Reader context
 * @param cmd Command
 * @param lr Length of response
 * @param rsp Response buffer
 * @return \ref OK, \ref ERR_MEMORY
 */
int setResponse(struct scr *ctx, unsigned char *cmd, unsigned int *lr,
				unsigned char *rsp)
{
	unsigned char index = 0;
	unsigned char what = cmd[3] & 0x0F;

	switch (what) {
	case 0x01: /* complete ATR     */

		if (*lr < ctx->LenOfATR + 2) {
			return ERR_MEMORY;
		}

		memcpy(rsp, ctx->ATR, ctx->LenOfATR);
		index = ctx->LenOfATR;
		rsp[index] = HIGH(SMARTCARD_SUCCESS);
		rsp[index + 1] = 0x01;
		*lr = ctx->LenOfATR + 2;
		break;
	case 0x02: /* historical Bytes */

		if (*lr < ctx->NumOfHB + 2) {
			return ERR_MEMORY;
		}

		memcpy(rsp, ctx->HCC, ctx->NumOfHB);
		index = ctx->NumOfHB;
		rsp[index] = HIGH(SMARTCARD_SUCCESS);
		rsp[index + 1] = 0x01;
		*lr = ctx->NumOfHB + 2;
		break;
	default: /* nothing          */
		memset(rsp, 0, sizeof(rsp));

		if (*lr < 2) {
			return ERR_MEMORY;
		}

		rsp[0] = HIGH(SMARTCARD_SUCCESS);
		rsp[1] = 0x01;
		*lr = 2;
		break;
	}

	return OK;
}



/**
 * CT-BCS Reset Card command
 *
 * @param ctx Reader context
 * @param lc Length of command
 * @param cmd Command
 * @param lr Length of response
 * @param rsp Response buffer
 * @return \ref OK, \ref ERR_MEMORY
 */
int ResetCard(struct scr *ctx, unsigned int lc, unsigned char *cmd,
			  unsigned int *lr, unsigned char *rsp)
{
	int response = 0;

	if (PC_to_RDR_IccPowerOn(ctx) < 0) {
		rsp[0] = HIGH(NOT_SUCCESSFUL);
		rsp[1] = LOW(NOT_SUCCESSFUL);
		*lr = 2;
		return OK;
	}

	if (RDR_APDUTransferMode(ctx))
		ccidAPDUInit(ctx);
	else
		ccidT1Init(ctx);

	if ((response = setResponse(ctx, cmd, lr, rsp)) < 0) {
		return response;
	}

	return OK;
}



/**
 * CT-BCS Request ICC command
 *
 * @param ctx Reader context
 * @param lc Length of command
 * @param cmd Command
 * @param lr Length of response
 * @param rsp Response buffer
 * @return \ref OK, \ref ERR_CT, \ref ERR_MEMORY
 */
int RequestICC(struct scr *ctx, unsigned int lc, unsigned char *cmd,
			   unsigned int *lr, unsigned char *rsp)
{
	int status, timeout;

	if ((lc > 4) && (cmd[4] == 1)) {
		timeout = cmd[5];
	} else {
		timeout = 0;
	}

	status = PC_to_RDR_GetSlotStatus(ctx);

	if (status < 0) {
		rsp[0] = HIGH(NOT_SUCCESSFUL);
		rsp[1] = LOW(NOT_SUCCESSFUL);
		*lr = 2;
		return ERR_CT;
	}

	timeout *= 4;

	do {

		status = PC_to_RDR_GetSlotStatus(ctx);

		if (status < 0) {
			rsp[0] = HIGH(NOT_SUCCESSFUL);
			rsp[1] = LOW(NOT_SUCCESSFUL);
			*lr = 2;
			return ERR_CT;
		}

		if ((status == ICC_PRESENT_AND_INACTIVE) || !timeout) {
			break;
		}

		usleep(250000);
		timeout--;
	} while (timeout);

	if (!timeout && (status == NO_ICC_PRESENT)) {
		rsp[0] = HIGH(W_NO_CARD_PRESENTED);
		rsp[1] = LOW(W_NO_CARD_PRESENTED);
		*lr = 2;
		return OK;
	}

	if ((status = ResetCard(ctx, lc, cmd, lr, rsp)) < 0) {
		return status;
	}

	return OK;
}



/**
 * CT-BCS Eject ICC command
 *
 * @param ctx Reader context
 * @param lc Length of command
 * @param cmd Command
 * @param lr Length of response
 * @param rsp Response buffer
 * @return \ref OK, \ref ERR_CT
 */
int EjectICC(struct scr *ctx, unsigned int lc, unsigned char *cmd,
			 unsigned int *lr, unsigned char *rsp)
{
	int status;
	unsigned char save_timeout;
	unsigned char timeout;

	/* Reader has no display or other goodies, so check for correct P2 parameter */
	/* Unmask bit 3, because we can always keep the card in the slot               */

	if ((cmd[3] & 0xFB) != 0x00) {
		rsp[0] = HIGH(WRONG_PARAMETERS_P1_P2);
		rsp[1] = LOW(WRONG_PARAMETERS_P1_P2);
		*lr = 2;
		return OK;
	}

	if ((lc > 4) && (cmd[4] > 0)) {
		timeout = cmd[5];
	} else {
		timeout = 0;
	}

	save_timeout = timeout;

	status = PC_to_RDR_IccPowerOff(ctx);

	if (status < 0) {
		rsp[0] = HIGH(NOT_SUCCESSFUL);
		rsp[1] = LOW(NOT_SUCCESSFUL);
		*lr = 2;
		return ERR_CT;
	}

	ctx->CTModFunc = NULL;
	ctx->LenOfATR = 0;
	ctx->NumOfHB = 0;

	save_timeout *= 4;

	if (save_timeout > 0) {
		do {

			status = PC_to_RDR_GetSlotStatus(ctx);

			if (status < 0) {
				rsp[0] = HIGH(NOT_SUCCESSFUL);
				rsp[1] = LOW(NOT_SUCCESSFUL);
				*lr = 2;
				return ERR_CT;
			}

			if (status == ICC_PRESENT_AND_INACTIVE || status == NO_ICC_PRESENT) {
				break;
			}

			usleep(250000);

		} while (--save_timeout);

	} else { /* Command OK,no timeout specified   */
		rsp[0] = HIGH(SMARTCARD_SUCCESS);
		rsp[1] = LOW(SMARTCARD_SUCCESS);
		*lr = 2;
		return OK;
	}

	if (save_timeout) { /* Command OK, card removed          */
		rsp[0] = HIGH(SMARTCARD_SUCCESS);
		rsp[1] = LOW(SMARTCARD_SUCCESS);
		*lr = 2;
		return OK;
	}

	if ((!save_timeout) && (timeout > 0)) { /* warning: card not removed */
		rsp[0] = HIGH(W_NO_CARD_PRESENTED);
		rsp[1] = LOW(W_NO_CARD_PRESENTED);
		*lr = 2;
	}

	return OK;
}



/**
 * Get ICC status
 *
 * @param ctx Reader context
 * @param lr Length of response
 * @param rsp Response buffer
 * @return \ref OK, \ref ERR_CT, \ref ERR_MEMORY
 */
int GetICCStatus(struct scr *ctx, unsigned int *lr, unsigned char *rsp)
{
	int status;

	status = PC_to_RDR_GetSlotStatus(ctx);

	if (status < 0) {
		rsp[0] = HIGH(NOT_SUCCESSFUL);
		rsp[1] = LOW(NOT_SUCCESSFUL);
		*lr = 2;
		return ERR_CT;
	}

	if (*lr < 5) {
		return ERR_MEMORY;
	}

	rsp[0] = 0x80;
	rsp[1] = 0x01;
	rsp[2] = 0x00; /* Set ICC Status DO - default is no ICC present */

	if (status == ICC_PRESENT_AND_INACTIVE) {
		rsp[2] |= 0x03; /* card in, no CVCC                  */
	}

	if (status == ICC_PRESENT_AND_ACTIVE) {
		rsp[2] |= 0x05; /* card in, CVCC on                  */
	}

	rsp[3] = HIGH(SMARTCARD_SUCCESS);
	rsp[4] = LOW(SMARTCARD_SUCCESS);
	*lr = 5;

	return OK;
}



/**
 * CT-BCS Get Status command
 *
 * @param ctx Reader context
 * @param cmd Command
 * @param lr Length of response
 * @param rsp Response buffer
 * @return \ref OK, \ref ERR_CT, \ref ERR_MEMORY
 */
int GetStatus(struct scr *ctx, unsigned char *cmd, unsigned int *lr,
			  unsigned char *rsp)
{
	int response;
	unsigned char func_unit = cmd[2];
	unsigned char what = cmd[3];

#ifdef DEBUG
	ctccid_debug("GetStatus(FU=%02x,%02x)\n", func_unit, what);
#endif

	if (func_unit == 0x00) {

		switch (what) {

		case 0x46: /* Card Manufacturer DO */

			if (*lr < 19) {
				return ERR_MEMORY;
			}

			memcpy(rsp, "\x46\x0F" "DESCMSCR3X00000", 17);
			rsp[17] = HIGH(SMARTCARD_SUCCESS);
			rsp[18] = LOW(SMARTCARD_SUCCESS);
			*lr = 17 + 2;
			break;

		case 0x80: /* ICC Status DO */

			if ((response = GetICCStatus(ctx, lr, rsp)) < 0) {
				return response;
			}

			break;

		case 0x81: /* Functional Unit DO */

			if (*lr < 5) {
				return ERR_MEMORY;
			}

			rsp[0] = 0x81; /* TAG */
			rsp[1] = 0x01; /* Length of following data */
			rsp[2] = 0x01; /* Status for CT/ICC-Interface1 */
			rsp[3] = HIGH(SMARTCARD_SUCCESS);
			rsp[4] = LOW(SMARTCARD_SUCCESS);
			*lr = 5;
			break;
		}

	} else {
		if ((response = GetICCStatus(ctx, lr, rsp)) < 0) {
			return response;
		}
	}

	return OK;
}

