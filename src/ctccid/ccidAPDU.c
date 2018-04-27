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
 * @brief Implementation of APDU Transfer Mode for USB CCID
 */

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <common/memset_s.h>

#include "ctapi.h"
#include "ccid_usb.h"
#include "ctccid_debug.h"



/**
 * Process a APDU using the CCID APDU transfer mode
 *
 * @param ctx Reader context
 * @param lc Length of command APDU
 * @param cmd Command APDU
 * @param lr Length of response APDU
 * @param rsp Response APDU
 * @return 0 on success, -1 on error
 */
static int ccidAPDUProcess (struct scr *ctx,
				   unsigned int  lc,
				   unsigned char *cmd,
				   unsigned int  *lr,
				   unsigned char *rsp)
{
	int rc,r,maxlr;
	unsigned int len;
	unsigned char buf[BUFFMAX],*po,status,error,chain;
	unsigned short level = 0;

	maxlr = *lr;
	*lr = 0;
	po = cmd;
	while (lc > 0) {
		len = lc;
		if (lc > BUFFMAX) {
			if (level)
				level = 3;			// Intermediate extended command
			else
				level = 1;			// First extended command
			len = BUFFMAX;
		} else {
			if (level)
				level = 2;			// Final extended command
		}

		rc = PC_to_RDR_XfrBlock(ctx, len, po, level);
		if (rc < 0) {
			memset_s(buf, sizeof(buf), 0, sizeof(buf));
			return -1;
		}

		lc -= len;
		po += len;

		len = BUFFMAX;
		rc = RDR_to_PC_DataBlock(ctx, &len, buf, &status, &error, &chain);
		if (rc < 0) {
			memset_s(buf, sizeof(buf), 0, sizeof(buf));
			return -1;
		}
	}

	r = 0;
	while (1) {
		if (len > maxlr) {
			len = maxlr;
			r = ERR_MEMORY;
		}

		memcpy(rsp, buf, len);
		rsp += len;
		maxlr -= len;
		*lr += len;

		if ((chain == 1) || (chain == 3)) {
			rc = PC_to_RDR_XfrBlock(ctx, 0, NULL, 0x10);
			if (rc < 0) {
				memset_s(buf, sizeof(buf), 0, sizeof(buf));
				return -1;
			}
			len = BUFFMAX;
			rc = RDR_to_PC_DataBlock(ctx, &len, buf, &status, &error, &chain);
			if (rc < 0) {
				memset_s(buf, sizeof(buf), 0, sizeof(buf));
				return -1;
			}
			continue;
		}
		break;
	}

	memset_s(buf, sizeof(buf), 0, sizeof(buf));
	return r;
}



/**
 * Initialize T=1 protocol driver module
 *
 * @param ctx Reader context
 */
int ccidAPDUInit (struct scr *ctx)
{
	ctx->CTModFunc = (CTModFunc_t) ccidAPDUProcess;

	return 0;
}
