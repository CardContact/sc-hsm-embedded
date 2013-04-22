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
 * Abstract :       Defines tools/types for CTBCS commands
 *
 * Author :         Frank Thater (FTH)
 *
 * Last modified:   2013-04-22
 *
 *****************************************************************************/

#ifndef _CTBCS_H_
#define _CTBCS_H_

#include "scr.h"

#define CTBCS_DATA_STATUS_CARD 4

int ResetTerminal(struct scr *ctx, unsigned int *lr, unsigned char *rsp);

int ResetCard(struct scr *ctx, unsigned int lc, unsigned char *cmd,
        unsigned int *lr, unsigned char *rsp);

int RequestICC(struct scr *ctx, unsigned int lc, unsigned char *cmd,
        unsigned int *lr, unsigned char *rsp);

int EjectICC(struct scr *ctx, unsigned int lc, unsigned char *cmd,
        unsigned int *lr, unsigned char *rsp);

int GetStatus(struct scr *ctx, unsigned char *cmd, unsigned int *lr,
        unsigned char *rsp);

#endif

