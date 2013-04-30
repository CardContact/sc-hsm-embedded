/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2003. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  --------- 
 *
 * The Smart Card Development Platform (SCDP) provides a basic framework to
 * implement smartcard aware applications.
 *
 * Abstract :       Debug and logging functions
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

#ifndef ___DEBUG_H_INC___
#define ___DEBUG_H_INC___

#include <stdio.h>

#include <pkcs11/p11generic.h>

void decodeBCDString(unsigned char *Inbuff, int len, char *Outbuff);
int initDebug(struct p11Context_t *context);
int debug(unsigned char *log, ...);
int termDebug(struct p11Context_t *context);

#endif /* ___DEBUG_H_INC___ */
