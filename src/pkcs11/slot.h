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
 * Abstract :       Functions for token management in a specific slot
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

#ifndef ___SLOT_H_INC___
#define ___SLOT_H_INC___

#include <pkcs11/cryptoki.h>
#include <pkcs11/p11generic.h>

int addToken(struct p11Slot_t *slot, struct p11Token_t *token);

int removeToken(struct p11Slot_t *slot, struct p11Token_t *token);

int checkForToken(struct p11Slot_t *slot, struct p11Token_t **token);

#endif /* ___SLOT_H_INC___ */
