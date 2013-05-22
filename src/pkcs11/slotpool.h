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
 * Abstract :       Functions for slot-pool management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

#ifndef ___SLOTPOOL_H_INC___
#define ___SLOTPOOL_H_INC___


#include <pkcs11/p11generic.h>
#include <pkcs11/cryptoki.h>

#define MAX_SLOTS 8

int initSlotPool(struct p11SlotPool_t *pool);

int terminateSlotPool(struct p11SlotPool_t *pool);

int updateSlots(struct p11SlotPool_t *pool);

int closeSlot(struct p11Slot_t *slot);

int addSlot(struct p11SlotPool_t *pool, struct p11Slot_t *slot);

int findSlot(struct p11SlotPool_t *pool, CK_SLOT_ID slotID, struct p11Slot_t **slot);

int removeSlot(struct p11SlotPool_t *pool, CK_SLOT_ID slotID);

#endif /* ___SLOTPOOL_H_INC___ */
