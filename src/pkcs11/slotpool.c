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

/**
 * \file    slotpool.c
 * \author  Frank Thater (fth)
 * \brief   Functions for slot-pool management
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>

extern struct p11Context_t *context;



/**
 * initSlotPool initializes the slot-pool structure.
 *
 * Call CT_init with increasing port number to determine number of readers attached
 *
 * Token found in a slot are added to specific slot structure for later use. 
 *
 * @param pool       Pointer to slot-pool structure.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_CRYPTOKI_NOT_INITIALIZED           </TD>
 *                   <TD>The cryptoki has not been initialized  </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_GENERAL_ERROR                      </TD>
 *                   <TD>General error                          </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_HOST_MEMORY                        </TD>
 *                   <TD>Error getting memory (malloc)          </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_HOST_MEMORY                        </TD>
 *                   <TD>Error getting memory (malloc)          </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int initSlotPool(struct p11SlotPool_t *pool)
{ 
	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "Not initialized");
	}

	pool->list = NULL;
	pool->numberOfSlots = 0;
	pool->nextSlotID = 0;

	FUNC_RETURNS(CKR_OK);
}



int terminateSlotPool(struct p11SlotPool_t *pool)
{
	struct p11Slot_t *pSlot, *pFreeSlot;
	struct p11Object_t *pObject, *tmp;
	int rc;

	FUNC_CALLED();

	pSlot = pool->list;

	/* clear the slot pool */
	while (pSlot) {
		if (pSlot->token) {
			freeToken(pSlot);
		}

		closeSlot(pSlot);

		pFreeSlot = pSlot;
		pSlot = pSlot->next;
		free(pFreeSlot);
	}

	FUNC_RETURNS(CKR_OK);
}



/**
 * addSlot adds a slot to the slot-pool.
 *
 * @param pool       Pointer to slot-pool structure.
 * @param slot       Pointer to slot structure.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                                 </TD>
 *                   <TD>Success                                </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int addSlot(struct p11SlotPool_t *pool, struct p11Slot_t *slot)
{
	struct p11Slot_t *prevSlot;

	FUNC_CALLED();

	slot->next = NULL;

	if (pool->list == NULL) {
		pool->list = slot;
	} else {
		prevSlot = pool->list;

		while (prevSlot->next != NULL) {
			prevSlot = prevSlot->next;
		}

		prevSlot->next = slot;
	}

	pool->numberOfSlots++;

	slot->id = pool->nextSlotID++;

	FUNC_RETURNS(CKR_OK);
}



/**
 * findSlot finds a slot in the slot-pool. 
 * The slot is specified by its slotID.
 *
 * @param pool       Pointer to slot-pool structure.
 * @param slotID     The id of the slot.
 * @param slot       Pointer to pointer to slot structure.
 *                   If the slot is found, this pointer holds the specific slot structure - otherwise NULL.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>>=0                                 </TD>
 *                   <TD>Success                             </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>-1                                  </TD>
 *                   <TD>The specified slot was not found    </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int findSlot(struct p11SlotPool_t *pool, CK_SLOT_ID slotID, struct p11Slot_t **slot)
{
	struct p11Slot_t *pslot;
	int pos = 0;            /* remember the current position in the list */

	FUNC_CALLED();

	pslot = pool->list;
	*slot = NULL;

	while (pslot != NULL) {
		if (pslot->id == slotID) {
			*slot = pslot;
			FUNC_RETURNS(pos);
		}

		pslot = pslot->next;
		pos++;
	}

	FUNC_RETURNS(-1);
}



/**
 * removeSlot removes a slot from the slot-pool. 
 * The slot to remove is specified by its slotID.
 *
 * @param pool       Pointer to slot-pool structure.
 * @param slotID     The id of the slot.
 *
 * @return          
 *                   <P><TABLE>
 *                   <TR><TD>Code</TD><TD>Meaning</TD></TR>
 *                   <TR>
 *                   <TD>CKR_OK                              </TD>
 *                   <TD>Success                             </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>-1                                  </TD>
 *                   <TD>The specified slot was not found    </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int removeSlot(struct p11SlotPool_t *pool, CK_SLOT_ID slotID)
{
	struct p11Slot_t *slot = NULL;
	struct p11Slot_t *prev = NULL;
	int rc;

	FUNC_CALLED();

	rc = findSlot(pool, slotID, &slot);

	/* no slot with this ID found */
	if (rc < 0) {
		FUNC_RETURNS(rc);
	}

	if (rc > 0) {      /* there is more than one element in the pool */
		prev = pool->list;

		while (prev->next->id != slotID) {
			prev = prev->next;
		}

		prev->next = slot->next;
	}

	free(slot);

	pool->numberOfSlots--;

	if (rc == 0) {      /* We removed the last element from the list */
		pool->list = NULL;
	}

	FUNC_RETURNS(CKR_OK);
}
