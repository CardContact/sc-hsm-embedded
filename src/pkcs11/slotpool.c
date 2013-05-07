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

#include <strbpcpy.h>

#include <ctccid/ctapi.h>

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
	char scr[10];
	int rc, i;

	struct p11Slot_t *slot;
	struct p11Token_t *token;

	FUNC_CALLED();

	if (context == NULL) {
		FUNC_FAILS(CKR_CRYPTOKI_NOT_INITIALIZED, "Not initialized");
	}

	pool->list = NULL;
	pool->numberOfSlots = 0;
	pool->nextSlotID = 1;

	for (i = 0; i < MAX_SLOTS; i++) {
		rc = CT_init((unsigned short)pool->nextSlotID, i);

		if (rc != OK) {
#ifdef DEBUG
			debug("CT_init returns %d\n", rc);
#endif
			break;
		}

		slot = (struct p11Slot_t *) malloc(sizeof(struct p11Slot_t));

		if (slot == NULL) {
			FUNC_FAILS(CKR_HOST_MEMORY, "Out of memory");
		}

		memset(slot, 0x00, sizeof(struct p11Slot_t));

		sprintf(scr, "Slot#%d", i);
		strbpcpy(slot->info.slotDescription,
				scr,
				sizeof(slot->info.slotDescription));

		strbpcpy(slot->info.manufacturerID,
				"CardContact",
				sizeof(slot->info.manufacturerID));

		slot->info.hardwareVersion.minor = 0;
		slot->info.hardwareVersion.major = 0;

		slot->info.firmwareVersion.minor = 0;
		slot->info.firmwareVersion.major = 0;

		slot->info.flags = CKF_REMOVABLE_DEVICE | CKF_HW_SLOT;
		addSlot(context->slotPool, slot);

		rc = checkForToken(slot, &token);

		if (rc != CKR_OK) {
			removeSlot(context->slotPool, slot->id);
			FUNC_FAILS(CKR_GENERAL_ERROR, "token check failed");
		}

		if (token != NULL) {
			addToken(slot, token);
		}
	}

	FUNC_RETURNS(CKR_OK);
}



int terminateSlotPool(struct p11SlotPool_t *pool)
{
	struct p11Slot_t *pSlot, *pFreeSlot;
	struct p11Object_t *pObject, *tmp;
	int rc;

	pSlot = pool->list;

	/* clear the slot pool */
	while (pSlot) {

		if (pSlot->token) {

			/* clear the public token objects */
			pObject = pSlot->token->tokenObjList;

			while (pObject) {
				tmp = pObject->next;

				removeAllAttributes(pObject);
				free(pObject);

				pObject = tmp;
			}

			/* clear the private token objects */
			pObject = pSlot->token->tokenPrivObjList;

			while (pObject) {
				tmp = pObject->next;

				removeAllAttributes(pObject);
				free(pObject);

				pObject = tmp;
			}
		}

#ifdef DEBUG
		debug("calling CT_close()\n", rc);
#endif
		rc = CT_close((unsigned short)pSlot->id);

		if (rc != OK) {
#ifdef DEBUG
			debug("CT_close returns %d\n", rc);
#endif
		}

		pFreeSlot = pSlot;

		pSlot = pSlot->next;

		free(pFreeSlot->token);
		free(pFreeSlot);
	}

	return 0;
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

	return CKR_OK;
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

	pslot = pool->list;
	*slot = NULL;

	while (pslot != NULL) {

		if (pslot->id == slotID) {

			*slot = pslot;
			return pos;
		}

		pslot = pslot->next;
		pos++;
	}

	return -1;
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

	rc = findSlot(pool, slotID, &slot);

	/* no slot with this ID found */
	if (rc < 0) {
		return rc;
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

	return CKR_OK;
}
