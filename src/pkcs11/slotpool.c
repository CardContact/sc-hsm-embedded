/**
 * SmartCard-HSM PKCS#11 Module
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
 * @file    slotpool.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for slot-pool management
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pkcs11/p11generic.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>
#include <pkcs11/token.h>
#include <pkcs11/debug.h>

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

	FUNC_CALLED();

	pSlot = pool->list;

	/* clear the slot pool */
	while (pSlot) {
		if (pSlot->token) {
			freeToken(pSlot->token);
			pSlot->token = NULL;
		}

		if (pSlot->removedToken) {
			freeToken(pSlot->removedToken);
			pSlot->removedToken = NULL;
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
	struct p11Slot_t **ppSlot;

	FUNC_CALLED();

	ppSlot = &pool->list;
	while (*ppSlot && (memcmp(slot->info.slotDescription, (*ppSlot)->info.slotDescription, sizeof(slot->info.slotDescription)) >= 0))
		ppSlot = &(*ppSlot)->next;

	slot->next = *ppSlot;
	*ppSlot = slot;

	pool->numberOfSlots++;

	/* Slot id might have been set during slot creation */
	if (slot->id == 0) {
		slot->id = pool->nextSlotID;
		pool->nextSlotID += 4;
	}

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
 *                   <TD>>CKR_OK                             </TD>
 *                   <TD>Success                             </TD>
 *                   </TR>
 *                   <TR>
 *                   <TD>CKR_SLOT_ID_INVALID                 </TD>
 *                   <TD>The specified slot was not found    </TD>
 *                   </TR>
 *                   </TABLE></P>
 */
int findSlot(struct p11SlotPool_t *pool, CK_SLOT_ID slotID, struct p11Slot_t **slot)
{
	struct p11Slot_t *pslot;

	FUNC_CALLED();

	pslot = pool->list;
	*slot = NULL;

	while (pslot != NULL) {
		if (pslot->id == slotID) {
			*slot = pslot;
			FUNC_RETURNS(CKR_OK);
		}

		pslot = pslot->next;
	}

	FUNC_RETURNS(CKR_SLOT_ID_INVALID);
}
