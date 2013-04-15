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

#ifdef WIN32
#include <io.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#endif

#include <pkcs11/p11generic.h>
#include <pkcs11/slotpool.h>
#include <pkcs11/slot.h>

#include <strbpcpy.h>

extern struct p11Context_t *context;


/**
 * initSlotPool initializes the slot-pool structure.
 *
 * All directories in the "SlotDirectory" are scanned for valid slots
 * and tokens.
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
    DIR *dir;
    struct dirent *dirent;
    int rc, i;
    
    struct p11Slot_t *slot;
    struct p11Token_t *token;

    if (context == NULL)
        return CKR_CRYPTOKI_NOT_INITIALIZED;

    pool->list = NULL;
    pool->numberOfSlots = 0;
    pool->nextSlotID = 1;
     
    dir = NULL;
    dirent = NULL;

    dir = opendir(context->slotDirectory);

#ifdef WIN32
    if (dir->handle == -1) {
        return CKR_GENERAL_ERROR;
    }
#else
    if (dir == NULL) {
            return CKR_GENERAL_ERROR;
    }
#endif

    while((dirent = readdir(dir)) != NULL) {
    
        if (memcmp(dirent->d_name, ".", 1)) {
                
            slot = (struct p11Slot_t *) malloc(sizeof(struct p11Slot_t));

            if (slot == NULL) {
                return CKR_HOST_MEMORY;
            }

            memset(slot, 0x00, sizeof(struct p11Slot_t));

#ifdef WIN32
            memcpy(slot->slotDir, dirent->d_name, dirent->d_size);
            i = dirent->d_size;
#else
            i = 0;
            while (dirent->d_name[i] != 0x00) {
            	i++;
            }
            memcpy(slot->slotDir, dirent->d_name, i);
#endif
            strbpcpy(slot->info.slotDescription,
                     dirent->d_name,
                     i);

            strbpcpy(slot->info.manufacturerID,
                     "CardContact",
                     sizeof(slot->info.manufacturerID));

            slot->info.hardwareVersion.minor = 0;
            slot->info.hardwareVersion.major = 0;
                
            slot->info.firmwareVersion.minor = 0;
            slot->info.firmwareVersion.major = 0;

            addSlot(context->slotPool, slot);
                
            rc = checkForToken(slot, &token);

            if (rc != CKR_OK) {
                removeSlot(context->slotPool, slot->id);
                return CKR_GENERAL_ERROR;
            }

            if (token != NULL) {  
                addToken(slot, token);
            }
                
            dirent = NULL;
        }

    }

    closedir(dir);
    
    return CKR_OK;
}


int terminateSlotPool(struct p11SlotPool_t *pool)

{   struct p11Slot_t *pSlot, *pFreeSlot;
    struct p11Object_t *pObject, *tmp;

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

