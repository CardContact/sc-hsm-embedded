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
 * Abstract :       Data types for the internal cryptoki management
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/


#ifndef ___P11GENERIC_H_INC___
#define ___P11GENERIC_H_INC___

#include <stdio.h>
#include <stdlib.h>

#include <pkcs11/cryptoki.h>

#include <pkcs11/session.h>
#include <pkcs11/object.h>

#ifndef _MAX_PATH
#define _MAX_PATH FILENAME_MAX
#endif

#ifdef DEBUG
#define FUNC_CALLED() do { \
		debug("Function %s called.\n", __FUNCTION__); \
} while (0)

#define FUNC_RETURNS(rc) do { \
		debug("Function %s completes with rc=%d.\n", __FUNCTION__, rc); \
		return rc; \
} while (0)

#define FUNC_FAILS(rc, msg) do { \
		debug("Function %s fails with rc=%d \"%s\"\n", __FUNCTION__, rc, msg); \
		return rc; \
} while (0)

#else
#define FUNC_CALLED()
#define FUNC_RETURNS(rc) return rc
#define FUNC_FAILS(rc, msg) return rc
#endif

/**
 * Internal structure to store information about a token.
 *
 */

struct p11Token_t {

	CK_TOKEN_INFO info;                 /**< General information about the token            */
	struct p11Slot_t *slot;				/**< The slot where the token is inserted			*/
	unsigned char pinSO[8];             /**< The encrypted pin of the SO                    */
	unsigned char pinUser[8];           /**< The encrypted pin of the user                  */
	int pinUserInitialized;
	unsigned char transportKey1[8];     /**< The transport key #1                           */
	unsigned char transportKey2[8];     /**< The transport key #2                           */
	unsigned char objMACKey[8];         /**< The key for MAC calculation                  */
	char tokenDir[_MAX_PATH];           /**< The directory that holds this token            */
	CK_ULONG freeObjectNumber;          /**< The number of objects in this token            */

	CK_MECHANISM_TYPE mechanism;        /**< Mechanisms supported by token                  */

	CK_ULONG numberOfTokenObjects;      /**< The number of public objects in this token     */
	struct p11Object_t *tokenObjList;   /**< Pointer to first object in pool                */

	CK_ULONG numberOfPrivateTokenObjects; /**< The number of private objects in this token  */
	struct p11Object_t *tokenPrivObjList; /**< Pointer to the first object in pool          */
};

/**
 * Internal structure to store information about a slot.
 *
 */

struct p11Slot_t {

	CK_SLOT_ID id;                  /**< The id of the slot                  */
	CK_SLOT_INFO info;              /**< General information about the slot  */
	int closed;                     /**< Slot hardware currently absent      */
	char slotDir[_MAX_PATH];        /**< The directory that holds this slot  */

	struct p11Token_t *token;       /**< Pointer to token in the slot        */

	struct p11Slot_t *next;         /**< Pointer to next available slot      */

};

/**
 * Internal structure to store information about all available slots.
 *
 */

struct p11SlotPool_t {

	CK_ULONG numberOfSlots;         /**< Number of slots in the pool         */
	CK_SLOT_ID nextSlotID;          /**< The next assigned slot ID value     */
	struct p11Slot_t *list;         /**< Pointer to first slot in pool       */

};

/**
 * Internal context structure of the cryptoki.
 *
 */

struct p11Context_t {

	CK_VERSION version;                     /**< Information about cryptoki version       */
	CK_INFO info;                           /**< General information about cryptoki       */
	CK_HW_FEATURE_TYPE hw_feature;          /**< Hardware feature type of device          */

	FILE *debugFileHandle;

	char slotDirectory[_MAX_PATH];          /**< The directory that holds the slots       */

	struct p11SessionPool_t *sessionPool;   /**< Pointer to session pool                  */

	struct p11SlotPool_t *slotPool;         /**< Pointer to pool of available slots       */

};

#endif /* ___P11GENERIC_H_INC___ */

