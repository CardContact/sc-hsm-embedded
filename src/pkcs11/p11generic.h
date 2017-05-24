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
 * @file    p11generic.h
 * @author  Frank Thater, Andreas Schwier
 * @brief   General module functions at the PKCS#11 interface
 */

#ifndef ___P11GENERIC_H_INC___
#define ___P11GENERIC_H_INC___

#include <stdio.h>
#include <stdlib.h>

#include <pkcs11/cryptoki.h>
#include <pkcs11/sc-hsm-pkcs11.h>
#include <pkcs11/object.h>

#ifndef VERSION_MAJOR
#define VERSION_MAJOR     2
#define VERSION_MINOR     9
#endif

#ifndef _MAX_PATH
#define _MAX_PATH FILENAME_MAX
#endif

#ifndef CTAPI
#ifdef _WIN32
#include <winscard.h>
#define  MAX_READERNAME   128
#else
#include <unistd.h>
#ifdef __APPLE__
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#else
#include <pcsclite.h>
#include <winscard.h>
#endif /* __APPLE__ */
#endif /* _WIN32 */
#endif /* CTAPI */

#ifdef DEBUG
#define FUNC_CALLED() do { \
		debug("Function %s called.\n", __FUNCTION__); \
} while (0)

#define FUNC_RETURNS(rc) do { \
		debug("Function %s completes with rc=%d.\n", __FUNCTION__, (rc)); \
		return rc; \
} while (0)

#define FUNC_FAILS(rc, msg) do { \
		debug("Function %s fails with rc=%d \"%s\"\n", __FUNCTION__, (rc), (msg)); \
		return rc; \
} while (0)

#else
#define FUNC_CALLED()
#define FUNC_RETURNS(rc) return (rc)
#define FUNC_FAILS(rc, msg) return (rc)
#endif



struct p11TokenDriver;

#define INT_CKU_NO_USER 0xFF

/**
 * Internal structure to store information about a token.
 *
 */
struct p11Token_t {
	CK_TOKEN_INFO info;                 /**< General information about the token            */
	struct p11Slot_t *slot;             /**< The slot where the token is inserted           */
	CK_USER_TYPE user;                  /**< The user of this session                       */
	int rosessions;                     /**< Number of read/only sessions                   */
	CK_ULONG freeObjectNumber;          /**< The number of objects in this token            */

	int pinUseCounter;                  /**< Number of crypto operations per PIN verify     */
	int pinChangeRequired;              /**< PIN change required before use                 */

	CK_ULONG numberOfTokenObjects;      /**< The number of public objects in this token     */
	struct p11Object_t *tokenObjList;   /**< Pointer to first object in pool                */

	CK_ULONG numberOfPrivateTokenObjects; /**< The number of private objects in this token  */
	struct p11Object_t *tokenPrivObjList; /**< Pointer to the first object in pool          */

	struct p11TokenDriver *drv;         /**< Driver for this token                          */
};



/**
 * Internal structure to store information about a slot.
 *
 */
struct p11Slot_t {
	CK_SLOT_ID id;                    /**< The id of the slot                  */
	CK_SLOT_INFO info;                /**< General information about the slot  */
	int closed;                       /**< Slot hardware currently absent      */
	unsigned long hasFeatureVerifyPINDirect;
#ifdef CTAPI
	unsigned short ctn;               /**< Card terminal number                */
#else
	char readername[MAX_READERNAME];  /**< The reader name for this slot       */
	SCARDCONTEXT context;             /**< Card manager context for slot       */
	SCARDHANDLE card;                 /**< Handle to card                      */
#endif
	int maxCAPDU;                     /**< Maximum length of command APDU      */
	int maxRAPDU;                     /**< Maximum length of response APDU     */
	int noExtLengthReadAll;           /**< Prevent using Le='000000'           */
	struct p11Slot_t *primarySlot;    /**< Base slot if slot is virtual        */
	struct p11Slot_t *virtualSlots[2];/**< Virtual slots using this as base    */
	struct p11Token_t *token;         /**< Pointer to token in the slot        */
	struct p11Token_t *removedToken;  /**< Removed but not freed token         */
	struct p11Slot_t *next;           /**< Pointer to next available slot      */
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
 * Internal structure to store information for session management and a list
 * of all active sessions.
 *
 */
struct p11SessionPool_t {
	CK_ULONG numberOfSessions;              /**< Number of active sessions             */
	CK_SESSION_HANDLE nextSessionHandle;    /**< Value of next assigned session handle */
	struct p11Session_t *list;              /**< Pointer to first session in pool      */
};



struct p11TokenDriver {
	const char *name;                   /**< Name of driver                                 */
	int version;                        /**< Differentiate among card family members        */
	int maxCAPDU;                       /**< Maximum length of command APDU                 */
	int maxRAPDU;                       /**< Maximum length of response APDU                */
	int maxHashBlock;                   /**< Maximum number of byte in a hash block         */
	/**< Allow driver to check if card is a candidate based on the ATR                      */
	int (*isCandidate)(unsigned char *atr, size_t atrLen);
	int (*newToken)(struct p11Slot_t *slot, struct p11Token_t **token);
	void (*freeToken)(struct p11Token_t *token);
	int (*getMechanismList)(CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount);
	int (*getMechanismInfo)(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);
	int (*login)(struct p11Slot_t *slot, int userType, unsigned char *pin, int pinlen);
	int (*logout)(struct p11Slot_t *slot);
	int (*initpin)(struct p11Slot_t *slot, unsigned char *pin, int pinlen);
	int (*setpin)(struct p11Slot_t *slot, unsigned char *oldpin, int oldpinlen, unsigned char *newpin, int newpinlen);

	int (*C_DecryptInit)  (struct p11Object_t *, CK_MECHANISM_PTR);
	int (*C_Decrypt)      (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
	int (*C_DecryptUpdate)(struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
	int (*C_DecryptFinal) (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);
	int (*C_SignInit)     (struct p11Object_t *, CK_MECHANISM_PTR);
	int (*C_Sign)         (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
	int (*C_SignUpdate)   (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG);
	int (*C_SignFinal)    (struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG_PTR);

	int (*C_GenerateKeyPair)  (struct p11Slot_t *, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);
};



#define CALLER_UNKNOWN			0
#define CALLER_FIREFOX			1

/**
 * Internal context structure of the cryptoki.
 *
 */
struct p11Context_t {
	CK_VERSION version;                     /**< Information about cryptoki version       */
	CK_INFO info;                           /**< General information about cryptoki       */
	CK_HW_FEATURE_TYPE hw_feature;          /**< Hardware feature type of device          */

	int caller;                             /**< Calling application                      */

	FILE *debugFileHandle;

	struct p11SessionPool_t sessionPool;    /**< Session pool                             */

	struct p11SlotPool_t slotPool;          /**< Pool of available slots                  */

	void *mutex;                            /**< Global lock used to protect internals    */
};

CK_RV p11CreateMutex(CK_VOID_PTR_PTR ppMutex);
CK_RV p11DestroyMutex(CK_VOID_PTR pMutex);
CK_RV p11LockMutex(CK_VOID_PTR pMutex);
CK_RV p11UnlockMutex(CK_VOID_PTR pMutex);

#endif /* ___P11GENERIC_H_INC___ */

