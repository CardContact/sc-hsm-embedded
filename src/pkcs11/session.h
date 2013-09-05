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
 * @file    session.h
 * @author  Frank Thater, Andreas Schwier
 * @brief   Data types and functions for session management
 */

#ifndef ___SESSION_H_INC___
#define ___SESSION_H_INC___

#include <pkcs11/p11generic.h>
#include <pkcs11/cryptoki.h>
#include <pkcs11/object.h>


struct p11ObjectSearch_t {
	int searchNumOfObjects;
	int objectsCollected;
	struct p11Object_t *searchList;
};


/**
 * Internal structure to store information about specific session.
 *
 */

struct p11Session_t {

	CK_SLOT_ID slotID;                  /**< The id of the slot for this session                */
	CK_FLAGS flags;                     /**< The flags of this session                          */
//	CK_STATE state;                     /**< The session state                                  */
	CK_SESSION_HANDLE handle;           /**< The handle of the session                          */
	int activeObjectHandle;             /**< The handle of the active object, -1 if no object   */
	CK_MECHANISM_TYPE activeMechanism;	/**< The currently active mechanism                     */
	CK_BYTE_PTR cryptoBuffer;           /**< Buffer storing intermediate results                */
	CK_ULONG cryptoBufferSize;          /**< Current content of crypto buffer                   */
	CK_ULONG cryptoBufferMax;           /**< Current size of crypto buffer                      */

	struct p11ObjectSearch_t searchObj; /**< Store the result of a search operation             */

	int numberOfSessionObjects;
	CK_LONG freeSessionObjNumber;
	struct p11Object_t *sessionObjList; /**< Pointer to first object in pool     */

	struct p11Session_t *next;          /**< Pointer to next active session      */
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


/* function prototypes */

void initSessionPool(struct p11SessionPool_t *pool);
void terminateSessionPool(struct p11SessionPool_t *pool);
void addSession(struct p11SessionPool_t *pool, struct p11Session_t *session);
int findSessionByHandle(struct p11SessionPool_t *pool, CK_SESSION_HANDLE handle, struct p11Session_t **session);
int findSessionBySlotID(struct p11SessionPool_t *pool, CK_SLOT_ID slotID, struct p11Session_t **session);
int removeSession(struct p11SessionPool_t *pool, CK_SESSION_HANDLE handle);
void closeSessionsForSlot(struct p11SessionPool_t *pool, CK_SLOT_ID slotID);
CK_STATE getSessionState(struct p11Session_t *session, struct p11Token_t *token);
void addSessionObject(struct p11Session_t *session, struct p11Object_t *object);
int findSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle, struct p11Object_t **object);
int removeSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle);
int addObjectToSearchList(struct p11Session_t *session, struct p11Object_t *object);
void clearSearchList(struct p11Session_t *session);
int appendToCryptoBuffer(struct p11Session_t *session, CK_BYTE_PTR data, CK_ULONG length);
void clearCryptoBuffer(struct p11Session_t *session);

#endif /* ___SESSION_H_INC___ */
