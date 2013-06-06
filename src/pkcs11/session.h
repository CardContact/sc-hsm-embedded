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
 * Abstract :       Data types and functions for session managment
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

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
	CK_STATE state;                     /**< The session state                                  */
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

int initSessionPool(struct p11SessionPool_t *pool);

int terminateSessionPool(struct p11SessionPool_t *pool);

int addSession(struct p11SessionPool_t *pool, struct p11Session_t *session);

int findSessionByHandle(struct p11SessionPool_t *pool, CK_SESSION_HANDLE handle, struct p11Session_t **session);

int findSessionBySlotID(struct p11SessionPool_t *pool, CK_SLOT_ID slotID, struct p11Session_t **session);

int removeSession(struct p11SessionPool_t *pool, CK_SESSION_HANDLE handle);

int addSessionObject(struct p11Session_t *session, struct p11Object_t *object);

int findSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle, struct p11Object_t **object);

int removeSessionObject(struct p11Session_t *session, CK_OBJECT_HANDLE handle);

int addObjectToSearchList(struct p11Session_t *session, struct p11Object_t *object);

int appendToCryptoBuffer(struct p11Session_t *session, CK_BYTE_PTR data, CK_ULONG length);

int clearCryptoBuffer(struct p11Session_t *session);

#endif /* ___SESSION_H_INC___ */
