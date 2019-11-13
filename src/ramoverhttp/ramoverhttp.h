/**
 * RAMoverHTTP Client
 *
 * Copyright (c) 2015, CardContact Systems GmbH, Minden, Germany
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
 * @file ramoverhttp.h
 * @author Andreas Schwier
 * @brief RAMoverHTTP Client
 */

/* Prevent from including twice ------------------------------------------- */

#ifndef __RAMOVERHTTP_H__
#define __RAMOVERHTTP_H__

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

// Return codes

#define RAME_OK				0			/** OK */
#define RAME_GENERAL_ERROR	-1			/** General error */
#define RAME_OUT_OF_MEMORY	-2			/** Out of heap memory */
#define RAME_INVALID_TLV	-3			/** TLV encoding corrupt */
#define RAME_INVALID_REQ	-4			/** POST response does not contain request object */
#define RAME_CURL_ERROR		-5			/** General error reported by libcurl */
#define RAME_CARD_ERROR		-6			/** Error in card communication */
#define RAME_NO_CONNECT		-7			/** Server did not send request in time */
#define RAME_SERVER_ABORT	-8			/** Server did not send request in time */
#define RAME_HOST_NOT_FOUND	-9			/** Host name was not found */
#define RAME_INVALID_URL	-10			/** URL is malformed or not found on server */
#define RAME_CONNECT_FAILED	-11			/** Connection to server failed */
#define RAME_HTTP_CODE		-12			/** Unexpected HTTP code */
#define RAME_TIMEOUT		-13			/** Connection timeout */


/* TLV tags */
#define RAM_INT				0x02
#define RAM_UTF8			0x0C
#define RAM_NUM_APDU		0x80
#define RAM_REQ_TEMPL		0xAA
#define RAM_RES_TEMPL		0xAB
#define RAM_INIT_TEMPL		0xE8
#define RAM_CAPDU			0x22
#define RAM_RAPDU			0x23
#define RAM_RESET			0xC0
#define RAM_NOTIFY			0xE0
#define RAM_CLOSE			0xE1


struct ramContext;

typedef int (*ramSendApdu_t) (struct ramContext *, unsigned char *, size_t , unsigned char *, size_t *);
typedef int (*ramReset_t) (struct ramContext *, unsigned char *, size_t *);
typedef int (*ramNotify_t) (struct ramContext *, int , char *);



struct ramByteBuffer {
	unsigned char *buffer;		// Buffer
	size_t len;					// Length of data in buffer
	size_t size;				// Size of buffer
};



struct ramContext {
	char *URL;
	unsigned char *atr;
	size_t atrlen;
	void *userObject;
	struct ramByteBuffer readbuffer;
	struct ramByteBuffer writebuffer;
	ramSendApdu_t sendApdu;
	ramReset_t reset;
	ramNotify_t notify;
};



int ramNewContext(struct ramContext **);
void ramFreeContext(struct ramContext **);
void ramSetUserObject(struct ramContext *, void *);
void *ramGetUserObject(struct ramContext *);
void ramSetURL(struct ramContext *, char *);
void ramSetATR(struct ramContext *, unsigned char *, size_t);
void ramSetSendApduHandler(struct ramContext *, ramSendApdu_t);
void ramSetResetHandler(struct ramContext *, ramReset_t);
void ramSetNotifyHandler(struct ramContext *, ramNotify_t);
int ramConnect(struct ramContext *);
void ramForceClose(struct ramContext *, char *msg);

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif

