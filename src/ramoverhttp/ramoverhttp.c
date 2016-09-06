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
 * @file ramoverhttp.c
 * @author Andreas Schwier
 * @brief RAMoverHTTP Client
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <common/memset_s.h>
#include "ramoverhttp.h"

#include <curl/curl.h>



/**
 * Initialize byte buffer and allocate initial memory block
 *
 * @param bb The byte buffer structure
 * @param size The initial byte buffer size
 * @return 0 or error code
 */
static int initByteBuffer(struct ramByteBuffer *bb, size_t size) {
	bb->size = size;
	bb->buffer = malloc(size);
	if (bb->buffer == NULL)
		return RAME_OUT_OF_MEMORY;
	bb->len = 0;
	return 0;
}



/**
 * Adjust the size of the buffer to accommodate the incremented size
 *
 * @param bb The byte buffer structure
 * @param increment The additional memory required
 * @return 0 or error code
 */
static int adjustByteBuffer(struct ramByteBuffer *bb, size_t increment) {
	if (bb->len + increment > bb->size) {
		do {
			bb->size <<= 1;
		} while (bb->len + increment > bb->size);

		bb->buffer = realloc(bb->buffer, bb->size);
		if (bb->buffer == NULL)
			return RAME_OUT_OF_MEMORY;
	}
	return 0;
}



/**
 * Add bytes to the byte buffer
 *
 * @param bb The byte buffer structure
 * @param data The data to add
 * @param len The length of the data to add
 * @return 0 or error code
 */
static int addByteBuffer(struct ramByteBuffer *bb, unsigned char *data, size_t len) {
	int rc;

	rc = adjustByteBuffer(bb, len);
	if (rc < 0)
		return rc;

	memcpy(bb->buffer + bb->len, data, len);
	bb->len += len;
	return 0;
}



/**
 * Insert bytes at the beginning of the byte buffer
 *
 * @param bb The byte buffer structure
 * @param data The data to insert
 * @param len The length of the data to insert
 * @return 0 or error code
 */
static int insertByteBuffer(struct ramByteBuffer *bb, unsigned char *data, size_t len) {
	int rc;

	rc = adjustByteBuffer(bb, len);
	if (rc < 0)
		return rc;

	memmove(bb->buffer + len, bb->buffer, bb->len);
	memcpy(bb->buffer, data, len);
	bb->len += len;
	return 0;
}



/**
 * Clear the byte buffer
 *
 * @param bb The byte buffer structure
 * @return 0 or error code
 */
static void clearByteBuffer(struct ramByteBuffer *bb) {
	memset_s(bb->buffer, bb->size, 0, bb->size);
	bb->len = 0;
}



/**
 * Free and release memory allocated for the byte buffer
 *
 * @param bb The byte buffer structure
 * @return 0 or error code
 */
static void freeByteBuffer(struct ramByteBuffer *bb) {
	if (bb->buffer) {
		memset_s(bb->buffer, bb->size, 0, bb->size);
		free(bb->buffer);
	}
	bb->buffer = NULL;
	bb->len = 0;
	bb->size = 0;
}



/**
 * Decode 1,2 or 3 byte length field
 *
 * @param Ref The pointer to a pointer which is updated during the parse
 * @return The decoded length field
 */
static int tlvLength(unsigned char **Ref) {
	int l,c;

	l = *(*Ref)++;

	if (l & 0x80) {
		c = l & 0x7F;
		if ((c == 0) || (c > 2)) {
			return RAME_INVALID_TLV;
		}
		l = 0;
		while(c--) {
			l = (l << 8) | *(*Ref)++;
		}
	}

	return l;
}



/**
 * Encode length field for TLV object on
 *
 * @param ref At least 3 byte buffer to receive the encoded length
 * @param length The length to be encoded
 * @return the length of the length field in bytes
 */
static size_t tlvEncodeLength(unsigned char *ref, int length)
{
	if (length >= 256) {
		*ref++ = 0x82;
		*ref++ = (unsigned char)(length >> 8);
		*ref = (unsigned char)(length & 0xFF);
		return 3;
	}
	if (length >= 128) {
		*ref++ = 0x81;
		*ref = (unsigned char)length;
		return 2;
	}
	*ref = (unsigned char)length;
	return 1;
}



/**
 * Decode the next TLV object
 *
 * Decode the tag and length of the next TLV object and set the value pointer
 * accordingly. The pointer and remaining buffer length is updated by this call.
 *
 * @param ref       Pointer to pointer to first byte of next tag
 * @param reflen    Pointer to variable containing the remaining buffer length
 * @param tag       Pointer to variable updated with the tag value
 * @param length    Pointer to variable updated with the length value
 * @param value     Pointer to a pointer updated with the value field
 * @return          true if further object has been decoded
 */
static int tlvNext(unsigned char **ref, size_t *reflen, int *tag, size_t *length, unsigned char **value)
{
	int rc;
	unsigned char *base;

	if (*reflen == 0) {
		return 0;
	}
	base = *ref;
	*tag = *(*ref)++;

	rc = tlvLength(ref);

	if (rc < 0)
		return RAME_INVALID_TLV;

	*length = rc;

	if (*ref - base + *length > *reflen)
		return RAME_INVALID_TLV;

	*value = *ref;
	*ref += *length;
	*reflen -= *ref - base;

	return 1;
}



/**
 * Encode a response object with the given tag and data value
 *
 * @param ctx The initialized context
 * @param tag The tag value
 * @param data The data for the value field
 * @param len The length of the data field
 * @return 0 or error code
 */
static int encodeResponse(struct ramContext *ctx, unsigned char tag, unsigned char *data, size_t len) {
	unsigned char tmp[4];
	int rc;
	size_t ll;

	tmp[0] = tag;
	ll = tlvEncodeLength(tmp + 1, len);
	rc = addByteBuffer(&ctx->writebuffer, tmp, ll + 1);
	if (rc < 0)
		return rc;
	rc = addByteBuffer(&ctx->writebuffer, data, len);
	return rc;
}



/**
 * Create initiation template which consists of a tag 8E with an embedded C0 tag
 *
 * 8E len
 *     C0 len <atr>
 *
 * @param ctx The initialized context
 * @return 0 or error code
 */
static int makeInitiationRequest(struct ramContext *ctx) {
	unsigned char tmp[4];
	int rc;
	size_t ll;

	rc = encodeResponse(ctx, RAM_RESET, ctx->atr, ctx->atrlen);
	if (rc < 0)
		return rc;

	tmp[0] = RAM_INIT_TEMPL;
	ll = tlvEncodeLength(tmp + 1, ctx->writebuffer.len);
	rc = insertByteBuffer(&ctx->writebuffer, tmp, ll + 1);

	return rc;
}



/**
 * Process a sendApdu command via the call-back set with ramSetSendApduHandler()
 *
 * @param ctx The initialized context
 * @param capdu The command APDU
 * @param clen The length of the command APDU
 * @return 0 or error code
 */
static int processSendApdu(struct ramContext *ctx, unsigned char *capdu, size_t clen) {
	int rc = 0;
	size_t rlen;
	unsigned char rapdu[4096];

	if (ctx->sendApdu) {
		rlen = sizeof(rapdu);
		rc = ctx->sendApdu(ctx, capdu, clen, rapdu, &rlen);
		if (rc == 0) {
			rc = encodeResponse(ctx, RAM_RAPDU, rapdu, rlen);
			memset_s(rapdu, sizeof(rapdu), 0, sizeof(rapdu));
		}
	}
	return rc;
}



/**
 * Process a reset object via the call-back set with ramSetResetHandler()
 *
 * @param ctx The initialized context
 * @return 0 or error code
 */
static int processReset(struct ramContext *ctx) {
	int rc = 0;
	size_t alen;
	unsigned char atr[36];

	if (ctx->reset) {
		alen = sizeof(atr);
		rc = ctx->reset(ctx, atr, &alen);
		if (rc == 0) {
			rc = encodeResponse(ctx, RAM_RESET, atr, alen);
		}
	}
	return rc;
}



/**
 * Process a notify object via the call-back set with ramSetNotifyHandler()
 *
 * @param ctx The initialized context
 * @param tl The value field of the notify TLV object
 * @param tlen The length of the value field
 * @return 0 or error code
 */
static int processNotify(struct ramContext *ctx, unsigned char *tl, size_t tlen) {
	unsigned char *v;
	int tag,msgid,rc;
	size_t taglen;
	char msg[4096];

	if (!ctx->notify)
		return 0;

	msgid = 0;
	while ((rc = tlvNext(&tl, &tlen, &tag, &taglen, &v)) > 0) {
		switch(tag) {
		case RAM_INT:
			if (taglen > 4)
				return RAME_INVALID_TLV;

			if (*v & 0x80)
				msgid = -1;

			while(taglen--) {
				msgid <<= 8;
				msgid |= *v++;
			}
			break;
		case RAM_UTF8:
			if (taglen > sizeof(msg) - 1)
				taglen = sizeof(msg) - 1;
			memcpy(msg, v, taglen);
			msg[taglen] = 0;
			break;
		}
	}

	if (rc < 0)
		return rc;

	rc = ctx->notify(ctx, msgid, msg);
	if (rc != 0)
		return rc;

	return msgid < 0 ? msgid : 0;
}



/**
 * Encode integer value in minimal number of bytes using MSB format
 *
 * @param p the buffer for a maximum of 4 bytes
 * @param v the value
 * @return the number of encoded bytes
 */
static int encodeInteger(unsigned char *p, int v) {
	int c,l = 0;

	if ((v <= 0x7F) && (v >= -0x80))
		l = 1;
	else if ((v <= 0x7FFF) && (v >= -0x8000))
		l = 2;
	else if ((v <= 0x7FFFFF) && (v >= -0x800000))
		l = 3;
	else
		l = 4;

	for (c = l - 1; c >= 0; c--) {
		*(p + c) = v & 0xFF;
		v >>= 8;
	}
	return l;
}



/**
 * Process requests received from the server
 *
 * @param ctx The initialized context
 * @return 0 or error code
 */
static int processRequests(struct ramContext *ctx) {
	unsigned char *p,*v;
	unsigned char tmp[4];
	size_t len,tl;
	int tag,rc,rrc,apducnt;

	p = ctx->readbuffer.buffer;

	if (*p != RAM_REQ_TEMPL)
		return RAME_INVALID_REQ;

	p++;
	len = tlvLength(&p);
	if ((p - ctx->readbuffer.buffer + len) > ctx->readbuffer.len)
		return RAME_INVALID_REQ;

	rc = 0;
	apducnt = 0;
	while (!rc && ((rc = tlvNext(&p, &len, &tag, &tl, &v)) > 0)) {
		switch(tag) {
		case RAM_CAPDU:
			rc = processSendApdu(ctx, v, tl);
			if (rc == 0)
				apducnt++;
			break;
		case RAM_RESET:
			rc = processReset(ctx);
			break;
		case RAM_NOTIFY:
			rc = processNotify(ctx, v, tl);
			break;
		}
	}

	// Even if processing is aborted, we encode a response template to notify the server

	// Number of processed APDUs
	tl = encodeInteger(tmp, apducnt);
	rrc = encodeResponse(ctx, RAM_NUM_APDU, tmp, tl);
	if (rrc < 0)
		return rrc;

	tmp[0] = RAM_RES_TEMPL;
	len = tlvEncodeLength(tmp + 1, ctx->writebuffer.len);
	insertByteBuffer(&ctx->writebuffer, tmp, len + 1);

	return rc;
}



/**
 * CURL call-back to process data send by the server
 *
 * @param buffer The data received
 * @param size The size of a single elements
 * @param nmemb The number of elements
 * @param userp The pointer to the user object, which must be the context
 * @return The length of processed bytes
 */
static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
	struct ramContext *c = (struct ramContext *)userp;
	size_t len = size * nmemb;

	if (addByteBuffer(&c->readbuffer, buffer, len) < 0)
		return 0;

	return len;
}



/**
 * Establish a connection to the RAM server at the given URL and process
 * requests until the server closed the connection
 *
 * Before calling ramConnect(), the context must be created with
 * ramNewContext(),  * the card's ATR must be set using ramSetATR() and the
 * server must be set using ramSetURL().
 *
 * The function uses the call-back functions set with ramSetSendApduHandler(),
 * ramSetResetHandler() and ramSetNotifyHandler() to perform the request card
 *  operations or notification.
 *
 * In order to obtain caller specific data in the call-back, you can register
 * a user object using ramSetUserObject(). In the call-back the user object
 * can be received with ramGetUserObject().
 *
 * @param ctx The initialized context
 * @return 0 or error code
 */
int ramConnect(struct ramContext *ctx) {
	struct curl_slist *headers=NULL;
	CURLcode res;
	long httpcode;
	int rc,excnt;
	CURL *curl;

	if (!ctx->URL)
		return RAME_INVALID_URL;

	if (!ctx->atr || !ctx->atrlen)
		return RAME_GENERAL_ERROR;

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, ctx->URL);

	headers = curl_slist_append(headers, "Content-Type: application/org.openscdp-content-mgt-response;version=1.0");
	headers = curl_slist_append(headers, "Accept: */*");
	headers = curl_slist_append(headers, "X-Admin-Protocol: globalplatform-remote-admin/1.0");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);

	clearByteBuffer(&ctx->writebuffer);
	makeInitiationRequest(ctx);

	rc = 0;
	excnt = 0;		// Counter number of received requests
	do {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void *)ctx->writebuffer.buffer);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)ctx->writebuffer.len);

		res = curl_easy_perform(curl);

		switch(res) {
		case CURLE_OK:
			break;
		case CURLE_COULDNT_RESOLVE_HOST:
			rc = RAME_HOST_NOT_FOUND;
			break;
		case CURLE_URL_MALFORMAT:
			rc = RAME_INVALID_URL;
			break;
		case CURLE_COULDNT_CONNECT:
			rc = RAME_CONNECT_FAILED;
			break;
		default:
			rc = RAME_CURL_ERROR;
			break;
		}

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpcode);

		if (httpcode == 200) {
			clearByteBuffer(&ctx->writebuffer);
			rc = processRequests(ctx);
			clearByteBuffer(&ctx->readbuffer);
			if ((rc != 0) && (rc != RAME_CARD_ERROR))
				break;
			excnt++;
		}
	} while (httpcode == 200);

	switch(httpcode) {
	case 504:			// Gateway timeout
		if (excnt)
			rc = RAME_SERVER_ABORT;
		else
			rc = RAME_NO_CONNECT;
		break;
	case 200:			// New request, but aborted
	case 204:			// Completed
		break;
	case 404:
		rc = RAME_INVALID_URL;
		break;
	default:
		printf("Server HTTP code %ld\n", httpcode);
		rc = RAME_HTTP_CODE;
	}

	curl_easy_cleanup(curl);
	return rc;
}



/**
 * Force closing a connection if an unrecoverable local error occurred (e.g. card removed)
 *
 * This causes a notification to be send to the server in order to perform a
 * clean shutdown of the connection. The method shall be called from within
 * the call-back.
 *
 * @param ctx The initialized context
 * @param msg The message for the server log
 * @return 0 or error code
 */
void ramForceClose(struct ramContext *ctx, char *msg) {
	unsigned char h1[4];
	unsigned char h2[4];
	size_t l1,l2,ml;

	ml = strlen(msg);

	h2[0] = RAM_UTF8;
	l2 = tlvEncodeLength(h2 + 1, ml) + 1;
	h1[0] = RAM_CLOSE;
	l1 = tlvEncodeLength(h1 + 1, ml + l2) + 1;

	// No error handling during bail-out
	addByteBuffer(&ctx->writebuffer, h1, l1);
	addByteBuffer(&ctx->writebuffer, h2, l2);
	addByteBuffer(&ctx->writebuffer, (unsigned char *)msg, ml);
}



/**
 * Allocate and initialize a new context.
 *
 * The context can be used multiple times. It must be released with ramFreeContext().
 *
 * @param ctx A pointer to the context pointer.
 * @return 0 or error code
 */
int ramNewContext(struct ramContext **ctx) {
	int rc;
	struct ramContext *c;

	c = (struct ramContext *)calloc(1, sizeof(struct ramContext));
	if (c == NULL)
		return RAME_OUT_OF_MEMORY;

	rc = initByteBuffer(&c->readbuffer, 512);
	if (rc < 0) {
		ramFreeContext(&c);
		return rc;
	}

	rc = initByteBuffer(&c->writebuffer, 512);
	if (rc < 0) {
		ramFreeContext(&c);
		return rc;
	}

	*ctx = c;
	return 0;
}



/**
 * Release context.
 *
 * @param ctx A pointer to the context pointer.
 * @return 0 or error code
 */
void ramFreeContext(struct ramContext **ctx) {
	freeByteBuffer(&(*ctx)->readbuffer);
	freeByteBuffer(&(*ctx)->writebuffer);

	free(*ctx);
	*ctx = NULL;
}



/**
 * Set user object for call-back functions
 *
 * @param ctx The initialized context
 * @param obj The user object to set
 */
void ramSetUserObject(struct ramContext *ctx, void *obj) {
	ctx->userObject = obj;
}



/**
 * Get user object for call-back functions
 *
 * @param ctx The initialized context
 * @return 0 or error code
 */
void *ramGetUserObject(struct ramContext *ctx) {
	return ctx->userObject;
}



/**
 * Set URL of Remote Application Management Server
 *
 * The code does not copy the URL.
 *
 * @param ctx The initialized context
 * @param url The URL
 */
void ramSetURL(struct ramContext *ctx, char *url) {
	ctx->URL = url;
}



/**
 * Set ATR of the card.
 *
 * The ATR is send in the initiation request and is used at the server to identify the card type.
 * The code does not copy the ATR.
 *
 * @param ctx The initialized context
 * @param atr The cards ATR
 * @param atrlen The length of the ATR
 */
void ramSetATR(struct ramContext *ctx, unsigned char *atr, size_t atrlen) {
	ctx->atr = atr;
	ctx->atrlen = atrlen;
}



/**
 * Set call-back to handle APDU exchange with the card
 *
 * The handler must be declared as
 *
 * int sendApdu(struct ramContext *ctx, unsigned char *capdu, size_t clen, unsigned char *rapdu, size_t *rlen)
 *
 * It must send the APDU contained in capdu with the length given in clen to the card and place
 * the response APDU (data + SW1/SW2) in rapdu. rlen is a pointer to the length. It is initialized with the
 * length of the buffer and must be set to the length of the response by the call-back.
 *
 * The call-back must return 0 if no error occurred or a value < 0 to indicates an error. An error
 * other than RAME_CARD_ERROR will immediately terminate processing of the server request.
 *
 * If an error occurs, then the call-back shall call ramForceClose() to notify the server of the problem
 * and to initiate a clean shut-down.
 *
 * @param ctx The initialized context
 * @param sendApduHandler The call-back
 */
void ramSetSendApduHandler(struct ramContext *ctx, ramSendApdu_t sendApduHandler) {
	ctx->sendApdu = sendApduHandler;
}



/**
 * Set call-back to handle a card reset
 *
 * The handler must be declared as
 *
 * int reset(struct ramContext *ctx, unsigned char *atr, size_t *alen)
 *
 * It must reset the card and fill the buffer pointed to by atr with the ATR, not exceeding the
 * length of the buffer indicated in alen. The length variable alen must be updated to reflect
 * the actual length of the ATR.
 *
 * The call-back must return 0 if no error occurred or a value < 0 to indicates an error. An error
 * other than RAME_CARD_ERROR will immediately terminate processing of the server request.
 *
 * If an error occurs, then the call-back shall call ramForceClose() to notify the server of the problem
 * and to initiate a clean shut-down.
 *
 * @param ctx The initialized context
 * @param sendApduHandler The call-back
 */
void ramSetResetHandler(struct ramContext *ctx, ramReset_t resetHandler) {
	ctx->reset = resetHandler;
}



/**
 * Set call-back to handle notification from the server
 *
 * The handler must be declared as
 *
 * int notify(struct ramContext *ctx, int msgid, char *msg)
 *
 * The server sends notification messages and ids. Usually messages shall be presented to the user.
 *
 * The call-back must return 0 if no error occurred or a value < 0 to indicates an error. An error
 * other than RAME_CARD_ERROR will immediately terminate processing of the server request.
 *
 * If an error occurs, then the call-back shall call ramForceClose() to notify the server of the problem
 * and to initiate a clean shut-down.
 *
 * @param ctx The initialized context
 * @param sendApduHandler The call-back
 */
void ramSetNotifyHandler(struct ramContext *ctx, ramNotify_t notifyHandler) {
	ctx->notify = notifyHandler;
}

