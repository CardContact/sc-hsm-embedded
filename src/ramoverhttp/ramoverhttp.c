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
#include <ramoverhttp.h>

#include <curl/curl.h>



static int initByteBuffer(struct ramByteBuffer *bb, size_t size) {
	bb->size = size;
	bb->buffer = malloc(size);
	if (bb->buffer == NULL)
		return RAME_OUT_OF_MEMORY;
	bb->len = 0;
	return 0;
}



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



static int addByteBuffer(struct ramByteBuffer *bb, unsigned char *data, size_t len) {
	int rc;

	rc = adjustByteBuffer(bb, len);
	if (rc < 0)
		return rc;

	memcpy(bb->buffer + bb->len, data, len);
	bb->len += len;
	return 0;
}



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



static void clearByteBuffer(struct ramByteBuffer *bb) {
	memset_s(bb->buffer, 0, bb->size);
	bb->len = 0;
}



static void freeByteBuffer(struct ramByteBuffer *bb) {
	if (bb->buffer) {
		memset_s(bb->buffer, 0, bb->size);
		free(bb->buffer);
	}
	bb->buffer = NULL;
	bb->len = 0;
	bb->size = 0;
}



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
	unsigned char *base;

	if (*reflen == 0) {
		return 0;
	}
	base = *ref;
	*tag = *(*ref)++;
	*length = tlvLength(ref);

	if ((*length < 0) || (*ref - base + *length > *reflen))
		return RAME_INVALID_TLV;

	*value = *ref;
	*ref += *length;
	*reflen -= *ref - base;

	return 1;
}



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



static int processSendApdu(struct ramContext *ctx, unsigned char *capdu, size_t clen) {
	int rc;
	size_t rlen;
	unsigned char rapdu[4096];

	if (ctx->sendApdu) {
		rlen = sizeof(rapdu);
		rc = ctx->sendApdu(ctx, capdu, clen, rapdu, &rlen);
		if (rc == 0) {
			rc = encodeResponse(ctx, RAM_RAPDU, rapdu, rlen);
		}
	}
	return rc;
}



static int processReset(struct ramContext *ctx) {
	int rc;
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



static int processNotify(struct ramContext *ctx, unsigned char *tl, size_t tlen) {
	unsigned char *v;
	int tag,msgid,rc;
	size_t taglen;
	char msg[4096];

	if (!ctx->notify)
		return 0;

	rc = 0;
	msgid = 0;
	while ((rc = tlvNext(&tl, &tlen, &tag, &taglen, &v)) > 0) {
		switch(tag) {
		case RAM_INT:
			if (taglen > 4)
				return RAME_INVALID_TLV;
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
	return rc;
}



static int processRequests(struct ramContext *ctx) {
	unsigned char *p,*v;
	unsigned char tmp[4];
	size_t len,tl;
	int tag,rc;

	p = ctx->readbuffer.buffer;

	if (*p != RAM_REQ_TEMPL)
		return RAME_INVALID_REQ;

	p++;
	len = tlvLength(&p);
	if ((p - ctx->readbuffer.buffer + len) > ctx->readbuffer.len)
		return RAME_INVALID_REQ;

	rc = 0;
	while (!rc && ((rc = tlvNext(&p, &len, &tag, &tl, &v)) > 0)) {
		switch(tag) {
		case RAM_CAPDU:
			rc = processSendApdu(ctx, v, tl);
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

	tmp[0] = RAM_RES_TEMPL;
	len = tlvEncodeLength(tmp + 1, ctx->writebuffer.len);
	insertByteBuffer(&ctx->writebuffer, tmp, len + 1);

	return rc;
}



static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
	struct ramContext *c = (struct ramContext *)userp;
	size_t len = size * nmemb;

	if (addByteBuffer(&c->readbuffer, buffer, len) < 0)
		return 0;

	return len;
}



int ramConnect(struct ramContext *ctx) {
	struct curl_slist *headers=NULL;
	CURLcode res;
	long httpcode;
	int rc;

	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, ctx->URL);

	headers = curl_slist_append(headers, "Content-Type: application/org.openscdp-content-mgt-response;version=1.0");
	headers = curl_slist_append(headers, "Accept: */*");
	headers = curl_slist_append(headers, "X-Admin-Protocol: globalplatform-remote-admin/1.0");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx);
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);

	makeInitiationRequest(ctx);

	rc = 0;
	do {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ctx->writebuffer.buffer);
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
		}
	} while (httpcode == 200);

	switch(httpcode) {
	case 504:
		rc = RAME_NO_CONNECT;
		break;
	}

	curl_easy_cleanup(curl);
	return rc;
}



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



void ramFreeContext(struct ramContext **ctx) {
	freeByteBuffer(&(*ctx)->readbuffer);
	freeByteBuffer(&(*ctx)->writebuffer);

	free(*ctx);
	*ctx = NULL;
}



void ramSetUserObject(struct ramContext *ctx, void *obj) {
	ctx->userObject = obj;
}



void *ramGetUserObject(struct ramContext *ctx) {
	return ctx->userObject;
}



void ramSetURL(struct ramContext *ctx, char *url) {
	ctx->URL = url;
}



void ramSetATR(struct ramContext *ctx, unsigned char *atr, size_t atrlen) {
	ctx->atr = atr;
	ctx->atrlen = atrlen;
}



void ramSetSendApduHandler(struct ramContext *ctx, ramSendApdu_t sendApduHandler) {
	ctx->sendApdu = sendApduHandler;
}



void ramSetResetHandler(struct ramContext *ctx, ramReset_t resetHandler) {
	ctx->reset = resetHandler;
}



void ramSetNotifyHandler(struct ramContext *ctx, ramNotify_t notifyHandler) {
	ctx->notify = notifyHandler;
}

