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
 * @file    bytebuffer.h
 * @author  Andreas Schwier
 * @brief   Functions to handle mutuable strings of bytes safely
 */

/* Prevent from including twice ------------------------------------------- */

#ifndef __BYTEBUFFER_H__
#define __BYTEBUFFER_H__

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <string.h>

#include "bytestring.h"

/**
 * A string of bytes with determined length
 */
struct bytebuffer_s {
	unsigned char *val;
	size_t len;
	// Order is important, so that a bytebuffer can be safely casted to a bytestring
	size_t capacity;
};

typedef struct bytebuffer_s *bytebuffer;

int bbCompare(bytebuffer s1, bytebuffer s2);
void bbClear(bytebuffer s);
int bbAppend(bytebuffer s1, bytestring s2);
int bbInsert(bytebuffer s1, size_t offset, bytestring s2);
int bbHasFailed(bytebuffer s1);
size_t bbGetLength(bytebuffer s1);

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif
