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
 * @file    bytebuffer.c
 * @author  Andreas Schwier
 * @brief   Functions to handle mutable strings of bytes safely
 */

#include "bytebuffer.h"



int bbCompare(bytebuffer s1, bytebuffer s2)
{
	if (s1->len != s2->len) {
		return s1->len - s2->len;
	}
	return memcmp(s1->val, s2->val, s1->len);
}



void bbClear(bytebuffer s)
{
	memset(s->val, 0, s->len);
	s->len = 0;
}



int bbAppend(bytebuffer s1, bytestring s2)
{
	return bbInsert(s1, s1->len, s2);
}



int bbInsert(bytebuffer s1, size_t offset, bytestring s2)
{
	if (s1->len + s2->len > s1->capacity) {
		// By setting the new length to capacity, the buffer is invalidated, so that
		// not all calls to bbInsert must validate the return code. It is sufficient
		// to check the last bbInsert in a sequence.
		s1->len = s1->capacity;
		return -1;
	}

	if (offset > s1->len) {
		s1->len = s1->capacity;
		return -1;
	}

	memmove(s1->val + offset + s2->len, s1->val + offset, s1->len - offset);
	memmove(s1->val + offset, s2->val, s2->len);
	s1->len += s2->len;
	return s1->len;
}



int bbHasFailed(bytebuffer s1)
{
	return s1->len >= s1->capacity ? 1 : 0;
}



size_t bbGetLength(bytebuffer s1)
{
	return s1->len;
}
