/**
 * CT-API for CCID Driver
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
 * @file dump.c
 * @author Christoph Brunhuber
 * @brief Simple hex dumper
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "dump.h"



#ifdef DEBUG
/*
 * Dump the memory pointed to by <ptr>
 *
 */
void ctccidDump(void *_ptr, int len)
{
	unsigned char *ptr = (unsigned char *)_ptr;
	int i;

	static char *MinStack = (char *)-1;
	static char *MaxStack; /* = 0; */
	if (MinStack > (char *)&ptr)
		MinStack = (char *)&ptr;
	if (MaxStack < (char *)&ptr)
		MaxStack = (char *)&ptr;
	printf("Dump(%p, %d) stack used so far: %d", ptr, len, (int)(MaxStack - MinStack));

	for (i = 0; i < len; i += 16) {
		int i1 = i + 16;
		int i2 = i1;
		int j;

		if (i1 > len) {
			i1 = len;
		}

		if (i % 16 == 0) {
			printf("\n  %04x: ", i);
		}

		for (j = i; j < i1; j++) {
			printf("%02x ", ptr[j]);
		}

		for (     ; j < i2; j++) {
			printf("   ");
		}

		printf(" ");

		for (j = i; j < i1; j++) {
			unsigned char ch = ptr[j];

			if (!isprint(ch)) {
				ch = '.';
			}

			printf("%c", ch);
		}
	}

	printf("\n");
}

#endif
