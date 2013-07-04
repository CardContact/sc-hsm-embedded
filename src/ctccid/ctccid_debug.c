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
 * @file    ctccid_debug.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Debug and logging functions
 */

#ifdef DEBUG

#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#ifdef WIN32
#include <io.h>
#include <ctype.h>
#endif

#include "ctccid_debug.h"

static FILE *debugFileHandle = (FILE *)1; /* uninitialized */


void ctccid_initDebug()
{
	static const char debug_fn[] = "/var/tmp/sc-hsm-embedded/ctccid.log";

	if (debugFileHandle != NULL && debugFileHandle != (FILE *)1) {
		return;
	}

	debugFileHandle = fopen(debug_fn, "a+");

	if (debugFileHandle != NULL) {
		fprintf(debugFileHandle, "Debugging initialized ...\n");
	} else {
		fprintf(stderr, "Can't create: '%s'.\n", debug_fn);
	}
}


void ctccid_debug(char *format, ...)
{
	struct tm *loctim;
	time_t elapsed;
	va_list argptr;

	if (debugFileHandle == (FILE *)1) { /* open on demand */
		ctccid_initDebug();
	}

	if (debugFileHandle == NULL) {
		return;
	}

	time(&elapsed);
	loctim = localtime(&elapsed);

	fprintf(debugFileHandle, "%02d.%02d.%04d %02d:%02d:%02d ",
			loctim->tm_mday,
			loctim->tm_mon,
			loctim->tm_year+1900,
			loctim->tm_hour,
			loctim->tm_min,
			loctim->tm_sec);

	va_start(argptr, format);
	vfprintf(debugFileHandle, format, argptr);
	fflush(debugFileHandle);
	va_end(argptr);
}


void ctccid_dump(void *_ptr, int len)
{
	unsigned char *ptr = (unsigned char *)_ptr;
	int i;

	static char *MinStack = (char *)-1;
	static char *MaxStack; /* = 0; */

	if (debugFileHandle == (FILE *)1) { /* open on demand */
		ctccid_initDebug();
	}

	if (debugFileHandle == NULL) {
		return;
	}

	if (MinStack > (char *)&ptr)
		MinStack = (char *)&ptr;
	if (MaxStack < (char *)&ptr)
		MaxStack = (char *)&ptr;

	ctccid_debug("Dump(%p, %d) stack used so far: %d\n", ptr, len, (int)(MaxStack - MinStack));
	ctccid_debug("Buffer content:\n", ptr, len, (int)(MaxStack - MinStack));

	for (i = 0; i < len; i += 16) {
		int i1 = i + 16;
		int i2 = i1;
		int j;

		if (i1 > len) {
			i1 = len;
		}

		if (i % 16 == 0) {
			fprintf(debugFileHandle, "\n  %04x: ", i);
		}

		for (j = i; j < i1; j++) {
			fprintf(debugFileHandle, "%02x ", ptr[j]);
		}

		for (     ; j < i2; j++) {
			fprintf(debugFileHandle, "   ");
		}

		fprintf(debugFileHandle, " ");

		for (j = i; j < i1; j++) {
			unsigned char ch = ptr[j];

			if (!isprint(ch)) {
				ch = '.';
			}

			fprintf(debugFileHandle, "%c", ch);
		}
	}

	fprintf(debugFileHandle, "\n");
}

void ctccid_termDebug()
{
	if (debugFileHandle != NULL && debugFileHandle != (FILE *)1) {
		fprintf(debugFileHandle, "Debugging terminated ...\n");
		fflush(debugFileHandle);
		fclose(debugFileHandle);
		debugFileHandle = NULL;
	}
}

#endif /* DEBUG */