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
 * @file    debug.c
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
#endif

#include <pkcs11/debug.h>

extern struct p11Context_t *context;

#define bcddigit(x) ((x) >= 10 ? 'A' - 10 + (x) : '0' + (x))



/*
 *  Convert a string of bytes in BCD coding to a string of hexadecimal char.
 *
 */
void decodeBCDString(unsigned char *Inbuff, int len, char *Outbuff)
{
	while (len--) {
		*Outbuff++ = bcddigit(*Inbuff >> 4);
		*Outbuff++ = bcddigit(*Inbuff & 15);
		Inbuff++;
	}
	*Outbuff++ = '\0';
}


void initDebug(struct p11Context_t *context)
{
	static const char debug_fn[] = "/var/tmp/sc-hsm-embedded/pkcs11.log";

	if (context->debugFileHandle != NULL) {
		return;
	}

	context->debugFileHandle = fopen(debug_fn, "a+");

	if (context->debugFileHandle != NULL) {
		fprintf(context->debugFileHandle, "Debugging initialized ...\n");
	} else {
		fprintf(stderr, "Can't create: '%s'.\n", debug_fn);
	}
}


void debug(char *format, ...)
{
	struct tm *loctim;
	time_t elapsed;
	va_list argptr;

	if ((context == NULL) || (context->debugFileHandle == NULL)) {
		return;
	}

	time(&elapsed);
	loctim = localtime(&elapsed);

	fprintf(context->debugFileHandle, "%02d.%02d.%04d %02d:%02d:%02d ",
			loctim->tm_mday,
			loctim->tm_mon,
			loctim->tm_year+1900,
			loctim->tm_hour,
			loctim->tm_min,
			loctim->tm_sec);

	va_start(argptr, format);
	vfprintf(context->debugFileHandle, format, argptr);
	fflush(context->debugFileHandle);
	va_end(argptr);
}


void termDebug(struct p11Context_t *context)
{
	if (context->debugFileHandle != NULL) {
		fprintf(context->debugFileHandle, "Debugging terminated ...\n");
		fflush(context->debugFileHandle);
		fclose(context->debugFileHandle);
		context->debugFileHandle = NULL;
	}
}

#endif /* DEBUG */
