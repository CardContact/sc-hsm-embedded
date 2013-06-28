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

#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#ifdef WIN32
#include <io.h>
#endif

#include <ctccid_debug.h>

#define bcddigit(x) ((x) >= 10 ? 'A' - 10 + (x) : '0' + (x))

static FILE *ctccid_debugFileHandle;



int ctccid_initDebug()
{
	ctccid_debugFileHandle = fopen("/var/tmp/sc-hsm-embedded/ctccid.log", "a+");

	if (ctccid_debugFileHandle == NULL) {
		/*
		 * Return success even if initialization of debugging fails
		 */
		return 0;
	}

	fprintf(ctccid_debugFileHandle, "Debugging initialized ...\n");

	return 0;
}



int ctccid_debug(char *log, ...)
{
	struct tm *loctim;
	time_t elapsed;
	va_list argptr;

	if (ctccid_debugFileHandle == NULL) {
		ctccid_initDebug();
	}

	if (ctccid_debugFileHandle != NULL) {

		time(&elapsed);
		loctim = localtime(&elapsed);

		fprintf(ctccid_debugFileHandle, "%02d.%02d.%04d %02d:%02d ",
				loctim->tm_mday,
				loctim->tm_mon,
				loctim->tm_year+1900,
				loctim->tm_hour,
				loctim->tm_min);

		va_start(argptr, log);
		vfprintf(ctccid_debugFileHandle, log, argptr);
		fflush(ctccid_debugFileHandle);
		va_end(argptr);
	}

	return 0;
}



int ctccid_debug_no_timestamp(char *log, ...)
{
	struct tm *loctim;
	time_t elapsed;
	va_list argptr;

	if (ctccid_debugFileHandle == NULL) {
		ctccid_initDebug();
	}

	if (ctccid_debugFileHandle != NULL) {

		va_start(argptr, log);
		vfprintf(ctccid_debugFileHandle, log, argptr);
		fflush(ctccid_debugFileHandle);
		va_end(argptr);
	}

	return 0;
}



int ctccid_termDebug()
{
	if (ctccid_debugFileHandle != NULL) {
		fprintf(ctccid_debugFileHandle, "Debugging terminated ...\n");
		fflush(ctccid_debugFileHandle);
		fclose(ctccid_debugFileHandle);
		ctccid_debugFileHandle = NULL;
	}

	return 0;
}

