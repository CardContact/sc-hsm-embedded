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

#ifdef _WIN32
#include <windows.h>
#include <KnownFolders.h>
#include <ShlObj.h>
#include <io.h>
#else
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#endif

#include "debug.h"

FILE *debugFileHandle = NULL;

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


void initDebug(char *progname)
{
	char scr[512];
	char *home, *prefix;
#ifdef WIN32
	DWORD pid;
	PWSTR dir;
	char homedir[512];
#else
	pid_t pid;
#endif

	if (debugFileHandle != NULL) {
		return;
	}

#ifdef WIN32
	if (SUCCEEDED(SHGetKnownFolderPath(&FOLDERID_LocalAppDataLow, 0, NULL, &dir))) {
		wcstombs(homedir, dir, sizeof(homedir));
		CoTaskMemFree(dir);
		home = homedir;
		prefix = "\\sc-hsm-embedded\\";
	} else {
		home = getenv("HOMEPATH");
		if (home == NULL)
			home = "c:\\";
		prefix = "\\AppData\\LocalLow\\sc-hsm-embedded\\";
	}
	pid = GetCurrentProcessId();
#else
	home = getenv("HOME");
	if (home == NULL)
		home = "/var";
	prefix = "/tmp/sc-hsm-embedded/";
	pid = getpid();
#endif

	sprintf(scr, "%s%s%s-%d.log", home, prefix, progname, pid);


	debugFileHandle = fopen(scr, "a+");

	if (debugFileHandle != NULL) {
		fprintf(debugFileHandle, "Debugging initialized ...\n");
	} else {
		fprintf(stderr, "Can't create: '%s'.\n", scr);
	}
}


void debug(char *format, ...)
{
	struct tm *loctim;
	time_t elapsed;
	va_list argptr;
#ifdef WIN32
	int tid = GetCurrentThreadId();
#else
	pthread_t tid = pthread_self();
#endif

	if (debugFileHandle == NULL) {
		return;
	}

	time(&elapsed);
	loctim = localtime(&elapsed);

	fprintf(debugFileHandle, "%02d.%02d.%04d %02d:%02d:%02d [%ld] ",
			loctim->tm_mday,
			loctim->tm_mon,
			loctim->tm_year+1900,
			loctim->tm_hour,
			loctim->tm_min,
			loctim->tm_sec,
			tid);

	va_start(argptr, format);
	vfprintf(debugFileHandle, format, argptr);
	fflush(debugFileHandle);
	va_end(argptr);
}


void termDebug()
{
	if (debugFileHandle != NULL) {
		fprintf(debugFileHandle, "Debugging terminated ...\n");
		fflush(debugFileHandle);
		fclose(debugFileHandle);
		debugFileHandle = NULL;
	}
}

#endif /* DEBUG */
