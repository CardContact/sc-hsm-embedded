/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2003. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  --------- 
 *
 * The Smart Card Development Platform (SCDP) provides a basic framework to
 * implement smartcard aware applications.
 *
 * Abstract :       Debug and logging functions
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

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



int initDebug(struct p11Context_t *context)
{
	FILE *fh;

	fh = fopen("/var/tmp/pkcs11.log", "a+");

	if (fh == NULL) {
		return -1;
	}

	context->debugFileHandle = fh;

	fprintf(fh, "Debugging initialized ...\n");

	return 0;
}



int debug(unsigned char *log, ...)
{
	struct tm *loctim;
	time_t elapsed;
	va_list argptr;

	time(&elapsed);
	loctim = localtime(&elapsed);

	if (context->debugFileHandle != NULL) {

		fprintf(context->debugFileHandle, "%02d.%02d.%04d %02d:%02d ",
				loctim->tm_mday,
				loctim->tm_mon,
				loctim->tm_year+1900,
				loctim->tm_hour,
				loctim->tm_min);

		va_start(argptr, log);
		vfprintf(context->debugFileHandle, log, argptr);
		fflush(context->debugFileHandle);
		va_end(argptr);
	}

	return 0;
}



int termDebug(struct p11Context_t *context)
{
	if (context->debugFileHandle != NULL) {
		fprintf(context->debugFileHandle, "Debugging terminated ...\n");
		fflush(context->debugFileHandle);
		fclose(context->debugFileHandle);
		context->debugFileHandle = NULL;
	}

	return 0;
}

