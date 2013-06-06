/*
 *  ---------
 * |.**> <**.|  CardContact
 * |*       *|  Software & System Consulting
 * |*       *|  Minden, Germany
 * |.**> <**.|  Copyright (c) 2013. All rights reserved
 *  ---------
 *
 * See file LICENSE for details on licensing
 *
 * Abstract :       Set of utility functions
 *
 * Author :         Frank Thater
 *
 * Last modified:   2013-05-07
 *
 *****************************************************************************/

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
	printf("Dump(%p, %d) stack used so far: %d", ptr, len, MaxStack - MinStack);

	for (i = 0; i < len; i += 16) {
		int i1 = i + 16;
		int i2 = i1;
		int j;

		if (i1 > len) {
			i1 = len;
		}

		if (i % 16 == 0) {
			printf("\n  %04x: ", (char*)i);
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
