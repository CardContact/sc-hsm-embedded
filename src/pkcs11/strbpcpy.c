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
 * Abstract :       String copy routine with blank padding
 *
 * Author :         Frank Thater (FTH)
 *
 *****************************************************************************/

/**
 * \file    strbpcpy.c
 * \author  Frank Thater (fth)
 * \brief   String copy routine with blank padding
 *
 */

#include <strbpcpy.h>

/**
 * strbpcpy() copies the source string to the destination string.
 *
 * If the source string has less characters than the destination string,
 * the destination string is padded with blanks.
 *
 * @param dst       Pointer to the destinantion buffer.
 * @param src       Pointer to the source buffer.
 * @param dstsize   The size of the destination buffer.
 *
 */
void strbpcpy(CK_CHAR *dst, const char *src, int dstsize)
{
	int c = strlen(src) > (unsigned int) dstsize ? dstsize : strlen(src);

	memcpy((char *) dst, src, c);
	dstsize -= c;
	memset((char *) dst + c, ' ', dstsize);
}



void removeBlanks(unsigned char *dst, const unsigned char *src)
{
	int i = 0; /* the maximum length of the label */

	memcpy(dst, src, 32);

	while (dst[i] != 0x20) { /* search for the first blank */
		i++;
	}

	dst[i] = '\0';
}
