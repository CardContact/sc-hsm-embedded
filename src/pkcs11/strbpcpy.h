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

#ifndef ___STRBPCPY_H_INC___
#define ___STRBPCPY_H_INC___

#include <stdio.h>
#include <string.h>

#include <pkcs11/cryptoki.h>

void strbpcpy(CK_CHAR *dst, const char *src, int dstsize);

void removeBlanks(unsigned char *dst, const unsigned char *src);

#endif /* ___STRBPCPY_H_INC___ */
