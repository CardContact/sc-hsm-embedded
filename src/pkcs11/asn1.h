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
 * @file    asn1.h
 * @author  Andreas Schwier
 * @brief   Encoding and decoding for TLV structures
 */

/* Prevent from including twice ------------------------------------------- */

#ifndef __ASN1_H__
#define __ASN1_H__

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

#define ASN1_INTEGER            0x02
#define ASN1_BIT_STRING         0x03
#define ASN1_OCTET_STRING       0x04
#define ASN1_OBJECT_IDENTIFIER  0x06
#define ASN1_UTF8String         0x0C
#define ASN1_SEQUENCE           0x30

unsigned int    asn1Tag(unsigned char **Ref);
int             asn1Length(unsigned char **Ref);
void            asn1StoreTag(unsigned char **Ref, unsigned short Tag);
void            asn1StoreLength(unsigned char **Ref, int Length);
int             asn1Encap(unsigned short Tag, unsigned char *Msg, int MsgLen);
unsigned char  *asn1Find(unsigned char *data, unsigned char *path, int level);
int             asn1Validate(unsigned char *data, size_t length);
int             asn1Next(unsigned char **ref, int *reflen, int *tag, int *length, unsigned char **value);
void            asn1DecodeFlags(unsigned char *data, size_t length, unsigned long *flags);
int             asn1DecodeInteger(unsigned char *data, size_t length, int *value);

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif

