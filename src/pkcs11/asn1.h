/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2004. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  --------- 
 *
 * The Smart Card Development Platform (SCDP) provides a basic framework to
 * implement smartcard aware applications.
 */

/**
 * @file    asn1.h
 * @author  Andreas Schwier (ASC)
 * @brief   Encoding and decoding for TLV structures
 *
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
#define ASN1_UTF8String         0x0C
#define ASN1_SEQUENCE           0x30

unsigned int    asn1Tag(unsigned char **Ref);
int             asn1Length(unsigned char **Ref);
void            asn1StoreTag(unsigned char **Ref, unsigned short Tag);
void            asn1StoreLength(unsigned char **Ref, int Length);
int             asn1Encap(unsigned short Tag, unsigned char *Msg, int MsgLen);
unsigned char  *asn1Find(unsigned char *data, unsigned char *path, int level);
int             asn1Validate(unsigned char *data, size_t length);
void            asn1DecodeFlags(unsigned char *data, size_t length, unsigned long *flags);
int             asn1DecodeInteger(unsigned char *data, size_t length, int *value);

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif

