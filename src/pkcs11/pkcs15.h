/*
 *  ---------
 * |.**> <**.|  CardContact Software & System Consulting
 * |*       *|  32429 Minden, Germany (www.cardcontact.de)
 * |*       *|  Copyright (c) 1999-2004. All rights reserved
 * |'**> <**'|  See file COPYING for details on licensing
 *  ---------
 */

/**
 * @file    pkcs15.c
 * @author  Andreas Schwier (ASC)
 * @brief   Decoder for PKCS#15 private key, certificate and data objects
 */

/* Prevent from including twice ------------------------------------------- */

#ifndef __PKCS15_H__
#define __PKCS15_H__

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

#define P15_KEYTYPE_RSA		0x30
#define P15_KEYTYPE_ECC		0xA0

struct p15PrivateKeyDescription {
	int				keytype;
	char			*label;
	unsigned char	*id;
	int				keysize;
};

int decodePrivateKeyDescription(unsigned char *prkd, size_t prkdlen, struct p15PrivateKeyDescription **p15);
void freePrivateKeyDescription(struct p15PrivateKeyDescription **p15);


/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif
