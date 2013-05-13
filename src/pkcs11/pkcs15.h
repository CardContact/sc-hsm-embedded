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

#define P15_KEYTYPE_RSA     0x30
#define P15_KEYTYPE_ECC     0xA0

#define P15_ENCIPHER        0x80000000
#define P15_DECIPHER        0x40000000
#define P15_SIGN            0x20000000
#define P15_SIGNRECOVER     0x10000000
#define P15_KEYENCIPHER     0x08000000
#define P15_KEYDECIPHER     0x04000000
#define P15_VERIFY          0x02000000
#define P15_VERIFYRECOVER   0x01000000
#define P15_DERIVE          0x00800000
#define P15_NONREPUDIATION  0x00400000

struct p15CommonObjectAttributes {
	char			*label;
};

struct p15PrivateKeyDescription {
	int				keytype;
	struct p15CommonObjectAttributes
					coa;
	size_t			idlen;
	unsigned char	*id;
	unsigned long	usage;
	int				keysize;
};

int decodePrivateKeyDescription(unsigned char *prkd, size_t prkdlen, struct p15PrivateKeyDescription **p15);
void freePrivateKeyDescription(struct p15PrivateKeyDescription **p15);


/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif
