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
 * Abstract :       Functions for
 *                  RSA-2k signing of SHA1, SHA-256, SHA-384, SHA-512
 *                  ECDSA-prime256 signing of SHA1, SHA-256
 *                  Card Devices, Version 1.0
 *
 * Author :         Christoph Brunhuber
 *
 * Last modified:   2013-05-13
 *
 *****************************************************************************/

#ifndef _SignHash_h_
#define _SignHash_h_

#ifndef ERR_INVALID
#define OK               0   /** Successful completion            */
#define ERR_INVALID     -1   /** Invalid parameter or value       */
#define ERR_CT          -8   /** Cardterminal error               */
#define ERR_TRANS       -10  /** Transmission error               */
#define ERR_MEMORY      -11  /** Memory allocate error            */
#define ERR_HOST        -127 /** Function aborted by host os      */
#define ERR_HTSI        -128 /** 'HTSI' error                     */
#endif
#define ERR_CARD      (-1000 -  0)
#define ERR_APDU      (-1000 -  1)
#define ERR_PIN       (-1000 -  2)
#define ERR_KEY       (-1000 -  3)
#define ERR_TEMPLATE  (-1000 -  4)
#define ERR_VERSION   (-1000 -  5)
#define ERR_SANITY    (-1000 -  6)
#define ERR_KEY_SIZE  (-1000 -  7)
#define ERR_HASH      (-1000 -  8)
#define ERR_TIME      (-1000 -  9)

int SignHash(const char *pin, const char *label,
	const unsigned char *hash, int hashLen,
	const unsigned char **ppCMS);

void ReleaseState();

typedef struct {
    unsigned int total[2];
    unsigned int state[8];
    unsigned char buffer[64];
} sha256_context;


void sha256_starts(sha256_context *ctx);
void sha256_update(sha256_context *ctx, unsigned char *input, unsigned int length);
void sha256_finish(sha256_context *ctx, unsigned char digest[32]);

#endif