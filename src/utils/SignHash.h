/**
 * SmartCard-HSM Ultra-Light Library
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
 * @file SignHash.h
 * @author Christoph Brunhuber
 * @brief Functions for RSA-2k signing of SHA1, SHA-256, SHA-384, SHA-512
 *                  ECDSA-prime256 signing of SHA1, SHA-256
 *                  Card Devices, Version 1.0
 */

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
