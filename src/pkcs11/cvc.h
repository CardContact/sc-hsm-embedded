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
 * @file    cvc.h
 * @author  Andreas Schwier
 * @brief   Encoding and decoding of card verifiable certificates
 */

#
/* Prevent from including twice ------------------------------------------- */

#ifndef __CVC_H__
#define __CVC_H__

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

#include <pkcs11/bytestring.h>

struct ec_curve {
	struct bytestring_s oid;
	struct bytestring_s prime;
	struct bytestring_s coefficientA;
	struct bytestring_s coefficientB;
	struct bytestring_s basePointG;
	struct bytestring_s order;
	struct bytestring_s coFactor;
};


/**
 * The cvc structure provides for a mapping into the field of an encoded CVC certificate.
 */
struct cvc {
	int cpi;								// Certificate profile indicator (0)
	struct bytestring_s car;				// Certification authority reference

	struct bytestring_s pukoid;				// Public key algorithm object identifier
	struct bytestring_s primeOrModulus;		// Prime for ECC or modulus for RSA
	struct bytestring_s coefficientAorExponent;			// Coefficient A for ECC or public exponent for RSA
	struct bytestring_s coefficientB;		// Coefficient B for ECC
	struct bytestring_s basePointG;			// Base point for ECC
	struct bytestring_s order;				// Order of the base point for ECC
	struct bytestring_s publicPoint;		// Public point for ECC
	struct bytestring_s cofactor;			// Cofactor for ECC

	int modulusSize;						// Size of RSA modulus in bits

	struct bytestring_s chr;				// Certificate holder reference

	struct bytestring_s signature;			// Certificate signature or request self-signed signature

	struct bytestring_s outer_car;			// Instance signing the request
	struct bytestring_s outerSignature;		// Request authenticating signature
};
typedef struct cvc cvc_t;

struct ec_curve *cvcGetCurveForOID(bytestring oid);

 /* Support for C++ compiler ----------------------------------------------- */

 #ifdef __cplusplus
 }
 #endif
 #endif
