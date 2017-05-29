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
 * @file    sc-hsm-pkcs11.h
 * @author  Andreas Schwier
 * @brief   Additional PKCS#11 Attributes
 */

/* Prevent from including twice ------------------------------------------- */

#ifndef __SC_HSM_PKCS11_H__
#define __SC_HSM_PKCS11_H__

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
extern "C" {
#endif

#define CKA_INNER_CAR				CKA_VENDOR_DEFINED + 0x00000100
#define CKA_OUTER_CAR				CKA_VENDOR_DEFINED + 0x00000101
#define CKA_CHR						CKA_VENDOR_DEFINED + 0x00000102
#define CKA_PUBLIC_KEY_ALGORITHM	CKA_VENDOR_DEFINED + 0x00000103
#define CKA_KEY_USE_COUNTER			CKA_VENDOR_DEFINED + 0x00000104
#define CKA_ALGORITHM_LIST			CKA_VENDOR_DEFINED + 0x00000105
#define CKA_CVC_REQUEST				CKA_VENDOR_DEFINED + 0x00000106

#define CKC_CVC_TR3110				CKC_VENDOR_DEFINED + 0x80000001

/* Support for C++ compiler ----------------------------------------------- */

#ifdef __cplusplus
}
#endif
#endif

