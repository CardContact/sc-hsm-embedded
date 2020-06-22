/**
 * SmartCard-HSM PKCS#11 Module
 *
 * Copyright (c) 2017, CardContact Systems GmbH, Minden, Germany
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
 * @file    crypto.h
 * @author  Andreas Schwier
 * @brief   Public key crypto implementation standard API
 */

#ifndef ___CRYPTO_INC___
#define ___CRYPTO_INC___

#include <pkcs11/object.h>



void cryptoInitialize();
void cryptoFinalize();
CK_RV stripOAEPPadding(unsigned char *raw, int rawlen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen, CK_RSA_PKCS_MGF_TYPE mgf1Type);
CK_RV cryptoVerifyInit(struct p11Object_t *, CK_MECHANISM_PTR);
CK_RV cryptoVerify(struct p11Object_t *, CK_MECHANISM_TYPE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
CK_RV cryptoEncryptInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech);
CK_RV cryptoEncrypt(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);
CK_RV cryptoDigestInit(struct p11Session_t * session, CK_MECHANISM_PTR mech);
CK_RV cryptoDigest(struct p11Session_t * session, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);
CK_RV cryptoDigestUpdate(struct p11Session_t * session, CK_BYTE_PTR pPart, CK_ULONG ulPartLen);
CK_RV cryptoDigestFinal(struct p11Session_t * session, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);


#endif /* ___CRYPTO_INC___ */
