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
 * @file    crypto-libcrypto.c
 * @author  Andreas Schwier
 * @brief   Public key crypto implementation using OpenSSLs libcrypto
 */

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include <common/cvc.h>
#include <pkcs11/crypto.h>


#ifdef DEBUG
#include <common/debug.h>
#endif



void cryptoInitialize()
{
#ifdef DEBUG
	ERR_load_crypto_strings();
#endif

	OPENSSL_no_config();
	OpenSSL_add_all_algorithms();

#ifdef DEBUG
	CRYPTO_malloc_debug_init();
	CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
#endif
}



void cryptoFinalize()
{
#ifdef DEBUG_OPENSSL
	ERR_free_strings();

	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);
#endif

	EVP_cleanup();

	CONF_modules_finish();
	CONF_modules_unload(1);
	CONF_modules_free();
}



/**
 * Digest input and verify signature
 */
static int digestVerify(EVP_PKEY *key, const EVP_MD *hash, int padding, const unsigned char *data, int data_len, unsigned char *signature, int signature_len)
{
	EVP_MD_CTX *md_ctx;
	EVP_PKEY_CTX *pkey_ctx;
	int rv, rc;

	md_ctx = EVP_MD_CTX_create();
	EVP_MD_CTX_init(md_ctx);

	if (!EVP_DigestVerifyInit(md_ctx, &pkey_ctx, hash, NULL, key)) {
		FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_DigestVerifyInit() failed");
	}

	if (padding) {
		if (!EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding)) {
			FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_PKEY_CTX_set_rsa_padding() failed");
		}

		if (padding == RSA_PKCS1_PSS_PADDING) {
			if (!EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -2)) {
				FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_PKEY_CTX_set_rsa_pss_saltlen() failed");
			}
		}
	}

	if (!EVP_DigestVerifyUpdate(md_ctx, data, data_len)) {
		FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_DigestVerifyUpdate() failed");
	}

	rc = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);

	if (rc < 0) {
		FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_DigestVerifyFinal() failed");
	}

	rv = rc == 1 ? CKR_OK : CKR_SIGNATURE_INVALID;

out:
	EVP_MD_CTX_destroy(md_ctx);

	FUNC_RETURNS(rv);
}



/**
 * Verify signature with provided hash value
 */
static int verifyHash(EVP_PKEY *key, const EVP_MD *hash, int padding, const unsigned char *data, int data_len, unsigned char *signature, int signature_len)
{
	EVP_PKEY_CTX *pkey_ctx;
	int rv, rc;

	pkey_ctx = EVP_PKEY_CTX_new(key, NULL);

	if (!EVP_PKEY_verify_init(pkey_ctx)) {
		FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_PKEY_verify_init() failed");
	}

	if (padding) {
		if (!EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, padding)) {
			FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_PKEY_CTX_set_rsa_padding() failed");
		}

		if (padding == RSA_PKCS1_PSS_PADDING) {
			if (!EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -2)) {
				FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_PKEY_CTX_set_rsa_pss_saltlen() failed");
			}
		}
	}

	if (!EVP_PKEY_CTX_set_signature_md(pkey_ctx, hash)) {
		FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_PKEY_CTX_set_signature_md() failed");
	}

	rc = EVP_PKEY_verify(pkey_ctx, signature, signature_len, data, data_len);
	if (rc < 0) {
		FUNC_FAILVIAOUT(CKR_DEVICE_ERROR, "EVP_PKEY_verify() failed");
	}

	rv = rc == 1 ? CKR_OK : CKR_SIGNATURE_INVALID;

out:
	EVP_PKEY_CTX_free(pkey_ctx);

	FUNC_RETURNS(rv);
}



/**
 * Verify signature against a provided DigestInfo block as used in CKM_RSA_PKCS
 *
 */
static int verifyDigestInfo(RSA *key, const unsigned char *data, int data_len, unsigned char *signature, int signature_len)
{
	unsigned char plain[512];
	int rc;

	FUNC_CALLED();

	if (signature_len != RSA_size(key)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Signature size does not match modulus size");
	}

	if (signature_len > sizeof(plain)) {
		FUNC_FAILS(CKR_ARGUMENTS_BAD, "Signature size exceeds 4096 bit");
	}

	rc = RSA_public_decrypt(signature_len, signature, plain, key, RSA_PKCS1_PADDING);

	if ((rc != data_len) || memcmp(plain, data, data_len)) {
		FUNC_FAILS(CKR_SIGNATURE_INVALID, "DigestInfo does not match input reference value");
	}

	FUNC_RETURNS(CKR_OK);
}



/**
 * Verify with RSA key
 */
static int verifyRSA(struct p11Object_t *obj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	struct p11Attribute_t *modulus;
	struct p11Attribute_t *public_exponent;
	RSA *rsa;
	EVP_PKEY *pkey;
	int rv = 0;

	FUNC_CALLED();

	rv = findAttribute(obj, CKA_MODULUS, &modulus);

	if (rv == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_MODULUS not found");

	if (modulus->attrData.ulValueLen != signature_len)
		FUNC_FAILS(CKR_SIGNATURE_LEN_RANGE, "Length of modulus does not match signature length");

	rv = findAttribute(obj, CKA_PUBLIC_EXPONENT, &public_exponent);

	if (rv == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_EXPONENT not found");

	rsa = RSA_new();

	rsa->n = BN_bin2bn(modulus->attrData.pValue, modulus->attrData.ulValueLen, NULL);
	rsa->e = BN_bin2bn(public_exponent->attrData.pValue, public_exponent->attrData.ulValueLen, NULL);

	pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);

	switch (mech) {
		case CKM_SHA1_RSA_PKCS:
			rv = digestVerify(pkey, EVP_sha1(), RSA_PKCS1_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA224_RSA_PKCS:
			rv = digestVerify(pkey, EVP_sha224(), RSA_PKCS1_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA256_RSA_PKCS:
			rv = digestVerify(pkey, EVP_sha256(), RSA_PKCS1_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA384_RSA_PKCS:
			rv = digestVerify(pkey, EVP_sha384(), RSA_PKCS1_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA512_RSA_PKCS:
			rv = digestVerify(pkey, EVP_sha512(), RSA_PKCS1_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA1_RSA_PKCS_PSS:
			rv = digestVerify(pkey, EVP_sha1(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA224_RSA_PKCS_PSS:
			rv = digestVerify(pkey, EVP_sha224(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA256_RSA_PKCS_PSS:
			rv = digestVerify(pkey, EVP_sha256(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA384_RSA_PKCS_PSS:
			rv = digestVerify(pkey, EVP_sha384(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SHA512_RSA_PKCS_PSS:
			rv = digestVerify(pkey, EVP_sha512(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_RSA_PKCS:
			rv = verifyDigestInfo(rsa, in, in_len, signature, signature_len);
			break;
		case CKM_SC_HSM_PSS_SHA1:
			rv = verifyHash(pkey, EVP_sha1(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SC_HSM_PSS_SHA224:
			rv = verifyHash(pkey, EVP_sha224(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SC_HSM_PSS_SHA256:
			rv = verifyHash(pkey, EVP_sha256(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SC_HSM_PSS_SHA384:
			rv = verifyHash(pkey, EVP_sha384(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		case CKM_SC_HSM_PSS_SHA512:
			rv = verifyHash(pkey, EVP_sha512(), RSA_PKCS1_PSS_PADDING, in, in_len, signature, signature_len);
			break;
		default:
			rv = CKR_MECHANISM_INVALID;
			break;
	}

	EVP_PKEY_free(pkey);

	FUNC_RETURNS(rv);
}



static const EVP_MD *getHashForHashLen(int len) {
	switch(len) {
	case 16: return EVP_md5();
	case 20: return EVP_sha1();
	case 28: return EVP_sha224();
	case 32: return EVP_sha256();
	case 48: return EVP_sha384();
	case 64: return EVP_sha512();
	}
	return NULL;
}



/**
 * Verify with ECDSA key
 */
static int verifyECDSA(struct p11Object_t *obj, CK_MECHANISM_TYPE mech, CK_BYTE_PTR in, CK_ULONG in_len, CK_BYTE_PTR signature, CK_ULONG signature_len)
{
	struct p11Attribute_t *ecparam;
	struct p11Attribute_t *ecpoint;
	const unsigned char *po;
	unsigned char wrappedSig[140];
	EC_GROUP *ecg = NULL;
	EC_POINT *ecp = NULL;
	EC_KEY *ec = NULL;
	EVP_PKEY *pkey = NULL;
	const EVP_MD *md = NULL;
	int rv = 0, len;

	FUNC_CALLED();

	rv = findAttribute(obj, CKA_EC_PARAMS, &ecparam);

	if (rv == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_EC_PARAMS not found");

	rv = findAttribute(obj, CKA_EC_POINT, &ecpoint);

	if (rv == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_EC_POINT not found");

	po = ecparam->attrData.pValue;

	ecg = NULL;
	if (d2i_ECPKParameters(&ecg, &po, ecparam->attrData.ulValueLen) == NULL) {
		FUNC_FAILVIAOUT(CKR_TEMPLATE_INCOMPLETE, "d2i_ECPKParameters() could not decode curve");
	}

	ec = EC_KEY_new();

	if (ec == NULL) {
		FUNC_FAILVIAOUT(CKR_HOST_MEMORY, "Out of memory");
	}

	ecp = EC_POINT_new(ecg);

	if (ecp == NULL) {
		FUNC_FAILVIAOUT(CKR_HOST_MEMORY, "Out of memory");
	}

	if (!EC_POINT_oct2point(ecg, ecp, ecpoint->attrData.pValue + 2, ecpoint->attrData.ulValueLen - 2, NULL)) {
		FUNC_FAILVIAOUT(CKR_TEMPLATE_INCOMPLETE, "EC_POINT_oct2point() could not decode point");
	}

	if (!EC_KEY_set_group(ec, ecg)) {
		FUNC_FAILVIAOUT(CKR_TEMPLATE_INCOMPLETE, "EC_KEY_set_group() failed");
	}

	if (!EC_KEY_set_public_key(ec, ecp)) {
		FUNC_FAILVIAOUT(CKR_TEMPLATE_INCOMPLETE, "EC_KEY_set_public_key() failed");
	}

	pkey = EVP_PKEY_new();

	if (pkey == NULL) {
		FUNC_FAILVIAOUT(CKR_HOST_MEMORY, "Out of memory");
	}

	if (!EVP_PKEY_assign_EC_KEY(pkey, ec)) {
		FUNC_FAILVIAOUT(CKR_TEMPLATE_INCOMPLETE, "EVP_PKEY_assign_EC_KEY() failed");
	}

	len = sizeof(wrappedSig);
	if (cvcWrapECDSASignature(signature, signature_len, wrappedSig, &len) < 0) {
		FUNC_FAILVIAOUT(CKR_HOST_MEMORY, "Out of memory");
	}

	switch (mech) {
		case CKM_ECDSA_SHA1:
			rv = digestVerify(pkey, EVP_sha1(), 0, in, in_len, wrappedSig, len);
			break;
		case CKM_ECDSA:
			md = getHashForHashLen(in_len);
			if (md == NULL) {
				FUNC_FAILVIAOUT(CKR_ARGUMENTS_BAD, "getHashForHashLen() failed");
			}
			rv = verifyHash(pkey, md, 0, in, in_len, wrappedSig, len);
			break;
		default:
			FUNC_FAILVIAOUT(CKR_MECHANISM_INVALID, "Invalid mechanism for ECDSA");
			break;
	}

out:
	if (ecg != NULL)
		EC_GROUP_free(ecg);

	if (ecp != NULL)
		EC_POINT_free(ecp);

	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	FUNC_RETURNS(rv);
}



int cryptoVerifyInit(struct p11Object_t *pObject, CK_MECHANISM_PTR mech)
{
	struct p11Attribute_t *keytype;
	int rv;

	FUNC_CALLED();

	rv = findAttribute(pObject, CKA_KEY_TYPE, &keytype);

	if (rv == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_KEY_TYPE not found");

	switch (*(CK_KEY_TYPE *)keytype->attrData.pValue) {
	case CKK_RSA:
		switch(mech->mechanism) {
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_RSA_PKCS:
		case CKM_SC_HSM_PSS_SHA1:
		case CKM_SC_HSM_PSS_SHA224:
		case CKM_SC_HSM_PSS_SHA256:
		case CKM_SC_HSM_PSS_SHA384:
		case CKM_SC_HSM_PSS_SHA512:
			break;
		default:
			FUNC_FAILS(CKR_MECHANISM_INVALID, "Invalid mechanism for RSA");
		}
		break;
	case CKK_EC:
		switch(mech->mechanism) {
		case CKM_ECDSA_SHA1:
		case CKM_ECDSA:
			break;
		default:
			FUNC_FAILS(CKR_MECHANISM_INVALID, "Invalid mechanism for ECDSA");
		}
		break;
	default:
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "CKA_KEY_TYPE is neither CKK_RSA nor CKK_EC");
	}

	FUNC_RETURNS(CKR_OK);
}



int cryptoVerify(struct p11Object_t *pObject, CK_MECHANISM_TYPE mech, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	struct p11Attribute_t *keytype;
	int rv;

	FUNC_CALLED();

	rv = findAttribute(pObject, CKA_KEY_TYPE, &keytype);

	if (rv == -1)
		FUNC_FAILS(CKR_TEMPLATE_INCOMPLETE, "CKA_KEY_TYPE not found");

	switch (*(CK_KEY_TYPE *)keytype->attrData.pValue) {
	case CKK_RSA:
		rv = verifyRSA(pObject, mech, pData, ulDataLen, pSignature, ulSignatureLen);
		break;
	case CKK_EC:
		rv = verifyECDSA(pObject, mech, pData, ulDataLen, pSignature, ulSignatureLen);
		break;
	default:
		FUNC_FAILS(CKR_KEY_HANDLE_INVALID, "CKA_KEY_TYPE is neither CKK_RSA nor CKK_EC");
	}

	FUNC_RETURNS(rv);
}
