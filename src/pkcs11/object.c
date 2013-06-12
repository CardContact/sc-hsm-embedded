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
 * @file    object.c
 * @author  Frank Thater, Andreas Schwier
 * @brief   Functions for object management
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pkcs11/object.h>

CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
CK_MECHANISM_TYPE ckMechType = CK_UNAVAILABLE_INFORMATION;


#define NEEDED_ATTRIBUTES_STORAGEOBJECT      4

static struct attributesForObject_t attributesStorageObject[NEEDED_ATTRIBUTES_STORAGEOBJECT] = {
		{{CKA_TOKEN, 0, 0}, FALSE},
		{{CKA_PRIVATE, 0, 0}, FALSE},
		{{CKA_MODIFIABLE, &ckTrue, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_LABEL, NULL, 0}, TRUE}
};

#define NEEDED_ATTRIBUTES_KEYOBJECT          7

static struct attributesForObject_t attributesKeyObject[NEEDED_ATTRIBUTES_KEYOBJECT] = {
		{{CKA_KEY_TYPE, 0, 0}, FALSE},
		{{CKA_ID, NULL, 0}, TRUE},
		{{CKA_START_DATE, NULL, 0}, TRUE},
		{{CKA_END_DATE, NULL, 0}, TRUE},
		{{CKA_DERIVE, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_LOCAL, &ckFalse, sizeof(CK_BBOOL)}, TRUE},
		{{CKA_KEY_GEN_MECHANISM, &ckMechType, sizeof(CK_MECHANISM_TYPE)}, TRUE}
};


#ifdef DEBUG

#include <pkcs11/debug.h>


struct id2name_t p11CKMName[] = {
{ CKM_RSA_PKCS_KEY_PAIR_GEN     , "RSA_PKCS_KEY_PAIR_GEN", 0 },
{ CKM_RSA_PKCS                  , "RSA_PKCS", 0 },
{ CKM_RSA_9796                  , "RSA_9796", 0 },
{ CKM_RSA_X_509                 , "RSA_X_509", 0 },
{ CKM_MD2_RSA_PKCS              , "MD2_RSA_PKCS", 0 },
{ CKM_MD5_RSA_PKCS              , "MD5_RSA_PKCS", 0 },
{ CKM_SHA1_RSA_PKCS             , "SHA1_RSA_PKCS", 0 },
{ CKM_RIPEMD128_RSA_PKCS        , "RIPEMD128_RSA_PKCS", 0 },
{ CKM_RIPEMD160_RSA_PKCS        , "RIPEMD160_RSA_PKCS", 0 },
{ CKM_RSA_PKCS_OAEP             , "RSA_PKCS_OAEP", 0 },
{ CKM_RSA_X9_31_KEY_PAIR_GEN    , "RSA_X9_31_KEY_PAIR_GEN", 0 },
{ CKM_RSA_X9_31                 , "RSA_X9_31", 0 },
{ CKM_SHA1_RSA_X9_31            , "SHA1_RSA_X9_31", 0 },
{ CKM_RSA_PKCS_PSS              , "RSA_PKCS_PSS", 0 },
{ CKM_SHA1_RSA_PKCS_PSS         , "SHA1_RSA_PKCS_PSS", 0 },
{ CKM_DSA_KEY_PAIR_GEN          , "DSA_KEY_PAIR_GEN", 0 },
{ CKM_DSA                       , "DSA", 0 },
{ CKM_DSA_SHA1                  , "DSA_SHA1", 0 },
{ CKM_DH_PKCS_KEY_PAIR_GEN      , "DH_PKCS_KEY_PAIR_GEN", 0 },
{ CKM_DH_PKCS_DERIVE            , "DH_PKCS_DERIVE", 0 },
{ CKM_X9_42_DH_KEY_PAIR_GEN     , "X9_42_DH_KEY_PAIR_GEN", 0 },
{ CKM_X9_42_DH_DERIVE           , "X9_42_DH_DERIVE", 0 },
{ CKM_X9_42_DH_HYBRID_DERIVE    , "X9_42_DH_HYBRID_DERIVE", 0 },
{ CKM_X9_42_MQV_DERIVE          , "X9_42_MQV_DERIVE", 0 },
{ CKM_RC2_KEY_GEN               , "RC2_KEY_GEN", 0 },
{ CKM_RC2_ECB                   , "RC2_ECB", 0 },
{ CKM_RC2_CBC                   , "RC2_CBC", 0 },
{ CKM_RC2_MAC                   , "RC2_MAC", 0 },
{ CKM_RC2_MAC_GENERAL           , "RC2_MAC_GENERAL", 0 },
{ CKM_RC2_CBC_PAD               , "RC2_CBC_PAD", 0 },
{ CKM_RC4_KEY_GEN               , "RC4_KEY_GEN", 0 },
{ CKM_RC4                       , "RC4", 0 },
{ CKM_DES_KEY_GEN               , "DES_KEY_GEN", 0 },
{ CKM_DES_ECB                   , "DES_ECB", 0 },
{ CKM_DES_CBC                   , "DES_CBC", 0 },
{ CKM_DES_MAC                   , "DES_MAC", 0 },
{ CKM_DES_MAC_GENERAL           , "DES_MAC_GENERAL", 0 },
{ CKM_DES_CBC_PAD               , "DES_CBC_PAD", 0 },
{ CKM_DES2_KEY_GEN              , "DES2_KEY_GEN", 0 },
{ CKM_DES3_KEY_GEN              , "DES3_KEY_GEN", 0 },
{ CKM_DES3_ECB                  , "DES3_ECB", 0 },
{ CKM_DES3_CBC                  , "DES3_CBC", 0 },
{ CKM_DES3_MAC                  , "DES3_MAC", 0 },
{ CKM_DES3_MAC_GENERAL          , "DES3_MAC_GENERAL", 0 },
{ CKM_DES3_CBC_PAD              , "DES3_CBC_PAD", 0 },
{ CKM_CDMF_KEY_GEN              , "CDMF_KEY_GEN", 0 },
{ CKM_CDMF_ECB                  , "CDMF_ECB", 0 },
{ CKM_CDMF_CBC                  , "CDMF_CBC", 0 },
{ CKM_CDMF_MAC                  , "CDMF_MAC", 0 },
{ CKM_CDMF_MAC_GENERAL          , "CDMF_MAC_GENERAL", 0 },
{ CKM_CDMF_CBC_PAD              , "CDMF_CBC_PAD", 0 },
{ CKM_MD2                       , "MD2", 0 },
{ CKM_MD2_HMAC                  , "MD2_HMAC", 0 },
{ CKM_MD2_HMAC_GENERAL          , "MD2_HMAC_GENERAL", 0 },
{ CKM_MD5                       , "MD5", 0 },
{ CKM_MD5_HMAC                  , "MD5_HMAC", 0 },
{ CKM_MD5_HMAC_GENERAL          , "MD5_HMAC_GENERAL", 0 },
{ CKM_SHA_1                     , "SHA_1", 0 },
{ CKM_SHA_1_HMAC                , "SHA_1_HMAC", 0 },
{ CKM_SHA_1_HMAC_GENERAL        , "SHA_1_HMAC_GENERAL", 0 },
{ CKM_RIPEMD128                 , "RIPEMD128", 0 },
{ CKM_RIPEMD128_HMAC            , "RIPEMD128_HMAC", 0 },
{ CKM_RIPEMD128_HMAC_GENERAL    , "RIPEMD128_HMAC_GENERAL", 0 },
{ CKM_RIPEMD160                 , "RIPEMD160", 0 },
{ CKM_RIPEMD160_HMAC            , "RIPEMD160_HMAC", 0 },
{ CKM_RIPEMD160_HMAC_GENERAL    , "RIPEMD160_HMAC_GENERAL", 0 },
{ CKM_CAST_KEY_GEN              , "CAST_KEY_GEN", 0 },
{ CKM_CAST_ECB                  , "CAST_ECB", 0 },
{ CKM_CAST_CBC                  , "CAST_CBC", 0 },
{ CKM_CAST_MAC                  , "CAST_MAC", 0 },
{ CKM_CAST_MAC_GENERAL          , "CAST_MAC_GENERAL", 0 },
{ CKM_CAST_CBC_PAD              , "CAST_CBC_PAD", 0 },
{ CKM_CAST3_KEY_GEN             , "CAST3_KEY_GEN", 0 },
{ CKM_CAST3_ECB                 , "CAST3_ECB", 0 },
{ CKM_CAST3_CBC                 , "CAST3_CBC", 0 },
{ CKM_CAST3_MAC                 , "CAST3_MAC", 0 },
{ CKM_CAST3_MAC_GENERAL         , "CAST3_MAC_GENERAL", 0 },
{ CKM_CAST3_CBC_PAD             , "CAST3_CBC_PAD", 0 },
{ CKM_CAST5_KEY_GEN             , "CAST5_KEY_GEN", 0 },
{ CKM_CAST128_KEY_GEN           , "CAST128_KEY_GEN", 0 },
{ CKM_CAST5_ECB                 , "CAST5_ECB", 0 },
{ CKM_CAST128_ECB               , "CAST128_ECB", 0 },
{ CKM_CAST5_CBC                 , "CAST5_CBC", 0 },
{ CKM_CAST128_CBC               , "CAST128_CBC", 0 },
{ CKM_CAST5_MAC                 , "CAST5_MAC", 0 },
{ CKM_CAST128_MAC               , "CAST128_MAC", 0 },
{ CKM_CAST5_MAC_GENERAL         , "CAST5_MAC_GENERAL", 0 },
{ CKM_CAST128_MAC_GENERAL       , "CAST128_MAC_GENERAL", 0 },
{ CKM_CAST5_CBC_PAD             , "CAST5_CBC_PAD", 0 },
{ CKM_CAST128_CBC_PAD           , "CAST128_CBC_PAD", 0 },
{ CKM_RC5_KEY_GEN               , "RC5_KEY_GEN", 0 },
{ CKM_RC5_ECB                   , "RC5_ECB", 0 },
{ CKM_RC5_CBC                   , "RC5_CBC", 0 },
{ CKM_RC5_MAC                   , "RC5_MAC", 0 },
{ CKM_RC5_MAC_GENERAL           , "RC5_MAC_GENERAL", 0 },
{ CKM_RC5_CBC_PAD               , "RC5_CBC_PAD", 0 },
{ CKM_IDEA_KEY_GEN              , "IDEA_KEY_GEN", 0 },
{ CKM_IDEA_ECB                  , "IDEA_ECB", 0 },
{ CKM_IDEA_CBC                  , "IDEA_CBC", 0 },
{ CKM_IDEA_MAC                  , "IDEA_MAC", 0 },
{ CKM_IDEA_MAC_GENERAL          , "IDEA_MAC_GENERAL", 0 },
{ CKM_IDEA_CBC_PAD              , "IDEA_CBC_PAD", 0 },
{ CKM_GENERIC_SECRET_KEY_GEN    , "GENERIC_SECRET_KEY_GEN", 0 },
{ CKM_CONCATENATE_BASE_AND_KEY  , "CONCATENATE_BASE_AND_KEY", 0 },
{ CKM_CONCATENATE_BASE_AND_DATA , "CONCATENATE_BASE_AND_DATA", 0 },
{ CKM_CONCATENATE_DATA_AND_BASE , "CONCATENATE_DATA_AND_BASE", 0 },
{ CKM_XOR_BASE_AND_DATA         , "XOR_BASE_AND_DATA", 0 },
{ CKM_EXTRACT_KEY_FROM_KEY      , "EXTRACT_KEY_FROM_KEY", 0 },
{ CKM_SSL3_PRE_MASTER_KEY_GEN   , "SSL3_PRE_MASTER_KEY_GEN", 0 },
{ CKM_SSL3_MASTER_KEY_DERIVE    , "SSL3_MASTER_KEY_DERIVE", 0 },
{ CKM_SSL3_KEY_AND_MAC_DERIVE   , "SSL3_KEY_AND_MAC_DERIVE", 0 },
{ CKM_SSL3_MASTER_KEY_DERIVE_DH , "SSL3_MASTER_KEY_DERIVE_DH", 0 },
{ CKM_TLS_PRE_MASTER_KEY_GEN    , "TLS_PRE_MASTER_KEY_GEN", 0 },
{ CKM_TLS_MASTER_KEY_DERIVE     , "TLS_MASTER_KEY_DERIVE", 0 },
{ CKM_TLS_KEY_AND_MAC_DERIVE    , "TLS_KEY_AND_MAC_DERIVE", 0 },
{ CKM_TLS_MASTER_KEY_DERIVE_DH  , "TLS_MASTER_KEY_DERIVE_DH", 0 },
{ CKM_SSL3_MD5_MAC              , "SSL3_MD5_MAC", 0 },
{ CKM_SSL3_SHA1_MAC             , "SSL3_SHA1_MAC", 0 },
{ CKM_MD5_KEY_DERIVATION        , "MD5_KEY_DERIVATION", 0 },
{ CKM_MD2_KEY_DERIVATION        , "MD2_KEY_DERIVATION", 0 },
{ CKM_SHA1_KEY_DERIVATION       , "SHA1_KEY_DERIVATION", 0 },
{ CKM_PBE_MD2_DES_CBC           , "PBE_MD2_DES_CBC", 0 },
{ CKM_PBE_MD5_DES_CBC           , "PBE_MD5_DES_CBC", 0 },
{ CKM_PBE_MD5_CAST_CBC          , "PBE_MD5_CAST_CBC", 0 },
{ CKM_PBE_MD5_CAST3_CBC         , "PBE_MD5_CAST3_CBC", 0 },
{ CKM_PBE_MD5_CAST5_CBC         , "PBE_MD5_CAST5_CBC", 0 },
{ CKM_PBE_MD5_CAST128_CBC       , "PBE_MD5_CAST128_CBC", 0 },
{ CKM_PBE_SHA1_CAST5_CBC        , "PBE_SHA1_CAST5_CBC", 0 },
{ CKM_PBE_SHA1_CAST128_CBC      , "PBE_SHA1_CAST128_CBC", 0 },
{ CKM_PBE_SHA1_RC4_128          , "PBE_SHA1_RC4_128", 0 },
{ CKM_PBE_SHA1_RC4_40           , "PBE_SHA1_RC4_40", 0 },
{ CKM_PBE_SHA1_DES3_EDE_CBC     , "PBE_SHA1_DES3_EDE_CBC", 0 },
{ CKM_PBE_SHA1_DES2_EDE_CBC     , "PBE_SHA1_DES2_EDE_CBC", 0 },
{ CKM_PBE_SHA1_RC2_128_CBC      , "PBE_SHA1_RC2_128_CBC", 0 },
{ CKM_PBE_SHA1_RC2_40_CBC       , "PBE_SHA1_RC2_40_CBC", 0 },
{ CKM_PKCS5_PBKD2               , "PKCS5_PBKD2", 0 },
{ CKM_PBA_SHA1_WITH_SHA1_HMAC   , "PBA_SHA1_WITH_SHA1_HMAC", 0 },
{ CKM_KEY_WRAP_LYNKS            , "KEY_WRAP_LYNKS", 0 },
{ CKM_KEY_WRAP_SET_OAEP         , "KEY_WRAP_SET_OAEP", 0 },
{ CKM_SKIPJACK_KEY_GEN          , "SKIPJACK_KEY_GEN", 0 },
{ CKM_SKIPJACK_ECB64            , "SKIPJACK_ECB64", 0 },
{ CKM_SKIPJACK_CBC64            , "SKIPJACK_CBC64", 0 },
{ CKM_SKIPJACK_OFB64            , "SKIPJACK_OFB64", 0},
{ CKM_SKIPJACK_CFB64            , "SKIPJACK_CFB64", 0 },
{ CKM_SKIPJACK_CFB32            , "SKIPJACK_CFB32", 0 },
{ CKM_SKIPJACK_CFB16            , "SKIPJACK_CFB16", 0 },
{ CKM_SKIPJACK_CFB8             , "SKIPJACK_CFB8", 0 },
{ CKM_SKIPJACK_WRAP             , "SKIPJACK_WRAP", 0 },
{ CKM_SKIPJACK_PRIVATE_WRAP     , "SKIPJACK_PRIVATE_WRAP", 0 },
{ CKM_SKIPJACK_RELAYX           , "SKIPJACK_RELAYX", 0 },
{ CKM_KEA_KEY_PAIR_GEN          , "KEA_KEY_PAIR_GEN", 0 },
{ CKM_KEA_KEY_DERIVE            , "KEA_KEY_DERIVE", 0 },
{ CKM_FORTEZZA_TIMESTAMP        , "FORTEZZA_TIMESTAMP", 0 },
{ CKM_BATON_KEY_GEN             , "BATON_KEY_GEN", 0 },
{ CKM_BATON_ECB128              , "BATON_ECB128", 0 },
{ CKM_BATON_ECB96               , "BATON_ECB96", 0 },
{ CKM_BATON_CBC128              , "BATON_CBC128", 0 },
{ CKM_BATON_COUNTER             , "BATON_COUNTER", 0 },
{ CKM_BATON_SHUFFLE             , "BATON_SHUFFLE", 0 },
{ CKM_BATON_WRAP                , "BATON_WRAP", 0 },
{ CKM_ECDSA_KEY_PAIR_GEN        , "ECDSA_KEY_PAIR_GEN", 0 },
{ CKM_EC_KEY_PAIR_GEN           , "EC_KEY_PAIR_GEN", 0 },
{ CKM_ECDSA                     , "ECDSA", 0 },
{ CKM_ECDSA_SHA1                , "ECDSA_SHA1", 0 },
{ CKM_ECDH1_DERIVE              , "ECDH1_DERIVE", 0 },
{ CKM_ECDH1_COFACTOR_DERIVE     , "ECDH1_COFACTOR_DERIVE", 0 },
{ CKM_ECMQV_DERIVE              , "ECMQV_DERIVE", 0 },
{ CKM_JUNIPER_KEY_GEN           , "JUNIPER_KEY_GEN", 0 },
{ CKM_JUNIPER_ECB128            , "JUNIPER_ECB128", 0 },
{ CKM_JUNIPER_CBC128            , "JUNIPER_CBC128", 0 },
{ CKM_JUNIPER_COUNTER           , "JUNIPER_COUNTER", 0 },
{ CKM_JUNIPER_SHUFFLE           , "JUNIPER_SHUFFLE", 0 },
{ CKM_JUNIPER_WRAP              , "JUNIPER_WRAP", 0 },
{ CKM_FASTHASH                  , "FASTHASH", 0 },
{ CKM_AES_KEY_GEN               , "AES_KEY_GEN", 0 },
{ CKM_AES_ECB                   , "AES_ECB", 0 },
{ CKM_AES_CBC                   , "AES_CBC", 0 },
{ CKM_AES_MAC                   , "AES_MAC", 0 },
{ CKM_AES_MAC_GENERAL           , "AES_MAC_GENERAL", 0 },
{ CKM_AES_CBC_PAD               , "AES_CBC_PAD", 0 },
{ CKM_DSA_PARAMETER_GEN         , "DSA_PARAMETER_GEN", 0 },
{ CKM_DH_PKCS_PARAMETER_GEN     , "DH_PKCS_PARAMETER_GEN", 0 },
{ CKM_X9_42_DH_PARAMETER_GEN    , "X9_42_DH_PARAMETER_GEN", 0 },
{ 0, NULL }
};


struct id2name_t p11CKRName[] = {
{ CKR_CANCEL                            , "CKR_CANCEL", 0 },
{ CKR_HOST_MEMORY                       , "CKR_HOST_MEMORY", 0 },
{ CKR_SLOT_ID_INVALID                   , "CKR_SLOT_ID_INVALID", 0 },
{ CKR_GENERAL_ERROR                     , "CKR_GENERAL_ERROR", 0 },
{ CKR_FUNCTION_FAILED                   , "CKR_FUNCTION_FAILED", 0 },
{ CKR_ARGUMENTS_BAD                     , "CKR_ARGUMENTS_BAD", 0 },
{ CKR_NO_EVENT                          , "CKR_NO_EVENT", 0 },
{ CKR_NEED_TO_CREATE_THREADS            , "CKR_NEED_TO_CREATE_THREADS", 0 },
{ CKR_CANT_LOCK                         , "CKR_CANT_LOCK", 0 },
{ CKR_ATTRIBUTE_READ_ONLY               , "CKR_ATTRIBUTE_READ_ONLY", 0 },
{ CKR_ATTRIBUTE_SENSITIVE               , "CKR_ATTRIBUTE_SENSITIVE", 0 },
{ CKR_ATTRIBUTE_TYPE_INVALID            , "CKR_ATTRIBUTE_TYPE_INVALID", 0 },
{ CKR_ATTRIBUTE_VALUE_INVALID           , "CKR_ATTRIBUTE_VALUE_INVALID", 0 },
{ CKR_DATA_INVALID                      , "CKR_DATA_INVALID", 0 },
{ CKR_DATA_LEN_RANGE                    , "CKR_DATA_LEN_RANGE", 0 },
{ CKR_DEVICE_ERROR                      , "CKR_DEVICE_ERROR", 0 },
{ CKR_DEVICE_MEMORY                     , "CKR_DEVICE_MEMORY", 0 },
{ CKR_DEVICE_REMOVED                    , "CKR_DEVICE_REMOVED", 0 },
{ CKR_ENCRYPTED_DATA_INVALID            , "CKR_ENCRYPTED_DATA_INVALID", 0 },
{ CKR_ENCRYPTED_DATA_LEN_RANGE          , "CKR_ENCRYPTED_DATA_LEN_RANGE", 0 },
{ CKR_FUNCTION_CANCELED                 , "CKR_FUNCTION_CANCELED", 0 },
{ CKR_FUNCTION_NOT_PARALLEL             , "CKR_FUNCTION_NOT_PARALLEL", 0 },
{ CKR_FUNCTION_NOT_SUPPORTED            , "CKR_FUNCTION_NOT_SUPPORTED", 0 },
{ CKR_KEY_HANDLE_INVALID                , "CKR_KEY_HANDLE_INVALID", 0 },
{ CKR_KEY_SIZE_RANGE                    , "CKR_KEY_SIZE_RANGE", 0 },
{ CKR_KEY_TYPE_INCONSISTENT             , "CKR_KEY_TYPE_INCONSISTENT", 0 },
{ CKR_KEY_NOT_NEEDED                    , "CKR_KEY_NOT_NEEDED", 0 },
{ CKR_KEY_CHANGED                       , "CKR_KEY_CHANGED", 0 },
{ CKR_KEY_NEEDED                        , "CKR_KEY_NEEDED", 0 },
{ CKR_KEY_INDIGESTIBLE                  , "CKR_KEY_INDIGESTIBLE", 0 },
{ CKR_KEY_FUNCTION_NOT_PERMITTED        , "CKR_KEY_FUNCTION_NOT_PERMITTED", 0 },
{ CKR_KEY_NOT_WRAPPABLE                 , "CKR_KEY_NOT_WRAPPABLE", 0 },
{ CKR_KEY_UNEXTRACTABLE                 , "CKR_KEY_UNEXTRACTABLE", 0 },
{ CKR_MECHANISM_INVALID                 , "CKR_MECHANISM_INVALID", 0 },
{ CKR_MECHANISM_PARAM_INVALID           , "CKR_MECHANISM_PARAM_INVALID", 0 },
{ CKR_OBJECT_HANDLE_INVALID             , "CKR_OBJECT_HANDLE_INVALID", 0 },
{ CKR_OPERATION_ACTIVE                  , "CKR_OPERATION_ACTIVE", 0 },
{ CKR_OPERATION_NOT_INITIALIZED         , "CKR_OPERATION_NOT_INITIALIZED", 0 },
{ CKR_PIN_INCORRECT                     , "CKR_PIN_INCORRECT", 0 },
{ CKR_PIN_INVALID                       , "CKR_PIN_INVALID", 0 },
{ CKR_PIN_LEN_RANGE                     , "CKR_PIN_LEN_RANGE", 0 },
{ CKR_PIN_EXPIRED                       , "CKR_PIN_EXPIRED", 0 },
{ CKR_PIN_LOCKED                        , "CKR_PIN_LOCKED", 0 },
{ CKR_SESSION_CLOSED                    , "CKR_SESSION_CLOSED", 0 },
{ CKR_SESSION_COUNT                     , "CKR_SESSION_COUNT", 0 },
{ CKR_SESSION_HANDLE_INVALID            , "CKR_SESSION_HANDLE_INVALID", 0 },
{ CKR_SESSION_PARALLEL_NOT_SUPPORTED    , "CKR_SESSION_PARALLEL_NOT_SUPPORTED", 0 },
{ CKR_SESSION_READ_ONLY                 , "CKR_SESSION_READ_ONLY", 0 },
{ CKR_SESSION_EXISTS                    , "CKR_SESSION_EXISTS", 0 },
{ CKR_SESSION_READ_ONLY_EXISTS          , "CKR_SESSION_READ_ONLY_EXISTS", 0 },
{ CKR_SESSION_READ_WRITE_SO_EXISTS      , "CKR_SESSION_READ_WRITE_SO_EXISTS", 0 },
{ CKR_SIGNATURE_INVALID                 , "CKR_SIGNATURE_INVALID", 0 },
{ CKR_SIGNATURE_LEN_RANGE               , "CKR_SIGNATURE_LEN_RANGE", 0 },
{ CKR_TEMPLATE_INCOMPLETE               , "CKR_TEMPLATE_INCOMPLETE", 0 },
{ CKR_TEMPLATE_INCONSISTENT             , "CKR_TEMPLATE_INCONSISTENT", 0 },
{ CKR_TOKEN_NOT_PRESENT                 , "CKR_TOKEN_NOT_PRESENT", 0 },
{ CKR_TOKEN_NOT_RECOGNIZED              , "CKR_TOKEN_NOT_RECOGNIZED", 0 },
{ CKR_TOKEN_WRITE_PROTECTED             , "CKR_TOKEN_WRITE_PROTECTED", 0 },
{ CKR_UNWRAPPING_KEY_HANDLE_INVALID     , "CKR_UNWRAPPING_KEY_HANDLE_INVALID", 0 },
{ CKR_UNWRAPPING_KEY_SIZE_RANGE         , "CKR_UNWRAPPING_KEY_SIZE_RANGE", 0 },
{ CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  , "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT", 0 },
{ CKR_USER_ALREADY_LOGGED_IN            , "CKR_USER_ALREADY_LOGGED_IN", 0 },
{ CKR_USER_NOT_LOGGED_IN                , "CKR_USER_NOT_LOGGED_IN", 0 },
{ CKR_USER_PIN_NOT_INITIALIZED          , "CKR_USER_PIN_NOT_INITIALIZED", 0 },
{ CKR_USER_TYPE_INVALID                 , "CKR_USER_TYPE_INVALID", 0 },
{ CKR_USER_ANOTHER_ALREADY_LOGGED_IN    , "CKR_USER_ANOTHER_ALREADY_LOGGED_IN", 0 },
{ CKR_USER_TOO_MANY_TYPES               , "CKR_USER_TOO_MANY_TYPES", 0 },
{ CKR_WRAPPED_KEY_INVALID               , "CKR_WRAPPED_KEY_INVALID", 0 },
{ CKR_WRAPPED_KEY_LEN_RANGE             , "CKR_WRAPPED_KEY_LEN_RANGE", 0 },
{ CKR_WRAPPING_KEY_HANDLE_INVALID       , "CKR_WRAPPING_KEY_HANDLE_INVALID", 0 },
{ CKR_WRAPPING_KEY_SIZE_RANGE           , "CKR_WRAPPING_KEY_SIZE_RANGE", 0 },
{ CKR_WRAPPING_KEY_TYPE_INCONSISTENT    , "CKR_WRAPPING_KEY_TYPE_INCONSISTENT", 0 },
{ CKR_RANDOM_SEED_NOT_SUPPORTED         , "CKR_RANDOM_SEED_NOT_SUPPORTED", 0 },
{ CKR_RANDOM_NO_RNG                     , "CKR_RANDOM_NO_RNG", 0 },
{ CKR_DOMAIN_PARAMS_INVALID             , "CKR_DOMAIN_PARAMS_INVALID", 0 },
{ CKR_BUFFER_TOO_SMALL                  , "CKR_BUFFER_TOO_SMALL", 0 },
{ CKR_SAVED_STATE_INVALID               , "CKR_SAVED_STATE_INVALID", 0 },
{ CKR_INFORMATION_SENSITIVE             , "CKR_INFORMATION_SENSITIVE", 0 },
{ CKR_STATE_UNSAVEABLE                  , "CKR_STATE_UNSAVEABLE", 0 },
{ CKR_CRYPTOKI_NOT_INITIALIZED          , "CKR_CRYPTOKI_NOT_INITIALIZED", 0 },
{ CKR_CRYPTOKI_ALREADY_INITIALIZED      , "CKR_CRYPTOKI_ALREADY_INITIALIZED", 0 },
{ CKR_MUTEX_BAD                         , "CKR_MUTEX_BAD", 0 },
{ CKR_MUTEX_NOT_LOCKED                  , "CKR_MUTEX_NOT_LOCKED", 0 }
};

struct id2name_t p11CKOName[] = {
{ CKO_DATA                              , "CKO_DATA", 0 },
{ CKO_CERTIFICATE                       , "CKO_CERTIFICATE", 0 },
{ CKO_PUBLIC_KEY                        , "CKO_PUBLIC_KEY", 0 },
{ CKO_PRIVATE_KEY                       , "CKO_PRIVATE_KEY", 0 },
{ CKO_SECRET_KEY                        , "CKO_SECRET_KEY", 0 },
{ CKO_HW_FEATURE                        , "CKO_HW_FEATURE", 0 },
{ CKO_DOMAIN_PARAMETERS                 , "CKO_DOMAIN_PARAMETERS", 0 }
};

#define CKT_BBOOL       1
#define CKT_BIN         2
#define CKT_DATE        3
#define CKT_LONG        4
#define CKT_ULONG       5


struct id2name_t p11CKAName[] = {
{ CKA_CLASS                              , "CKA_CLASS", CKT_LONG },
{ CKA_TOKEN                              , "CKA_TOKEN", CKT_BBOOL },
{ CKA_PRIVATE                            , "CKA_PRIVATE", CKT_BBOOL },
{ CKA_LABEL                              , "CKA_LABEL", 0 },
{ CKA_APPLICATION                        , "CKA_APPLICATION", 0 },
{ CKA_VALUE                              , "CKA_VALUE", CKT_BIN },
{ CKA_OBJECT_ID                          , "CKA_OBJECT_ID", 0 },
{ CKA_CERTIFICATE_TYPE                   , "CKA_CERTIFICATE_TYPE", CKT_ULONG },
{ CKA_ISSUER                             , "CKA_ISSUER", 0 },
{ CKA_SERIAL_NUMBER                      , "CKA_SERIAL_NUMBER", 0 },
{ CKA_AC_ISSUER                          , "CKA_AC_ISSUER", 0 },
{ CKA_OWNER                              , "CKA_OWNER", 0 },
{ CKA_ATTR_TYPES                         , "CKA_ATTR_TYPES", 0 },
{ CKA_TRUSTED                            , "CKA_TRUSTED", 0 },
{ CKA_KEY_TYPE                           , "CKA_KEY_TYPE", 0 },
{ CKA_SUBJECT                            , "CKA_SUBJECT", 0 },
{ CKA_ID                                 , "CKA_ID", CKT_BIN },
{ CKA_SENSITIVE                          , "CKA_SENSITIVE", CKT_BBOOL },
{ CKA_ENCRYPT                            , "CKA_ENCRYPT", CKT_BBOOL },
{ CKA_DECRYPT                            , "CKA_DECRYPT", CKT_BBOOL },
{ CKA_WRAP                               , "CKA_WRAP", CKT_BBOOL },
{ CKA_UNWRAP                             , "CKA_UNWRAP", CKT_BBOOL },
{ CKA_SIGN                               , "CKA_SIGN", CKT_BBOOL },
{ CKA_SIGN_RECOVER                       , "CKA_SIGN_RECOVER", CKT_BBOOL },
{ CKA_VERIFY                             , "CKA_VERIFY", CKT_BBOOL },
{ CKA_VERIFY_RECOVER                     , "CKA_VERIFY_RECOVER", 0 },
{ CKA_DERIVE                             , "CKA_DERIVE", CKT_BBOOL },
{ CKA_START_DATE                         , "CKA_START_DATE", CKT_DATE },
{ CKA_END_DATE                           , "CKA_END_DATE", CKT_DATE },
{ CKA_MODULUS                            , "CKA_MODULUS", 0 },
{ CKA_MODULUS_BITS                       , "CKA_MODULUS_BITS", 0 },
{ CKA_PUBLIC_EXPONENT                    , "CKA_PUBLIC_EXPONENT", 0 },
{ CKA_PRIVATE_EXPONENT                   , "CKA_PRIVATE_EXPONENT", 0 },
{ CKA_PRIME_1                            , "CKA_PRIME_1", 0 },
{ CKA_PRIME_2                            , "CKA_PRIME_2", 0 },
{ CKA_EXPONENT_1                         , "CKA_EXPONENT_1", 0 },
{ CKA_EXPONENT_2                         , "CKA_EXPONENT_2", 0 },
{ CKA_COEFFICIENT                        , "CKA_COEFFICIENT", 0 },
{ CKA_PRIME                              , "CKA_PRIME", 0 },
{ CKA_SUBPRIME                           , "CKA_SUBPRIME", 0 },
{ CKA_BASE                               , "CKA_BASE", 0 },
{ CKA_PRIME_BITS                         , "CKA_PRIME_BITS", 0 },
{ CKA_SUBPRIME_BITS                      , "CKA_SUBPRIME_BITS", 0 },
{ CKA_VALUE_BITS                         , "CKA_VALUE_BITS", 0 },
{ CKA_VALUE_LEN                          , "CKA_VALUE_LEN", CKT_LONG },
{ CKA_EXTRACTABLE                        , "CKA_EXTRACTABLE", CKT_BBOOL },
{ CKA_LOCAL                              , "CKA_LOCAL", CKT_BBOOL },
{ CKA_NEVER_EXTRACTABLE                  , "CKA_NEVER_EXTRACTABLE", CKT_BBOOL },
{ CKA_ALWAYS_SENSITIVE                   , "CKA_ALWAYS_SENSITIVE", CKT_BBOOL },
{ CKA_KEY_GEN_MECHANISM                  , "CKA_KEY_GEN_MECHANISM", CKT_LONG },
{ CKA_MODIFIABLE                         , "CKA_MODIFIABLE", CKT_BBOOL },
{ CKA_EC_PARAMS                          , "CKA_EC_PARAMS", 0 },
{ CKA_EC_POINT                           , "CKA_EC_POINT", 0 },
{ CKA_SECONDARY_AUTH                     , "CKA_SECONDARY_AUTH", 0 },
{ CKA_AUTH_PIN_FLAGS                     , "CKA_AUTH_PIN_FLAGS", 0 },
{ CKA_HW_FEATURE_TYPE                    , "CKA_HW_FEATURE_TYPE", 0 },
{ CKA_RESET_ON_INIT                      , "CKA_RESET_ON_INIT", 0 },
{ CKA_HAS_RESET                          , "CKA_HAS_RESET", 0 },
};


struct id2name_t p11CKKName[] = {
{ CKK_RSA                                , "CKK_RSA", 0 },
{ CKK_DSA                                , "CKK_DSA", 0 },
{ CKK_DH                                 , "CKK_DH", 0 },
{ CKK_EC                                 , "CKK_EC", 0 },
{ CKK_X9_42_DH                           , "CKK_X9_42_DH", 0 },
{ CKK_KEA                                , "CKK_KEA", 0 },
{ CKK_GENERIC_SECRET                     , "CKK_GENERIC_SECRET", 0 },
{ CKK_RC2                                , "CKK_RC2", 0 },
{ CKK_RC4                                , "CKK_RC4", 0 },
{ CKK_DES                                , "CKK_DES", 0 },
{ CKK_DES2                               , "CKK_DES2", 0 },
{ CKK_DES3                               , "CKK_DES3", 0 },
{ CKK_CAST                               , "CKK_CAST", 0 },
{ CKK_CAST3                              , "CKK_CAST3", 0 },
{ CKK_CAST128                            , "CKK_CAST128", 0 },
{ CKK_RC5                                , "CKK_RC5", 0 },
{ CKK_IDEA                               , "CKK_IDEA", 0 },
{ CKK_SKIPJACK                           , "CKK_SKIPJACK", 0 },
{ CKK_BATON                              , "CKK_BATON", 0 },
{ CKK_JUNIPER                            , "CKK_JUNIPER", 0 },
{ CKK_CDMF                               , "CKK_CDMF", 0 },
{ CKK_AES                                , "CKK_AES", 0 },
};



char *id2name(struct id2name_t *p, unsigned long id, unsigned long *attr)
{
	static char scr[40];

	if (attr)
		*attr = 0;

	if (id & 0x80000000) {
		sprintf(scr, "Vendor defined 0x%lx", id);
	} else {
		while (p->name && (p->id != id))
			p++;

		if (p->name) {
			strcpy(scr, p->name);
			if (attr)
				*attr = p->attr;
		} else {
			sprintf(scr, "*** Undefined 0x%lx ***", id);
		}
	}
	return scr;
}



static void bin2str(char *st, int stlen, unsigned char *data, int datalen)
{
	int ascii, i;
	unsigned char *d;

	ascii = 1;
	d = data;
	i = datalen;

	while (i && (stlen > 2)) {
		sprintf(st, "%02X", *d);

		if (ascii && !isprint(*d) && *d)
			ascii = 0;

		st += 2;
		stlen -= 2;
		i--;
		d++;
	}

	if (ascii && (stlen > datalen + 3)) {
		*st++ = ' ';
		*st++ = '"';
		memcpy(st, data, datalen);
		st += datalen;
		*st++ = '"';
	}

	*st = '\0';
}



void dumpAttribute(CK_ATTRIBUTE_PTR attr)
{
	char attribute[30], scr[100];
	unsigned long atype;

	strcpy(attribute, id2name(p11CKAName, attr->type, &atype));

	// printf("\n %s", attribute);

	switch(attr->type) {

	case CKA_KEY_TYPE:
		debug("\n  %s = %s\n", attribute, id2name(p11CKKName, *(CK_KEY_TYPE *)attr->pValue, NULL));
		break;

	default:
		switch(atype) {
		case CKT_BBOOL:
			if (attr->pValue) {
				debug("\n  %s = %s [%d]\n", attribute, *(CK_BBOOL *)attr->pValue ? "TRUE" : "FALSE", *(CK_BBOOL *)attr->pValue);
			} else {
				debug("\n  %s\n", attribute);
			}
			break;
		case CKT_DATE:
			// pdate = (CK_DATE *)attr->pValue;
			// if (pdate != NULL) {
			//     sprintf(res, "  %s = %4s-%2s-%2s", attribute, pdate->year, pdate->month, pdate->day);
			// }
			debug("\n  %s\n", attribute);
			break;
		case CKT_LONG:
			debug("\n  %s = %d [0x%X]\n", attribute, *(CK_LONG *)attr->pValue, *(CK_LONG *)attr->pValue);
			break;
		case CKT_ULONG:
			debug("\n  %s = %u [0x%X]\n", attribute, *(CK_ULONG *)attr->pValue, *(CK_ULONG *)attr->pValue);
			break;
		case CKT_BIN:
		default:
			bin2str(scr, sizeof(scr), attr->pValue, attr->ulValueLen);
			debug("\n  %s = %s\n", attribute, scr);
			break;
		}
	}
}
#endif



int isValidPtr(void *ptr)
{
#ifdef CHECK_PTR_ABOVE_ETEXT
	extern char _etext;

	// This works on some architectures, but notably not on AMD64 systems
	return ((ptr != NULL) && ((char *)ptr > &_etext));
#else
	return (ptr != NULL);
#endif
}



int addAttribute(struct p11Object_t *object, CK_ATTRIBUTE_PTR pTemplate)
{
	struct p11Attribute_t *attr;
	struct p11Attribute_t *pAttribute;

	pAttribute = (struct p11Attribute_t *) malloc (sizeof(struct p11Attribute_t));

	if (pAttribute == NULL) {
		return -1;
	}

	memset(pAttribute, 0x00, sizeof(struct p11Attribute_t));
	memcpy(&pAttribute->attrData, pTemplate, sizeof(CK_ATTRIBUTE));

	pAttribute->attrData.pValue = malloc(pAttribute->attrData.ulValueLen);

	if (pAttribute->attrData.pValue == NULL) {
		free(pAttribute);
		return -1;
	}

	memcpy(pAttribute->attrData.pValue, pTemplate->pValue, pAttribute->attrData.ulValueLen);

	if (object->attrList == NULL) {
		object->attrList = pAttribute;
	} else {
		attr = object->attrList;

		while (attr->next != NULL) {
			attr = attr->next;
		}

		attr->next = pAttribute;
	}

	return CKR_OK;
}



int findAttribute(struct p11Object_t *object, CK_ATTRIBUTE_PTR attributeTemplate, struct p11Attribute_t **attribute)
{
	struct p11Attribute_t *attr;
	int pos = 0;            /* remember the current position in the list */

	attr = object->attrList;
	*attribute = NULL;

	while (attr != NULL) {
		if (attr->attrData.type == attributeTemplate->type) {
			*attribute = attr;
			return pos;
		}

		attr = attr->next;
		pos++;
	}

	return -1;
}



int findAttributeInTemplate(CK_ATTRIBUTE_TYPE attributeType, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount) 
{
	unsigned int i;

	for (i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == attributeType) {
			return i;
		}
	}

	return -1;
}



int removeAttribute(struct p11Object_t *object, CK_ATTRIBUTE_PTR attributeTemplate)
{
	struct p11Attribute_t *attr = NULL;
	struct p11Attribute_t *prev = NULL;
	int rc;

	rc = findAttribute(object, attributeTemplate, &attr);

	/* no object for this template found */
	if (rc < 0) {
		return rc;
	}

	if (rc > 0) {      /* there is more than one element in the pool */
		prev = object->attrList;

		while (prev->next->attrData.type != attributeTemplate->type) {
			prev = prev->next;
		}

		prev->next = attr->next;
	}

	free(attr->attrData.pValue);
	free(attr);

	if (rc == 0) {      /* We removed the last element from the list */
		object->attrList = NULL;
	}

	return CKR_OK;
}



int removeAllAttributes(struct p11Object_t *object) 
{
	struct p11Attribute_t *pAttr, *pAttr2;

	pAttr = object->attrList;

	while (pAttr) {
		pAttr2 = pAttr;
		pAttr = pAttr->next;
		free(pAttr2);
	}

	return 0;

}



#ifdef DEBUG

int dumpAttributeList(struct p11Object_t *pObject)
{
	CK_ATTRIBUTE_PTR attr;
	struct p11Attribute_t *p11Attr;


	debug("\n******** attribute list for object ********\n");

	p11Attr = pObject->attrList;

	while (p11Attr != NULL) {

		attr = &p11Attr->attrData;

		dumpAttribute(attr);

		p11Attr = p11Attr->next;
	}

	debug("\n******** end attribute list ********\n");

	return 0;
}

#endif



int createObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	int index;

	/* Check if the attribute is present */

	index = findAttributeInTemplate(CKA_CLASS, pTemplate, ulCount);

	if (index == -1) { /* Attribute is not present */
#ifdef DEBUG
		debug("[createObject] Error creating object - the attribute CKA_CLASS is not present!");
#endif
		return CKR_TEMPLATE_INCOMPLETE;
	} else {
		addAttribute(pObject, &pTemplate[index]);
	}

	return 0;
}



int createStorageObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	int index;
	unsigned int i, rc;

	rc = createObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	for (i = 0; i < NEEDED_ATTRIBUTES_STORAGEOBJECT; i++) {
		index = findAttributeInTemplate(attributesStorageObject[i].attribute.type, pTemplate, ulCount);

		if (index == -1) { /* The attribute is not present - is it optional? */
			if (attributesStorageObject[i].optional) {
				addAttribute(pObject, &attributesStorageObject[i].attribute);
			} else { /* the attribute is not optional */
#ifdef DEBUG
				debug("[createStorageObject] Error creating storage object - the following attribute is not present!");
				dumpAttribute(&(attributesStorageObject[i].attribute));
#endif
				removeAllAttributes(pObject);
				return CKR_TEMPLATE_INCOMPLETE;
			}
		} else {
			addAttribute(pObject, &pTemplate[index]);

			/* The object is public */
			if ((pTemplate[index].type == CKA_PRIVATE ) &&
					(*(CK_BBOOL *)pTemplate[index].pValue == CK_FALSE)) {
				pObject->publicObj = TRUE;
			}

			/* The object is a token object */
			if ((pTemplate[index].type == CKA_TOKEN ) &&
					(*(CK_BBOOL *)pTemplate[index].pValue == CK_TRUE)) {
				pObject->tokenObj = TRUE;
			}
		}
	}

	return 0;
}



int createKeyObject(CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, struct p11Object_t *pObject)
{
	unsigned int i;
	int index, rc;

	rc = createStorageObject(pTemplate, ulCount, pObject);

	if (rc) {
		return rc;
	}

	for (i = 0; i < NEEDED_ATTRIBUTES_KEYOBJECT; i++) {
		index = findAttributeInTemplate(attributesKeyObject[i].attribute.type, pTemplate, ulCount);

		if (index == -1) { /* The attribute is not present - is it optional? */
			if (attributesKeyObject[i].optional) {
				addAttribute(pObject, &attributesKeyObject[i].attribute);
			} else { /* the attribute is not optional */
#ifdef DEBUG
				debug("[createKeyObject] Error creating key object - the following attribute is not present!");
				dumpAttribute(&(attributesKeyObject[i].attribute));
#endif
				return CKR_TEMPLATE_INCOMPLETE;
			}
		} else {
			addAttribute(pObject, &pTemplate[index]);
		}
	}

	return 0;
}



/**
 * Serialize all attributes of the object to an unsigned char array 
 */
int serializeObject(struct p11Object_t *pObject, unsigned char **pBuffer, unsigned int *bufLength)
{
	struct p11Attribute_t *pAttribute;
	unsigned char *buf;
	unsigned int l, i;

	l = 0;

	pAttribute = pObject->attrList;

	/* Determine the size of the object */
	while (pAttribute) {
		l += sizeof(CK_ATTRIBUTE);
		l += pAttribute->attrData.ulValueLen;
		pAttribute = pAttribute->next;
	}

	buf = (unsigned char *) malloc(l);

	if (buf == NULL) {
		return -1;
	}

	memset(buf, 0x00, l);

	pAttribute = pObject->attrList;
	i = 0;

	/* Fill the buffer */
	while (pAttribute) {
		memcpy(buf + i, &(pAttribute->attrData), sizeof(CK_ATTRIBUTE));
		i += sizeof(CK_ATTRIBUTE);

		memcpy(buf + i, pAttribute->attrData.pValue, pAttribute->attrData.ulValueLen);
		i += pAttribute->attrData.ulValueLen;

		pAttribute = pAttribute->next;
	}

	*pBuffer = buf;
	*bufLength = l;

	return 0;
}
