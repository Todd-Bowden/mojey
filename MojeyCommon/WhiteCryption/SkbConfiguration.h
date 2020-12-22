/*****************************************************************
|
|   whiteCryption Secure Key Box
|
|   $Id: SkbConfiguration.h 12989 2019-03-14 15:30:24Z kstraupe $
|
|   This software is provided to you pursuant to your Software
|   license agreement (SLA) with whiteCryption Corporation
|   ("whiteCryption") and Intertrust Technologies Corporation
|   ("Intertrust"). This software may be used only in accordance
|   with the terms of this agreement.
|
|   Copyright (c) 2000-2019, whiteCryption Corporation. All rights reserved.
|   Copyright (c) 2004-2019, Intertrust Technologies Corporation. All rights reserved.
|
****************************************************************/

/**
 * This file contains variable definitions for currently enabled Secure Key Box features
 * which are used in SKB tests and examples for testing of the current configuration.
 *
 * This file should closely match the modules registered in the SkbModules.h file.
  */

#pragma once

/* ENCRYPTION/DECRYPTION */
#ifndef __cplusplus
#include <stdbool.h>
#endif

/* High-security AES encryption */
static const bool SKB_MODULE_ENABLED_AesEncrypt = false;

/* High-security AES decryption */
static const bool SKB_MODULE_ENABLED_AesDecrypt = false;

/* AES Nist Key Wrap Decryption */
static const bool SKB_MODULE_ENABLED_AesNistKeyWrapDecrypt = false;

/* High-speed 128-bit AES encryption */
static const bool SKB_MODULE_ENABLED_Aes128HighSpeedEncrypt = false;

/* High-speed 192-bit AES encryption */
static const bool SKB_MODULE_ENABLED_Aes192HighSpeedEncrypt = false;

/* High-speed 256-bit AES encryption */
static const bool SKB_MODULE_ENABLED_Aes256HighSpeedEncrypt = false;

/* High-speed 128-bit AES decryption */
static const bool SKB_MODULE_ENABLED_Aes128HighSpeedDecrypt = false;

/* High-speed 192-bit AES decryption */
static const bool SKB_MODULE_ENABLED_Aes192HighSpeedDecrypt = false;

/* High-speed 256-bit AES decryption */
static const bool SKB_MODULE_ENABLED_Aes256HighSpeedDecrypt = false;

/* 2048-bit RSA decryption */
static const bool SKB_MODULE_ENABLED_Rsa2048Decrypt = false;

/* 4096-bit RSA decryption */
static const bool SKB_MODULE_ENABLED_Rsa4096Decrypt = false;

/* ElGamal ECC decryption */
static const bool SKB_MODULE_ENABLED_ElGamalDecrypt = false;

/* DES encryption */
static const bool SKB_MODULE_ENABLED_DesEncrypt = false;

/* DES decryption */
static const bool SKB_MODULE_ENABLED_DesDecrypt = false;

/* Triple DES encryption */
static const bool SKB_MODULE_ENABLED_TripleDesEncrypt = false;

/* Triple DES decryption */
static const bool SKB_MODULE_ENABLED_TripleDesDecrypt = false;

/* Speck encryption */
static const bool SKB_MODULE_ENABLED_SpeckEncrypt = false;

/* Speck decryption */
static const bool SKB_MODULE_ENABLED_SpeckDecrypt = false;

/* SIGNING/VERIFICATION */

/* AES-CMAC signing and verification */
static const bool SKB_MODULE_ENABLED_CmacAes = false;

/* Speck-CMAC signing and verification */
static const bool SKB_MODULE_ENABLED_CmacSpeck = false;

/* HMAC signing and verification using SHA-1 */
static const bool SKB_MODULE_ENABLED_HmacSha1 = false;

/* HMAC signing and verification using SHA-224 */
static const bool SKB_MODULE_ENABLED_HmacSha224 = false;

/* HMAC signing and verification using SHA-256 */
static const bool SKB_MODULE_ENABLED_HmacSha256 = false;

/* HMAC signing and verification using SHA-384 */
static const bool SKB_MODULE_ENABLED_HmacSha384 = false;

/* HMAC signing and verification using SHA-512 */
static const bool SKB_MODULE_ENABLED_HmacSha512 = false;

/* HMAC signing and verification using MD5 */
static const bool SKB_MODULE_ENABLED_HmacMd5 = false;

/* ISO/IEC 9797-1 MAC algorithm 3 (DES Retail MAC) */
static const bool SKB_MODULE_ENABLED_DesRetailMac = false;

/* 2048-bit RSA signing */
static const bool SKB_MODULE_ENABLED_RsaSign2048 = false;

/* 4096-bit RSA signing */
static const bool SKB_MODULE_ENABLED_RsaSign4096 = false;

/* ECDSA signing using up to 264-bit prime curves */
static const bool SKB_MODULE_ENABLED_EcdsaSign264 = true;

/* ECDSA signing using up to 528-bit prime curves */
static const bool SKB_MODULE_ENABLED_EcdsaSign528 = false;

/* DSA signing */
static const bool SKB_MODULE_ENABLED_DsaSign = false;

/* KEY WRAPPING */

/* Wrapping using AES CBC submodule */
static const bool SKB_MODULE_ENABLED_AesWrap = false;

/* Wrapping raw bytes using AES */
static const bool SKB_MODULE_ENABLED_WrapRawBytesWithAes = false;

/* Wrapping raw bytes using 1024-bit and 2048-bit RSA */
static const bool SKB_MODULE_ENABLED_WrapRawBytesWithRsa2048 = false;

/* Wrapping private ECC keys using AES */
static const bool SKB_MODULE_ENABLED_WrapEccPrivateWithAes = false;

/* Wrapping private DSA keys using AES */
static const bool SKB_MODULE_ENABLED_WrapDsaPrivateWithAes = false;

/* Wrapping plain data using AES */
static const bool SKB_MODULE_ENABLED_WrapDataFromPlainWithAes = false;

/* Wrapping plain data using 3DES */
static const bool SKB_MODULE_ENABLED_WrapDataFromPlainWithTripleDes = false;

/* Wrapping of AES keys defined by NIST */
static const bool SKB_MODULE_ENABLED_WrapRawBytesWithNistAes = false;

/* XOR-based wrapping */
static const bool SKB_MODULE_ENABLED_WrapRawBytesWithXor = false;

/* KEY UNWRAPPING */

/* Unwrapping using AES ECB/CBC submodule */
static const bool SKB_MODULE_ENABLED_AesUnwrap = false;

/* Unwrapping using AES CTR submodule */
static const bool SKB_MODULE_ENABLED_AesCtrUnwrap = false;

/* Unwrapping raw bytes using AES */
static const bool SKB_MODULE_ENABLED_RawBytesWithAes = false;

/* Unwrapping raw bytes using 2048-bit RSA */
static const bool SKB_MODULE_ENABLED_RawBytesWithRsa2048 = false;

/* Unwrapping raw bytes using 2048-bit RSA with Pkcs v1.5 padding */
static const bool SKB_MODULE_ENABLED_RawBytesWithRsa2048Pkcs = false;

/* Unwrapping raw bytes using 2048-bit RSA with OAEP padding */
static const bool SKB_MODULE_ENABLED_RawBytesWithRsa2048Oaep = false;

/* Unwrapping raw bytes using ElGamal ECC */
static const bool SKB_MODULE_ENABLED_RawBytesWithEcc = false;

/* Unwrapping private RSA keys using AES */
static const bool SKB_MODULE_ENABLED_RsaPrivateWithAes = false;

/* Unwrapping private RSA keys using AES GCM from JWE */
static const bool SKB_MODULE_ENABLED_RsaPrivateWithAesJson = false;

/* Unwrapping private RSA keys from CRT */
static const bool SKB_MODULE_ENABLED_RsaPrivateFromCRT = false;

/* Unwrapping private ECC keys using AES */
static const bool SKB_MODULE_ENABLED_EccPrivateWithAes = false;

/* Unwrapping private DSA keys using AES */
static const bool SKB_MODULE_ENABLED_DsaPrivateWithAes = false;

/* CMLA unwrapping using AES */
static const bool SKB_MODULE_ENABLED_RawBytesWithAesCmla = false;

/* CMLA unwrapping using RSA */
static const bool SKB_MODULE_ENABLED_RawBytesWithRsaCmla = false;

/* Unwrapping of AES keys defined by NIST */
static const bool SKB_MODULE_ENABLED_RawBytesWithNistAes = false;

/* XOR-based unwrapping */
static const bool SKB_MODULE_ENABLED_RawBytesWithXor = false;

/* KEY GENERATION */

/* ECC key pair using up to 264-bit prime curves */
static const bool SKB_MODULE_ENABLED_GenerateEcc264 = false;

/* ECC key pair using up to 528-bit prime curves */
static const bool SKB_MODULE_ENABLED_GenerateEcc528 = false;

/* DSA key pair */
static const bool SKB_MODULE_ENABLED_GenerateDsa = false;

/* RSA key pair */
static const bool SKB_MODULE_ENABLED_GenerateRsa = false;

/* LOADING PLAIN KEYS */

/* Raw bytes */
static const bool SKB_MODULE_ENABLED_RawBytesFromPlain = false;

/* Private 1024-bit and 2048-bit RSA keys */
static const bool SKB_MODULE_ENABLED_RsaPrivateFromPlain = false;

/* Private ECC keys */
static const bool SKB_MODULE_ENABLED_EccPrivateFromPlain = false;

/* KEY IMPORTING AND EXPORTING */

/* ECC private keys */
static const bool SKB_MODULE_ENABLED_EccPrivateImportExport = true;

/* Raw bytes */
static const bool SKB_MODULE_ENABLED_RawBytesImportExport = false;

/* Unwrap bytes */
static const bool SKB_MODULE_ENABLED_UnwrapBytesImportExport = false;

/* RSA private keys */
static const bool SKB_MODULE_ENABLED_RsaPrivateImportExport = false;

/* DSA private keys */
static const bool SKB_MODULE_ENABLED_DsaPrivateImportExport = false;

/* DIGESTS */

/* SHA-1 */
static const bool SKB_MODULE_ENABLED_Sha1Digest = false;

/* SHA-224 */
static const bool SKB_MODULE_ENABLED_Sha224Digest = false;

/* SHA-256 */
static const bool SKB_MODULE_ENABLED_Sha256Digest = true;

/* SHA-384 */
static const bool SKB_MODULE_ENABLED_Sha384Digest = false;

/* SHA-512 */
static const bool SKB_MODULE_ENABLED_Sha512Digest = false;

/* MD5 */
static const bool SKB_MODULE_ENABLED_Md5Digest = false;

/* KEY AGREEMENT */

/* Classical Diffie-Hellman */
static const bool SKB_MODULE_ENABLED_PrimeDh1024 = false;

/* ECDH using up to 264-bit prime curves */
static const bool SKB_MODULE_ENABLED_Ecdh264 = false;

/* ECDH using up to 528-bit prime curves */
static const bool SKB_MODULE_ENABLED_Ecdh528 = false;

/* KEY DERIVATION */

/* Byte reversing */
static const bool SKB_MODULE_ENABLED_ReverseRawBytesDerive = false;

/* Iterated SHA-1 */
static const bool SKB_MODULE_ENABLED_Sha1Derive = false;

/* SHA-256 with plain prefix and suffix */
static const bool SKB_MODULE_ENABLED_Sha256Derive = false;

/* SHA-384 */
static const bool SKB_MODULE_ENABLED_Sha384Derive = false;

/* Slicing */
static const bool SKB_MODULE_ENABLED_SlicingDerive = false;

/* Concatenation */
static const bool SKB_MODULE_ENABLED_BlockConcatenateDerive = false;

/* Block slicing */
static const bool SKB_MODULE_ENABLED_BlockSlicingDerive = false;

/* Selecting odd or even bytes */
static const bool SKB_MODULE_ENABLED_SelectBytesDerive = false;

/* NIST 800-108 key derivation using AES128 */
static const bool SKB_MODULE_ENABLED_Nist800108CounterCmacAes128 = false;

/* NIST 800-108 key derivation using Speck 64-bit blocks / 128-bit keys */
static const bool SKB_MODULE_ENABLED_Nist800108CounterCmacSpeck = false;

/* KDF2 used in the RSAES-KEM-KWS scheme of the Open Mobile Alliance DRM specification */
static const bool SKB_MODULE_ENABLED_OmaDrmKdf2Derive = false;

/* Deriving a new key by encrypting raw bytes using AES */
static const bool SKB_MODULE_ENABLED_AesEncryptDerive = false;

/* Deriving a new key by decrypting raw bytes using AES */
static const bool SKB_MODULE_ENABLED_AesDecryptDerive = false;

/* Deriving a new key by encrypting raw bytes using DES */
static const bool SKB_MODULE_ENABLED_DesEncryptDerive = false;

/* Deriving a new key by decrypting raw bytes using DES */
static const bool SKB_MODULE_ENABLED_DesDecryptDerive = false;

/* Deriving raw bytes from an ECC private key */
static const bool SKB_MODULE_ENABLED_RawBytesFromEccPrivateDerive = false;

/* CMLA key derivation */
static const bool SKB_MODULE_ENABLED_CmlaKdfDerive = false;

/* AES encryption with a concatenated key and an optional SHA-1 function */
static const bool SKB_MODULE_ENABLED_ShaAesDerive = false;

/* Deriving a key by Xor */
static const bool SKB_MODULE_ENABLED_XorDerive = false;

/* Deriving a key by Xor-Aes */
static const bool SKB_MODULE_ENABLED_DoubleAesEncryptDerive = false;

/* Deriving a key by Aes using plain key */
static const bool SKB_MODULE_ENABLED_AesPlainKeyDecryptDerive = false;

/* Deriving a key by mixing with plain data */
static const bool SKB_MODULE_ENABLED_MixWithPlainDerive = false;

/* OTHER FEATURES */

static const bool SKB_MODULE_ENABLED_Sushi = false;

static const bool SKB_MODULE_ENABLED_AesHighSpeedFallback = false;
