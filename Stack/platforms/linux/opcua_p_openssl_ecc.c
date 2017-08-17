/* Copyright (c) 1996-2017, OPC Foundation. All rights reserved.

   The source code in this file is covered under a dual-license scenario:
     - RCL: for OPC Foundation members in good-standing
     - GPL V2: everybody else

   RCL license terms accompanied with this source code. See http://opcfoundation.org/License/RCL/1.00/

   GNU General Public License as published by the Free Software Foundation;
   version 2 of the License are accompanied with this source code. See http://opcfoundation.org/License/GPLv2

   This source code is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

/* UA platform definitions */
#include <opcua_p_internal.h>
#include <opcua_p_memory.h>

#if OPCUA_REQUIRE_OPENSSL

/* System Headers */
#include <openssl/bn.h>
#include <openssl/x509.h>

/* own headers */
#include <opcua_p_openssl.h>
#include <opcua_p_pki.h>

/* local macros */
#define bn2bin_pad(bn,to,len)                           \
    do {                                                \
        int pad_len = (len) - BN_num_bytes(bn);         \
        OpcUa_GotoErrorIfTrue((pad_len < 0), OpcUa_Bad);\
        OpcUa_MemSet(to, 0, pad_len);                   \
        BN_bn2bin(bn, (to) + pad_len);                  \
    } while(0)

/*============================================================================
 * OpcUa_P_OpenSSL_EC_GenerateKeys
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_EC_GenerateKeys(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_UInt32            a_bits,
    OpcUa_Key*              a_pPublicKey,
    OpcUa_Key*              a_pPrivateKey)
{
#ifdef OPENSSL_NO_EC
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_bits);
    OpcUa_ReferenceParameter(a_pPublicKey);
    OpcUa_ReferenceParameter(a_pPrivateKey);
    return OpcUa_BadNotSupported;
#else
    EC_KEY*         pEcKey      = OpcUa_Null;
    unsigned char*  pData;
    int             i;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "EC_GenerateKeys");

    OpcUa_ReturnErrorIfArgumentNull(a_pPublicKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pPrivateKey);

    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_bits);

    a_pPublicKey->Key.Data      = OpcUa_Null;
    a_pPrivateKey->Key.Data     = OpcUa_Null;

    pEcKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    OpcUa_GotoErrorIfNull(pEcKey, OpcUa_Bad);

    i = EC_KEY_generate_key(pEcKey);
    OpcUa_GotoErrorIfTrue((i <= 0), OpcUa_Bad);

    /* get required length */
    a_pPublicKey->Key.Length = i2d_EC_PUBKEY(pEcKey, NULL);
    OpcUa_GotoErrorIfTrue((a_pPublicKey->Key.Length <= 0), OpcUa_Bad);

    /* allocate target buffer */
    a_pPublicKey->Key.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(a_pPublicKey->Key.Length);
    OpcUa_GotoErrorIfAllocFailed(a_pPublicKey->Key.Data);

    pData = a_pPublicKey->Key.Data;
    a_pPublicKey->Key.Length = i2d_EC_PUBKEY(pEcKey, &pData);

    /* get required length */
    a_pPrivateKey->Key.Length = i2d_ECPrivateKey(pEcKey, NULL);
    OpcUa_GotoErrorIfTrue((a_pPrivateKey->Key.Length <= 0), OpcUa_Bad);

    /* allocate target buffer */
    a_pPrivateKey->Key.Data = (OpcUa_Byte*)OpcUa_P_Memory_Alloc(a_pPrivateKey->Key.Length);
    OpcUa_GotoErrorIfAllocFailed(a_pPrivateKey->Key.Data);

    pData = a_pPrivateKey->Key.Data;
    a_pPrivateKey->Key.Length = i2d_ECPrivateKey(pEcKey, &pData);

    /* clean up */
    EC_KEY_free(pEcKey);

    a_pPublicKey->Type = OpcUa_Crypto_KeyType_Ec_Public;
    a_pPrivateKey->Type = OpcUa_Crypto_KeyType_Ec_Private;

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(a_pPublicKey->Key.Data != OpcUa_Null)
    {
        OpcUa_P_Memory_Free(a_pPublicKey->Key.Data);
        a_pPublicKey->Key.Data = OpcUa_Null;
    }

    if(pEcKey != OpcUa_Null)
    {
        EC_KEY_free(pEcKey);
    }

OpcUa_FinishErrorHandling;
#endif
}

/*===========================================================================*
OpcUa_P_OpenSSL_EC_Public_GetKeyLength
*===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_EC_Public_GetKeyLength(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Key               a_publicKey,
    OpcUa_UInt32*           a_pKeyLen)
{
#ifdef OPENSSL_NO_EC
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_publicKey);
    OpcUa_ReferenceParameter(a_pKeyLen);
    return OpcUa_BadNotSupported;
#else
    EC_KEY*                 pEcPublicKey    = OpcUa_Null;
    OpcUa_UInt32            uKeySize;
    const unsigned char*    pData;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "EC_Public_GetKeyLength");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_publicKey.Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pKeyLen);

    *a_pKeyLen = 0;

    if(a_publicKey.Type != OpcUa_Crypto_KeyType_Ec_Public)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    pData = a_publicKey.Key.Data;
    pEcPublicKey = d2i_EC_PUBKEY(OpcUa_Null, &pData, a_publicKey.Key.Length);

    if(pEcPublicKey == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    uKeySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPublicKey));
    if(uKeySize == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    uKeySize = (uKeySize + 7) / 8;
    uKeySize *= 2; /* Raw signature size on bytes */

    if((uKeySize < a_pProvider->MinimumAsymmetricKeyLength) || (uKeySize > a_pProvider->MaximumAsymmetricKeyLength))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadSecurityConfig);
    }

    *a_pKeyLen = uKeySize * 8;

    EC_KEY_free(pEcPublicKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pEcPublicKey != OpcUa_Null)
    {
        EC_KEY_free(pEcPublicKey);
    }

    *a_pKeyLen = (OpcUa_UInt32)-1;

OpcUa_FinishErrorHandling;
#endif
}

/*** EC ASYMMETRIC SIGNATURE ***/

/*===========================================================================*
OpcUa_P_OpenSSL_ECDSA_Private_Sign
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_ECDSA_Private_Sign(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_ByteString        a_data,
    OpcUa_Key*              a_privateKey,
    OpcUa_ByteString*       a_pSignature)       /* output length >= key length */
{
#ifdef OPENSSL_NO_ECDSA
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_data);
    OpcUa_ReferenceParameter(a_privateKey);
    OpcUa_ReferenceParameter(a_pSignature);
    return OpcUa_BadNotSupported;
#else
    EC_KEY*                 pEcPrivateKey   = OpcUa_Null;
    ECDSA_SIG*              pEcSignature    = OpcUa_Null;
    OpcUa_Int32             keySize;
    const BIGNUM*           r;
    const BIGNUM*           s;
    const unsigned char*    pData;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "ECDSA_Private_Sign");

    /* unused parameters */
    OpcUa_ReferenceParameter(a_pProvider);

    /* check parameters */
    OpcUa_ReturnErrorIfArgumentNull(a_data.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_privateKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);
    OpcUa_ReturnErrorIfArgumentNull(a_pSignature->Data);

    pData = a_privateKey->Key.Data;
    OpcUa_ReturnErrorIfArgumentNull(pData);
    OpcUa_ReturnErrorIfTrue((a_privateKey->Type != OpcUa_Crypto_KeyType_Ec_Private), OpcUa_BadInvalidArgument);

    /* convert private key and check key length against buffer length */
    pEcPrivateKey = d2i_ECPrivateKey(OpcUa_Null, &pData, a_privateKey->Key.Length);
    OpcUa_GotoErrorIfTrue((pEcPrivateKey == OpcUa_Null), OpcUa_BadInvalidArgument);

    keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));
    if(keySize == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    keySize = (keySize + 7) / 8;
    OpcUa_GotoErrorIfTrue((a_pSignature->Length < 2 * keySize), OpcUa_BadInvalidArgument);

    /* sign data */
    pEcSignature = ECDSA_do_sign(a_data.Data, a_data.Length, pEcPrivateKey);
    OpcUa_GotoErrorIfTrue((pEcSignature == OpcUa_Null), OpcUa_BadUnexpectedError);

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ECDSA_SIG_get0(pEcSignature, &r, &s);
#else
    r = pEcSignature->r;
    s = pEcSignature->s;
#endif

    bn2bin_pad(r, a_pSignature->Data, keySize);
    bn2bin_pad(s, a_pSignature->Data + keySize, keySize);
    a_pSignature->Length = 2 * keySize;

    /* free internal key representation */
    ECDSA_SIG_free(pEcSignature);
    EC_KEY_free(pEcPrivateKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pEcSignature != OpcUa_Null)
    {
        ECDSA_SIG_free(pEcSignature);
    }

    if(pEcPrivateKey != OpcUa_Null)
    {
        EC_KEY_free(pEcPrivateKey);
    }

OpcUa_FinishErrorHandling;
#endif
}

/*============================================================================
 * OpcUa_P_OpenSSL_ECDSA_Public_Verify
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_OpenSSL_ECDSA_Public_Verify(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_ByteString        a_data,
    OpcUa_Key*              a_publicKey,
    OpcUa_ByteString*       a_pSignature)
{
#ifdef OPENSSL_NO_ECDSA
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_data);
    OpcUa_ReferenceParameter(a_publicKey);
    OpcUa_ReferenceParameter(a_pSignature);
    return OpcUa_BadNotSupported;
#else
    EC_KEY*                 pEcPublicKey    = OpcUa_Null;
    ECDSA_SIG*              pEcSignature    = OpcUa_Null;
    OpcUa_Int32             keySize;
    BIGNUM*                 r;
    BIGNUM*                 s;
    const unsigned char*    pData;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "ECDSA_Public_Verify");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_data.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_publicKey);
    OpcUa_ReturnErrorIfArgumentNull(a_publicKey->Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pSignature);

    if(a_publicKey->Type != OpcUa_Crypto_KeyType_Ec_Public)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    pData = a_publicKey->Key.Data;
    pEcPublicKey = d2i_EC_PUBKEY(OpcUa_Null, &pData, a_publicKey->Key.Length);

    if(pEcPublicKey == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPublicKey));
    if(keySize == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    keySize = (keySize + 7) / 8;
    OpcUa_GotoErrorIfTrue((a_pSignature->Length < 2 * keySize), OpcUa_BadInvalidArgument);

    pEcSignature = ECDSA_SIG_new();
    if(pEcSignature == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    r = BN_bin2bn(a_pSignature->Data, keySize, OpcUa_Null);
    if(r == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    s = BN_bin2bn(a_pSignature->Data + keySize, keySize, OpcUa_Null);
    if(s == OpcUa_Null)
    {
        BN_free(r);
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

#if OPENSSL_VERSION_NUMBER >= 0x1010000fL
    ECDSA_SIG_set0(pEcSignature, r, s);
#else
    BN_free(pEcSignature->r);
    BN_free(pEcSignature->s);
    pEcSignature->r = r;
    pEcSignature->s = s;
#endif

    if(ECDSA_do_verify(a_data.Data, a_data.Length, pEcSignature, pEcPublicKey) != 1)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadSignatureInvalid);
    }

    /* free internal key representation */
    ECDSA_SIG_free(pEcSignature);
    EC_KEY_free(pEcPublicKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pEcSignature != OpcUa_Null)
    {
        ECDSA_SIG_free(pEcSignature);
    }

    if(pEcPublicKey != OpcUa_Null)
    {
        EC_KEY_free(pEcPublicKey);
    }

OpcUa_FinishErrorHandling;
#endif
}

/*============================================================================
 * OpcUa_P_Crypto_EC_ComputeNonceFromPublicKey
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_EC_ComputeNonceFromPublicKey(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_Key*              a_publicKey,
    OpcUa_ByteString*       a_pNonce)
{
#ifdef OPENSSL_NO_EC
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_publicKey);
    OpcUa_ReferenceParameter(a_pNonce);
    return OpcUa_BadNotSupported;
#else
    EC_KEY*                 pEcPublicKey    = OpcUa_Null;
    BN_CTX*                 pCtx            = OpcUa_Null;
    OpcUa_Int32             keySize;
    BIGNUM*                 x;
    BIGNUM*                 y;
    const unsigned char*    pData;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "EC_ComputeNonceFromPublicKey");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_publicKey);
    OpcUa_ReturnErrorIfArgumentNull(a_publicKey->Key.Data);
    OpcUa_ReturnErrorIfArgumentNull(a_pNonce);

    if(a_publicKey->Type != OpcUa_Crypto_KeyType_Ec_Public)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    pData = a_publicKey->Key.Data;
    pEcPublicKey = d2i_EC_PUBKEY(OpcUa_Null, &pData, a_publicKey->Key.Length);

    if(pEcPublicKey == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadInvalidArgument);
    }

    keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPublicKey));
    if(keySize == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    keySize = (keySize + 7) / 8;

    if(a_pNonce->Data == OpcUa_Null)
    {
       a_pNonce->Length = 2 * keySize;
       EC_KEY_free(pEcPublicKey);
       OpcUa_ReturnStatusCode;
    }

    OpcUa_GotoErrorIfTrue((a_pNonce->Length < 2 * keySize), OpcUa_BadInvalidArgument);

    pCtx = BN_CTX_new();
    OpcUa_GotoErrorIfTrue((pCtx == OpcUa_Null), OpcUa_BadUnexpectedError);

    x = BN_CTX_get(pCtx);
    y = BN_CTX_get(pCtx);
    OpcUa_GotoErrorIfTrue((y == OpcUa_Null), OpcUa_BadUnexpectedError);

    if(!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcPublicKey),
                                            EC_KEY_get0_public_key(pEcPublicKey), x, y, pCtx))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    bn2bin_pad(x, a_pNonce->Data, keySize);
    bn2bin_pad(y, a_pNonce->Data + keySize, keySize);
    a_pNonce->Length = 2 * keySize;

    BN_CTX_free(pCtx);
    EC_KEY_free(pEcPublicKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(pCtx != OpcUa_Null)
    {
        BN_CTX_free(pCtx);
    }

    if(pEcPublicKey != OpcUa_Null)
    {
        EC_KEY_free(pEcPublicKey);
    }

OpcUa_FinishErrorHandling;
#endif
}

/*============================================================================
 * OpcUa_P_Crypto_EC_ComputeSecretsFromNonce
 *===========================================================================*/
OpcUa_StatusCode OpcUa_P_Crypto_EC_ComputeSecretsFromNonce(
    OpcUa_CryptoProvider*   a_pProvider,
    OpcUa_ByteString*       a_pNonce,
    OpcUa_Key*              a_privateKey,
    OpcUa_ByteString*       a_pX,
    OpcUa_ByteString*       a_pY)
{
#ifdef OPENSSL_NO_EC
    OpcUa_ReferenceParameter(a_pProvider);
    OpcUa_ReferenceParameter(a_pNonce);
    OpcUa_ReferenceParameter(a_privateKey);
    OpcUa_ReferenceParameter(a_pX);
    OpcUa_ReferenceParameter(a_pY);
    return OpcUa_BadNotSupported;
#else
    EC_KEY*                 pEcPrivateKey   = OpcUa_Null;
    BN_CTX*                 pCtx            = OpcUa_Null;
    EC_POINT*               p1              = OpcUa_Null;
    EC_POINT*               p2              = OpcUa_Null;
    OpcUa_Int32             keySize;
    BIGNUM*                 x;
    BIGNUM*                 y;
    const unsigned char*    pData;

OpcUa_InitializeStatus(OpcUa_Module_P_OpenSSL, "EC_ComputeSecretsFromNonce");

    OpcUa_ReferenceParameter(a_pProvider);

    OpcUa_ReturnErrorIfArgumentNull(a_pNonce);
    OpcUa_ReturnErrorIfArgumentNull(a_pNonce->Data);
    OpcUa_ReturnErrorIfArgumentNull(a_privateKey);
    OpcUa_ReturnErrorIfArgumentNull(a_pX);
    OpcUa_ReturnErrorIfArgumentNull(a_pY);

    pData = a_privateKey->Key.Data;
    OpcUa_ReturnErrorIfArgumentNull(pData);
    OpcUa_ReturnErrorIfTrue((a_privateKey->Type != OpcUa_Crypto_KeyType_Ec_Private), OpcUa_BadInvalidArgument);

    pEcPrivateKey = d2i_ECPrivateKey(OpcUa_Null, &pData, a_privateKey->Key.Length);
    OpcUa_GotoErrorIfTrue((pEcPrivateKey == OpcUa_Null), OpcUa_BadInvalidArgument);

    keySize = EC_GROUP_get_degree(EC_KEY_get0_group(pEcPrivateKey));
    if(keySize == 0)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    keySize = (keySize + 7) / 8;
    OpcUa_GotoErrorIfTrue((a_pNonce->Length != 2 * keySize), OpcUa_BadInvalidArgument);

    if(a_pX->Data == OpcUa_Null || a_pY->Data == OpcUa_Null)
    {
       a_pX->Length = keySize;
       a_pY->Length = keySize;
       EC_KEY_free(pEcPrivateKey);
       OpcUa_ReturnStatusCode;
    }

    pCtx = BN_CTX_new();
    OpcUa_GotoErrorIfTrue((pCtx == OpcUa_Null), OpcUa_BadUnexpectedError);

    x = BN_CTX_get(pCtx);
    y = BN_CTX_get(pCtx);
    OpcUa_GotoErrorIfTrue((y == OpcUa_Null), OpcUa_BadUnexpectedError);

    x = BN_bin2bn(a_pNonce->Data, keySize, x);
    if(x == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    y = BN_bin2bn(a_pNonce->Data + keySize, keySize, y);
    if(y == OpcUa_Null)
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    p1 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));
    OpcUa_GotoErrorIfTrue((p1 == OpcUa_Null), OpcUa_BadUnexpectedError);

    if(!EC_POINT_set_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey),
                                            p1, x, y, pCtx))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    p2 = EC_POINT_new(EC_KEY_get0_group(pEcPrivateKey));
    OpcUa_GotoErrorIfTrue((p2 == OpcUa_Null), OpcUa_BadUnexpectedError);

    if(!EC_POINT_mul(EC_KEY_get0_group(pEcPrivateKey), p2, NULL, p1,
                     EC_KEY_get0_private_key(pEcPrivateKey), pCtx))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    if(!EC_POINT_get_affine_coordinates_GFp(EC_KEY_get0_group(pEcPrivateKey),
                                            p2, x, y, pCtx))
    {
        OpcUa_GotoErrorWithStatus(OpcUa_BadUnexpectedError);
    }

    bn2bin_pad(x, a_pX->Data, keySize);
    a_pX->Length = keySize;

    bn2bin_pad(y, a_pY->Data, keySize);
    a_pY->Length = keySize;

    EC_POINT_free(p1);
    EC_POINT_clear_free(p2);
    BN_CTX_free(pCtx);
    EC_KEY_free(pEcPrivateKey);

OpcUa_ReturnStatusCode;
OpcUa_BeginErrorHandling;

    if(p1 != OpcUa_Null)
    {
        EC_POINT_free(p1);
    }

    if(p2 != OpcUa_Null)
    {
        EC_POINT_free(p2);
    }

    if(pCtx != OpcUa_Null)
    {
        BN_CTX_free(pCtx);
    }

    if(pEcPrivateKey != OpcUa_Null)
    {
        EC_KEY_free(pEcPrivateKey);
    }

OpcUa_FinishErrorHandling;
#endif
}

#endif /* OPCUA_REQUIRE_OPENSSL */
