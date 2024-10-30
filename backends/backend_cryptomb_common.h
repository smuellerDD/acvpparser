/*************************************************************************
* Copyright (C) 2024 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

#ifndef _CRYPTOMB_COMMON_H
#define _CRYPTOMB_COMMON_H

#include <strings.h>
#include <ctype.h>

#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <crypto_mb/ec_nistp256.h>
#include <crypto_mb/ec_nistp384.h>
#include <crypto_mb/ec_nistp521.h>
#include <crypto_mb/ed25519.h>
#include <crypto_mb/rsa.h>

#include <ippcp.h>

#include "backend_common.h"

#define NUM_OF_DIGS(bitsize, digsize)   (((bitsize) + (digsize)-1)/(digsize))

#define GF256_BITLEN (256)
#define GF384_BITLEN (384)
#define GF521_BITLEN (521)

// data in residual (2^64) domain
#define GF256_LEN64 (NUM_OF_DIGS(GF256_BITLEN, 64))
#define GF256_LEN8  (NUM_OF_DIGS(GF256_BITLEN, 8))

#define GF384_LEN64 (NUM_OF_DIGS(GF384_BITLEN, 64))
#define GF384_LEN8  (NUM_OF_DIGS(GF384_BITLEN, 8))

#define GF521_LEN64 (NUM_OF_DIGS(GF521_BITLEN, 64))
#define GF521_LEN8  (NUM_OF_DIGS(GF521_BITLEN, 8))

#define MAX_LEN64 GF521_LEN64
#define MAX_LEN8  GF521_LEN8

// macroses for buffers allocat9ion
// use to reduce repeatable code lines number
#define create_mbx_buffer_int64u(name) \
    __ALIGN64 int64u name[8][MAX_LEN64]; \
    int64u* pa_##name[8] = {name[0], name[1], name[2], name[3], name[4], name[5], name[6], name[7]};

#define create_mbx_buffer_int8u(name) \
    __ALIGN64 int8u name[8][MAX_LEN8]; \
    int8u* pa_##name[8] = {name[0], name[1], name[2], name[3], name[4], name[5], name[6], name[7]};

#define create_and_clean_mbx_buffer_int64u(name) \
    create_mbx_buffer_int64u(name) \
    memset(name, 0, sizeof(name));

#define create_and_clean_mbx_buffer_int8u(name) \
    create_mbx_buffer_int8u(name) \
    memset(name, 0, sizeof(name));

/************************************************
 * ECDSA interface functions
 ************************************************/
#define MBX_ALIGNMENT   (8)
#define MBX_NUM_BUFFERS (8)

typedef enum {
    nistp256,
    nistp384,
    nistp521,
    ec_unset
} ec_type;

#define maxMsgDigestSize (67)
#define maxSize64u       ((maxMsgDigestSize + 7)/8)

static int8u* reverse_bytes(int8u* out, const int8u* inp, int len)
{
    if (out == inp) { // inplace
        for (int i = 0; i < len / 2; i++) {
            int8u a = inp[i];
            out[i] = inp[len - 1 - i];
            out[len - 1 - i] = a;
        }
    }
    else { // not inplace
        for (int i = 0; i < len; i++) {
            out[i] = inp[len - 1 - i];
        }
    }
    return out;
}


/* Stuff functions */
static BIGNUM* set_BN_data(BIGNUM* bn, const int64u x[], const int len8)
{
    int8u* tmp = malloc(len8);
    reverse_bytes(tmp, (int8u*)x, len8);
    BN_bin2bn(tmp, len8, bn);
    free(tmp);
    return bn;
}

static int64u* get_BN_data(int64u x[], const BIGNUM* bn, const int len64)
{
    // clear buffer
    memset(x, 0, sizeof(int64u) * len64);
    int num_bytes = BN_num_bytes(bn);

    BN_bn2bin(bn, (int8u*)x);
    reverse_bytes((int8u*)x, (int8u*)x, num_bytes);

    return x;
}

typedef enum {
    affine_coords,
    projective_coords
} coords_type;

/* Produce OpenSSL public and private keys and return BIGNUMs */
static EVP_PKEY* openssl_generate_keys_bn(BIGNUM* priv_key, BIGNUM* pubx_key, BIGNUM* puby_key, BIGNUM* pubz_key, EC_GROUP* EC, const char *curvename, int len8, coords_type coords)
{
    (void)pubz_key; (void)coords;
    EVP_PKEY* keyA = NULL;
    BN_CTX* ctx = BN_CTX_new();

#if OPENSSL_VERSION_MAJOR >= 3
    EVP_PKEY_CTX *evp_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY_keygen_init(evp_ctx);
    EVP_PKEY_CTX_set_group_name(evp_ctx, (char *)curvename);

    // Generate key pairs
    EVP_PKEY_generate(evp_ctx, &keyA);

    // Set the point conversion format as compressed in order to apply changes from 3.0.8 version
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("point-format",(char*)"compressed", 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_set_params(keyA, params);

    // We don't need private key for verification
    if (priv_key != NULL) {
        // extract private keys and store
        BIGNUM *tmp_out = NULL;
        EVP_PKEY_get_bn_param(keyA, "priv", &tmp_out);
        BN_copy(priv_key, tmp_out);
    }

    // We don't need public key for signature
    if (pubx_key != NULL && puby_key != NULL) {
        // extract public key and store it affine coordinates (OpenSSL3.0 doesn't support projective coordinates)
        unsigned char* out_pubkey = (unsigned char* )malloc(len8 + 1);
        size_t out_pubkey_len = 0;
        EC_POINT* tmp_point = EC_POINT_new(EC);
        EVP_PKEY_get_octet_string_param(keyA, "pub", out_pubkey, len8 + 1, &out_pubkey_len);
        EC_POINT_oct2point(EC, tmp_point, out_pubkey, out_pubkey_len, ctx);
        EC_POINT_get_affine_coordinates(EC, tmp_point, pubx_key, puby_key, ctx);
        EC_POINT_free(tmp_point);
        free(out_pubkey);
    }

    // release resources
    EVP_PKEY_CTX_free(evp_ctx);
#else
    keyA = NEW_OPENSSL_KEY();
    EC_KEY_set_group(keyA, EC);
    EC_KEY_generate_key(keyA);

    // We don't need private key for verification
    if (priv_key != NULL) {
        // extract private keys and store
        BN_copy(priv_key, EC_KEY_get0_private_key(keyA));
    }

    // We don't need public key for signature
    if (pubx_key != NULL && puby_key != NULL) {
        // extract public key and store it projective/affine coordinates
        if (coords == coords_type::projective_coords) {
#if !defined(OPENSSL_IS_BORINGSSL)
            EC_POINT_get_Jprojective_coordinates_GFp(EC, EC_KEY_get0_public_key(keyA), pubx_key, puby_key, pubz_key, ctx);

#endif
        }
        else
            EC_POINT_get_affine_coordinates_GFp(EC, EC_KEY_get0_public_key(keyA), pubx_key, puby_key, ctx);
    }
#endif

    // release resources
    BN_CTX_free(ctx);
    return keyA;
}

/* Produce OpenSSL public and private keys and return data*/
static EVP_PKEY* openssl_generate_keys(int64u* priv_key, int64u* pubx_key, int64u* puby_key, int64u* pubz_key, EC_GROUP* EC, const char *curvename, int len8, int len64, coords_type coords)
{
    (void)pubz_key;
    EVP_PKEY* keyA = NULL;

    BIGNUM* bn_priv_key = BN_new();
    BIGNUM* bn_pubx_key = BN_new();
    BIGNUM* bn_puby_key = BN_new();
    BIGNUM* bn_pubz_key = BN_new();

    keyA = openssl_generate_keys_bn(bn_priv_key, bn_pubx_key, bn_puby_key, bn_pubz_key, EC, curvename, len8, coords);

#if OPENSSL_VERSION_MAJOR >= 3
    // We don't need private key for verification
    if (priv_key != NULL) {
        // extract private keys and store
        get_BN_data(priv_key, bn_priv_key, len64);
    }

    // We don't need public key for signature
    if (pubx_key != NULL && puby_key != NULL) {
        get_BN_data(pubx_key, bn_pubx_key, len64);
        get_BN_data(puby_key, bn_puby_key, len64);
    }
#else
    // We don't need private key for verification
    if (priv_key != NULL) {
        // extract private keys and store
        get_BN_data(priv_key, bn_priv_key, len64);
    }

    // We don't need public key for signature
    if (pubx_key != NULL && puby_key != NULL) {
        // extract public key and store it projective/affine coordinates
        if (coords == coords_type::projective_coords) {
#if !defined(OPENSSL_IS_BORINGSSL)
            get_BN_data(pubx_key, bn_pubx_key, len64);
            get_BN_data(puby_key, bn_puby_key, len64);
            get_BN_data(pubz_key, bn_pubz_key, len64);
#endif
        }
        else {
            get_BN_data(pubx_key, bn_pubx_key, len64);
            get_BN_data(puby_key, bn_puby_key, len64);
        }
    }
#endif

    // release resources
    BN_free(bn_priv_key);
    BN_free(bn_pubx_key);
    BN_free(bn_puby_key);
    BN_free(bn_pubz_key);

    return keyA;
}

static ECDSA_SIG* openssl_generate_signature(int8u* msg_buffer, int msg_byte_size, EVP_PKEY* key)
{
    ECDSA_SIG* sign = 0;
    (void)key;

    EVP_PKEY_CTX *sign_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    EVP_PKEY_sign_init(sign_ctx);

    // Calculate sign's size
    size_t sig_len;
    EVP_PKEY_sign(sign_ctx, NULL, &sig_len, msg_buffer, msg_byte_size);

    unsigned char *sig = malloc(sig_len);
    EVP_PKEY_sign(sign_ctx, sig, &sig_len, msg_buffer, msg_byte_size);

    const unsigned char * p = sig;
    sign = d2i_ECDSA_SIG(NULL, &p, (long)sig_len);
    // free
    EVP_PKEY_CTX_free(sign_ctx);
    free(sig);

    return sign;
}

/* Restore ephemeral private key to BIGNUM */
void openssl_restore_eph_key_bn(BIGNUM** eph_key, BIGNUM* priv_key, const BIGNUM* signR, const BIGNUM* signS, BIGNUM* bn_msg, EC_GROUP* EC) {
    // get order
    BIGNUM *order = BN_new();
    EC_GROUP_get_order(EC, order, 0);
    BN_CTX *bn_ctx = BN_CTX_new();

    BIGNUM* tmp_1 = BN_new();
    BIGNUM* tmp_2 = BN_new();

    BN_mod_mul(tmp_1, priv_key, signR, order, bn_ctx);
    BN_mod_add(tmp_1, tmp_1, bn_msg, order, bn_ctx);

    BN_mod_inverse(tmp_2, signS, order, bn_ctx);
    BN_mod_mul(*eph_key, tmp_1, tmp_2, order, bn_ctx);

    BN_free(tmp_1);
    BN_free(tmp_2);

    BN_CTX_free(bn_ctx);
    BN_free(order);
}

/* Restore ephemeral private key */
void openssl_restore_eph_key(int64u* eph_key, int64u* priv_key, const BIGNUM* signR, const BIGNUM* signS, BIGNUM* bn_msg, int len8, int len64, EC_GROUP* EC) {

    BIGNUM* bn_k = BN_new();
    BIGNUM* bn_priv_key = BN_new();

    set_BN_data(bn_priv_key, priv_key, len8);
    openssl_restore_eph_key_bn(&bn_k, bn_priv_key, signR, signS, bn_msg, EC);
    get_BN_data(eph_key, bn_k, len64);

    // free
    BN_free(bn_k);
    BN_free(bn_priv_key);
}

/***********************************************************
 * RSA priv and pub exponents testing - rsa decrypt privitive
 ***********************************************************/
#define MBX_RSA2K_DATA_BIT_LEN (2048)
#define MBX_RSA2K_DATA_BYTE_LEN ( (MBX_RSA2K_DATA_BIT_LEN) >> 3 )

#define MBX_RSA4K_DATA_BIT_LEN (4096)
#define MBX_RSA4K_DATA_BYTE_LEN ( (MBX_RSA4K_DATA_BIT_LEN) >> 3 )

#define NUM_OF_DIGS(bitsize, digsize)   (((bitsize) + (digsize)-1)/(digsize))
#define RSA_MAX_LEN64 (NUM_OF_DIGS(MBX_RSA4K_DATA_BIT_LEN, 64))


static void dataReverse(int8u* pBuf, const char* str, int size) {
    for(int i=0;i<size;i++){
        pBuf[i] = str[size-i-1];
    }
}

static int8u* wsp_str(int8u* tofrom, int len)
{
    int i;
    for (i = 0; i < len / 2; i++) {
        int8u x = tofrom[i];
        tofrom[i] = tofrom[len - 1 - i];
        tofrom[len - 1 - i] = x;
    }
    return tofrom;
}

/* Generate OpenSSL RSA key */
static int openssl_generate_rsa_key(EVP_PKEY* rsa, BIGNUM* bn_e, unsigned int rsaBitsize) {
    int ret = 1;

    EVP_PKEY_CTX * pctx = EVP_PKEY_CTX_new_from_name(NULL, "rsa", NULL);
    ret = EVP_PKEY_keygen_init(pctx);
    ret = EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, rsaBitsize) & ret;
    ret = EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pctx, bn_e) & ret;
    ret = EVP_PKEY_keygen(pctx, &rsa) & ret;

    return ret;
}

__attribute__((aligned(64))) static const int8u pSeed[]  = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                                           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                                           "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                                           "\x00\x00";

/* XOR block */
static void XorBlock(const void* pSrc1, const void* pSrc2, void* pDst, int len)
{
   const Ipp8u* p1 = (const Ipp8u*)pSrc1;
   const Ipp8u* p2 = (const Ipp8u*)pSrc2;
   Ipp8u* d  = (Ipp8u*)pDst;
   int k;
   for(k=0; k<len; k++)
      d[k] = (Ipp8u)(p1[k] ^p2[k]);
}

#endif //_CRYPTOMB_COMMON_H
