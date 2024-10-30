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

#include <strings.h>
#include <ctype.h>

#include "backend_common.h"
#include "backend_cryptomb_common.h"

/************************************************
 * ECDSA interface functions - SSL API
 ************************************************/
static int len8, msglen;

// globals (group)
static EC_GROUP* EC = NULL;
static const char *curvename;

/************************************************
 * ECDSA interface functions - SSL verdion
 ************************************************/
typedef mbx_status (*p_mbx_nistp_ecpublic_key_ssl_mb8)(BIGNUM**, BIGNUM**, BIGNUM**, const BIGNUM** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_sign_ssl_mb8)(int8u**, int8u**, const int8u** const, const BIGNUM** const, const BIGNUM** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_sign_ssl_setup_mb8)(BIGNUM**, BIGNUM**, const BIGNUM** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_sign_ssl_complete_mb8)(int8u**, int8u**, const int8u** const, const BIGNUM** const, const BIGNUM** const, const BIGNUM** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_verify_ssl_mb8)(const ECDSA_SIG** const, const int8u** const, const BIGNUM** const, const BIGNUM** const, const BIGNUM** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdh_ssl_mb8)(int8u**, const BIGNUM** const, const BIGNUM** const, const BIGNUM** const, const BIGNUM** const, int8u*);

static p_mbx_nistp_ecpublic_key_ssl_mb8 mbx_nistp_ecpublic_key_ssl_mb8 = NULL;
static p_mbx_nistp_ecdsa_sign_ssl_mb8 mbx_nistp_ecdsa_sign_ssl_mb8 = NULL;
static p_mbx_nistp_ecdsa_sign_ssl_setup_mb8 mbx_nistp_ecdsa_sign_setup_ssl_mb8 = NULL;
static p_mbx_nistp_ecdsa_sign_ssl_complete_mb8 mbx_nistp_ecdsa_sign_complete_ssl_mb8 = NULL;
static p_mbx_nistp_ecdsa_verify_ssl_mb8 mbx_nistp_ecdsa_verify_ssl_mb8 = NULL;
static p_mbx_nistp_ecdh_ssl_mb8 mbx_nistp_ecdh_ssl_mb8 = NULL;

static void set_ec_ssl_params(ec_type ec)
{
    switch (ec)
    {
    case nistp256:
        EC = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        len8  = GF256_LEN8;
        curvename = "P-256";
        mbx_nistp_ecpublic_key_ssl_mb8 = mbx_nistp256_ecpublic_key_ssl_mb8;
        mbx_nistp_ecdsa_sign_ssl_mb8 = mbx_nistp256_ecdsa_sign_ssl_mb8;
        mbx_nistp_ecdsa_sign_setup_ssl_mb8 = mbx_nistp256_ecdsa_sign_setup_ssl_mb8;
        mbx_nistp_ecdsa_sign_complete_ssl_mb8 = mbx_nistp256_ecdsa_sign_complete_ssl_mb8;
        mbx_nistp_ecdsa_verify_ssl_mb8 = mbx_nistp256_ecdsa_verify_ssl_mb8;
        mbx_nistp_ecdh_ssl_mb8 = mbx_nistp256_ecdh_ssl_mb8;
        msglen = GF256_BITLEN;
        break;
    case nistp384:
        EC = EC_GROUP_new_by_curve_name(NID_secp384r1);
        len8  = GF384_LEN8;
        curvename = "P-384";
        mbx_nistp_ecpublic_key_ssl_mb8 = mbx_nistp384_ecpublic_key_ssl_mb8;
        mbx_nistp_ecdsa_sign_ssl_mb8 = mbx_nistp384_ecdsa_sign_ssl_mb8;
        mbx_nistp_ecdsa_sign_setup_ssl_mb8 = mbx_nistp384_ecdsa_sign_setup_ssl_mb8;
        mbx_nistp_ecdsa_sign_complete_ssl_mb8 = mbx_nistp384_ecdsa_sign_complete_ssl_mb8;
        mbx_nistp_ecdsa_verify_ssl_mb8 = mbx_nistp384_ecdsa_verify_ssl_mb8;
        mbx_nistp_ecdh_ssl_mb8 = mbx_nistp384_ecdh_ssl_mb8;
        msglen = GF384_BITLEN;
        break;
    case nistp521:
        EC = EC_GROUP_new_by_curve_name(NID_secp521r1);
        len8  = GF521_LEN8;
        curvename = "P-521";
        mbx_nistp_ecpublic_key_ssl_mb8 = mbx_nistp521_ecpublic_key_ssl_mb8;
        mbx_nistp_ecdsa_sign_ssl_mb8 = mbx_nistp521_ecdsa_sign_ssl_mb8;
        mbx_nistp_ecdsa_sign_setup_ssl_mb8 = mbx_nistp521_ecdsa_sign_setup_ssl_mb8;
        mbx_nistp_ecdsa_sign_complete_ssl_mb8 = mbx_nistp521_ecdsa_sign_complete_ssl_mb8;
        mbx_nistp_ecdsa_verify_ssl_mb8 = mbx_nistp521_ecdsa_verify_ssl_mb8;
        mbx_nistp_ecdh_ssl_mb8 = mbx_nistp521_ecdh_ssl_mb8;
        // length of msg must be mutiple 8 (OpenSSL specific)
        msglen = GF521_BITLEN - (GF521_BITLEN % 8);
        break;
    default:
        break;
    }
}

typedef struct {
    EVP_PKEY* pEcKeyPair;
    BIGNUM*   pRegKey_BN;
} pKeysSSL;

static int cryptomb_ssl_ecdsa_keygen_en(uint64_t curve, struct buffer *Qx_buf,
				                        struct buffer *Qy_buf, void **privkey)
{
    (void)Qx_buf; (void)Qy_buf; (void)privkey;
    int ret = 0;

    ec_type ec = ec_unset;
    switch (curve & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
            ec = nistp256;
			break;
		case ACVP_NISTP384:
            ec = nistp384;
			break;
		case ACVP_NISTP521:
            ec = nistp521;
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
	}
    set_ec_ssl_params(ec);

    BIGNUM* st_reg_skey = BN_new();
    BIGNUM* data_pub_x = BN_new();
    BIGNUM* data_pub_y = BN_new();

    EVP_PKEY* ecKeyPair = 0;
    ecKeyPair = openssl_generate_keys_bn(st_reg_skey, data_pub_x, data_pub_y, NULL, EC, curvename, len8, 0);

    pKeysSSL* sslPrivKey = (pKeysSSL*)malloc(sizeof(pKeysSSL));
    sslPrivKey->pEcKeyPair = ecKeyPair;
    sslPrivKey->pRegKey_BN = st_reg_skey;
    *privkey = sslPrivKey;

    /* Get X component of pub key */
    alloc_buf(len8, Qx_buf);
    memset(Qx_buf->buf, 0, len8);
    BN_bn2binpad(data_pub_x, Qx_buf->buf, Qx_buf->len);

    /* Get Y component of pub key */
    alloc_buf(len8, Qy_buf);
    memset(Qy_buf->buf, 0, len8);
    BN_bn2binpad(data_pub_y, Qy_buf->buf, Qy_buf->len);

	return ret;
}

static void cryptomb_ssl_ecdsa_free_key(void *privkey)
{
    (void)privkey;

    EC_GROUP_free(EC);

    pKeysSSL* sslPrivKey = ( pKeysSSL* )privkey;
    EVP_PKEY_free(sslPrivKey->pEcKeyPair);
    BN_free(&sslPrivKey->pRegKey_BN);
    free(sslPrivKey);
}

static int cryptomb_ssl_ecdsa_siggen(struct ecdsa_siggen_data *data, flags_t parsed_flags)
{
    (void)parsed_flags; (void)data;
    int ret = 0;

    ec_type ec = ec_unset;

    int add = 0;
    switch (data->cipher & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
            ec = nistp256;
			break;
		case ACVP_NISTP384:
            ec = nistp384;
			break;
		case ACVP_NISTP521:
            ec = nistp521;
            add = 2;
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
	}
    (void)ec; (void)add;

    // message
    int msgByteSize = data->msg.len;
    int8u data_msg_digest[MBX_NUM_BUFFERS][maxMsgDigestSize] = { 0 };
    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        memcpy(data_msg_digest[i]+add, data->msg.buf, msgByteSize);
    }
    int8u* pa_msg_digest[MBX_NUM_BUFFERS] = {data_msg_digest[0], data_msg_digest[1], data_msg_digest[2], data_msg_digest[3],
                                       data_msg_digest[4], data_msg_digest[5], data_msg_digest[6], data_msg_digest[7]};
    BIGNUM* bn_msg = BN_new();
    BN_hex2bn(&bn_msg, (char*)data_msg_digest[0]);

    /* private keys */
    BIGNUM* bn_k[MBX_NUM_BUFFERS] = {0,0,0,0,0,0,0,0};
    BIGNUM* bn_regk[MBX_NUM_BUFFERS] = {0,0,0,0,0,0,0,0};

    pKeysSSL* sslPrivKey = (pKeysSSL*)data->privkey;
    bn_regk[0] = BN_new();
    BN_copy(bn_regk[0], sslPrivKey->pRegKey_BN);

    ECDSA_SIG* sign = openssl_generate_signature(data_msg_digest[0], BN_num_bytes(bn_msg), sslPrivKey->pEcKeyPair);

    // reference to sign' components
    const BIGNUM* signR = 0; const BIGNUM* signS = 0;
    ECDSA_SIG_get0(sign, &signR, &signS);

    bn_k[0] = BN_new();
    openssl_restore_eph_key_bn(&bn_k[0], bn_regk[0], signR, signS, bn_msg, EC);

    for(int i = 1; i < MBX_NUM_BUFFERS; i++) {
        bn_k[i] = BN_new();
        bn_regk[i] = BN_new();

        BN_copy(bn_k[i], bn_k[0]);
        BN_copy(bn_regk[i], bn_regk[0]);
    }

    /* Output signature */
    create_and_clean_mbx_buffer_int8u(sign_r);
    create_and_clean_mbx_buffer_int8u(sign_s);
    create_and_clean_mbx_buffer_int8u(sign_r_partial_api);
    create_and_clean_mbx_buffer_int8u(sign_s_partial_api);

    /* Main API*/
    mbx_status sts = mbx_nistp_ecdsa_sign_ssl_mb8(pa_sign_r, pa_sign_s,
                                                 (const int8u**)pa_msg_digest,
                                                 (const int64u**)bn_k,
                                                 (const int64u**)bn_regk,
                                                 0);

    /* Patrial API */
    BIGNUM* pabn_inv_eph_key[8] = {0,0,0,0,0,0,0,0};
    BIGNUM* pabn_sign_rp[8]     = {0,0,0,0,0,0,0,0};
    for(int k = 0; k < 8; k++) {
        pabn_inv_eph_key[k] = BN_new();
        pabn_sign_rp[k] = BN_new();
    }

    mbx_status sts_partial = mbx_nistp_ecdsa_sign_setup_ssl_mb8(pabn_inv_eph_key, pabn_sign_rp, bn_k, NULL);
    CKNULL_LOG((sts_partial == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecdsa_sign_setup_ssl_mb8")

    sts_partial = mbx_nistp_ecdsa_sign_complete_ssl_mb8(pa_sign_r_partial_api, pa_sign_s_partial_api, pa_msg_digest,
       (const BIGNUM**)pabn_sign_rp, (const BIGNUM**)pabn_inv_eph_key, bn_regk, NULL);
    CKNULL_LOG((sts_partial == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecdsa_sign_complete_ssl_mb8")


    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        int flag_r = memcmp(pa_sign_r[0], pa_sign_r[i], len8);
        int flag_s = memcmp(pa_sign_s[0], pa_sign_s[i], len8);

        if(flag_r || flag_s) {
            logger(LOGGER_ERR, "Result NOT VALID, buffers differ\n");
            sts = MBX_SET_STS_ALL(MBX_STATUS_MISMATCH_PARAM_ERR);
            break;
        }
    }

    if(sts == MBX_STATUS_OK) {
        /* Get S component */
        alloc_buf(len8, &data->S);
        memset(data->S.buf, 0, len8);
        memcpy(data->S.buf, pa_sign_s[0], len8);

        /* Get R component */
        alloc_buf(len8, &data->R);
        memset(data->R.buf, 0, len8);
        memcpy(data->R.buf, pa_sign_r[0], len8);
    }

out:
    BN_free(bn_msg);
    ECDSA_SIG_free(sign);

    return ret;
}

static int cryptomb_ssl_ecdsa_sigver(struct ecdsa_sigver_data *data, flags_t parsed_flags)
{
    (void)parsed_flags;
    int ret = 0;

    IppStatus ipp_sts = ippStsNoErr;
    IppsHashMethod* method = NULL;

    /* "Feature" of p521 curve - padd the message with leading zeros to 528 bits */
    int offset = 0;
    ec_type ec = ec_unset;
    switch (data->cipher & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
            ec = nistp256;
            method = (IppsHashMethod*)ippsHashMethod_SHA256();
			break;
		case ACVP_NISTP384:
            ec = nistp384;
            method = (IppsHashMethod*)ippsHashMethod_SHA384();
			break;
		case ACVP_NISTP521:
            ec = nistp521;
            offset = 2;
            method = (IppsHashMethod*)ippsHashMethod_SHA512();
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
	}

    set_ec_ssl_params(ec);

    int8u data_msg_digest[MBX_NUM_BUFFERS][maxMsgDigestSize] = { 0 };
    ECDSA_SIG* pabn_sign[MBX_NUM_BUFFERS] = { 0,0,0,0,0,0,0,0 };
    BIGNUM* pabn_pubX[MBX_NUM_BUFFERS]    = { 0,0,0,0,0,0,0,0 };
    BIGNUM* pabn_pubY[MBX_NUM_BUFFERS]    = { 0,0,0,0,0,0,0,0 };

    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        BIGNUM *BN_r = BN_new();
        BIGNUM *BN_s = BN_new();
        pabn_sign[i] = ECDSA_SIG_new();
        BN_bin2bn(data->R.buf, data->R.len, BN_r);
        BN_bin2bn(data->S.buf, data->S.len, BN_s);
        ECDSA_SIG_set0(pabn_sign[i], BN_r, BN_s);

        // Use single-buffer to prepare the hash of the raw messages passed from FIPS Lab
        ipp_sts = ippsHashMessage_rmf(data->msg.buf, data->msg.len, data_msg_digest[i]+offset, method);
        CKNULL_LOG((ipp_sts == ippStsNoErr), ipp_sts, "Error in ippsHashMessage_rmf")

        pabn_pubX[i] = BN_new();
        BN_bin2bn(data->Qx.buf, data->Qx.len, pabn_pubX[i]);

        pabn_pubY[i] = BN_new();
        BN_bin2bn(data->Qy.buf, data->Qy.len, pabn_pubY[i]);
    }

    /* msg */
    int8u* pa_msg_digest[MBX_NUM_BUFFERS] = {data_msg_digest[0], data_msg_digest[1], data_msg_digest[2], data_msg_digest[3],
                                       data_msg_digest[4], data_msg_digest[5], data_msg_digest[6], data_msg_digest[7]};

    /* Verify */
    mbx_status sts = mbx_nistp_ecdsa_verify_ssl_mb8((const ECDSA_SIG**)pabn_sign,
                                                       (const int8u**)pa_msg_digest,
                                                       (const BIGNUM**)pabn_pubX,
                                                       (const BIGNUM**)pabn_pubY,
                                                       NULL, 0);
    data->sigver_success = 1;
    if (MBX_STATUS_OK != sts) {
        data->sigver_success = 0;
    }

out:

    return ret;
}

static struct ecdsa_backend cryptomb_ssl_ecdsa =
{
	NULL,                        /* ecdsa_keygen_testing */
	NULL,
	NULL,                        /* ecdsa_pkvver */
	cryptomb_ssl_ecdsa_siggen,   /* ecdsa_siggen */
	cryptomb_ssl_ecdsa_sigver,   /* ecdsa_sigver */
	cryptomb_ssl_ecdsa_keygen_en,
	cryptomb_ssl_ecdsa_free_key,
};

ACVP_DEFINE_CONSTRUCTOR(cryptomb_ssl_ecdsa_backend)
static void cryptomb_ssl_ecdsa_backend(void)
{
	register_ecdsa_impl(&cryptomb_ssl_ecdsa);
}

/************************************************
 * ECDH interface functions
 ************************************************/
static int
cryptomb_ssl_ecdh_ss_common(uint64_t cipher, struct buffer *Qxrem, struct buffer *Qyrem,
                            struct buffer *privloc, struct buffer *Qxloc, struct buffer *Qyloc,
                            struct buffer *hashzz)
{
    int ret = 0;
    mbx_status sts = MBX_STATUS_OK;
    ec_type ec = ec_unset;

    int add = 0;
    switch (cipher & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
            ec = nistp256;
			break;
		case ACVP_NISTP384:
            ec = nistp384;
			break;
		case ACVP_NISTP521:
            ec = nistp521;
            add = 2;
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
	}
    (void)add;
    set_ec_ssl_params(ec);

    // A - remote
    // B - local
    create_and_clean_mbx_buffer_int64u(ifma_sharedAB);
    BIGNUM* pa_pubAx[] = {0,0,0,0,0,0,0,0};
    BIGNUM* pa_pubAy[] = {0,0,0,0,0,0,0,0};
    BIGNUM* pa_pubBx[] = {0,0,0,0,0,0,0,0};
    BIGNUM* pa_pubBy[] = {0,0,0,0,0,0,0,0};
    BIGNUM* pa_prvB[] = {0,0,0,0,0,0,0,0};

    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        pa_pubBx[i] = BN_new();
        pa_pubBy[i] = BN_new();
        pa_prvB[i] = BN_new();

        pa_pubAx[i] = BN_new();
        pa_pubAy[i] = BN_new();
    }

    if (Qxloc->len && Qyloc->len) {
        for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
            BN_bin2bn(Qxloc->buf, Qxloc->len, pa_pubBx[i]);
            BN_bin2bn(Qyloc->buf, Qyloc->len, pa_pubBy[i]);
        }
	}
    if (privloc->len) {
        for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
            BN_bin2bn(privloc->buf, privloc->len, pa_prvB[i]);
        }
	}
    if(!(privloc->len && Qxloc->len && Qyloc->len)) {
        // generate local keys - private with OpenSSL and public with crypto_mb
        EVP_PKEY* ecKeyPair = 0;
        ecKeyPair = openssl_generate_keys_bn(pa_prvB[0], NULL, NULL, NULL, EC, curvename, len8, 0);
        (void)ecKeyPair;

        for(int i = 1; i < MBX_NUM_BUFFERS; i++) {
            BN_copy(pa_prvB[i], pa_prvB[0]);
        }

        sts = mbx_nistp_ecpublic_key_ssl_mb8(pa_pubBx, pa_pubBy, NULL, (const BIGNUM **)pa_prvB, 0);
        CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecpublic_key_ssl_mb8")

        alloc_buf(len8, Qxloc);
        alloc_buf(len8, Qyloc);
        BN_bn2binpad(pa_pubBx[0], Qxloc->buf, len8);
        BN_bn2binpad(pa_pubBy[0], Qyloc->buf, len8);
	}

    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        BN_bin2bn(Qxrem->buf, Qxrem->len, pa_pubAx[i]);
        BN_bin2bn(Qyrem->buf, Qyrem->len, pa_pubAy[i]);
    }

    sts = mbx_nistp_ecdh_ssl_mb8(pa_ifma_sharedAB, (const BIGNUM**)pa_prvB, (const BIGNUM**)pa_pubAx, (const BIGNUM**)pa_pubAy, NULL, 0);

    for(int i = 1; i < MBX_NUM_BUFFERS; i++){
        int cmp_flag = memcmp(pa_ifma_sharedAB[i],pa_ifma_sharedAB[0], len8);

        if(cmp_flag){
			logger(LOGGER_ERR, "Bad result, buffers differ\n");
            ret = 0;
            break;
        }
    }

    /* Release resources */
    for (int i = 0; i < 8; i++) {
            BN_free(pa_pubAx[i]);
            BN_free(pa_pubAy[i]);
            BN_free(pa_pubBx[i]);
            BN_free(pa_pubBy[i]);
            BN_free(pa_prvB[i]);
    }

    if(hashzz->len){
        if(memcmp(hashzz->buf, pa_ifma_sharedAB[0], len8)){
            ret = -ENOENT;
            goto out;
        }
    }
    else{
        alloc_buf(len8, hashzz);
        memcpy(hashzz->buf, pa_ifma_sharedAB[0], len8);
    }

    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecdh_ssl_mb8")

out:

    return ret;
}

static int cryptomb_ssl_ecdh_ss(struct ecdh_ss_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

	return cryptomb_ssl_ecdh_ss_common(data->cipher, &data->Qxrem, &data->Qyrem,
				      &data->privloc, &data->Qxloc,
				      &data->Qyloc, &data->hashzz);
}

static int cryptomb_ssl_ecdh_ss_ver(struct ecdh_ss_ver_data *data,
		flags_t parsed_flags)
{
    int ret = 0;
	(void)parsed_flags;

	ret = cryptomb_ssl_ecdh_ss_common(data->cipher, &data->Qxrem,
                                      &data->Qyrem, &data->privloc,
                                      &data->Qxloc, &data->Qyloc,
                                      &data->hashzz);

	if (ret == -EOPNOTSUPP || ret == -ENOENT) {
		data->validity_success = 0;
        return 0;
	} else if (!ret) {
		data->validity_success = 1;
        return 0;
	}

	return ret;
}

static struct ecdh_backend cryptomb_ssl_ecdh =
{
	cryptomb_ssl_ecdh_ss,
	cryptomb_ssl_ecdh_ss_ver,
};

ACVP_DEFINE_CONSTRUCTOR(cryptomb_ssl_ecdh_backend)
static void cryptomb_ssl_ecdh_backend(void)
{
    register_ecdh_impl(&cryptomb_ssl_ecdh);
}

/************************************************
 * RSA pub exponent testing - OAEP KTS
 ************************************************/
static int cryptomb_rsa_kas_ifc_encrypt_common(struct kts_ifc_data *data, uint32_t *validation_success)
{
    (void)validation_success;

    int ret = 0;
    mbx_status sts = MBX_STATUS_OK;

    struct kts_ifc_init_data *init = &data->u.kts_ifc_init;

    int keyBitlen = data->keylen;

    struct buffer *dkm_p, *c_p;

    left_pad_buf(&init->n, data->modulus >> 3);
    if (!init->dkm.len) {
        alloc_buf(keyBitlen >> 3, &init->dkm);
        RAND_bytes(init->dkm.buf, (int)init->dkm.len);

        /*
        * Ensure that in case of raw encryption, the value is
        * not too large.
        */
        init->dkm.buf[0] &= ~0x80;
    }
    dkm_p = &init->dkm;
    c_p = &init->iut_c;

    /* output ciphertext */
    int8u out_ciphertext[MBX_NUM_BUFFERS][MBX_RSA4K_DATA_BYTE_LEN];
    int8u *pa_ciphertext[MBX_NUM_BUFFERS] = {
        out_ciphertext[0], out_ciphertext[1], out_ciphertext[2], out_ciphertext[3],
        out_ciphertext[4], out_ciphertext[5], out_ciphertext[6], out_ciphertext[7]};

    // e
    BIGNUM* BN_e = BN_new();
    BN_bin2bn(init->e.buf, init->e.len, BN_e);
    const BIGNUM *pa_e[MBX_NUM_BUFFERS] = {
        (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e,
        (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e, (const BIGNUM *)BN_e};
    // moduli
    BIGNUM* BN_moduli = BN_new();
    BN_bin2bn(init->n.buf, init->n.len, BN_moduli);
    const BIGNUM *pa_moduli[MBX_NUM_BUFFERS] = {
        (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli,
        (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli, (const BIGNUM *)BN_moduli};

    int rsaBitLen = init->n.len * 8;
    int rsaByteLen = init->n.len;

    // oaep encoding
        int8u  seedMask[32] = {0};
        int hashLen = 32;
        int k = rsaByteLen;
        int srcLen = dkm_p->len;
        int8u* pSrc = dkm_p->buf;

        int8u* pMaskedSeed = (int8u*)out_ciphertext[0]+1;
        int8u* pMaskedDB = (int8u*)out_ciphertext[0] +hashLen +1;

        out_ciphertext[0][0] = 0;
        const IppsHashMethod* pMethod = ippsHashMethod_SHA256();

        /* maskedDB = MGF(seed, k-1-hashLen)*/
        ippsMGF1_rmf(pSeed, hashLen, pMaskedDB, k-1-hashLen, pMethod);

        /* seedMask = HASH(pLab) */
        ippsHashMessage_rmf(NULL, 0, seedMask, pMethod);

        /* maskedDB ^= concat(HASH(pLab),PS,0x01,pSc) */
        XorBlock(pMaskedDB, seedMask, pMaskedDB, hashLen);
        pMaskedDB[k-srcLen-hashLen-2] ^= 0x01;
        XorBlock(pMaskedDB+k-srcLen-hashLen-2+1, pSrc, pMaskedDB+k-srcLen-hashLen-2+1, srcLen);

        /* seedMask = MGF(maskedDB, hashLen) */
        ippsMGF1_rmf(pMaskedDB, k-1-hashLen, seedMask, hashLen, pMethod);
        /* maskedSeed = seed ^ seedMask */
        XorBlock(pSeed, seedMask, pMaskedSeed, hashLen);

    sts = mbx_rsa_public_ssl_mb8(pa_ciphertext, pa_ciphertext, pa_e, pa_moduli, rsaBitLen);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_rsa_public_ssl_mb8\n")

	alloc_buf(rsaByteLen, c_p);
    memcpy(c_p->buf, pa_ciphertext[0], rsaByteLen);

out:
    BN_free(BN_moduli);
    BN_free(BN_e);

    return ret;
}

static int cryptomb_kts_ifc_generate(struct kts_ifc_data *data,
				    flags_t parsed_flags)
{
	int ret = 0;

    (void)data; (void)parsed_flags;
    if ((parsed_flags & FLAG_OP_KAS_ROLE_INITIATOR) &&
	    (parsed_flags & FLAG_OP_AFT)) {
		cryptomb_rsa_kas_ifc_encrypt_common(data, NULL);
    }
    else {
        logger(LOGGER_ERR, "Unsupported test, only public exponent is tested with KTS.\n");
        logger(LOGGER_ERR, "For private exponent test please use rsa_backend and rsa decryption primitive testing\n");
        ret = -1;
    }

	return ret;
}

static struct kts_ifc_backend cryptomb_kts_ifc =
{
	cryptomb_kts_ifc_generate,
};

ACVP_DEFINE_CONSTRUCTOR(cryptomb_kts_ifc_backend)
static void cryptomb_kts_ifc_backend(void)
{
	register_kts_ifc_impl(&cryptomb_kts_ifc);
}

/****************************************************
 * RSA priv exponent testing - rsa decrypt privitive
 ****************************************************/
static int cryptombssl_rsa_keygen_en(struct buffer *ebuf, uint32_t modulus, void **privkey, struct buffer *nbuf)
{
    int ret = 0;

	BIGNUM *egen = BN_new();
    BIGNUM *n = BN_new();
	EVP_PKEY *rsa = EVP_PKEY_new();

    int64u e = 65537;
    BIGNUM* bn_e = BN_new();
    BN_set_word(bn_e, e);

    int rsaBitsize = modulus;

    ret = openssl_generate_rsa_key(rsa, bn_e, rsaBitsize);
    CKNULL_LOG((ret == 1), ret, "Error in openssl_generate_rsa_key")

    EVP_PKEY_get_bn_param(rsa, "n", &n);
    EVP_PKEY_get_bn_param(rsa, "e", &egen);

    /* Store n and e in output buffers */
    alloc_buf(BN_num_bytes(egen), ebuf);
	BN_bn2binpad(egen, ebuf->buf, BN_num_bytes(egen));
    alloc_buf(BN_num_bytes(n), nbuf);
    BN_bn2binpad(n, nbuf->buf, BN_num_bytes(n));

    *privkey = rsa;

out:
    BN_free(bn_e);
    BN_free(egen);
    BN_free(n);

	return ret;
}

static void cryptombssl_rsa_free_key(void *privkey)
{
	EVP_PKEY *rsa = (EVP_PKEY *)privkey;

	if (rsa)
		EVP_PKEY_free(rsa);
}

static int
cryptombssl_rsa_decryption_primitive(struct rsa_decryption_primitive_data *data, flags_t parsed_flags)
{
	int ret = 1;
    mbx_status sts = MBX_STATUS_OK;
	(void)parsed_flags;

    /* Define RSA bitlen */
    int rsaByteLen = data->n.len;
    int rsaBitsize = rsaByteLen*8;

    /* output plaintext - allocate maximum possible buffer */
    int8u out_plaintext_basic[MBX_NUM_BUFFERS][MBX_RSA4K_DATA_BYTE_LEN] = {0};
    int8u *pa_plaintext_basic[MBX_NUM_BUFFERS] = {
        out_plaintext_basic[0], out_plaintext_basic[1], out_plaintext_basic[2], out_plaintext_basic[3],
        out_plaintext_basic[4], out_plaintext_basic[5], out_plaintext_basic[6], out_plaintext_basic[7]};
    int8u out_plaintext_crt[MBX_NUM_BUFFERS][MBX_RSA4K_DATA_BYTE_LEN] = {0};
    int8u *pa_plaintext_crt[MBX_NUM_BUFFERS] = {
        out_plaintext_crt[0], out_plaintext_crt[1], out_plaintext_crt[2], out_plaintext_crt[3],
        out_plaintext_crt[4], out_plaintext_crt[5], out_plaintext_crt[6], out_plaintext_crt[7]};
    /* input ciphertext  */
    int8u msg_buff[MBX_NUM_BUFFERS][MBX_RSA4K_DATA_BYTE_LEN];
    for(int i = 0; i < MBX_NUM_BUFFERS; i++){
        memcpy(msg_buff[i], (const char*)data->msg.buf, data->msg.len);
    }
    int8u *pa_ciphertext[MBX_NUM_BUFFERS] = {
        msg_buff[0], msg_buff[1], msg_buff[2], msg_buff[3],
        msg_buff[4], msg_buff[5], msg_buff[6], msg_buff[7] };

    /* classic parameters */
    // private exponent and moduli
    int64u *pa_d[MBX_NUM_BUFFERS];
    int64u *pa_e[MBX_NUM_BUFFERS];
    int64u *pa_n[MBX_NUM_BUFFERS];

    /* CRT parameters */
    // p, q primes and their CRT private exponent
    BIGNUM *pa_p[MBX_NUM_BUFFERS];
    BIGNUM *pa_q[MBX_NUM_BUFFERS];
    BIGNUM *pa_dp[MBX_NUM_BUFFERS];
    BIGNUM *pa_dq[MBX_NUM_BUFFERS];
    /* CRT coefficient */
    BIGNUM *pa_inv_q[MBX_NUM_BUFFERS];

    /* Get RSA key info */
	EVP_PKEY *rsa = data->privkey;

    /* Get bignum components */
    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        pa_n[i] = BN_new();
        pa_e[i] = BN_new();
        pa_d[i] = BN_new();
        pa_p[i] = BN_new();
        pa_q[i] = BN_new();
        pa_dp[i] = BN_new();
        pa_dq[i] = BN_new();
        pa_inv_q[i] = BN_new();
        EVP_PKEY_get_bn_param(rsa, "n", &pa_n[i]);
        EVP_PKEY_get_bn_param(rsa, "e", &pa_e[i]);
        EVP_PKEY_get_bn_param(rsa, "d", &pa_d[i]);
        EVP_PKEY_get_bn_param(rsa, "rsa-factor1", &pa_p[i]);
        EVP_PKEY_get_bn_param(rsa, "rsa-factor2", &pa_q[i]);
        EVP_PKEY_get_bn_param(rsa, "rsa-exponent1", &pa_dp[i]);
        EVP_PKEY_get_bn_param(rsa, "rsa-exponent2", &pa_dq[i]);
        EVP_PKEY_get_bn_param(rsa, "rsa-coefficient1", &pa_inv_q[i]);
    }

    data->dec_result = 1;

    /* Check message and generated modulus */
    BIGNUM *bn_msg = BN_new();
    BN_bin2bn(data->msg.buf, data->msg.len, bn_msg);
    int cmp_bn_res = BN_cmp(bn_msg, pa_n[0]);
    if(cmp_bn_res == 1){
        logger(LOGGER_WARN, "Error, message is bigger than modulus\n");
        data->dec_result = 0;
        goto out;
    }

    sts = mbx_rsa_private_crt_ssl_mb8(pa_ciphertext, pa_plaintext_crt, pa_p, pa_q,
                                  pa_dp, pa_dq, pa_inv_q, rsaBitsize);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_rsa_private_crt_ssl_mb8")

    sts = mbx_rsa_private_ssl_mb8(pa_ciphertext, pa_plaintext_basic,
                                (const int64u **)pa_d,
                                (const int64u **)pa_n,
                                rsaBitsize);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_rsa_private_ssl_mb8")

    /* Check the output */
    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        int cmp_flag = memcmp(pa_plaintext_basic[i], pa_plaintext_basic[0], rsaByteLen);
        if(cmp_flag){
			logger(LOGGER_ERR, "Different output in buffers, the result is unexpected\n");
            ret = -1;
            break;
        }
        cmp_flag = memcmp(pa_plaintext_crt[i], pa_plaintext_basic[i], rsaByteLen);
        if(cmp_flag){
			logger(LOGGER_ERR, "Different output between crt and basic decryption\n");
            ret = -1;
            break;
        }
    }

    if(!ret) {
        data->dec_result = 0;
    }
    else{
        alloc_buf(rsaByteLen, &data->s);
        memcpy(data->s.buf, pa_plaintext_basic[0], rsaByteLen);
    }

out:
    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        BN_free(pa_n[i]);
        BN_free(pa_e[i]);
        BN_free(pa_d[i]);
        BN_free(pa_p[i]);
        BN_free(pa_q[i]);
        BN_free(pa_dp[i]);
        BN_free(pa_dq[i]);
        BN_free(pa_inv_q[i]);
    }
    BN_free(bn_msg);

    return ret;
}

static struct rsa_backend cryptombssl_rsa =
{
	NULL, /* rsa_keygen */
	NULL, /* rsa_siggen */
	NULL, /* rsa_sigver */
	NULL, /* rsa_keygen_prime */
	NULL, /* rsa_keygen_prov_prime */
	cryptombssl_rsa_keygen_en,
	cryptombssl_rsa_free_key,
	NULL,
	cryptombssl_rsa_decryption_primitive,
};

ACVP_DEFINE_CONSTRUCTOR(cryptombssl_rsa_backend)
static void cryptombssl_rsa_backend(void)
{
	register_rsa_impl(&cryptombssl_rsa);
}
