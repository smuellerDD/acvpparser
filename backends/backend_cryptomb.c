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

static int len64, len8, msglen;

// globals (group)
static EC_GROUP* EC = NULL;
static const char *curvename;

/************************************************
 * ECDSA interface functions
 ************************************************/
typedef mbx_status (*p_mbx_nistp_ecpublic_key_mb8)(int64u**, int64u**, int64u**, const int64u** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_sign_mb8)(int8u**, int8u**, const int8u** const, const int64u** const, const int64u** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_sign_setup_mb8)(int64u**, int64u**, const int64u** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_sign_complete_mb8)(int8u**, int8u**, const int8u** const, const int64u** const, const int64u** const, const int64u** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdsa_verify_mb8)(const int8u** const, const int8u** const, const int8u** const, const int64u** const, const int64u** const, const int64u** const, int8u*);
typedef mbx_status (*p_mbx_nistp_ecdh_mb8)(int8u**, const int64u**, const int64u**, const int64u**, const int64u**, int8u*);

static p_mbx_nistp_ecpublic_key_mb8 mbx_nistp_ecpublic_key_mb8 = NULL;
static p_mbx_nistp_ecdsa_sign_mb8 mbx_nistp_ecdsa_sign_mb8 = NULL;
static p_mbx_nistp_ecdsa_sign_setup_mb8 mbx_nistp_ecdsa_sign_setup_mb8 = NULL;
static p_mbx_nistp_ecdsa_sign_complete_mb8 mbx_nistp_ecdsa_sign_complete_mb8 = NULL;
static p_mbx_nistp_ecdsa_verify_mb8 mbx_nistp_ecdsa_verify_mb8 = NULL;
static p_mbx_nistp_ecdh_mb8 mbx_nistp_ecdh_mb8 = NULL;

static void set_ec_params(ec_type ec)
{
    switch (ec)
    {
    case nistp256:
        EC = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        curvename = "P-256";
        len64 = GF256_LEN64;
        len8 = GF256_LEN8;
        mbx_nistp_ecpublic_key_mb8 = mbx_nistp256_ecpublic_key_mb8;
        mbx_nistp_ecdsa_sign_mb8 = mbx_nistp256_ecdsa_sign_mb8;
        mbx_nistp_ecdsa_sign_setup_mb8 = mbx_nistp256_ecdsa_sign_setup_mb8;
        mbx_nistp_ecdsa_sign_complete_mb8 = mbx_nistp256_ecdsa_sign_complete_mb8;
        mbx_nistp_ecdsa_verify_mb8 = mbx_nistp256_ecdsa_verify_mb8;
        mbx_nistp_ecdh_mb8 = mbx_nistp256_ecdh_mb8;
        msglen = GF256_BITLEN;
        break;
    case nistp384:
        EC = EC_GROUP_new_by_curve_name(NID_secp384r1);
        curvename = "P-384";
        len64 = GF384_LEN64;
        len8 = GF384_LEN8;
        mbx_nistp_ecpublic_key_mb8 = mbx_nistp384_ecpublic_key_mb8;
        mbx_nistp_ecdsa_sign_mb8 = mbx_nistp384_ecdsa_sign_mb8;
        mbx_nistp_ecdsa_sign_setup_mb8 = mbx_nistp384_ecdsa_sign_setup_mb8;
        mbx_nistp_ecdsa_sign_complete_mb8 = mbx_nistp384_ecdsa_sign_complete_mb8;
        mbx_nistp_ecdsa_verify_mb8 = mbx_nistp384_ecdsa_verify_mb8;
        mbx_nistp_ecdh_mb8 = mbx_nistp384_ecdh_mb8;
        msglen = GF384_BITLEN;
        break;
    case nistp521:
        EC = EC_GROUP_new_by_curve_name(NID_secp521r1);
        curvename = "P-521";
        len64 = GF521_LEN64;
        len8 = GF521_LEN8;
        mbx_nistp_ecpublic_key_mb8 = mbx_nistp521_ecpublic_key_mb8;
        mbx_nistp_ecdsa_sign_mb8 = mbx_nistp521_ecdsa_sign_mb8;
        mbx_nistp_ecdsa_sign_setup_mb8 = mbx_nistp521_ecdsa_sign_setup_mb8;
        mbx_nistp_ecdsa_sign_complete_mb8 = mbx_nistp521_ecdsa_sign_complete_mb8;
        mbx_nistp_ecdsa_verify_mb8 = mbx_nistp521_ecdsa_verify_mb8;
        mbx_nistp_ecdh_mb8 = mbx_nistp521_ecdh_mb8;
        // length of msg must be mutiple 8 (OpenSSL specific)
        msglen = GF521_BITLEN - (GF521_BITLEN % 8);
        break;
    default:
        break;
    }
}

typedef struct {
    EVP_PKEY* pEcKeyPair;
    int8u*    pRegKey;
} pKeys;

static int cryptomb_ecdsa_keygen_en(uint64_t curve, struct buffer *Qx_buf,
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
    set_ec_params(ec);

    // ifma's regular private key and public key
     __ALIGN64 int64u st_reg_skey[MAX_LEN64];
     __ALIGN64 int64u data_pub_x[MAX_LEN64];
     __ALIGN64 int64u data_pub_y[MAX_LEN64];

    EVP_PKEY* ecKeyPair = 0;
    ecKeyPair = openssl_generate_keys(st_reg_skey, data_pub_x, data_pub_y, NULL, EC, curvename, len8, len64, 0);

    BUFFER_INIT(reg_skey)
    alloc_buf(MAX_LEN8, &reg_skey);
    memcpy(reg_skey.buf, st_reg_skey, MAX_LEN8);

    (void)ecKeyPair;
    pKeys* sslPrivKey = ( pKeys* )malloc(sizeof( pKeys));
    sslPrivKey->pEcKeyPair = ecKeyPair;
    sslPrivKey->pRegKey = reg_skey.buf;

    *privkey = sslPrivKey;

    /* Get X component of pub key */
    alloc_buf(len8, Qx_buf);
    memset(Qx_buf->buf, 0, len8);
    reverse_bytes(Qx_buf->buf, data_pub_x, Qx_buf->len);

    /* Get Y component of pub key */
    alloc_buf(len8, Qy_buf);
    memset(Qy_buf->buf, 0, len8);
    reverse_bytes(Qy_buf->buf, data_pub_y, Qy_buf->len);

	return ret;
}

static void cryptomb_ecdsa_free_key(void *privkey)
{
    (void)privkey;

    EC_GROUP_free(EC);

    pKeys* sslPrivKey = ( pKeys* )privkey;
    EVP_PKEY_free(sslPrivKey->pEcKeyPair);
    free_buf(&sslPrivKey->pRegKey);
    free(sslPrivKey);
}

static int cryptomb_ecdsa_keygen(struct ecdsa_keygen_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;
    int ret = 0;
    mbx_status sts = MBX_STATUS_OK;

    ec_type ec = ec_unset;
    switch (data->cipher & ACVP_CURVEMASK) {
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
    set_ec_params(ec);

    // local regular private and public keys
    create_and_clean_mbx_buffer_int64u(prvB);
    create_and_clean_mbx_buffer_int64u(pubBx);
    create_and_clean_mbx_buffer_int64u(pubBy);

    EVP_PKEY* ecKeyPair = 0;
    ecKeyPair = openssl_generate_keys(pa_prvB[0], NULL, NULL, NULL, EC, curvename, len8, len64, 0);
    (void)ecKeyPair;

    for(int i = 1; i < MBX_NUM_BUFFERS; i++) {
            memcpy(pa_prvB[i], pa_prvB[0], len8);
    }
    sts = mbx_nistp_ecpublic_key_mb8(pa_pubBx, pa_pubBy, NULL, (const int64u**)pa_prvB, 0);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecpublic_key_mb8")

    /* Output the private key */
    alloc_buf(len8, &data->d);
    memset(data->d.buf, 0, len8);
    reverse_bytes(data->d.buf, pa_prvB[0], len8);

    /* Get X component of pub key */
    alloc_buf(len8, &data->Qx);
    memset(data->Qx.buf, 0, len8);
    reverse_bytes(data->Qx.buf, pa_pubBx[0], len8);

    /* Get Y component of pub key */
    alloc_buf(len8, &data->Qy);
    memset(data->Qy.buf, 0, len8);
    reverse_bytes(data->Qy.buf, pa_pubBy[0], len8);

out:
    return ret;
}

static int cryptomb_ecdsa_siggen(struct ecdsa_siggen_data *data, flags_t parsed_flags)
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

    create_and_clean_mbx_buffer_int64u(eph_skey);
    create_and_clean_mbx_buffer_int64u(reg_skey);

    pKeys* sslPrivKey = (pKeys*)data->privkey;

    memcpy(reg_skey[0], sslPrivKey->pRegKey, len8);

    ECDSA_SIG* sign = openssl_generate_signature(data_msg_digest[0], BN_num_bytes(bn_msg), sslPrivKey->pEcKeyPair);

    // reference to sign' components
    const BIGNUM* signR = 0; const BIGNUM* signS = 0;
    ECDSA_SIG_get0(sign, &signR, &signS);

    openssl_restore_eph_key(eph_skey[0], reg_skey[0], signR, signS, bn_msg, len8, len64, EC);

    for(int i = 1; i < MBX_NUM_BUFFERS; i++) {
        memcpy(reg_skey[i], reg_skey[0], len8);
        memcpy(eph_skey[i], eph_skey[0], len8);
    }

    /* Output signature */
    create_and_clean_mbx_buffer_int8u(sign_r);
    create_and_clean_mbx_buffer_int8u(sign_s);
    create_and_clean_mbx_buffer_int8u(sign_r_partial_api);
    create_and_clean_mbx_buffer_int8u(sign_s_partial_api);

    /* Main API*/
    mbx_status sts = mbx_nistp_ecdsa_sign_mb8(pa_sign_r, pa_sign_s,
                                            (const int8u**)pa_msg_digest,
                                            (const int64u**)pa_eph_skey,
                                            (const int64u**)pa_reg_skey,
                                            0);

    /* Partial API */
    create_and_clean_mbx_buffer_int64u(sign_rp);
    create_and_clean_mbx_buffer_int64u(inv_eph_skey);

    mbx_status sts_partial = mbx_nistp_ecdsa_sign_setup_mb8(pa_inv_eph_skey, pa_sign_rp, pa_eph_skey, NULL);
    CKNULL_LOG((sts_partial == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecdsa_sign_setup_mb8")

    sts_partial = mbx_nistp_ecdsa_sign_complete_mb8(pa_sign_r_partial_api, pa_sign_s_partial_api, pa_msg_digest,
       (const int64u**)pa_sign_rp, (const int64u**)pa_inv_eph_skey, pa_reg_skey, NULL);
    CKNULL_LOG((sts_partial == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecdsa_sign_complete_mb8")


    /* Check that all buffers are the same before write the answer */
    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        int flag_r = memcmp(pa_sign_r[0], pa_sign_r[i], len8) || memcmp(pa_sign_r[0], pa_sign_r_partial_api[i], len8);
        int flag_s = memcmp(pa_sign_s[0], pa_sign_s[i], len8) || memcmp(pa_sign_s[0], pa_sign_s_partial_api[i], len8);

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

static int cryptomb_ecdsa_sigver(struct ecdsa_sigver_data *data, flags_t parsed_flags)
{
    (void)parsed_flags;
    int ret = 0;

    IppStatus ipp_sts = ippStsNoErr;
    IppsHashMethod* method = NULL;

    /* "Feature" of p521 curve - pad the message with leading zeros to 528 bits */
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

    set_ec_params(ec);

    int8u data_sig_r[MBX_NUM_BUFFERS][maxMsgDigestSize] = { 0 };
    int8u data_sig_s[MBX_NUM_BUFFERS][maxMsgDigestSize] = { 0 };
    int8u data_msg_digest[MBX_NUM_BUFFERS][maxMsgDigestSize] = { 0 };

    /* public X | Y | Z */
    int64u data_pub_x_init[MBX_NUM_BUFFERS][maxSize64u] = { 0 };
    int64u data_pub_y_init[MBX_NUM_BUFFERS][maxSize64u] = { 0 };
    int64u data_pub_x[MBX_NUM_BUFFERS][maxSize64u] = { 0 };
    int64u data_pub_y[MBX_NUM_BUFFERS][maxSize64u] = { 0 };

    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        memcpy(data_sig_s[i], data->S.buf,data->S.len);
        memcpy(data_sig_r[i], data->R.buf,data->R.len);

        // Use single-buffer to prepare the hash of the raw messages passed from FIPS Lab
        ipp_sts = ippsHashMessage_rmf(data->msg.buf, data->msg.len, data_msg_digest[i]+offset, method);
        CKNULL_LOG((ipp_sts == ippStsNoErr), ipp_sts, "Error in ippsHashMessage_rmf")

        memcpy(data_pub_x_init[i], data->Qx.buf,data->Qx.len);
        reverse_bytes((int8u*)data_pub_x[i], (int8u*)data_pub_x_init[i], data->Qx.len);

        memcpy(data_pub_y_init[i], data->Qy.buf,data->Qy.len);
        reverse_bytes((int8u*)data_pub_y[i], (int8u*)data_pub_y_init[i], data->Qy.len);
    }

    /* signature */
    int8u* pa_sig_r[MBX_NUM_BUFFERS] = {data_sig_r[0], data_sig_r[1], data_sig_r[2], data_sig_r[3],
                                  data_sig_r[4], data_sig_r[5], data_sig_r[6], data_sig_r[7]};
    int8u* pa_sig_s[MBX_NUM_BUFFERS] = {data_sig_s[0], data_sig_s[1], data_sig_s[2], data_sig_s[3],
                                  data_sig_s[4], data_sig_s[5], data_sig_s[6], data_sig_s[7]};

    /* msg */
    int8u* pa_msg_digest[MBX_NUM_BUFFERS] = {data_msg_digest[0], data_msg_digest[1], data_msg_digest[2], data_msg_digest[3],
                                       data_msg_digest[4], data_msg_digest[5], data_msg_digest[6], data_msg_digest[7]};

    /* key */
    int64u* pa_pub_x[MBX_NUM_BUFFERS] = {data_pub_x[0], data_pub_x[1], data_pub_x[2], data_pub_x[3],
                                   data_pub_x[4], data_pub_x[5], data_pub_x[6], data_pub_x[7]};
    int64u* pa_pub_y[MBX_NUM_BUFFERS] = {data_pub_y[0], data_pub_y[1], data_pub_y[2], data_pub_y[3],
                                   data_pub_y[4], data_pub_y[5], data_pub_y[6], data_pub_y[7]};

    /* Verify */
    mbx_status sts = 0;
    sts = mbx_nistp_ecdsa_verify_mb8((const int8u**)pa_sig_r, (const int8u**)pa_sig_s,
                                     (const int8u**)pa_msg_digest, (const int64u**)pa_pub_x, (const int64u**)pa_pub_y,
                                     NULL, NULL);

    data->sigver_success = 1;
    if (MBX_STATUS_OK != sts) {
        data->sigver_success = 0;
    }

out:
    return ret;
}

static struct ecdsa_backend cryptomb_ecdsa =
{
	cryptomb_ecdsa_keygen,   /* ecdsa_keygen_testing */
	NULL,
	NULL,                    /* ecdsa_pkvver */
	cryptomb_ecdsa_siggen,   /* ecdsa_siggen */
	cryptomb_ecdsa_sigver,   /* ecdsa_sigver */
	cryptomb_ecdsa_keygen_en,
	cryptomb_ecdsa_free_key,
};

ACVP_DEFINE_CONSTRUCTOR(cryptomb_ecdsa_backend)
static void cryptomb_ecdsa_backend(void)
{
	register_ecdsa_impl(&cryptomb_ecdsa);
}

/************************************************
 * ECDH interface functions
 ************************************************/
static int cryptomb_ecdh_common(uint64_t cipher, struct buffer *Qxrem, struct buffer *Qyrem,
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
    set_ec_params(ec);

    // A - remote
    // B - local
    create_and_clean_mbx_buffer_int64u(ifma_sharedAB);
    create_and_clean_mbx_buffer_int64u(pubBx);
    create_and_clean_mbx_buffer_int64u(pubBy);
    create_and_clean_mbx_buffer_int64u(pubAx);
    create_and_clean_mbx_buffer_int64u(pubAy);
    create_and_clean_mbx_buffer_int64u(prvB);


    if (Qxloc->len && Qyloc->len) {
        for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
            reverse_bytes(pa_pubBx[i], Qxloc->buf, Qxloc->len);
            reverse_bytes(pa_pubBy[i], Qyloc->buf, Qyloc->len);
        }
	}
    if (privloc->len) {
        for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
            reverse_bytes(pa_prvB[i], privloc->buf, privloc->len);
        }
	}
    if(!(privloc->len && Qxloc->len && Qyloc->len)) {
        // generate local keys
        EVP_PKEY* ecKeyPair = 0;
        ecKeyPair = openssl_generate_keys(pa_prvB[0], NULL, NULL, NULL, EC, curvename, len8, len64, 0);
        (void)ecKeyPair;

        for(int i = 1; i < MBX_NUM_BUFFERS; i++) {
            memcpy(pa_prvB[i], pa_prvB[0], len8);
        }

        sts = mbx_nistp_ecpublic_key_mb8(pa_pubBx, pa_pubBy, NULL, (const int64u**)pa_prvB, 0);
        CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecpublic_key_mb8")

        alloc_buf(len8, Qxloc);
        alloc_buf(len8, Qyloc);
        reverse_bytes(Qxloc->buf, pa_pubBx[0], len8);
        reverse_bytes(Qyloc->buf, pa_pubBy[0], len8);
	}

    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        reverse_bytes(pa_pubAx[i], Qxrem->buf, Qxrem->len);
        reverse_bytes(pa_pubAy[i], Qyrem->buf, Qyrem->len);
    }

    sts = mbx_nistp_ecdh_mb8(pa_ifma_sharedAB, (const int64u**)pa_prvB, (const int64u**)pa_pubAx, (const int64u**)pa_pubAy, NULL, 0);

    for(int i = 1; i < MBX_NUM_BUFFERS; i++){
        int cmp_flag = memcmp(pa_ifma_sharedAB[i],pa_ifma_sharedAB[0], len8);

        if(cmp_flag){
			logger(LOGGER_ERR, "Bad result, buffers differ\n");
            ret = 0;
            break;
        }
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
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_nistp_ecdh_mb8")


out:

    return ret;
}

static int cryptomb_ecdh_ss(struct ecdh_ss_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

	return cryptomb_ecdh_common(data->cipher, &data->Qxrem, &data->Qyrem,
                                &data->privloc, &data->Qxloc,
                                &data->Qyloc, &data->hashzz);
}

static int cryptomb_ecdh_ss_ver(struct ecdh_ss_ver_data *data, flags_t parsed_flags)
{
    int ret = 0;
	(void)parsed_flags;

	ret = cryptomb_ecdh_common(data->cipher, &data->Qxrem,
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

static struct ecdh_backend cryptomb_ecdh =
{
	cryptomb_ecdh_ss,
	cryptomb_ecdh_ss_ver,
};

ACVP_DEFINE_CONSTRUCTOR(cryptomb_ecdh_backend)
static void cryptomb_ecdh_backend(void)
{
    register_ecdh_impl(&cryptomb_ecdh);
}

/************************************************
 * Edward Curve testing
 ************************************************/
#define EDDSA_COMPONENT_SIGN_LEN (32)

typedef struct {
    ed25519_public_key* pub_key_;
    ed25519_private_key* priv_key_;
} eddsaKeyPair;

static int  cryptomb_eddsa_keygen_en(struct buffer *qbuf, uint64_t curve, void **privkey)
{
    (void)qbuf; (void)curve; (void)privkey;
    int ret = 0;

    /* Pub key buffer */
    ed25519_public_key* pub_key = (ed25519_public_key*)malloc(sizeof(ed25519_public_key));

    /* Priv key buffer */
    ed25519_private_key* priv_key = (ed25519_private_key*)malloc(sizeof(ed25519_private_key));

    EVP_PKEY *key = NULL;
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();

    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL); //get EVP_PKEY context
    EVP_PKEY_keygen_init(key_ctx); // init EVP_PKEY context

    // generate key pair using OpenSSL
    int evpres = EVP_PKEY_keygen(key_ctx, &key);
    CKNULL_LOG((evpres == 1), evpres, "Error in EVP_PKEY_keygen")

    EVP_PKEY_CTX_free(key_ctx);
    key_ctx = NULL;

    EVP_DigestSignInit(md_ctx, &key_ctx, NULL, NULL, key);

    // extract private and public kyes considered as "known"
    size_t privale_len = 32, public_len = 32;
    if(1 != EVP_PKEY_get_raw_private_key(key, priv_key, &privale_len)) {
        logger(LOGGER_ERR, "Error in EVP_PKEY_get_raw_private_key\n");
    }
    if(1 != EVP_PKEY_get_raw_public_key(key, pub_key, &public_len)) {
        logger(LOGGER_ERR, "Error in EVP_PKEY_get_raw_public_key\n");
    }

    eddsaKeyPair* keyPair = (eddsaKeyPair*)malloc(sizeof(eddsaKeyPair));
    keyPair->pub_key_ = pub_key;
    keyPair->priv_key_ = priv_key;

    *privkey = keyPair;
out:
    return ret;
}

static void cryptomb_eddsa_free_key(void *privkey)
{
    eddsaKeyPair* keyPair = (eddsaKeyPair*)privkey;

    free(keyPair->pub_key_);
    free(keyPair->priv_key_);
    free(keyPair);
}

static int cryptomb_eddsa_keygen(struct eddsa_keygen_data *data, flags_t parsed_flags)
{
    int ret = 0;
    (void)parsed_flags;
    mbx_status sts = MBX_STATUS_OK;

    EVP_PKEY_CTX* key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL); //get EVP_PKEY context
    EVP_PKEY_keygen_init(key_ctx); // init EVP_PKEY context
    EVP_PKEY *key = NULL;

    ed25519_public_key public_key[8];
    /* Priv key buffer */
    ed25519_private_key* priv_key = (ed25519_private_key*)malloc(sizeof(ed25519_private_key));

    /* Array of pointers */
    ed25519_public_key* pa_public_key[8] = {
        &public_key[0], &public_key[1], &public_key[2], &public_key[3],
        &public_key[4], &public_key[5], &public_key[6], &public_key[7]
    };
    ed25519_private_key* pa_secret_key[8] = {
      priv_key, priv_key, priv_key, priv_key,
      priv_key, priv_key, priv_key, priv_key
   };

    // generate key pair using OpenSSL
    int evpres = EVP_PKEY_keygen(key_ctx, &key);
    if(1!=evpres) {
        logger(LOGGER_ERR, "Error in EVP_PKEY_keygen\n");
    }

    // extract private and public kyes considered as "known"
    size_t privale_len = 32;
    if(1 != EVP_PKEY_get_raw_private_key(key, priv_key, &privale_len)) {
        logger(LOGGER_ERR, "Error in EVP_PKEY_get_raw_private_key\n");
    }

    sts =  mbx_ed25519_public_key_mb8(pa_public_key, pa_secret_key);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_ed25519_public_key_mb8")

    for(int i = 1; i < MBX_NUM_BUFFERS; i++){
        int cmp_flag = memcmp(pa_public_key[i], pa_public_key[0], EDDSA_COMPONENT_SIGN_LEN);
        if(cmp_flag) logger(LOGGER_ERR, "Results are not valid, buffers are different\n");
    }

    alloc_buf(EDDSA_COMPONENT_SIGN_LEN, &data->d);
    memcpy(data->d.buf, priv_key, EDDSA_COMPONENT_SIGN_LEN);

    alloc_buf(EDDSA_COMPONENT_SIGN_LEN, &data->q);
    memcpy(data->q.buf, pa_public_key[0], EDDSA_COMPONENT_SIGN_LEN);

out:
    free(priv_key);
    return ret;
}

static int cryptomb_eddsa_siggen(struct eddsa_siggen_data *data, flags_t parsed_flags) {
    (void)parsed_flags; (void)data;
    int ret = 0;
    mbx_status sts;

    /* output signature */
    ed25519_sign_component out_r[MBX_NUM_BUFFERS] = {0};
    ed25519_sign_component out_s[MBX_NUM_BUFFERS] = {0};
    ed25519_sign_component *pa_sign_r[MBX_NUM_BUFFERS] = { (ed25519_sign_component *)out_r[0], (ed25519_sign_component *)out_r[1],
                                                     (ed25519_sign_component *)out_r[2], (ed25519_sign_component *)out_r[3],
                                                     (ed25519_sign_component *)out_r[4], (ed25519_sign_component *)out_r[5],
                                                     (ed25519_sign_component *)out_r[6], (ed25519_sign_component *)out_r[7]};
    ed25519_sign_component *pa_sign_s[MBX_NUM_BUFFERS] = { (ed25519_sign_component *)out_s[0], (ed25519_sign_component *)out_s[1],
                                                     (ed25519_sign_component *)out_s[2], (ed25519_sign_component *)out_s[3],
                                                     (ed25519_sign_component *)out_s[4], (ed25519_sign_component *)out_s[5],
                                                     (ed25519_sign_component *)out_s[6], (ed25519_sign_component *)out_s[7]};

    /* Set up message*/
    int msgLen = data->msg.len;
    int8u* msg = malloc(msgLen);
    memcpy(msg, data->msg.buf, msgLen);
    int8u* pa_msg[8]    = { msg, msg, msg, msg, msg, msg, msg, msg };
    int32u msgLenArr[8] = { msgLen, msgLen, msgLen, msgLen, msgLen, msgLen, msgLen, msgLen };

    /* Key pair */
    eddsaKeyPair* keyPair = (eddsaKeyPair*)data->privkey;

    /* Set up private key */
    ed25519_private_key prv_key;
    memcpy(prv_key, keyPair->priv_key_, EDDSA_COMPONENT_SIGN_LEN);
    const ed25519_private_key *const pa_prv_key[MBX_NUM_BUFFERS] = { (const ed25519_private_key *const)&prv_key, (const ed25519_private_key *const)&prv_key,
                                                                     (const ed25519_private_key *const)&prv_key, (const ed25519_private_key *const)&prv_key,
                                                                     (const ed25519_private_key *const)&prv_key, (const ed25519_private_key *const)&prv_key,
                                                                     (const ed25519_private_key *const)&prv_key, (const ed25519_private_key *const)&prv_key };
    /* Set up public key */
    ed25519_public_key pub_key;
    memcpy(pub_key, keyPair->pub_key_, EDDSA_COMPONENT_SIGN_LEN);
    const ed25519_public_key *const pa_pub_key[MBX_NUM_BUFFERS] = { (const ed25519_private_key *const)&pub_key, (const ed25519_private_key *const)&pub_key,
                                                                    (const ed25519_private_key *const)&pub_key, (const ed25519_private_key *const)&pub_key,
                                                                    (const ed25519_private_key *const)&pub_key, (const ed25519_private_key *const)&pub_key,
                                                                    (const ed25519_private_key *const)&pub_key, (const ed25519_private_key *const)&pub_key };

    /* Sign the message */
    sts = mbx_ed25519_sign_mb8(pa_sign_r, pa_sign_s, pa_msg, msgLenArr, pa_prv_key, pa_pub_key);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_ed25519_sign_mb8")

    /* Output the result */
    alloc_buf(2*EDDSA_COMPONENT_SIGN_LEN, &data->signature);
    memcpy(data->signature.buf, pa_sign_r[0], EDDSA_COMPONENT_SIGN_LEN);
    memcpy(data->signature.buf+EDDSA_COMPONENT_SIGN_LEN, pa_sign_s[0], EDDSA_COMPONENT_SIGN_LEN);

    alloc_buf(EDDSA_COMPONENT_SIGN_LEN, &data->q);
    memcpy(data->q.buf, pub_key, EDDSA_COMPONENT_SIGN_LEN);

out:
    free(msg);

    return ret;
}

static int cryptomb_eddsa_sigver(struct eddsa_sigver_data *data, flags_t parsed_flags) {
    (void)parsed_flags;
    int ret = 0;
    mbx_status sts = MBX_STATUS_OK;

    ed25519_sign_component sign_r[8];
    ed25519_sign_component sign_s[8];
    ed25519_sign_component* pa_sign_r[8] = { &sign_r[0], &sign_r[1], &sign_r[2], &sign_r[3], &sign_r[4], &sign_r[5], &sign_r[6], &sign_r[7] };
    ed25519_sign_component* pa_sign_s[8] = { &sign_s[0], &sign_s[1], &sign_s[2], &sign_s[3], &sign_s[4], &sign_s[5], &sign_s[6], &sign_s[7] };

    for(int i = 0; i < MBX_NUM_BUFFERS; i++){
        memcpy(sign_r[i], data->signature.buf, EDDSA_COMPONENT_SIGN_LEN);
        memcpy(sign_s[i], data->signature.buf+EDDSA_COMPONENT_SIGN_LEN, EDDSA_COMPONENT_SIGN_LEN);
    }

    /* Set message */
    int msgLen = data->msg.len;
    int8u* msg = malloc(msgLen);
    memcpy(msg, data->msg.buf, msgLen);
    int8u* pa_msg[8] = { msg, msg, msg, msg, msg, msg, msg, msg };

    int32u msgLenArr[8] = { msgLen, msgLen, msgLen, msgLen, msgLen, msgLen, msgLen, msgLen };

    /* Set public key */
    int8u* public_key = malloc(data->q.len);
    memcpy(public_key, data->q.buf, data->q.len);
    ed25519_public_key* pa_public_key[8] = { (ed25519_public_key*)public_key, (ed25519_public_key*)public_key,
                                             (ed25519_public_key*)public_key, (ed25519_public_key*)public_key,
                                             (ed25519_public_key*)public_key, (ed25519_public_key*)public_key,
                                             (ed25519_public_key*)public_key, (ed25519_public_key*)public_key };

    sts =  mbx_ed25519_verify_mb8((const ed25519_sign_component**)pa_sign_r,
                                  (const ed25519_sign_component**)pa_sign_s,
                                  pa_msg, msgLenArr,
                                  (const ed25519_public_key**)pa_public_key);

    ret = MBX_STATUS_OK == sts ? 1 : 0;

    data->sigver_success = 1;
    if(!ret){
        data->sigver_success = 0;
    }

    free(msg);
    free(public_key);

    return ret;
}

static struct eddsa_backend cryptomb_eddsa =
{
	cryptomb_eddsa_keygen,
	NULL, // eddsa_keyver,
	cryptomb_eddsa_siggen,
	cryptomb_eddsa_sigver,
    cryptomb_eddsa_keygen_en,
	cryptomb_eddsa_free_key
};

ACVP_DEFINE_CONSTRUCTOR(cryptomb_eddsa_backend)
static void cryptomb_eddsa_backend(void)
{
	register_eddsa_impl(&cryptomb_eddsa);
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
    int modBytelen = data->modulus >> 3;

	struct buffer *dkm_p, *c_p;

    left_pad_buf(&init->n, modBytelen);
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

    // moduli
    int8u* pN = malloc(init->n.len);
    dataReverse(pN, (const char*)init->n.buf, init->n.len);
    const int64u *pa_moduli[MBX_NUM_BUFFERS] = {
        (int64u *)pN, (int64u *)pN, (int64u *)pN, (int64u *)pN,
        (int64u *)pN, (int64u *)pN, (int64u *)pN, (int64u *)pN};

    const mbx_RSA_Method* method = mbx_RSA_pub65537_Method(data->modulus);

    // oaep encoding
        int8u  seedMask[32] = {0};
        int hashLen = 32;
        int k = modBytelen;
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

    sts = mbx_rsa_public_mb8(pa_ciphertext, pa_ciphertext, pa_moduli, data->modulus, method, NULL);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_rsa_public_mb8\n")

	alloc_buf(modBytelen, c_p);
    memcpy(c_p->buf, pa_ciphertext[0], modBytelen);

out:
   free(pN);

    return ret;
}

static int cryptomb_kts_ifc_generate(struct kts_ifc_data *data, flags_t parsed_flags)
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
static int cryptomb_rsa_keygen_en(struct buffer *ebuf, uint32_t modulus, void **privkey, struct buffer *nbuf) {
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

static void cryptomb_rsa_free_key(void *privkey)
{
	EVP_PKEY *rsa = (EVP_PKEY *)privkey;

	if (rsa)
		EVP_PKEY_free(rsa);
}

static int
cryptomb_rsa_decryption_primitive(struct rsa_decryption_primitive_data *data, flags_t parsed_flags)
{
	int ret = 1;
    mbx_status sts = MBX_STATUS_OK;
	(void)parsed_flags;

    /* Define RSA bitlen */
    int rsaByteLen = data->n.len;
    int rsaBitsize = rsaByteLen*8;

    /* Set RSA method */
    const mbx_RSA_Method* rsaMethodPrv = mbx_RSA_private_Method(rsaBitsize);
    const mbx_RSA_Method* rsaMethodPrvCrt = mbx_RSA_private_crt_Method(rsaBitsize);

    int8u* rsaBufferPrv = malloc(mbx_RSA_Method_BufSize(rsaMethodPrv));
    int8u* rsaBufferPrvCrt = malloc(mbx_RSA_Method_BufSize(rsaMethodPrvCrt));

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
    int64u d_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64] = {0};
    int64u e_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64] = {0};
    int64u n_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64] = {0};
    const int64u *pa_d[MBX_NUM_BUFFERS] = {
        d_buff[0], d_buff[1], d_buff[2], d_buff[3],
        d_buff[4], d_buff[5], d_buff[6], d_buff[7],
    };
    const int64u *pa_e[MBX_NUM_BUFFERS] = {
        e_buff[0], e_buff[1], e_buff[2], e_buff[3],
        e_buff[4], e_buff[5], e_buff[6], e_buff[7],
    };
    const int64u *pa_moduli[MBX_NUM_BUFFERS] = {
        n_buff[0], n_buff[1], n_buff[2], n_buff[3],
        n_buff[4], n_buff[5], n_buff[6], n_buff[7],
    };

    /* CRT parameters */
    // p, q primes and their CRT private exponent
    int64u p_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64 / 2] = {0};
    int64u q_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64 / 2] = {0};
    int64u dp_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64 / 2] = {0};
    int64u dq_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64 / 2] = {0};
    int64u iq_buff[MBX_NUM_BUFFERS][RSA_MAX_LEN64 / 2] = {0};
    const int64u *pa_p[MBX_NUM_BUFFERS] = {
        p_buff[0], p_buff[1], p_buff[2], p_buff[3],
        p_buff[4], p_buff[5], p_buff[6], p_buff[7],
    };
    const int64u *pa_q[MBX_NUM_BUFFERS] = {
        q_buff[0], q_buff[1], q_buff[2], q_buff[3],
        q_buff[4], q_buff[5], q_buff[6], q_buff[7],
    };
    const int64u *pa_dp[MBX_NUM_BUFFERS] = {
        dp_buff[0], dp_buff[1], dp_buff[2], dp_buff[3],
        dp_buff[4], dp_buff[5], dp_buff[6], dp_buff[7],
    };
    const int64u *pa_dq[MBX_NUM_BUFFERS] = {
        dq_buff[0], dq_buff[1], dq_buff[2], dq_buff[3],
        dq_buff[4], dq_buff[5], dq_buff[6], dq_buff[7],
    };
    /* CRT coefficient */
    const int64u *pa_inv_q[MBX_NUM_BUFFERS] = {
        iq_buff[0], iq_buff[1], iq_buff[2], iq_buff[3],
        iq_buff[4], iq_buff[5], iq_buff[6], iq_buff[7],
    };

    /* Get RSA key info */
	EVP_PKEY *rsa = data->privkey;

    /* Get bignum components */
    BIGNUM *bn_n = BN_new();
    BIGNUM *bn_e = BN_new();
    BIGNUM *bn_d = BN_new();
    BIGNUM *bn_p = BN_new();
    BIGNUM *bn_q = BN_new();
    BIGNUM *bn_dp = BN_new();
    BIGNUM *bn_dq = BN_new();
    BIGNUM *bn_qinvp = BN_new();
    EVP_PKEY_get_bn_param(rsa, "n", &bn_n);
    EVP_PKEY_get_bn_param(rsa, "e", &bn_e);
    EVP_PKEY_get_bn_param(rsa, "d", &bn_d);
    EVP_PKEY_get_bn_param(rsa, "rsa-factor1", &bn_p);
    EVP_PKEY_get_bn_param(rsa, "rsa-factor2", &bn_q);
    EVP_PKEY_get_bn_param(rsa, "rsa-exponent1", &bn_dp);
    EVP_PKEY_get_bn_param(rsa, "rsa-exponent2", &bn_dq);
    EVP_PKEY_get_bn_param(rsa, "rsa-coefficient1", &bn_qinvp);

    /* Convert bignumms to strings */
    for(int i = 0; i < MBX_NUM_BUFFERS; i++) {
        BN_bn2bin(bn_d, (int8u*)(pa_d[i]));
        wsp_str((int8u*)(pa_d[i]), BN_num_bytes(bn_d));
        BN_bn2bin(bn_n, (int8u*)(pa_moduli[i]));
        wsp_str((int8u*)(pa_moduli[i]), BN_num_bytes(bn_n));

        BN_bn2bin(bn_e, (int8u*)(pa_e[i]));
        wsp_str((int8u*)(pa_e[i]), BN_num_bytes(bn_e));

        BN_bn2bin(bn_p, (int8u*)(pa_p[i]));
        wsp_str((int8u*)(pa_p[i]), BN_num_bytes(bn_p));
        BN_bn2bin(bn_q, (int8u*)(pa_q[i]));
        wsp_str((int8u*)(pa_q[i]), BN_num_bytes(bn_q));
        BN_bn2bin(bn_dp, (int8u*)(pa_dp[i]));
        wsp_str((int8u*)(pa_dp[i]), BN_num_bytes(bn_dp));
        BN_bn2bin(bn_dq, (int8u*)(pa_dq[i]));
        wsp_str((int8u*)(pa_dq[i]), BN_num_bytes(bn_dq));
        BN_bn2bin(bn_qinvp, (int8u*)(pa_inv_q[i]));
        wsp_str((int8u*)(pa_inv_q[i]), BN_num_bytes(bn_qinvp));
    }

    data->dec_result = 1;

    /* Check message and generated modulus */
    BIGNUM *bn_msg = BN_new();
    BN_bin2bn(data->msg.buf, data->msg.len, bn_msg);
    int cmp_bn_res = BN_cmp(bn_msg, bn_n);
    if(cmp_bn_res == 1){
        logger(LOGGER_WARN, "Error, message is bigger than modulus\n");
        data->dec_result = 0;
        goto out;
    }

    sts = mbx_rsa_private_crt_mb8(pa_ciphertext, pa_plaintext_crt, pa_p, pa_q,
                                  pa_dp, pa_dq, pa_inv_q, rsaBitsize,
                                  rsaMethodPrvCrt, rsaBufferPrvCrt);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_rsa_private_crt_mb8")

    sts = mbx_rsa_private_mb8(pa_ciphertext, pa_plaintext_basic,
                            (const int64u **)pa_d,
                            (const int64u **)pa_moduli,
                            rsaBitsize,
                            rsaMethodPrv, rsaBufferPrv);
    CKNULL_LOG((sts == MBX_STATUS_OK), sts, "Error in mbx_rsa_private_mb8")

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
    BN_free(bn_n);
    BN_free(bn_e);
    BN_free(bn_d);
    BN_free(bn_p);
    BN_free(bn_q);
    BN_free(bn_dp);
    BN_free(bn_dq);
    BN_free(bn_qinvp);

    BN_free(bn_msg);

    free(rsaBufferPrv);
    free(rsaBufferPrvCrt);

    return ret;
}

static struct rsa_backend cryptomb_rsa =
{
	NULL, /* rsa_keygen */
	NULL, /* rsa_siggen */
	NULL, /* rsa_sigver */
	NULL, /* rsa_keygen_prime */
	NULL, /* rsa_keygen_prov_prime */
	cryptomb_rsa_keygen_en,
	cryptomb_rsa_free_key,
	NULL,
	cryptomb_rsa_decryption_primitive,
};

ACVP_DEFINE_CONSTRUCTOR(cryptomb_rsa_backend)
static void cryptomb_rsa_backend(void)
{
	register_rsa_impl(&cryptomb_rsa);
}
