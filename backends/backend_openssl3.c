/*
 * Copyright 2021 VMware, Inc.
 *
 * License: see LICENSE file
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * The code uses the interface offered by OpenSSL-3
 */

#include "openssl_common.h"

/************************************************
 * General helper functions
 ************************************************/
static void openssl_dh_get0_key(const EVP_PKEY *r, BIGNUM **pub_key,
				BIGNUM **priv_key)
{
	EVP_PKEY_get_bn_param(r,OSSL_PKEY_PARAM_PRIV_KEY, priv_key);
	EVP_PKEY_get_bn_param(r,OSSL_PKEY_PARAM_PUB_KEY, pub_key);
}

/************************************************
 * KMAC cipher interface functions
 ************************************************/
static int openssl_kmac_generate(struct kmac_data *data, flags_t parsed_flags)
{
	EVP_MAC_CTX *ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM params[4], *p;
	int blocklen = (int) data->maclen/8;
	int ret =0;
	int xof_enabled =0;
	const char *algo;
	(void)parsed_flags;

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");

	convert_cipher_algo(data->cipher & ACVP_KMACMASK, ACVP_CIPHERTYPE_KMAC, &algo);

	mac = EVP_MAC_fetch(NULL, algo, NULL);
	CKNULL(mac, -EFAULT);
	ctx = EVP_MAC_CTX_new(mac);
	CKNULL(ctx, -EFAULT);
	if(mac)
		EVP_MAC_free(mac);

	p=params;
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, data->key.buf, data->key.len);
	if (data->customization.buf != NULL && data->customization.len != 0)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, data->customization.buf, data->customization.len);
	*p = OSSL_PARAM_construct_end();

	CKINT_O_LOG(EVP_MAC_CTX_set_params(ctx, params),
			"EVP_MAC_CTX_set_params failed\n");
	CKINT_O_LOG(EVP_MAC_init(ctx, NULL, 0, NULL),
			"EVP_MAC_init failed\n");

	xof_enabled =(int)data->xof_enabled;

	p = params;
	*p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &xof_enabled);
	*p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_SIZE, &blocklen);
	*p = OSSL_PARAM_construct_end();

	CKINT_O_LOG(EVP_MAC_CTX_set_params(ctx, params),
			"EVP_MAC_CTX_set_params failed\n");

	CKINT_O_LOG(EVP_MAC_update(ctx, data->msg.buf, data->msg.len),
			"EVP_MAC_update failed\n");
	CKINT_LOG(alloc_buf((size_t)blocklen, &data->mac),
			"KMAC buffer cannot be allocated\n");
	CKINT_O_LOG(EVP_MAC_final(ctx, data->mac.buf, &data->mac.len, blocklen),
			"EVP_MAC_final failed\n");

	logger(LOGGER_DEBUG, "taglen = %zu\n", data->mac.len);
	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "KMAC");
out:
	if(mac)
		EVP_MAC_free(mac);
	if(ctx)
		EVP_MAC_CTX_free(ctx);
	return 0;
}

static int openssl_kmac_ver(struct kmac_data *data, flags_t parsed_flags)
{
	EVP_MAC_CTX *ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM params[4], *p;
	BUFFER_INIT(kmac);
	int blocklen = (int) data->maclen/8;
	size_t maclen =0;
	int ret =0;
	int xof_enabled =0;
	const char *algo;
	(void)parsed_flags;

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");

	convert_cipher_algo(data->cipher & ACVP_KMACMASK, ACVP_CIPHERTYPE_KMAC, &algo);

	mac = EVP_MAC_fetch(NULL, algo, NULL);
	CKNULL(mac, -EFAULT);
	ctx = EVP_MAC_CTX_new(mac);
	CKNULL(ctx, -EFAULT);
	if(mac)
		EVP_MAC_free(mac);

	p=params;
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, data->key.buf, data->key.len);
	if (data->customization.buf != NULL && data->customization.len != 0)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM, data->customization.buf, data->customization.len);
	*p = OSSL_PARAM_construct_end();

	CKINT_O_LOG(EVP_MAC_CTX_set_params(ctx, params),
			"EVP_MAC_CTX_set_params failed\n");
	CKINT_O_LOG(EVP_MAC_init(ctx,NULL,0,NULL),
			"EVP_MAC_init failed\n");

	xof_enabled =(int)data->xof_enabled;

	p = params;
	*p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_XOF, &xof_enabled);
	*p++ = OSSL_PARAM_construct_int(OSSL_MAC_PARAM_SIZE, &blocklen);
	*p = OSSL_PARAM_construct_end();

	CKINT_O_LOG(EVP_MAC_CTX_set_params(ctx, params),
			"EVP_MAC_CTX_set_params failed\n");
	CKINT_O_LOG(EVP_MAC_update(ctx, data->msg.buf, data->msg.len),
			"EVP_MAC_update failed\n");
	CKINT_LOG(alloc_buf((size_t)blocklen, &kmac),
			"KMAC buffer cannot be allocated\n");
	CKINT_O_LOG(EVP_MAC_final(ctx, kmac.buf, &maclen, blocklen),
			"EVP_MAC_update failed\n");

	logger(LOGGER_DEBUG, "taglen = %zu\n", maclen);
	logger_binary(LOGGER_DEBUG, kmac.buf, maclen, "Generated KMAC");
	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "Input KMAC");

	if(memcmp(data->mac.buf,kmac.buf,data->mac.len))
		data->verify_result = 0;
	else
		data->verify_result = 1;

	logger(LOGGER_DEBUG, "Generated result= %" PRIu32 "\n",data->verify_result);

out:
	if(ctx)
		EVP_MAC_CTX_free(ctx);
	free_buf(&kmac);
	return 0;
}

static struct kmac_backend openssl_kmac =
{
	openssl_kmac_generate,
	openssl_kmac_ver
};

ACVP_DEFINE_CONSTRUCTOR(openssl_kmac_backend)
static void openssl_kmac_backend(void)
{
	register_kmac_impl(&openssl_kmac);
}

/************************************************
 * DH interface functions
 ************************************************/
static int openssl_dh_ss_common(uint64_t cipher,
				uint64_t safeprime,
				struct buffer *P,
				struct buffer *Q,
				struct buffer *G,
				struct buffer *Yrem,
				struct buffer *Xloc,
				struct buffer *Yloc,
				struct buffer *hashzz)
{
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *dctx = NULL;		/* Create a EVP_PKEY_CTX to perform key derivation */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *peerkey = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	OSSL_PARAM *params_peer = NULL;
	EVP_PKEY *genkey = NULL;
    EVP_PKEY_CTX *gctx = NULL;
	BIGNUM *p_bn = NULL, *q_bn = NULL,*g_bn = NULL;
	BIGNUM *bn_Yrem = NULL, *bn_Xloc = NULL, *bn_Yloc = NULL;
	BIGNUM *cbn_Xloc = NULL, *cbn_Yloc = NULL;
	BUFFER_INIT(ss);
	unsigned int localkey_consumed = 0;
	size_t keylen = 0;
	int ret = 0;
	(void) safeprime;

	bld = OSSL_PARAM_BLD_new();
	p_bn = BN_bin2bn((const unsigned char *)P->buf, (int)P->len, NULL);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p_bn);
	q_bn = BN_bin2bn((const unsigned char *)Q->buf, (int)Q->len, NULL);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q_bn);
	g_bn = BN_bin2bn((const unsigned char *)G->buf, (int)G->len, NULL);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g_bn);

	if (!Xloc->len || !Yloc->len) {
		pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
		CKNULL(pctx, -EFAULT);
		CKINT_O_LOG(EVP_PKEY_fromdata_init(pctx),
					"EVP_PKEY_fromdata_init failed\n");

		params = OSSL_PARAM_BLD_to_param(bld);
		CKINT_O_LOG(EVP_PKEY_fromdata(pctx, &genkey, EVP_PKEY_KEYPAIR, params),
					"EVP_PKEY_keygen failed\n");
		gctx = EVP_PKEY_CTX_new_from_pkey(NULL, genkey, NULL);
		CKNULL(gctx, -EFAULT);
		CKINT_O_LOG(EVP_PKEY_keygen_init(gctx),
					"EVP_PKEY_keygen_init failed\n");
		CKINT_O_LOG(EVP_PKEY_generate(gctx, &pkey),
					"EVP_PKEY_generate failed\n");

		openssl_dh_get0_key(pkey, &cbn_Yloc, &cbn_Xloc);
		CKINT(openssl_bn2buffer(cbn_Yloc, Yloc));
		logger_binary(LOGGER_DEBUG, Yloc->buf, Yloc->len,
			      "generated Yloc");
	} else {
		logger_binary(LOGGER_DEBUG, Xloc->buf, Xloc->len, "used Xloc");
		bn_Xloc = BN_bin2bn((const unsigned char *)Xloc->buf,
				    (int)Xloc->len, NULL);
		CKNULL_LOG(bn_Xloc, -ENOMEM, "BN_bin2bn() failed\n");
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, bn_Xloc);
		localkey_consumed = 1;
		params = OSSL_PARAM_BLD_to_param(bld);

		pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
		CKNULL(pctx, -EFAULT);
		CKINT_O_LOG(EVP_PKEY_fromdata_init(pctx),
					"EVP_PKEY_fromdata_init failed\n");
		EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params);
	}

	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P, p_bn);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q, q_bn);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G, g_bn);
	logger_binary(LOGGER_DEBUG, Yrem->buf, Yrem->len, "Yremote");
	bn_Yrem = BN_bin2bn((const unsigned char *)Yrem->buf, (int)Yrem->len, NULL);
	OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, bn_Yrem);
	params_peer = OSSL_PARAM_BLD_to_param(bld);

	pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	CKNULL(pctx, -EFAULT);
	CKINT_O_LOG(EVP_PKEY_fromdata_init(pctx),
			"EVP_PKEY_fromdata_init failed\n");
	CKINT_O_LOG(EVP_PKEY_fromdata(pctx, &peerkey, EVP_PKEY_PUBLIC_KEY, params_peer),
			"EVP_PKEY_fromdata failed\n");
	CKINT_LOG(alloc_buf(keylen, &ss), "Cannot allocate ss\n");

	/* Compute the shared secret */
	dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	CKNULL(dctx, -EFAULT);
	CKINT_O_LOG(EVP_PKEY_derive_init(dctx),
			"EVP_PKEY_derive_init failed\n");
	if(EVP_PKEY_derive_set_peer(dctx, peerkey)<0){
		ERR_print_errors_fp(stderr);
		goto out;
	}
	CKINT_O_LOG(EVP_PKEY_derive(dctx, NULL, &ss.len),
			"EVP_PKEY_derive failed\n");
	CKINT(alloc_buf(ss.len, &ss));
	if(EVP_PKEY_derive(dctx, ss.buf, &ss.len)<=0){
		ERR_print_errors_fp(stderr);
		goto out;
	}
	ret = openssl_hash_ss(cipher, &ss, hashzz);
	logger_binary(LOGGER_DEBUG, ss.buf, ss.len, "Generated shared secret");

	/* We do not use CKINT here, because -ENOENT is no real error */
out:
	if(pkey)
		EVP_PKEY_free(pkey);
	if(peerkey)
		EVP_PKEY_free(peerkey);
	if(pctx)
		EVP_PKEY_CTX_free(pctx);
	if(dctx)
		EVP_PKEY_CTX_free(dctx);
	if(params_peer)
		OSSL_PARAM_free(params_peer);
	if(params)
		OSSL_PARAM_free(params);
	if(bld)
		OSSL_PARAM_BLD_free(bld);
	if (bn_Yrem)
		BN_free(bn_Yrem);
	if (!localkey_consumed && bn_Xloc)
		BN_free(bn_Xloc);
	if (!localkey_consumed && bn_Yloc)
		BN_free(bn_Yloc);
	free_buf(&ss);
	return ret;
}

static int openssl_dh_ss(struct dh_ss_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

	return openssl_dh_ss_common(data->cipher, data->safeprime,
					&data->P, &data->Q, &data->G,
					&data->Yrem,
					&data->Xloc, &data->Yloc,
					&data->hashzz);
}

static int openssl_dh_ss_ver(struct dh_ss_ver_data *data,
			       flags_t parsed_flags)
{
	int ret = openssl_dh_ss_common(data->cipher, data->safeprime,
					&data->P, &data->Q,
					&data->G,
					&data->Yrem,
					&data->Xloc, &data->Yloc,
					&data->hashzz);

	(void)parsed_flags;

	if (ret == -EOPNOTSUPP || ret == -ENOENT) {
		data->validity_success = 0;
		logger(LOGGER_DEBUG, "DH validity test failed\n");
		return 0;
	} else if (!ret) {
		data->validity_success = 1;
		logger(LOGGER_DEBUG, "DH validity test passed\n");
		return 0;
	}

	logger(LOGGER_DEBUG, "DH validity test: general error\n");
	return ret;
}

static struct dh_backend openssl_dh =
{
	openssl_dh_ss,
	openssl_dh_ss_ver,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_dh_backend)
static void openssl_dh_backend(void)
{
	register_dh_impl(&openssl_dh);
}

/************************************************
 * ECDH cipher interface functions
 ************************************************/

static int openssl_ecdh_ss_common(uint64_t cipher,
		struct buffer *Qxrem, struct buffer *Qyrem,
		struct buffer *privloc,
		struct buffer *Qxloc, struct buffer *Qyloc,
		struct buffer *hashzz)
{
	int nid = 0, ret = 0;
	EVP_PKEY_CTX *kactx = NULL, *dctx = NULL;
	EVP_PKEY *pkey = NULL, *remotekey = NULL;
	OSSL_PARAM *params = NULL;
	OSSL_PARAM *params_remote = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	BUFFER_INIT(ss);
	BUFFER_INIT(publoc);
	BUFFER_INIT(pubrem);
	BIGNUM  *privloc_bn = NULL;
	char dgst[50];

	bld = OSSL_PARAM_BLD_new();

	CKINT_LOG(_openssl_ecdsa_curves(cipher, &nid , dgst),
			"Conversion of curve failed\n");
	const char *digest = dgst;
	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, digest, 0);
	OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, 1);
	if(Qxloc->len){
		CKINT(alloc_buf(Qxloc->len + Qyloc->len + 1, &publoc));
		publoc.buf[0]= POINT_CONVERSION_UNCOMPRESSED;
		memcpy(publoc.buf + 1, Qxloc->buf, Qxloc->len);
		memcpy(publoc.buf + 1 + Qxloc->len, Qyloc->buf, Qyloc->len);
		logger_binary(LOGGER_DEBUG, publoc.buf, publoc.len, "publoc");
		OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, publoc.buf,publoc.len);
	}
	if(privloc->len){
		privloc_bn = BN_bin2bn((const unsigned char *)privloc->buf, (int)privloc->len, NULL);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, privloc_bn);
	}
	params = OSSL_PARAM_BLD_to_param(bld);
	CKNULL_LOG(params, -ENOMEM, "bld to param failed\n");
	kactx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	CKNULL_LOG(kactx, -ENOMEM, "EVP_PKEY_CTX_new_from_name failed\n");
	CKINT_O_LOG(EVP_PKEY_fromdata_init(kactx),
				"EVP_PKEY_fromdata_init failed with status=%d\n", ret);

	if(!(Qxloc->len) && !(privloc->len)) {
		pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", digest);
		CKNULL_LOG(pkey, -EFAULT, "EVP_PKEY_Q_keygen failed\n");
	}
	else {
		CKINT_O_LOG(EVP_PKEY_fromdata(kactx, &pkey, EVP_PKEY_KEYPAIR, params),
					"EVP_PKEY_fromdata failed\n");
	}

	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
			digest, strlen(digest)+1);

	CKINT(alloc_buf(Qxrem->len + Qyrem->len + 1, &pubrem));
	pubrem.buf[0]= POINT_CONVERSION_UNCOMPRESSED;
	memcpy(pubrem.buf + 1, Qxrem->buf, Qxrem->len);
	memcpy(pubrem.buf + 1 + Qxrem->len, Qyrem->buf, Qyrem->len);

	logger_binary(LOGGER_DEBUG, Qxrem->buf, Qxrem->len, "Qxrem");
	logger_binary(LOGGER_DEBUG, Qyrem->buf, Qyrem->len, "Qyrem");
	logger_binary(LOGGER_DEBUG, pubrem.buf, pubrem.len, "pubrem");

	OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
			pubrem.buf,pubrem.len);

	params_remote = OSSL_PARAM_BLD_to_param(bld);
	CKNULL_LOG(params_remote, -ENOMEM, "bld to param failed\n");
	kactx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	CKNULL_LOG(kactx, -ENOMEM, "EVP_PKEY_CTX_new_from_name failed\n");

	CKINT_O_LOG(EVP_PKEY_fromdata_init(kactx),
				"EVP_PKEY_fromdata_init failed\n");
	CKINT_O_LOG(EVP_PKEY_fromdata(kactx, &remotekey, EVP_PKEY_PUBLIC_KEY,
			params_remote), "EVP_PKEY_fromdata failed\n");
	dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	CKNULL_LOG(dctx, -ENOMEM, "EVP_PKEY_CTX_new_from_pkey failed\n");

	ret = EVP_PKEY_derive_init(dctx);
	if(ret <= 0) {
		logger(LOGGER_ERR, "EVP_PKEY_derive_init filed: %d\n", ret);
		goto out;
	}
	ret = EVP_PKEY_derive_set_peer(dctx, remotekey);
	if(ret <= 0) {
		logger(LOGGER_ERR, "EVP_PKEY_derive_set_peer filed: %d\n", ret);
		goto out;
	}
	ret = EVP_PKEY_derive(dctx, NULL, &ss.len);
	if(ret <= 0) {
		logger(LOGGER_ERR, "EVP_PKEY_derive filed: %d\n", ret);
		goto out;
	}
	CKINT(alloc_buf(ss.len, &ss));
	ret = EVP_PKEY_derive(dctx, ss.buf, &ss.len);
	if(ret <= 0) {
		logger(LOGGER_ERR, "EVP_PKEY_derive filed: %d\n", ret);
		goto out;
	}
	logger_binary(LOGGER_DEBUG, ss.buf, ss.len, "Generated shared secret");

	/* We do not use CKINT here, because -ENOENT is no real error */
	ret = openssl_hash_ss(cipher, &ss, hashzz);
out:
	if(pkey)
		EVP_PKEY_free(pkey);
	if(remotekey)
		EVP_PKEY_free(remotekey);
	if(kactx)
		EVP_PKEY_CTX_free(kactx);
	if(dctx)
		EVP_PKEY_CTX_free(dctx);
	if(params_remote)
		OSSL_PARAM_free(params_remote);
	if(params)
		OSSL_PARAM_free(params);
	if(bld)
		OSSL_PARAM_BLD_free(bld);
	if(privloc_bn)
		BN_free(privloc_bn);
	free_buf(&ss);
	free_buf(&publoc);
	free_buf(&pubrem);
	return ret;
}

static int openssl_ecdh_ss(struct ecdh_ss_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

	return openssl_ecdh_ss_common(data->cipher, &data->Qxrem, &data->Qyrem,
			&data->privloc,
			&data->Qxloc, &data->Qyloc,
			&data->hashzz);
}

static int openssl_ecdh_ss_ver(struct ecdh_ss_ver_data *data,
		flags_t parsed_flags)
{
	int ret = openssl_ecdh_ss_common(data->cipher, &data->Qxrem,
			&data->Qyrem,
			&data->privloc,
			&data->Qxloc, &data->Qyloc,
			&data->hashzz);

	(void)parsed_flags;

	if (ret == -EOPNOTSUPP || ret == -ENOENT) {
		data->validity_success = 0;
		logger(LOGGER_DEBUG, "ECDH validity test failed\n");
		return 0;
	} else if (!ret) {
		data->validity_success = 1;
		logger(LOGGER_DEBUG, "ECDH validity test passed\n");
		return 0;
	}
	logger(LOGGER_DEBUG, "ECDH validity test: general error\n");
	return ret;
}

static struct ecdh_backend openssl_ecdh =
{
	openssl_ecdh_ss,
	openssl_ecdh_ss_ver,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_ecdh_backend)
static void openssl_ecdh_backend(void)
{
	register_ecdh_impl(&openssl_ecdh);
}
