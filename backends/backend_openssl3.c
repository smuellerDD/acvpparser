/*
 * Copyright 2021 VMware, Inc.
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include "backend_openssl_common.h"
#include <openssl/provider.h>

OSSL_PROVIDER *fips;
OSSL_PROVIDER *base;

ACVP_DEFINE_CONSTRUCTOR(openssl_backend_init)
static void openssl_backend_init(void)
{
	/* Explicitly load the FIPS provider as per fips_module(7) */
	fips = OSSL_PROVIDER_load(NULL, "fips");
	if (fips == NULL) {
		printf("Failed to load FIPS provider\n");
		exit(-EFAULT);
	}
	base = OSSL_PROVIDER_load(NULL, "base");
	if (base == NULL) {
		OSSL_PROVIDER_unload(fips);
		printf("Failed to load base provider\n");
		exit(-EFAULT);
	}
}

ACVP_DEFINE_DESTRUCTOR(openssl_backend_fini)
static void openssl_backend_fini(void)
{
	#pragma message "Deliberate memleak required for OpenSSL 3 - OpenSSL cleans itself using atexit"
	//OSSL_PROVIDER_unload(base);
	//OSSL_PROVIDER_unload(fips);
}

/************************************************
 * General helper functions
 ************************************************/
static int openssl_pkey_get_bn_bytes(EVP_PKEY *pkey, const char *name,
				     struct buffer *out)
{
	BIGNUM *bn = NULL;
	size_t len;
	int ret = 0;

	CKNULL(EVP_PKEY_get_bn_param(pkey, name, &bn), -EINVAL);
	len = BN_num_bytes(bn);
	CKINT(alloc_buf(len, out));
	CKNULL(BN_bn2binpad(bn, out->buf, len), -EINVAL);

out:
	if (bn)
		BN_free(bn);
	return ret;
}

static int openssl_pkey_get_octet_bytes(EVP_PKEY *pkey, const char *name,
					struct buffer *out)
{
	size_t len;
	int ret = 0;

	CKNULL(EVP_PKEY_get_octet_string_param(pkey, name, NULL, 0, &len),
	       -EFAULT);
	CKINT(alloc_buf(len, out));
	CKNULL(EVP_PKEY_get_octet_string_param(pkey, name, out->buf, len,
					       &out->len), -EFAULT);

out:
	return ret;
}

static int openssl_set_rsa_padding(EVP_PKEY_CTX *pkey_ctx, flags_t parsed_flags,
				   uint32_t saltlen)
{
	int ret = 0;

	if (parsed_flags & FLAG_OP_RSA_SIG_PKCS15) {
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
							 RSA_PKCS1_PADDING),
			    "EVP_PKEY_CTX_set_rsa_padding failed\n");
	}
	if (parsed_flags & FLAG_OP_RSA_SIG_X931) {
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
							 RSA_X931_PADDING),
			    "EVP_PKEY_CTX_set_rsa_padding failed\n");
	}
	if (parsed_flags & FLAG_OP_RSA_SIG_PKCS1PSS) {
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
							 RSA_PKCS1_PSS_PADDING),
			    "EVP_PKEY_CTX_set_rsa_padding failed\n");
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen),
			    "EVP_PKEY_CTX_set_rsa_pss_saltlen failed\n");
	}

out:
	return ret;
}

static int openssl_sig_gen(EVP_PKEY *pkey, const EVP_MD *md,
			   flags_t parsed_flags, uint32_t saltlen,
			   struct buffer *msg, struct buffer *sig)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	size_t sz = EVP_PKEY_size(pkey);
	CKINT(alloc_buf(sz, sig));

	if (md) {
		md_ctx = EVP_MD_CTX_new();
		CKNULL(md_ctx, -EFAULT);

		CKINT_O(EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey));

		CKINT(openssl_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(md_ctx),
					      parsed_flags, saltlen));

		CKINT_O(EVP_DigestSign(md_ctx, sig->buf, &sig->len, msg->buf,
				       msg->len));
	} else {
		pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
		CKNULL(pkey_ctx, -EFAULT);

		CKINT_O(EVP_PKEY_sign_init(pkey_ctx));

		CKINT(openssl_set_rsa_padding(pkey_ctx, parsed_flags, saltlen));

		CKINT_O(EVP_PKEY_sign(pkey_ctx, sig->buf, &sig->len, msg->buf,
				      msg->len));
	}

out:
	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);
	if (pkey_ctx)
		EVP_PKEY_CTX_free(pkey_ctx);
	return ret;
}

static int openssl_sig_ver(EVP_PKEY *pkey, const EVP_MD *md,
			   flags_t parsed_flags, uint32_t saltlen,
			   struct buffer *msg, struct buffer *sig,
			   uint32_t *sig_result)
{
	int ret = 0;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;

	if (md) {
		md_ctx = EVP_MD_CTX_new();
		CKNULL(md_ctx, -EFAULT);

		CKINT_O(EVP_DigestVerifyInit_ex(md_ctx, NULL, EVP_MD_name(md),
						NULL, NULL, pkey, NULL));

		CKINT(openssl_set_rsa_padding(EVP_MD_CTX_get_pkey_ctx(md_ctx),
					      parsed_flags, saltlen));

		ret = EVP_DigestVerify(md_ctx, sig->buf, sig->len, msg->buf,
				       msg->len);
	} else {
		pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
		CKNULL(pkey_ctx, -EFAULT);

		CKINT_O(EVP_PKEY_verify_init(pkey_ctx));

		CKINT(openssl_set_rsa_padding(pkey_ctx, parsed_flags, saltlen));

		ret = EVP_PKEY_verify(pkey_ctx, sig->buf, sig->len, msg->buf,
				      msg->len);
	}

	if (!ret) {
		logger(LOGGER_DEBUG, "Signature verification: signature bad\n");
		*sig_result = 0;
	} else if (ret == 1) {
		logger(LOGGER_DEBUG,
			"Signature verification: signature good\n");
		*sig_result = 1;
		ret = 0;
	} else {
		logger(LOGGER_WARN, "Signature verification: general error\n");
		ret = -EFAULT;
	}

out:
	if (md_ctx)
		EVP_MD_CTX_free(md_ctx);
	if (pkey_ctx)
		EVP_PKEY_CTX_free(pkey_ctx);
	return ret;
}

static int openssl_get_safeprime_group(uint64_t safeprime, const char **group)
{
	int ret = 0;

	switch (safeprime) {
	case ACVP_DH_MODP_2048:
		*group = "modp_2048";
		break;
	case ACVP_DH_MODP_3072:
		*group = "modp_3072";
		break;
	case ACVP_DH_MODP_4096:
		*group = "modp_4096";
		break;
	case ACVP_DH_MODP_6144:
		*group = "modp_6144";
		break;
	case ACVP_DH_MODP_8192:
		*group = "modp_8192";
		break;
	case ACVP_DH_FFDHE_2048:
		*group = "ffdhe2048";
		break;
	case ACVP_DH_FFDHE_3072:
		*group = "ffdhe3072";
		break;
	case ACVP_DH_FFDHE_4096:
		*group = "ffdhe4096";
		break;
	case ACVP_DH_FFDHE_6144:
		*group = "ffdhe6144";
		break;
	case ACVP_DH_FFDHE_8192:
		*group = "ffdhe8192";
		break;
	default:
		logger(LOGGER_ERR,
		       "Unknown safeprime group\n");
		ret = -EFAULT;
		goto out;
	}
out:
	return ret;
}

static int openssl_ffc_create_pkey(EVP_PKEY **key,
				   int validate_pq, int validate_g,
				   struct buffer *p, struct buffer *q,
				   struct buffer *g, uint64_t safeprime,
				   struct buffer *x, struct buffer *y,
				   struct buffer *seed, struct buffer *index,
				   struct buffer *h, uint32_t counter,
				   const EVP_MD *md, const char *ctx_name)
{
	int ret = 0;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	const char *group;
	BIGNUM *p_bn = NULL, *q_bn = NULL, *g_bn = NULL;
	BIGNUM *x_bn = NULL, *y_bn = NULL;
	BUFFER_INIT(hex);

	bld = OSSL_PARAM_BLD_new();

	CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ,
					validate_pq));
	CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_VALIDATE_G,
					validate_g));

	if (p && p->len && q && q->len) {
		p_bn = BN_new();
		BN_bin2bn(p->buf, p->len, p_bn);
		CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_P,
					       p_bn));
		q_bn = BN_new();
		BN_bin2bn(q->buf, q->len, q_bn);
		CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_Q,
					       q_bn));
	} else {
		CKINT(openssl_get_safeprime_group(safeprime, &group));
		OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
						(char *)group, 0);
	}

	if (g && g->len) {
		g_bn = BN_new();
		BN_bin2bn(g->buf, g->len, g_bn);
		CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_FFC_G,
					       g_bn));
	}

	if (seed && seed->len) {
		CKINT_O(OSSL_PARAM_BLD_push_octet_string(bld,
							 OSSL_PKEY_PARAM_FFC_SEED,
							 seed->buf, seed->len));
	}

	if (index && index->len) {
		bin2hex_alloc(index->buf, index->len, (char **)&hex.buf,
			      &hex.len);
		int number = (int)strtol((const char *)hex.buf, NULL, 16);
		CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_GINDEX,
						number));
		free_buf(&hex);
	}

	if (h && h->len) {
		int number = (int)strtol((const char *)h->buf, NULL, 10);
		CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_H,
						number));
	}

	CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_PCOUNTER,
					counter));

	if (x && x->len) {
		x_bn = BN_new();
		BN_bin2bn(x->buf, x->len, x_bn);
		CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
					       x_bn));
	}

	if (y && y->len) {
		y_bn = BN_new();
		BN_bin2bn(y->buf, y->len, y_bn);
		CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY,
					       y_bn));
	}

	if (md) {
		CKINT_O(OSSL_PARAM_BLD_push_utf8_string(bld,
							OSSL_PKEY_PARAM_FFC_DIGEST,
							EVP_MD_name(md), 0));
	}

	params = OSSL_PARAM_BLD_to_param(bld);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, ctx_name, NULL);
	CKNULL(ctx, -EFAULT);
	CKINT_O(EVP_PKEY_fromdata_init(ctx));
	CKINT_O(EVP_PKEY_fromdata(ctx, key, EVP_PKEY_KEYPAIR, params));

out:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (params)
		OSSL_PARAM_free(params);
	if (p_bn)
		BN_free(p_bn);
	if (q_bn)
		BN_free(q_bn);
	if (g_bn)
		BN_free(g_bn);
	if (x_bn)
		BN_free(x_bn);
	if (y_bn)
		BN_free(y_bn);
	return ret;
}

/************************************************
 * CMAC/HMAC cipher interface functions
 ************************************************/
static int openssl_mac_generate_helper(struct hmac_data *data, char *mac_algo,
				       char *param_name, char *param_val)
{
	EVP_MAC_CTX *ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM params[3], *p;
	int ret = 0;

	mac = EVP_MAC_fetch(NULL, mac_algo, NULL);
	CKNULL(mac, -EFAULT);
	ctx = EVP_MAC_CTX_new(mac);
	CKNULL(ctx, -EFAULT);

	p = params;
	// OpenSSL wants us to use the cipher name here...
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY, data->key.buf, data->key.len);
	*p++ = OSSL_PARAM_construct_utf8_string(param_name, param_val, 0);
	*p = OSSL_PARAM_construct_end();

	CKINT_O_LOG(EVP_MAC_CTX_set_params(ctx, params),
			"EVP_MAC_CTX_set_params failed\n");
	CKINT_O_LOG(EVP_MAC_init(ctx, NULL, 0, NULL),
			"EVP_MAC_init failed\n");

	CKINT_O_LOG(EVP_MAC_update(ctx, data->msg.buf, data->msg.len),
			"EVP_MAC_update failed\n");
	CKINT_LOG(alloc_buf((size_t)EVP_MAC_CTX_get_mac_size(ctx), &data->mac),
			"%s buffer cannot be allocated\n", mac_algo);
	CKINT_O_LOG(EVP_MAC_final(ctx, data->mac.buf, &data->mac.len, data->mac.len),
			"EVP_MAC_final failed\n");

	logger(LOGGER_DEBUG, "taglen = %zu\n", data->mac.len);
	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, mac_algo);

	ret = 0;

out:
	if (mac)
		EVP_MAC_free(mac);
	if (ctx)
		EVP_MAC_CTX_free(ctx);
	return ret;
}

static int openssl_cmac_generate(struct hmac_data *data)
{
	const EVP_CIPHER *type = NULL;
	int ret = 0;

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	if (openssl_mac_generate_helper(data, "CMAC", OSSL_MAC_PARAM_CIPHER,
		(char *)EVP_CIPHER_name(type)))
	{
		ret = -EFAULT;
		goto out;
	}

	// Truncate to desired macLen, which is in bits
	if (data->mac.len > data->maclen / 8) {
		data->mac.buf[data->maclen / 8] = '\0';
		data->mac.len = data->maclen / 8;
		logger(LOGGER_DEBUG, "Truncated mac to maclen: %d\n", data->maclen);
		logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "mac");
	}

	ret = 0;

out:
	return ret;
}

static int openssl_hmac_generate(struct hmac_data *data)
{
	const EVP_MD *md = NULL;
	int ret = 0;

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");

	CKINT(openssl_md_convert(data->cipher, &md));

	if (openssl_mac_generate_helper(data, "HMAC", OSSL_MAC_PARAM_DIGEST,
		(char *)EVP_MD_name(md)))
	{
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	return ret;
}

static int openssl_mac_generate(struct hmac_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

	switch(data->cipher) {
	case ACVP_AESCMAC:
	case ACVP_TDESCMAC:
		return openssl_cmac_generate(data);
		break;
	default:
		return openssl_hmac_generate(data);
		break;
	}

	return -EFAULT;
}

static struct hmac_backend openssl_mac =
{
	openssl_mac_generate,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_mac_backend)
static void openssl_mac_backend(void)
{
	register_hmac_impl(&openssl_mac);
}

/************************************************
 * KMAC cipher interface functions
 ************************************************/
static int openssl_kmac_generate(struct kmac_data *data, flags_t parsed_flags)
{
	EVP_MAC_CTX *ctx = NULL;
	EVP_MAC *mac = NULL;
	OSSL_PARAM params[4], *p;
	int blocklen = (int) data->maclen / 8;
	int ret = 0;
	int xof_enabled = 0;
	const char *algo;

	(void)parsed_flags;

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");

	convert_cipher_algo(data->cipher & ACVP_KMACMASK, ACVP_CIPHERTYPE_KMAC,
			    &algo);

	mac = EVP_MAC_fetch(NULL, algo, NULL);
	CKNULL(mac, -EFAULT);
	ctx = EVP_MAC_CTX_new(mac);
	CKNULL(ctx, -EFAULT);

	p = params;
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_KEY,
						 data->key.buf, data->key.len);
	if (data->customization.buf != NULL && data->customization.len != 0)
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_MAC_PARAM_CUSTOM,
							 data->customization.buf,
							 data->customization.len);
	*p = OSSL_PARAM_construct_end();

	CKINT_O_LOG(EVP_MAC_CTX_set_params(ctx, params),
		    "EVP_MAC_CTX_set_params failed\n");
	CKINT_O_LOG(EVP_MAC_init(ctx, NULL, 0, NULL), "EVP_MAC_init failed\n");

	xof_enabled = (int)data->xof_enabled;

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
	if (mac)
		EVP_MAC_free(mac);
	if (ctx)
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
static int _openssl_dh_keygen(uint64_t safeprime, EVP_PKEY **key)
{
	int ret = 0;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM params[2];
	const char *group;

	CKINT(openssl_get_safeprime_group(safeprime, &group));

	params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
						     (char *)group, 0);
	params[1] = OSSL_PARAM_construct_end();

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
	CKNULL(ctx, -EFAULT);
	CKINT_O(EVP_PKEY_keygen_init(ctx));
	CKINT_O(EVP_PKEY_CTX_set_params(ctx, params));
	CKINT_O(EVP_PKEY_keygen(ctx, key));

out:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

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
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *peerkey = NULL;
	EVP_PKEY_CTX *pctx = NULL;
	EVP_PKEY_CTX *dctx = NULL;
	BUFFER_INIT(ss);
	size_t keylen = 0;
	int ret = 0;

	if (!Xloc->len || !Yloc->len) {
		CKINT(openssl_ffc_create_pkey(&pkey, 0, 0, P, Q, G, safeprime,
					      NULL, NULL, NULL, NULL, NULL, 0,
					      NULL, "DH"));

		pctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
		CKNULL(pctx, -EFAULT);
		CKINT_O_LOG(EVP_PKEY_keygen_init(pctx),
			    "EVP_PKEY_keygen_init failed\n");
		CKINT_O_LOG(EVP_PKEY_generate(pctx, &pkey),
			    "EVP_PKEY_generate failed\n");

		CKINT(openssl_pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_PUB_KEY,
						Yloc));
	} else {
		CKINT(openssl_ffc_create_pkey(&pkey, 0, 0, P, Q, G, safeprime,
					      Xloc, Yloc, NULL, NULL, NULL, 0,
					      NULL, "DH"));
	}

	CKINT(openssl_ffc_create_pkey(&peerkey, 0, 0, P, Q, G, safeprime,
				      NULL, Yrem, NULL, NULL, NULL, 0,
				      NULL, "DH"));

	/* Compute the shared secret */
	dctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	CKNULL(dctx, -EFAULT);
	CKINT_O_LOG(EVP_PKEY_derive_init(dctx), "EVP_PKEY_derive_init failed\n");
	CKINT_O_LOG(EVP_PKEY_derive_set_peer(dctx, peerkey),
		    "EVP_PKEY_derive_set_peer failed\n");
	CKINT_O_LOG(EVP_PKEY_derive(dctx, NULL, &keylen),
		    "EVP_PKEY_derive failed\n");
	CKINT(alloc_buf(keylen, &ss));
	CKINT_O_LOG(EVP_PKEY_derive(dctx, ss.buf, &keylen),
		    "EVP_PKEY_derive failed\n");

	/* We do not use CKINT here, because -ENOENT is no real error */
	ret = openssl_hash_ss(cipher, &ss, hashzz);
	logger_binary(LOGGER_DEBUG, ss.buf, ss.len, "Generated shared secret");

out:
	ERR_print_errors_fp(stderr);
	if(pkey)
		EVP_PKEY_free(pkey);
	if(peerkey)
		EVP_PKEY_free(peerkey);
	if(pctx)
		EVP_PKEY_CTX_free(pctx);
	if(dctx)
		EVP_PKEY_CTX_free(dctx);
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

static int openssl_dh_keygen(struct dh_keygen_data *data,
			     flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	int ret = 0;

	(void)parsed_flags;

	CKINT(_openssl_dh_keygen(data->safeprime, &key));

	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_PRIV_KEY,
					&data->X));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_PUB_KEY,
					&data->Y));

	logger_binary(LOGGER_DEBUG, data->X.buf, data->X.len, "X");
	logger_binary(LOGGER_DEBUG, data->Y.buf, data->Y.len, "Y");

out:
	if (key)
		EVP_PKEY_free(key);
	return ret;
}

static int openssl_dh_keyver(struct dh_keyver_data *data,
			     flags_t parsed_flags){
	int ret = 0;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *key = NULL;

	(void) parsed_flags;

	if (openssl_ffc_create_pkey(&key, 0, 0, NULL, NULL, NULL,
				    data->safeprime, &data->X, &data->Y, NULL,
				    NULL, NULL, 0, NULL, "DH") <= 0) {
		data->keyver_success = 0;
	}

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "fips=yes");
	CKNULL(ctx, -EFAULT);

	if (EVP_PKEY_check(ctx) > 0) {
		data->keyver_success = 1;
	} else {
		data->keyver_success = 0;
	}

	ret = 0;

out:
	if (key)
		EVP_PKEY_free(key);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

static struct dh_backend openssl_dh =
{
	openssl_dh_ss,
	openssl_dh_ss_ver,
	openssl_dh_keygen,
	openssl_dh_keyver,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_dh_backend)
static void openssl_dh_backend(void)
{
	register_dh_impl(&openssl_dh);
}

/************************************************
 * ECDH cipher interface functions
 ************************************************/

static int
openssl_ecdh_ss_common(uint64_t cipher,
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
	char *curve_name;

	bld = OSSL_PARAM_BLD_new();

	CKINT_LOG(_openssl_ecdsa_curves(cipher, &nid, &curve_name),
			"Conversion of curve failed\n");
	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					curve_name, 0);
	OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, 1);
	if (Qxloc->len && Qyloc->len) {
		CKINT(alloc_buf(Qxloc->len + Qyloc->len + 1, &publoc));
		publoc.buf[0]= POINT_CONVERSION_UNCOMPRESSED;
		memcpy(publoc.buf + 1, Qxloc->buf, Qxloc->len);
		memcpy(publoc.buf + 1 + Qxloc->len, Qyloc->buf, Qyloc->len);
		logger_binary(LOGGER_DEBUG, publoc.buf, publoc.len, "publoc");
		OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
						 publoc.buf,publoc.len);
	}
	if (privloc->len) {
		privloc_bn = BN_bin2bn((const unsigned char *)privloc->buf,
				       (int)privloc->len, NULL);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, privloc_bn);
	}
	params = OSSL_PARAM_BLD_to_param(bld);
	CKNULL_LOG(params, -ENOMEM, "bld to param failed\n");
	kactx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	CKNULL_LOG(kactx, -ENOMEM, "EVP_PKEY_CTX_new_from_name failed\n");
	CKINT_O_LOG(EVP_PKEY_fromdata_init(kactx),
		    "EVP_PKEY_fromdata_init failed with status=%d\n", ret);

	if(!(privloc->len && Qxloc->len && Qyloc->len)) {
		pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve_name);
		CKNULL_LOG(pkey, -EFAULT, "EVP_PKEY_Q_keygen failed\n");

		CKINT(openssl_pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
						privloc));
		CKINT(openssl_pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_EC_PUB_X,
						Qxloc));
		CKINT(openssl_pkey_get_bn_bytes(pkey, OSSL_PKEY_PARAM_EC_PUB_Y,
						Qyloc));
	} else {
		CKINT_O_LOG(EVP_PKEY_fromdata(kactx, &pkey, EVP_PKEY_KEYPAIR,
					      params),
					      "EVP_PKEY_fromdata failed\n");
	}

	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					curve_name, strlen(curve_name) + 1);

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
				      &data->privloc, &data->Qxloc,
				      &data->Qyloc, &data->hashzz);
}

static int openssl_ecdh_ss_ver(struct ecdh_ss_ver_data *data,
		flags_t parsed_flags)
{
	(void)parsed_flags;

	int ret = openssl_ecdh_ss_common(data->cipher, &data->Qxrem,
					 &data->Qyrem, &data->privloc,
					 &data->Qxloc, &data->Qyloc,
					 &data->hashzz);

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

/************************************************
 * DRBG cipher interface functions
 ************************************************/
static int openssl_get_drbg_name(struct drbg_data *data, char *cipher,
		char *drbg_name)
{
	logger(LOGGER_DEBUG, "cipher: %" PRIu64 "\n", data->cipher);
	if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA1) {
		strcpy(cipher, "SHA1");
		strcpy(drbg_name, ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				"HMAC-DRBG" : "HASH-DRBG");
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA224) {
		strcpy(cipher,  "SHA224");
		strcpy(drbg_name, ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				"HMAC-DRBG" : "HASH-DRBG");
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA256) {
		strcpy(cipher, "SHA256");
		strcpy(drbg_name, ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				"HMAC-DRBG" : "HASH-DRBG");
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA384) {
		strcpy(cipher,  "SHA384");
		strcpy(drbg_name, ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				"HMAC-DRBG" : "HASH-DRBG");
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA512224) {
		strcpy(cipher,  "SHA512-224");
		strcpy(drbg_name, ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				"HMAC-DRBG" : "HASH-DRBG");
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA512256) {
		strcpy(cipher, "SHA512-256");
		strcpy(drbg_name, ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				"HMAC-DRBG" : "HASH-DRBG");
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA512) {
		strcpy(cipher,  "SHA512");
		strcpy(drbg_name, ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				"HMAC-DRBG" : "HASH-DRBG");
	} else if ((data->cipher & ACVP_AESMASK) == ACVP_AES128) {
		strcpy(cipher, "AES-128-CTR");
		strcpy(drbg_name, "CTR-DRBG");
	} else if ((data->cipher & ACVP_AESMASK) == ACVP_AES192) {
		strcpy(cipher, "AES-192-CTR");
		strcpy(drbg_name, "CTR-DRBG");
	} else if ((data->cipher & ACVP_AESMASK) == ACVP_AES256) {
		strcpy(cipher, "AES-256-CTR");
		strcpy(drbg_name, "CTR-DRBG");
	} else {
		logger(LOGGER_WARN, "DRBG with unhandled cipher detected\n");
		return -EFAULT;
	}
	return 0;
}

static int openssl_drbg_generate(struct drbg_data *data, flags_t parsed_flags)
{

	OSSL_PARAM params[4];
	char cipher[50];
	char drbg_name[50];
	EVP_RAND *rand = NULL;
	EVP_RAND_CTX *ctx = NULL, *parent = NULL;
	int df = 0;
	int ret = 0;
	unsigned int strength = 256;
	unsigned char *z;
	int res = 0;
	(void)parsed_flags;

	if (openssl_get_drbg_name(data, cipher, drbg_name) < 0)
		goto out;
	df = !!data->df;

	/* Create the seed source */
	rand = EVP_RAND_fetch(NULL, "TEST-RAND", "-fips");
	CKNULL(rand, -ENOMEM);
	parent = EVP_RAND_CTX_new(rand, NULL);
	CKNULL(parent, -ENOMEM);
	EVP_RAND_free(rand);
	rand = NULL;

	params[0] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
	params[1] = OSSL_PARAM_construct_end();
	CKINT(EVP_RAND_CTX_set_params(parent, params));
	/* Get the DRBG */
	rand = EVP_RAND_fetch(NULL, drbg_name, NULL);
	CKNULL(rand, -ENOMEM);
	ctx = EVP_RAND_CTX_new(rand, parent);
	CKNULL(ctx, -ENOMEM);
	/* Set the DRBG up */
	strength = EVP_RAND_get_strength(ctx);
	params[0] = OSSL_PARAM_construct_int(OSSL_DRBG_PARAM_USE_DF,
			(int *)(&df));
	if(!strcmp(drbg_name,"CTR-DRBG")){
		params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_CIPHER,
				(char *)cipher, 0);
	}
	else {
		params[1] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_DIGEST,
				(char *)cipher, strlen(cipher));
	}

	params[2] = OSSL_PARAM_construct_utf8_string(OSSL_DRBG_PARAM_MAC, "HMAC", 0);
	params[3] = OSSL_PARAM_construct_end();

	CKINT(EVP_RAND_CTX_set_params(ctx, params));
	/* Feed in the entropy and nonce */
	logger_binary(LOGGER_DEBUG, data->entropy.buf, data->entropy.len, "entropy");
	logger_binary(LOGGER_DEBUG, data->nonce.buf, data->nonce.len, "nonce");

	params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
			(void *)data->entropy.buf,
			data->entropy.len);
	params[1] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_NONCE,
			(void *)data->nonce.buf,
			data->nonce.len);
	params[2] = OSSL_PARAM_construct_end();

	if (!EVP_RAND_instantiate(parent, strength, 0, NULL, 0, params)) {
		EVP_RAND_CTX_free(ctx);
		goto out;
	}
	/*
	 * Run the test
	 * A NULL personalisation string defaults to the built in so something
	 * non-NULL is needed if there is no personalisation string
	 */
	logger_binary(LOGGER_DEBUG, data->pers.buf, data->pers.len,
			"personalization string");

	z = data->pers.buf != NULL ? data->pers.buf : (unsigned char *)"";
	if (!EVP_RAND_instantiate(ctx, strength, data->pr, z, data->pers.len, NULL)) {
		logger(LOGGER_DEBUG, "DRBG instantiation failed: %s\n",
				ERR_error_string(ERR_get_error(), NULL));
		EVP_RAND_CTX_free(ctx);
		goto out;
	}

	if (data->entropy_reseed.buffers[0].len) {
		logger_binary(LOGGER_DEBUG,
				data->entropy_reseed.buffers[0].buf,
				data->entropy_reseed.buffers[0].len,
				"entropy reseed");

		params[0] = OSSL_PARAM_construct_octet_string
			(OSSL_RAND_PARAM_TEST_ENTROPY, data->entropy_reseed.buffers[0].buf,
			 data->entropy_reseed.buffers[0].len);
		params[1] = OSSL_PARAM_construct_end();
		CKINT(EVP_RAND_CTX_set_params(parent, params));
		if (data->addtl_reseed.buffers[0].len) {
			logger_binary(LOGGER_DEBUG,
					data->addtl_reseed.buffers[0].buf,
					data->addtl_reseed.buffers[0].len,
					"addtl reseed");
		}
		CKINT_O(EVP_RAND_reseed(ctx,data->pr,
					NULL, 0,
					data->addtl_reseed.buffers[0].buf,
					data->addtl_reseed.buffers[0].len));
	}
	if (data->entropy_generate.buffers[0].len) {
		logger_binary(LOGGER_DEBUG,
				data->entropy_generate.buffers[0].buf,
				data->entropy_generate.buffers[0].len,
				"entropy generate 1");
		params[0] = OSSL_PARAM_construct_octet_string
			(OSSL_RAND_PARAM_TEST_ENTROPY,
			 data->entropy_generate.buffers[0].buf,
			 data->entropy_generate.buffers[0].len);
		params[1] = OSSL_PARAM_construct_end();
		CKINT(EVP_RAND_CTX_set_params(parent, params));
	}

	logger_binary(LOGGER_DEBUG, data->addtl_generate.buffers[0].buf,
			data->addtl_generate.buffers[0].len, "addtl generate 1");
	CKINT(alloc_buf(data->rnd_data_bits_len / 8, &data->random));
	CKINT_O_LOG(EVP_RAND_generate(ctx, data->random.buf, data->random.len, strength,
				data->entropy_generate.buffers[0].len?1:0,
				data->addtl_generate.buffers[0].buf,
				data->addtl_generate.buffers[0].len),
			"FIPS_drbg_generate failed\n");
	logger_binary(LOGGER_DEBUG, data->random.buf, data->random.len,
			"random tmp");
	if (data->entropy_generate.buffers[1].len) {
		logger_binary(LOGGER_DEBUG, data->entropy_generate.buffers[1].buf,
				data->entropy_generate.buffers[1].len,
				"entropy generate 1");
		params[0] = OSSL_PARAM_construct_octet_string
			(OSSL_RAND_PARAM_TEST_ENTROPY,
			 data->entropy_generate.buffers[1].buf,
			 data->entropy_generate.buffers[1].len);
		params[1] = OSSL_PARAM_construct_end();
		CKINT(EVP_RAND_CTX_set_params(parent, params));
	}

	logger_binary(LOGGER_DEBUG, data->addtl_generate.buffers[1].buf,
			data->addtl_generate.buffers[1].len, "addtl generate 2");
	CKINT_O_LOG(EVP_RAND_generate(ctx, data->random.buf, data->random.len, strength,
				data->entropy_generate.buffers[1].len?1:0,
				data->addtl_generate.buffers[1].buf,
				data->addtl_generate.buffers[1].len),
			"FIPS_drbg_generate failed\n");
	logger_binary(LOGGER_DEBUG, data->random.buf, data->random.len,
			"random");

	/* Verify the output */
	res = 0;
out:
	if (ctx) {
		EVP_RAND_uninstantiate(ctx);
		EVP_RAND_CTX_free(ctx);
	}
	if(parent) {
		EVP_RAND_uninstantiate(parent);
		EVP_RAND_CTX_free(parent);
	}
	if(rand)
		EVP_RAND_free(rand);
	return res;
}

static struct drbg_backend openssl_drbg =
{
	openssl_drbg_generate,  /* drbg_generate */
};

ACVP_DEFINE_CONSTRUCTOR(openssl_drbg_backend)
static void openssl_drbg_backend(void)
{
	register_drbg_impl(&openssl_drbg);
}

/************************************************
 * SSHv2 KDF
 ************************************************/

static int openssl_kdf_ssh_internal(struct kdf_ssh_data *data,
				    int id, const EVP_MD *md,
				    struct buffer *out)
{
	EVP_KDF *kdf = NULL;
	EVP_KDF_CTX *ctx = NULL;
	OSSL_PARAM params[6], *p;
	int ret = 0;

	kdf = EVP_KDF_fetch(NULL, "SSHKDF", NULL);
	CKNULL_LOG(kdf, -EFAULT, "Cannot allocate SSHv2 KDF\n");
	ctx = EVP_KDF_CTX_new(kdf);
	CKNULL_LOG(ctx, -EFAULT, "Cannot allocate SSHv2 PRF\n");

	p = params;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
						(char *)EVP_MD_name(md), 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
						 data->k.buf, data->k.len);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_XCGHASH,
						 data->h.buf, data->h.len);
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_SSHKDF_TYPE,
						(char *) &id, 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
						 data->session_id.buf,
						 data->session_id.len);
	*p = OSSL_PARAM_construct_end();

	CKINT_O(EVP_KDF_derive(ctx, out->buf, out->len, params));

out:
	if (kdf)
		EVP_KDF_free(kdf);
	if (ctx)
		EVP_KDF_CTX_free(ctx);
	return ret;
}

static int openssl_kdf_ssh(struct kdf_ssh_data *data, flags_t parsed_flags)
{
	const EVP_MD *md;
	unsigned int ivlen, enclen, maclen;
	int ret;

	(void)parsed_flags;

	CKINT(openssl_md_convert(data->cipher, &md));

	switch (data->cipher & ACVP_SYMMASK) {
	case ACVP_AES128:
		enclen = 16;
		ivlen = 16;
		break;
	case ACVP_AES192:
		enclen = 24;
		ivlen = 16;
		break;
	case ACVP_AES256:
		enclen = 32;
		ivlen = 16;
		break;
	case ACVP_TDESECB:
		enclen = 24;
		ivlen = 8;
		break;
	default:
		logger(LOGGER_WARN, "Cipher not identified\n");
		ret = -EINVAL;
		goto out;
	}

	switch (data->cipher & ACVP_HASHMASK) {
	case ACVP_SHA1:
		maclen = 20;
		break;
	case ACVP_SHA256:
		maclen = 32;
		break;
	case ACVP_SHA384:
		maclen = 48;
		break;
	case ACVP_SHA512:
		maclen = 64;
		break;
	default:
		logger(LOGGER_WARN, "Mac not identified\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(alloc_buf(ivlen, &data->initial_iv_client));
	CKINT(alloc_buf(ivlen, &data->initial_iv_server));
	CKINT(alloc_buf(enclen, &data->encryption_key_client));
	CKINT(alloc_buf(enclen, &data->encryption_key_server));
	CKINT(alloc_buf(maclen, &data->integrity_key_client));
	CKINT(alloc_buf(maclen, &data->integrity_key_server));

	CKINT(openssl_kdf_ssh_internal(data,  'A' + 0, md,
				       &data->initial_iv_client));
	CKINT(openssl_kdf_ssh_internal(data,  'A' + 1, md,
				       &data->initial_iv_server));
	CKINT(openssl_kdf_ssh_internal(data,  'A' + 2, md,
				       &data->encryption_key_client));
	CKINT(openssl_kdf_ssh_internal(data,  'A' + 3, md,
				       &data->encryption_key_server));
	CKINT(openssl_kdf_ssh_internal(data,  'A' + 4, md,
				       &data->integrity_key_client));
	CKINT(openssl_kdf_ssh_internal(data,  'A' + 5, md,
				       &data->integrity_key_server));

out:
	return ret;
}

static struct kdf_ssh_backend openssl_kdf =
{
	openssl_kdf_ssh,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_kdf_ssh_backend)
static void openssl_kdf_ssh_backend(void)
{
	register_kdf_ssh_impl(&openssl_kdf);
}

#ifdef OPENSSL_KBKDF
/************************************************
 * SP 800-108 KBKDF interface functions
 ************************************************/

static int openssl_kdf108(struct kdf_108_data *data, flags_t parsed_flags)
{
	EVP_KDF *kdf = NULL;
	EVP_KDF_CTX *ctx = NULL;
	OSSL_PARAM params[8], *p;
	const EVP_MD *md = NULL;
	const EVP_CIPHER *type = NULL;
	uint32_t derived_key_bytes = data->derived_key_length / 8;
	uint32_t l = be32(data->derived_key_length);
	BUFFER_INIT(label);
	BUFFER_INIT(context);
	int ret = 0, alloced = 0;
	(void)parsed_flags;

	logger(LOGGER_VERBOSE, "data->kdfmode = %" PRIu64 "\n", data->kdfmode);
	if (!(data->kdfmode & ACVP_CIPHERTYPE_KDF)) {
		logger(LOGGER_ERR, "The cipher type isn't a KDF");
		ret = -EINVAL;
		goto out;
	}

	if (data->kdfmode == ACVP_KDF_108_DOUBLE_PIPELINE) {
		logger(LOGGER_ERR, "Double pipeline mode is not supported");
		ret = -EINVAL;
		goto out;
	}

	kdf = EVP_KDF_fetch(NULL, "KBKDF", NULL);
	CKNULL_LOG(kdf, -EFAULT, "Cannot allocate KB KDF\n");
	ctx = EVP_KDF_CTX_new(kdf);
	CKNULL_LOG(ctx, -EFAULT, "Cannot allocate KB PRF\n");


	p = params;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE,
				(data->kdfmode == ACVP_KDF_108_COUNTER) ?
				"counter" : "feedback", 0);

	logger(LOGGER_VERBOSE, "data->mac = %" PRIu64 "\n", data->mac);
	if (data->mac & ACVP_CIPHERTYPE_HMAC) {
		CKINT(openssl_md_convert(data->mac, &md));
		CKNULL(md, -ENOMEM);

		*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
						(char *)EVP_MD_name(md), 0);
		*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
							"HMAC", 0);
	} else if (data->mac & ACVP_CIPHERTYPE_CMAC) {
		CKINT(openssl_cipher(data->mac == ACVP_AESCMAC ? ACVP_AESCMAC :
				     ACVP_TDESCMAC, data->key.len, &type));
		CKNULL(type, -ENOMEM);

		*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER,
						(char *)EVP_CIPHER_name(type),
						0);
		*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MAC,
							"CMAC", 0);
	}

	logger_binary(LOGGER_VERBOSE, data->key.buf, data->key.len, "data->key");
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
						 data->key.buf, data->key.len);

	logger(LOGGER_VERBOSE, "L = %u\n", derived_key_bytes);
	logger_binary(LOGGER_VERBOSE, (unsigned char *)&l, sizeof(l), "[L]_2");

	if (data->fixed_data.len) {
		if (data->fixed_data.len != (data->key.len * 2 + 1 + sizeof(l))) {
			logger(LOGGER_ERR, "KBKDF fixed data unexpected length for regression testing\n");
			ret = -EINVAL;
			goto out;
		}
		label.buf = data->fixed_data.buf;
		label.len = data->key.len;
		context.buf = data->fixed_data.buf + 1 + label.len;
		context.len = data->key.len;
	} else {
		alloced = 1;

		CKINT(alloc_buf(data->key.len, &label));
		CKINT(alloc_buf(data->key.len, &context));
		/*
		 * Allocate the fixed_data to hold
		 * Label || 0x00 || Context || [L]_2
		 */
		CKINT(alloc_buf(label.len + 1 + context.len + sizeof(l),
			&data->fixed_data));

		/* Randomly choose the label and context */
		RAND_bytes(label.buf, (int)label.len);
		RAND_bytes(context.buf, (int)context.len);

		/*
		 * Fixed data = Label || 0x00 || Context || [L]_2
		 * The counter i is not part of it
		 */
		memcpy(data->fixed_data.buf, label.buf, label.len);
		       data->fixed_data.buf[label.len] = 0x00;
		memcpy(data->fixed_data.buf + label.len + 1, context.buf,
		       context.len);
		memcpy(data->fixed_data.buf + label.len + 1 + context.len,
		       (unsigned char *)&l, sizeof(l));

		logger_binary(LOGGER_VERBOSE, data->fixed_data.buf,
			      data->fixed_data.len, "data->fixed_data");
	}

	logger_binary(LOGGER_VERBOSE, label.buf, label.len, "label");
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, label.buf,
						 label.len);

	logger_binary(LOGGER_VERBOSE, context.buf, context.len, "context");
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
						 context.buf, context.len);

	if (data->iv.len) {
		logger_binary(LOGGER_VERBOSE, data->iv.buf, data->iv.len,
			      "data->iv");
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED,
							 data->iv.buf,
							 data->iv.len);
	}

	*p = OSSL_PARAM_construct_end();

	CKINT(alloc_buf(derived_key_bytes, &data->derived_key));
	CKINT_O_LOG(EVP_KDF_derive(ctx, data->derived_key.buf,
				   derived_key_bytes, params),
		    "EVP_KDF_derive failed\n");
	logger_binary(LOGGER_VERBOSE, data->derived_key.buf,
                      derived_key_bytes, "data->derived_key");

out:
	if (kdf)
		EVP_KDF_free(kdf);
	if (ctx)
		EVP_KDF_CTX_free(ctx);

	if (alloced) {
		free_buf(&label);
		free_buf(&context);
	}
	return ret;
}

static struct kdf_108_backend openssl_kdf108_backend =
{
	openssl_kdf108,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_kdf_108_backend)
static void openssl_kdf_108_backend(void)
{
	register_kdf_108_impl(&openssl_kdf108_backend);
}
#endif

/************************************************
 * DSA interface functions
 ************************************************/
static int _openssl_dsa_pqg_gen(uint32_t L, uint32_t N, uint64_t cipher,
				struct buffer *p, struct buffer *q,
				struct buffer *g, struct buffer *seed,
				struct buffer *index, uint32_t *counter,
				EVP_PKEY *pkey)
{
	int ret = 0;
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	BIGNUM *p_bn = NULL, *q_bn = NULL;
	BUFFER_INIT(hex);
	const EVP_MD *md = NULL;

	CKINT(openssl_md_convert(cipher & ACVP_HASHMASK, &md));

	bld = OSSL_PARAM_BLD_new();
	CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_PBITS,
					L));
	CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_QBITS,
					N));
	CKINT_O(OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_FFC_DIGEST,
						EVP_MD_name(md), 0));

	if (seed && seed->len) {
		CKINT_O(OSSL_PARAM_BLD_push_octet_string(bld,
							 OSSL_PKEY_PARAM_FFC_SEED,
							 seed->buf, seed->len));
	}

	if (index && index->len) {
		bin2hex_alloc(index->buf, index->len, (char **)&hex.buf,
			      &hex.len);
		int number = (int)strtol((const char *)hex.buf, NULL, 16);
		CKINT_O(OSSL_PARAM_BLD_push_int(bld, OSSL_PKEY_PARAM_FFC_GINDEX,
						number));
		free_buf(&hex);
	}

	params = OSSL_PARAM_BLD_to_param(bld);

	// If a key was provided, we construct a context from it. This allows us
	// to generate the G value when P and Q are already given by the server.
	if (pkey)
		ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
	else
		ctx = EVP_PKEY_CTX_new_from_name(NULL, "DSA", NULL);
	CKNULL(ctx, -EFAULT);
	CKINT_O(EVP_PKEY_paramgen_init(ctx));
	CKINT_O(EVP_PKEY_CTX_set_params(ctx, params));
	CKINT_O(EVP_PKEY_paramgen(ctx, &key));

	if (p && !p->len)
		CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_FFC_P, p));
	if (q && !q->len)
		CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_FFC_Q, q));
	if (g && !g->len)
		CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_FFC_G, g));
	// Seed will only be present if a key was not provided (i.e. we
	// generated P and Q).
	if (seed && !pkey)
		CKINT(openssl_pkey_get_octet_bytes(key, OSSL_PKEY_PARAM_FFC_SEED,
						   seed));
	if (counter)
		CKINT_O(EVP_PKEY_get_int_param(key, OSSL_PKEY_PARAM_FFC_PCOUNTER,
					       (int *)counter));

out:
	if (key)
		EVP_PKEY_free(key);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (params)
		OSSL_PARAM_free(params);
	if (p_bn)
		BN_free(p_bn);
	if (q_bn)
		BN_free(q_bn);
	return ret;
}

static int openssl_dsa_pq_gen(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;
	return _openssl_dsa_pqg_gen(data->L, data->N, data->cipher, &data->P,
				    &data->Q, &data->G, &data->domainseed, NULL,
				    &data->pq_prob_counter, NULL);
}

static int openssl_dsa_g_gen(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	int ret = 0;
	EVP_PKEY *key = NULL;

	(void)parsed_flags;

	CKINT(openssl_ffc_create_pkey(&key, 0, 0, &data->P, &data->Q, NULL, 0,
				      NULL, NULL, NULL, NULL, NULL, 0, NULL,
				      "DSA"));
	CKINT(_openssl_dsa_pqg_gen(data->L, data->N, data->cipher, &data->P,
				   &data->Q, &data->G, &data->domainseed,
				   &data->g_canon_index, NULL, key));

out:
	if (key)
		EVP_PKEY_free(key);
	return ret;
}

static int openssl_dsa_pq_ver(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int ret = 0;
	const EVP_MD *md = NULL;

	(void)parsed_flags;

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	CKINT(openssl_ffc_create_pkey(&key, 1, 0, &data->P, &data->Q, NULL, 0,
				      NULL, NULL, &data->domainseed, NULL, NULL,
				      data->pq_prob_counter, md, "DSA"));

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	CKNULL(ctx, -EFAULT);
	ret = EVP_PKEY_param_check(ctx);

	if (1 == ret) {
		data->pqgver_success = 1;
		logger(LOGGER_DEBUG, "PQ verification successful\n");
	} else {
		data->pqgver_success = 0;
		logger(LOGGER_DEBUG, "PQ verification failed\n");
	}

	ret = 0;

out:
	if (key)
		EVP_PKEY_free(key);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	return ret;
}

static int openssl_dsa_pqg_ver(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int ret = 0;
	const EVP_MD *md = NULL;

	(void)parsed_flags;

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	CKINT(openssl_ffc_create_pkey(&key, 0, 1, &data->P, &data->Q, &data->G,
				      0, NULL, NULL, &data->domainseed,
				      &data->g_canon_index, &data->g_unver_h, 0,
				      md, "DSA"));

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
	CKNULL(ctx, -EFAULT);
	ret = EVP_PKEY_param_check(ctx);
	if (1 == ret) {
		data->pqgver_success = 1;
		logger(LOGGER_DEBUG, "G verification successful\n");
	} else {
		data->pqgver_success = 0;
		logger(LOGGER_DEBUG, "G verification failed\n");
	}
	ret = 0;

out:
	if (key)
		EVP_PKEY_free(key);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	return ret;
}

static int openssl_dsa_pqggen(struct dsa_pqggen_data *data,
			      flags_t parsed_flags)
{
	(void)parsed_flags;
	return _openssl_dsa_pqg_gen(data->L, data->N, data->cipher, &data->P,
				    &data->Q, &data->G, NULL, NULL, NULL, NULL);
}

static int openssl_dsa_pqg(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	parsed_flags &= ~FLAG_OP_GDT;
	if (parsed_flags ==
		(FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_PROBABLE_PQ_GEN))
		return openssl_dsa_pq_gen(data, parsed_flags);
	else if (parsed_flags ==
		(FLAG_OP_DSA_TYPE_PQGVER | FLAG_OP_DSA_PROBABLE_PQ_GEN))
		return openssl_dsa_pq_ver(data, parsed_flags);
	else if (parsed_flags ==
		(FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_UNVERIFIABLE_G_GEN))
		return openssl_dsa_g_gen(data, parsed_flags);
	else if (parsed_flags ==
		(FLAG_OP_DSA_TYPE_PQGVER | FLAG_OP_DSA_UNVERIFIABLE_G_GEN))
		return openssl_dsa_pqg_ver(data, parsed_flags);
	else if (parsed_flags ==
		(FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_CANONICAL_G_GEN))
		return openssl_dsa_g_gen(data, parsed_flags);
	else if (parsed_flags ==
		(FLAG_OP_DSA_TYPE_PQGVER | FLAG_OP_DSA_CANONICAL_G_GEN))
		return openssl_dsa_pqg_ver(data, parsed_flags);
	else {
		logger(LOGGER_WARN,
			"Unknown DSA PQG generation / verification definition (parsed flags: %" PRIu64 ")\n",
			parsed_flags);
		return -EINVAL;
	}
}

static int _openssl_dsa_keygen(struct buffer *P, struct buffer *Q,
			       struct buffer *G, uint64_t safeprime,
			       EVP_PKEY **key)
{
	int ret = 0;
	EVP_PKEY_CTX *ctx = NULL;

	CKINT(openssl_ffc_create_pkey(key, 0, 0, P, Q, G, safeprime, NULL, NULL,
				      NULL, NULL, NULL, 0, NULL, "DSA"));

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, *key, NULL);
	CKNULL(ctx, -EFAULT);
	CKINT_O(EVP_PKEY_keygen_init(ctx));
	CKINT(EVP_PKEY_param_check(ctx));
	CKINT_O(EVP_PKEY_keygen(ctx, key));

out:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

static int openssl_dsa_keygen(struct dsa_keygen_data *data,
			      flags_t parsed_flags)
{
	struct dsa_pqggen_data *pqg = &data->pqg;
	EVP_PKEY *key = NULL;
	int ret = 0;

	(void)parsed_flags;

	CKINT(_openssl_dsa_keygen(&pqg->P, &pqg->Q, &pqg->G, pqg->safeprime,
				  &key));

	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_PRIV_KEY,
					&data->X));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_PUB_KEY,
					&data->Y));

	logger_binary(LOGGER_DEBUG, data->X.buf, data->X.len, "X");
	logger_binary(LOGGER_DEBUG, data->Y.buf, data->Y.len, "Y");

out:
	if (key)
		EVP_PKEY_free(key);
	return ret;
}

static int openssl_dsa_keyver(struct dsa_keyver_data *data,
			      flags_t parsed_flags){
	int ret = 0;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *key = NULL;

	(void) parsed_flags;

	if (openssl_ffc_create_pkey(&key, 0, 0, NULL, NULL, NULL,
				    data->pqg.safeprime, &data->X, &data->Y,
				    NULL, NULL, NULL, 0, NULL, "DSA") <= 0) {
		data->keyver_success = 0;
	}

	ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, "fips=yes");
	CKNULL(ctx, -EFAULT);

	if (EVP_PKEY_check(ctx) > 0) {
		data->keyver_success = 1;
	} else {
		data->keyver_success = 0;
	}

	ret = 0;

out:
	if (key)
		EVP_PKEY_free(key);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

static int openssl_dsa_siggen(struct dsa_siggen_data *data,
			      flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	int ret = 0;
	BUFFER_INIT(sig);
	const EVP_MD *md = NULL;
	size_t r_len, s_len;
	const BIGNUM *r, *s;
	DSA_SIG *dsa_sig = NULL;

	if (!data->privkey) {
		logger(LOGGER_ERR, "Private key missing\n");
		return -EINVAL;
	}
	key = data->privkey;

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));
	CKINT(openssl_sig_gen(key, md, parsed_flags, 0, &data->msg, &sig));

	// We need a copy of the pointer here because d2i_DSA_SIG modifies it.
	const unsigned char *sig_buf = sig.buf;
	dsa_sig = d2i_DSA_SIG(NULL, &sig_buf, sig.len);
	CKNULL_LOG(dsa_sig, -EINVAL, "dsa_sig not generated\n");

	DSA_SIG_get0(dsa_sig, &r, &s);
	CKNULL_LOG(r, -EINVAL, "r not generated\n");
	CKNULL_LOG(s, -EINVAL, "s not generated\n");
	r_len = BN_num_bytes(r);
	s_len = BN_num_bytes(s);
	CKINT(alloc_buf(r_len, &data->R));
	CKINT(alloc_buf(s_len, &data->S));
	CKINT(BN_bn2binpad(r, data->R.buf, r_len));
	CKINT(BN_bn2binpad(s, data->S.buf, s_len));

	logger_binary(LOGGER_DEBUG, data->R.buf, data->R.len, "R");
	logger_binary(LOGGER_DEBUG, data->S.buf, data->S.len, "S");

	ret = 0;
out:
	free_buf(&sig);
	if (dsa_sig)
		DSA_SIG_free(dsa_sig);
	return ret;
}

static int openssl_dsa_sigver(struct dsa_sigver_data *data,
			      flags_t parsed_flags)
{
	struct dsa_pqggen_data *pqg = &data->pqg;
	EVP_PKEY *key = NULL;
	int ret = 0;
	BUFFER_INIT(sig);
	const EVP_MD *md = NULL;
	BIGNUM *r, *s;
	DSA_SIG *dsa_sig = NULL;

	// 1024 bytes should be sufficient.
	CKINT(alloc_buf(1024, &sig));

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));
	CKINT(openssl_ffc_create_pkey(&key, 0, 0, &pqg->P, &pqg->Q, &pqg->G, 0,
				      NULL, &data->Y, NULL, NULL, NULL, 0, NULL,
				      "DSA"));

	r = BN_bin2bn((const unsigned char *)data->R.buf, (int)data->R.len, NULL);
	CKNULL(r, -ENOMEM);
	s = BN_bin2bn((const unsigned char *)data->S.buf, (int)data->S.len, NULL);
	CKNULL(s, -ENOMEM);

	dsa_sig = DSA_SIG_new();
	CKINT_O_LOG(DSA_SIG_set0(dsa_sig, r, s), "DSA_SIG_set0 failed\n");
	// We need a copy of the pointer here because i2d_DSA_SIG modifies it.
	unsigned char *sig_buf = sig.buf;
	sig.len = i2d_DSA_SIG(dsa_sig, &sig_buf);

	CKINT(openssl_sig_ver(key, md, parsed_flags, 0, &data->msg, &sig,
			      &data->sigver_success));

	ret = 0;

out:
	free_buf(&sig);
	if (key)
		EVP_PKEY_free(key);
	if (dsa_sig)
		DSA_SIG_free(dsa_sig);
	return ret;
}

static int openssl_dsa_keygen_en(struct dsa_pqggen_data *pqg, struct buffer *Y,
				 void **privkey)
{
	EVP_PKEY *key = NULL;
	int ret;

	CKINT(_openssl_dsa_keygen(&pqg->P, &pqg->Q, &pqg->G, pqg->safeprime,
				  &key));

	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_PUB_KEY, Y));

	*privkey = key;

out:
	if (ret && key)
		EVP_PKEY_free(key);
	return ret;
}

static void openssl_dsa_free_key(void *privkey)
{
	EVP_PKEY *key = (EVP_PKEY *)privkey;

	if (key)
		EVP_PKEY_free(key);
}

static struct dsa_backend openssl_dsa =
{
	openssl_dsa_keygen,	/* dsa_keygen */
	openssl_dsa_keyver,
	openssl_dsa_siggen,	/* dsa_siggen */
	openssl_dsa_sigver,	/* dsa_sigver */
	openssl_dsa_pqg,	/* dsa_pqg */
	openssl_dsa_pqggen,
	openssl_dsa_keygen_en,
	openssl_dsa_free_key
};

ACVP_DEFINE_CONSTRUCTOR(openssl_dsa_backend)
static void openssl_dsa_backend(void)
{
	register_dsa_impl(&openssl_dsa);
}

/************************************************
 * ECDSA cipher interface functions
 ************************************************/
static int _openssl_ecdsa_keygen(uint64_t curve, EVP_PKEY **key)
{
	EVP_PKEY_CTX *ctx = NULL;
	int ret = 0, nid = 0;
	char *curve_name;
	CKINT_LOG(_openssl_ecdsa_curves(curve, &nid , &curve_name),
		  "Conversion of curve failed\n");

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	CKNULL(ctx, -ENOMEM);
	CKINT_O(EVP_PKEY_keygen_init(ctx));
	CKINT_O_LOG(EVP_PKEY_CTX_set_group_name(ctx, curve_name),
		   "EC_KEY_new_by_curve_name() failed\n");
	CKINT_O_LOG(EVP_PKEY_keygen(ctx, key),
		   "EC_KEY_generate_key() failed\n");

out:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

static int openssl_ecdsa_keygen(struct ecdsa_keygen_data *data,
				flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	int ret = 0;

	(void)parsed_flags;

	CKINT(_openssl_ecdsa_keygen(data->cipher, &key));

	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_PRIV_KEY,
					&data->d));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_EC_PUB_X,
					&data->Qx));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_EC_PUB_Y,
					&data->Qy));
	
	logger_binary(LOGGER_DEBUG, data->Qx.buf, data->Qx.len, "Qx");
	logger_binary(LOGGER_DEBUG, data->Qy.buf, data->Qy.len, "Qy");
	logger_binary(LOGGER_DEBUG, data->d.buf, data->d.len, "d");

out:
	if (key)
		EVP_PKEY_free(key);
	return ret;
}

static int openssl_ecdsa_create_pkey(EVP_PKEY **pkey, uint64_t cipher,
				     struct buffer *Qx, struct buffer *Qy)
{
	int ret = 0;
	int nid = NID_undef;
	char *curve_name;
	BUFFER_INIT(pub);
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;

	CKINT(_openssl_ecdsa_curves(cipher, &nid, &curve_name));

	CKINT(alloc_buf(Qx->len + Qy->len + 1, &pub));

	pub.buf[0] = POINT_CONVERSION_UNCOMPRESSED;
	memcpy(pub.buf + 1, Qx->buf, Qx->len);
	memcpy(pub.buf + 1 + Qx->len, Qy->buf, Qy->len);

	logger_binary(LOGGER_DEBUG, pub.buf, pub.len, "pub");

	bld = OSSL_PARAM_BLD_new();
	OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					curve_name, 0);
	OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub.buf,
					 pub.len);
	params = OSSL_PARAM_BLD_to_param(bld);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	EVP_PKEY_fromdata_init(ctx);
	if (EVP_PKEY_fromdata(ctx, pkey, EVP_PKEY_PUBLIC_KEY, params) == 1)
		ret = 1;

out:
	free_buf(&pub);
	if(params)
		OSSL_PARAM_free(params);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

static int openssl_ecdsa_pkvver(struct ecdsa_pkvver_data *data,
				flags_t parsed_flags)
{
	EVP_PKEY_CTX *ctx = NULL;
	int ret = 0;
	EVP_PKEY *key = NULL;
	(void)parsed_flags;

	ret = openssl_ecdsa_create_pkey(&key, data->cipher, &data->Qx,
					&data->Qy);

	if (ret) {
		logger(LOGGER_DEBUG, "ECDSA key successfully verified\n");
		data->keyver_success = 1;
	} else {
		logger(LOGGER_DEBUG, "ECDSA key verification failed\n");
		data->keyver_success = 0;
	}
	ret = 0;

	if (key)
		EVP_PKEY_free(key);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

static int openssl_ecdsa_siggen(struct ecdsa_siggen_data *data,
				flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	int ret = 0;
	BUFFER_INIT(sig);
	const EVP_MD *md = NULL;
	size_t r_len, s_len;
	const BIGNUM *r, *s;
	ECDSA_SIG *ecdsa_sig = NULL;

	if (!data->privkey) {
		logger(LOGGER_ERR, "Private key missing\n");
		return -EINVAL;
	}
	key = data->privkey;

	if (data->component) {
		CKINT(openssl_sig_gen(key, NULL, parsed_flags, 0, &data->msg,
				      &sig));
	} else {
		CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));
		CKINT(openssl_sig_gen(key, md, parsed_flags, 0, &data->msg,
				      &sig));
	}

	// We need a copy of the pointer here because d2i_ECDSA_SIG modifies it.
	const unsigned char *sig_buf = sig.buf;
	ecdsa_sig = d2i_ECDSA_SIG(NULL, &sig_buf, sig.len);
	CKNULL_LOG(ecdsa_sig, -EINVAL, "ecdsa_sig not generated\n");

	ECDSA_SIG_get0(ecdsa_sig, &r, &s);
	CKNULL_LOG(r, -EINVAL, "r not generated\n");
	CKNULL_LOG(s, -EINVAL, "s not generated\n");
	r_len = BN_num_bytes(r);
	s_len = BN_num_bytes(s);
	CKINT(alloc_buf(r_len, &data->R));
	CKINT(alloc_buf(s_len, &data->S));
	CKINT(BN_bn2binpad(r, data->R.buf, r_len));
	CKINT(BN_bn2binpad(s, data->S.buf, s_len));

	logger_binary(LOGGER_DEBUG, data->R.buf, data->R.len, "R");
	logger_binary(LOGGER_DEBUG, data->S.buf, data->S.len, "S");

	ret = 0;

out:
	free_buf(&sig);
	if (ecdsa_sig)
		ECDSA_SIG_free(ecdsa_sig);
	return ret;
}

static int openssl_ecdsa_sigver(struct ecdsa_sigver_data *data,
				flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	BUFFER_INIT(sig);
	int ret = 0;
	const EVP_MD *md = NULL;
	BIGNUM *r, *s;
	ECDSA_SIG *ecdsa_sig = NULL;

	(void)parsed_flags;

	// 1024 bytes should be sufficient.
	CKINT(alloc_buf(1024, &sig));

	CKINT(openssl_ecdsa_create_pkey(&key, data->cipher, &data->Qx,
					&data->Qy));

	r = BN_bin2bn((const unsigned char *)data->R.buf, (int)data->R.len, NULL);
	CKNULL(r, -ENOMEM);
	s = BN_bin2bn((const unsigned char *)data->S.buf, (int)data->S.len, NULL);
	CKNULL(s, -ENOMEM);

	ecdsa_sig = ECDSA_SIG_new();
	CKINT_O_LOG(ECDSA_SIG_set0(ecdsa_sig, r, s), "ECDSA_SIG_set0 failed\n");
	// We need a copy of the pointer here because i2d_ECDSA_SIG modifies it.
	unsigned char *sig_buf = sig.buf;
	sig.len = i2d_ECDSA_SIG(ecdsa_sig, &sig_buf);

	if (data->component) {
		CKINT(openssl_sig_ver(key, NULL, parsed_flags, 0, &data->msg,
				      &sig, &data->sigver_success));
	} else {
		CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));
		CKINT(openssl_sig_ver(key, md, parsed_flags, 0, &data->msg,
				      &sig, &data->sigver_success));
	}

	ret = 0;

out:
	free_buf(&sig);
	if (key)
		EVP_PKEY_free(key);
	if (ecdsa_sig)
		ECDSA_SIG_free(ecdsa_sig);
	return ret;
}

static int openssl_ecdsa_keygen_en(uint64_t curve, struct buffer *Qx_buf,
				   struct buffer *Qy_buf, void **privkey)
{
	EVP_PKEY *key = NULL;
	int ret;

	CKINT(_openssl_ecdsa_keygen(curve, &key));

	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_EC_PUB_X, Qx_buf));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_EC_PUB_Y, Qy_buf));

	logger_binary(LOGGER_DEBUG, Qx_buf->buf, Qx_buf->len, "Qx");
	logger_binary(LOGGER_DEBUG, Qy_buf->buf, Qy_buf->len, "Qy");

	*privkey = key;

out:
	if (ret && key)
		EVP_PKEY_free(key);
	return ret;
}

static void openssl_ecdsa_free_key(void *privkey)
{
	EVP_PKEY *ecdsa = (EVP_PKEY *)privkey;
	if (ecdsa)
		EVP_PKEY_free(ecdsa);
}

static struct ecdsa_backend openssl_ecdsa =
{
	openssl_ecdsa_keygen,   /* ecdsa_keygen_testing */
	NULL,
	openssl_ecdsa_pkvver,   /* ecdsa_pkvver */
	openssl_ecdsa_siggen,   /* ecdsa_siggen */
	openssl_ecdsa_sigver,   /* ecdsa_sigver */
	openssl_ecdsa_keygen_en,
	openssl_ecdsa_free_key,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_ecdsa_backend)
static void openssl_ecdsa_backend(void)
{
	register_ecdsa_impl(&openssl_ecdsa);
}

/************************************************
 * RSA cipher interface functions
 ************************************************/
// 1 / sqrt(2) * 2^256, rounded up
const char *ossl_bn_inv_sqrt_2_hex = "b504f333f9de6484597d89b3754abe9f1d6f60ba893ba84ced17ac8583339916";
BIGNUM *ossl_bn_inv_sqrt_2;

// Copied from crypto/bn/bn_rsa_fips186_4.c.
static int openssl_rsa_fips186_5_aux_prime_min_size(int nbits)
{
	if (nbits >= 4096)
		return 201;
	if (nbits >= 3072)
		return 171;
	if (nbits >= 2048)
		return 141;
	return 0;
}

static int openssl_generate_xps(uint32_t modulus, BIGNUM *xp, BIGNUM *xp1,
				BIGNUM *xp2, unsigned int *bitlen)
{
	BIGNUM *base = NULL, *range = NULL;
	int bits = modulus >> 1;
	int ret = 0;

	if (!ossl_bn_inv_sqrt_2) {
		CKNULL(BN_hex2bn(&ossl_bn_inv_sqrt_2, ossl_bn_inv_sqrt_2_hex),
		       -EFAULT);
	}

	base = BN_new();
	CKNULL(base, -ENOMEM);
	range = BN_new();
	CKNULL(range, -ENOMEM);

	// See ossl_bn_rsa_fips186_4_derive_prime in
	// crypto/bn/bn_rsa_fips186_4.c for why this works.
	if (bits < BN_num_bits(ossl_bn_inv_sqrt_2)) {
		ret = -EFAULT;
		goto out;
	}
	CKNULL(BN_lshift(base, ossl_bn_inv_sqrt_2,
			 bits - BN_num_bits(ossl_bn_inv_sqrt_2)), -EFAULT);
	CKNULL(BN_lshift(range, BN_value_one(), bits), -EFAULT);
	CKNULL(BN_sub(range, range, base), -EFAULT);
	CKNULL(BN_priv_rand_range_ex(xp, range, 0, NULL), -EFAULT);
	CKNULL(BN_add(xp, xp, base), -EFAULT);

	// See ossl_bn_rsa_fips186_4_gen_prob_primes in
	// crypto/bn/bn_rsa_fips186_4.c.
	bitlen[0] = openssl_rsa_fips186_5_aux_prime_min_size(modulus);
	CKNULL(BN_priv_rand_ex(xp1, bitlen[0], BN_RAND_TOP_ONE,
			       BN_RAND_BOTTOM_ODD, 0, NULL), -EFAULT);
	bitlen[1] = openssl_rsa_fips186_5_aux_prime_min_size(modulus);
	CKNULL(BN_priv_rand_ex(xp2, bitlen[1], BN_RAND_TOP_ONE,
			       BN_RAND_BOTTOM_ODD, 0, NULL), -EFAULT);

out:
	if (base)
		BN_free(base);
	if (range)
		BN_free(range);
	return ret;
}

static int openssl_rsa_create_pkey(EVP_PKEY **key, struct buffer *n,
				   struct buffer *e, struct buffer *d)
{
	int ret = 0;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	BIGNUM *n_bn = NULL, *e_bn = NULL, *d_bn = NULL;
	int selection = EVP_PKEY_PUBLIC_KEY;

	bld = OSSL_PARAM_BLD_new();

	n_bn = BN_new();
	BN_bin2bn(n->buf, n->len, n_bn);
	CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n_bn));

	e_bn = BN_new();
	BN_bin2bn(e->buf, e->len, e_bn);
	CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn));

	if (d) {
		d_bn = BN_new();
		BN_bin2bn(d->buf, d->len, d_bn);
		CKINT_O(OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D,
					       d_bn));
		selection = EVP_PKEY_KEYPAIR;
	}

	params = OSSL_PARAM_BLD_to_param(bld);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	CKNULL(ctx, -EFAULT);
	CKINT_O(EVP_PKEY_fromdata_init(ctx));
	CKINT_O(EVP_PKEY_fromdata(ctx, key, selection, params));

out:
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (params)
		OSSL_PARAM_free(params);
	if (n_bn)
		BN_free(n_bn);
	if (e_bn)
		BN_free(e_bn);
	if (d_bn)
		BN_free(d_bn);
	return ret;
}

static int openssl_rsa_keygen_internal(uint32_t modulus, struct buffer *ebuf,
				       struct buffer *xpbuf,
				       struct buffer *xp1buf,
				       struct buffer *xp2buf,
				       struct buffer *xqbuf,
				       struct buffer *xq1buf,
				       struct buffer *xq2buf,
				       unsigned int bitlen[4], EVP_PKEY **key)
{
	BIGNUM *e = NULL;
	BIGNUM *xp = NULL, *xp1 = NULL, *xp2 = NULL;
	BIGNUM *xq = NULL, *xq1 = NULL, *xq2 = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	int ret = 0;

	if (!ebuf->len) {
		unsigned int a;
		uint8_t bitsset = 0;

		/* WARNING Buffer must be at least 3 bytes in size ! */
		CKINT(alloc_buf(sizeof(unsigned int), ebuf));

		/* generate random odd e */
		RAND_bytes(ebuf->buf, (int)ebuf->len);
		/* make sure it is odd */
		ebuf->buf[ebuf->len - 1] |= 1;

		for (a = 0; a < ebuf->len - 2; a++)
			bitsset |= ebuf->buf[a];

		/* Make sure that value is >= 65537 */
		if (!bitsset)
			ebuf->buf[ebuf->len - 3] |= 1;
	}

	e = BN_bin2bn(ebuf->buf, ebuf->len, e);
	CKNULL(e, -ENOMEM);

	bld = OSSL_PARAM_BLD_new();
	if (xpbuf && xp1buf && xp2buf && bitlen) {
		xp = BN_new();
		CKNULL(xp, -ENOMEM);
		xp1 = BN_new();
		CKNULL(xp1, -ENOMEM);
		xp2 = BN_new();
		CKNULL(xp2, -ENOMEM);
		CKINT(openssl_generate_xps(modulus, xp, xp1, xp2, &bitlen[0]));
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP, xp);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP1, xp1);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XP2, xp2);
		CKINT(openssl_bn2buffer(xp, xpbuf));
		CKINT(openssl_bn2buffer(xp1, xp1buf));
		CKINT(openssl_bn2buffer(xp2, xp2buf));
	}
	if (xqbuf && xq1buf && xq2buf && bitlen) {
		xq = BN_new();
		CKNULL(xq, -ENOMEM);
		xq1 = BN_new();
		CKNULL(xq1, -ENOMEM);
		xq2 = BN_new();
		CKNULL(xq2, -ENOMEM);
		CKINT(openssl_generate_xps(modulus, xq, xq1, xq2, &bitlen[2]));
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ, xq);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ1, xq1);
		OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_TEST_XQ2, xq2);
		CKINT(openssl_bn2buffer(xq, xqbuf));
		CKINT(openssl_bn2buffer(xq1, xq1buf));
		CKINT(openssl_bn2buffer(xq2, xq2buf));
	}
	params = OSSL_PARAM_BLD_to_param(bld);

	ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	CKNULL(ctx, -ENOMEM);
	CKINT_O(EVP_PKEY_keygen_init(ctx));
	CKINT_O(EVP_PKEY_CTX_set_params(ctx, params));
	CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, modulus),
		   "EVP_PKEY_CTX_set_rsa_keygen_bits() failed\n");
	CKINT_O_LOG(EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e),
		   "EVP_PKEY_CTX_set1_rsa_keygen_pubexp() failed\n");
	CKINT_O_LOG(EVP_PKEY_keygen(ctx, key),
		   "EC_KEY_generate_key() failed\n");

out:
	if (e)
		BN_free(e);
	if (xp)
		BN_free(xp);
	if (xp1)
		BN_free(xp1);
	if (xp2)
		BN_free(xp2);
	if (xq)
		BN_free(xq);
	if (xq1)
		BN_free(xq1);
	if (xq2)
		BN_free(xq2);
	if (bld)
		OSSL_PARAM_BLD_free(bld);
	if (params)
		OSSL_PARAM_free(params);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	return ret;
}

static int openssl_rsa_keygen(struct rsa_keygen_data *data,
			      flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	int ret = 0;

	(void)parsed_flags;

	CKINT(openssl_rsa_keygen_internal(data->modulus, &data->e, &data->xp,
					  &data->xp1, &data->xp2, &data->xq,
					  &data->xq1, &data->xq2, data->bitlen,
					  &key));

	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_RSA_N, &data->n));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_RSA_D, &data->d));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_RSA_FACTOR1,
					&data->p));
	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_RSA_FACTOR2,
					&data->q));

out:
	if (key)
		EVP_PKEY_free(key);
	return ret;
}

static int openssl_rsa_siggen(struct rsa_siggen_data *data,
			      flags_t parsed_flags)
{
	EVP_PKEY *key;
	int ret = 0;
	const EVP_MD *md = NULL;

	if (!data->privkey) {
		logger(LOGGER_ERR, "Private key missing\n");
		return -EINVAL;
	}
	key = data->privkey;

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));
	CKINT(openssl_sig_gen(key, md, parsed_flags, data->saltlen, &data->msg,
			      &data->sig));

	logger_binary(LOGGER_DEBUG, data->sig.buf, data->sig.len, "sig");

	ret = 0;

out:
	return ret;
}

static int openssl_rsa_sigver(struct rsa_sigver_data *data,
			      flags_t parsed_flags)
{
	EVP_PKEY *key = NULL;
	int ret = 0;
	const EVP_MD *md = NULL;

	CKINT(openssl_rsa_create_pkey(&key, &data->n, &data->e, NULL));

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));
	CKINT(openssl_sig_ver(key, md, parsed_flags, data->saltlen, &data->msg,
			      &data->sig, &data->sig_result));

out:
	if (key)
		EVP_PKEY_free(key);
	return ret;
}

static int openssl_rsa_keygen_en(struct buffer *ebuf, uint32_t modulus,
				 void **privkey, struct buffer *nbuf)
{
	EVP_PKEY *key = NULL;
	int ret;

	CKINT(openssl_rsa_keygen_internal(modulus, ebuf, NULL, NULL, NULL, NULL,
					  NULL, NULL, NULL, &key));

	CKINT(openssl_pkey_get_bn_bytes(key, OSSL_PKEY_PARAM_RSA_N, nbuf));

	logger_binary(LOGGER_DEBUG, nbuf->buf, nbuf->len, "N");

	*privkey = key;

out:
	if (ret && key)
		EVP_PKEY_free(key);
	return ret;
}

static void openssl_rsa_free_key(void *privkey)
{
	EVP_PKEY *rsa = (EVP_PKEY *)privkey;
	if (rsa)
		EVP_PKEY_free(rsa);
}

static struct rsa_backend openssl_rsa =
{
	openssl_rsa_keygen,
	openssl_rsa_siggen,
	openssl_rsa_sigver,
	NULL,
	NULL,
	openssl_rsa_keygen_en,
	openssl_rsa_free_key,
	NULL,
	NULL,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_rsa_backend)
static void openssl_rsa_backend(void)
{
	register_rsa_impl(&openssl_rsa);
}

/************************************************
 * SP800-56B rev 2 KTS IFC cipher interface functions
 ************************************************/

static int openssl_rsa_kas_ifc_encrypt_common(struct kts_ifc_data *data,
					      uint32_t *validation_success)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pk = NULL;
	BUFFER_INIT(label);
	BUFFER_INIT(new_c);
	struct buffer *dkm_p, *c_p;
	size_t outlen, keylen = (data->keylen) ? data->keylen : data->modulus;
	int ret;

	if (keylen > data->modulus)
		return -EINVAL;

	if (validation_success) {
		struct kts_ifc_init_validation_data *init_val =
					&data->u.kts_ifc_init_validation;

		CKINT(left_pad_buf(&init_val->n, data->modulus >> 3));

		CKINT(openssl_rsa_create_pkey(&pk, &init_val->n, &init_val->e,
					      NULL));

		dkm_p = &init_val->dkm;
		c_p = &new_c;
	} else {
		struct kts_ifc_init_data *init = &data->u.kts_ifc_init;

		CKINT(left_pad_buf(&init->n, data->modulus >> 3));

		CKINT(openssl_rsa_create_pkey(&pk, &init->n, &init->e, NULL));

		if (!init->dkm.len) {
			CKINT(alloc_buf(keylen >> 3, &init->dkm));
			RAND_bytes(init->dkm.buf, (int)init->dkm.len);

			/*
			 * Ensure that in case of raw encryption, the value is
			 * not too large.
			 */
			init->dkm.buf[0] &= ~0x80;
		}

		dkm_p = &init->dkm;
		c_p = &init->iut_c;
	}

	ctx = EVP_PKEY_CTX_new(pk, NULL);
	CKNULL_LOG(ctx, -EFAULT, "Cannot allocate PKEY context\n");

	CKINT_O_LOG(EVP_PKEY_encrypt_init(ctx), "PKEY encrypt init failed\n");

	if (data->kts_hash) {
		/* OAEP Padding */
		const EVP_MD *md = NULL;

		CKINT(openssl_md_convert(data->kts_hash, &md));
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_padding(ctx,
							 RSA_PKCS1_OAEP_PADDING),
			    "Setting OAEP padding failed\n");
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md),
			   "Setting of OAEP MD failed\n");

		/* Evaluate encoding and concatenate Server and IUT Ids */

		if (convert_cipher_match(data->kts_encoding,
					 ACVP_KAS_ENCODING_CONCATENATION,
					 ACVP_CIPHERTYPE_KAS)) {
			CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md),
				    "Setting MFGL MD failed\n");
			CKINT(alloc_buf(data->server_id.len + data->iut_id.len,
					&label));
			memcpy(label.buf, data->iut_id.buf, data->iut_id.len);
			memcpy(label.buf + data->iut_id.len, data->server_id.buf,
			data->server_id.len);


			CKINT_O_LOG(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx,
								     label.buf,
								     label.len),
				    "Setting OAEP label failed\n");
		}
	} else {
		/* Raw encryption */
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING),
			    "Setting no padding failed\n");
	}

	/* Determine buffer length */
	CKINT_O_LOG(EVP_PKEY_encrypt(ctx, NULL, &outlen, dkm_p->buf,
				     dkm_p->len),
		    "Getting ciphertext length failed %s\n",
		    ERR_error_string(ERR_get_error(), NULL));

	CKINT(alloc_buf(outlen, c_p));

	ret = EVP_PKEY_encrypt(ctx, c_p->buf, &outlen, dkm_p->buf, dkm_p->len);

	if (validation_success) {
		struct kts_ifc_init_validation_data *init_val =
					&data->u.kts_ifc_init_validation;

		/* OpenSSL returns 0 on failure */
		if (ret != 1) {
			logger(LOGGER_DEBUG,
			       "Validation: RSA encryption failed %s\n",
			       ERR_error_string(ERR_get_error(), NULL));
			*validation_success = 0;
		} else if (outlen != init_val->c.len ||
			   memcmp(init_val->c.buf, c_p->buf, outlen)) {
			logger(LOGGER_DEBUG, "lens %zu %zu\n", outlen,
			       init_val->c.len);
			logger_binary(LOGGER_DEBUG, init_val->c.buf,
				      init_val->c.len,
				      "expected encrypted secret");
			logger_binary(LOGGER_DEBUG, c_p->buf, c_p->len,
				      "calculated encrypted secret");

			*validation_success = 0;
		} else {
			*validation_success = 1;
		}

		ret = 0;
	} else if (ret != 1) {
		logger(LOGGER_ERR, "RSA encryption failed %s\n",
		       ERR_error_string(ERR_get_error(), NULL));
		ret = -EFAULT;
	} else {
		ret = 0;
	}

out:
	if (pk)
		EVP_PKEY_free(pk);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);
	free_buf(&new_c);

	/*
	 * The man page for EVP_PKEY_CTX_set0_rsa_oaep_label reads:
	 *
	 * "The library takes ownership of the label so the caller should
	 * not free the original memory pointed to by label."
	 *
	 * So, this call is not needed.
	 * free_buf(&label);
	 */

	return ret;
}

static int openssl_rsa_kas_ifc_decrypt_common(struct kts_ifc_data *data,
					      uint32_t *validation_success)
{
	BUFFER_INIT(tmp);
	BUFFER_INIT(label);
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pk = NULL;

	struct buffer *c_p;
	size_t outlen, keylen = (data->keylen) ? data->keylen : data->modulus;
	int ret;

	if (keylen > data->modulus)
		return -EINVAL;

	if (validation_success) {
		struct kts_ifc_resp_validation_data *resp_val =
					&data->u.kts_ifc_resp_validation;

		CKINT(left_pad_buf(&resp_val->n, data->modulus >> 3));

		CKINT(openssl_rsa_create_pkey(&pk, &resp_val->n, &resp_val->e,
					      &resp_val->d));

		c_p = &resp_val->c;
	} else {
		struct kts_ifc_resp_data *resp = &data->u.kts_ifc_resp;

		CKINT(left_pad_buf(&resp->n, data->modulus >> 3));

		CKINT(openssl_rsa_create_pkey(&pk, &resp->n, &resp->e,
					      &resp->d));

		c_p = &resp->c;
	}

	ctx = EVP_PKEY_CTX_new(pk, NULL);
	CKNULL_LOG(ctx, -EFAULT, "Cannot allocate PKEY context\n");

	CKINT_O_LOG(EVP_PKEY_decrypt_init(ctx), "PKEY decrypt init failed\n");

	if (data->kts_hash) {
		/* OAEP Padding */
		const EVP_MD *md = NULL;

		CKINT(openssl_md_convert(data->kts_hash, &md));
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_padding(ctx,
							 RSA_PKCS1_OAEP_PADDING),
			    "Setting OAEP padding failed\n");
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md),
			    "Setting of OAEP MD failed\n");

		/* Evaluate encoding and concatenate IUT and Server Ids */

		if (convert_cipher_match(data->kts_encoding,
					 ACVP_KAS_ENCODING_CONCATENATION,
					 ACVP_CIPHERTYPE_KAS)) {
			CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md),
				    "Setting MFGL MD failed\n");
			CKINT(alloc_buf(data->server_id.len + data->iut_id.len,
					&label));
			memcpy(label.buf, data->server_id.buf, data->server_id.len);
			memcpy(label.buf + data->server_id.len, data->iut_id.buf,
			data->iut_id.len);

			CKINT_O_LOG(EVP_PKEY_CTX_set0_rsa_oaep_label(ctx,
								     label.buf,
								     label.len),
				    "Setting OAEP label failed\n");
		}
	} else {
		/* Raw encryption */
		CKINT_O_LOG(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING),
			    "Setting padding failed\n");
	}

	/* Determine buffer length */
	CKINT_O_LOG(EVP_PKEY_decrypt(ctx, NULL, &outlen, c_p->buf, c_p->len),
		    "Getting plaintext length failed %s\n",
		    ERR_error_string(ERR_get_error(), NULL));

	CKINT(alloc_buf(outlen, &tmp));

	ret = EVP_PKEY_decrypt(ctx, tmp.buf, &tmp.len, c_p->buf, c_p->len);

	if (validation_success) {
		struct kts_ifc_resp_validation_data *resp_val =
					&data->u.kts_ifc_resp_validation;

		/* OpenSSL returns 0 on failure */
		if (ret != 1) {
			logger(LOGGER_DEBUG,
			       "Validation: RSA encryption failed %s\n",
			       ERR_error_string(ERR_get_error(), NULL));
			*validation_success = 0;
		} else if (outlen != resp_val->dkm.len ||
			   memcmp(resp_val->dkm.buf, tmp.buf, outlen)) {
			logger(LOGGER_DEBUG, "lens %zu %zu\n", outlen,
			       resp_val->dkm.len);
			logger_binary(LOGGER_DEBUG, resp_val->dkm.buf,
				      resp_val->dkm.len,
				      "expected decrypted secret");
			logger_binary(LOGGER_DEBUG, tmp.buf, tmp.len,
				      "calculated decrypted secret");

			*validation_success = 0;
		} else {
			*validation_success = 1;
		}

		ret = 0;
	} else if (ret != 1) {
		logger(LOGGER_ERR, "RSA decryption failed %s\n",
		    ERR_error_string(ERR_get_error(), NULL));
		ret = -EFAULT;
	} else {
		struct kts_ifc_resp_data *resp = &data->u.kts_ifc_resp;

		if (tmp.len < (keylen >> 3)) {
			logger(LOGGER_ERR,
			       "RSA decrypted data has insufficient size\n");
			ret = -EFAULT;
			goto out;
		}

		CKINT(alloc_buf(keylen >> 3, &resp->dkm));
		memcpy(resp->dkm.buf, tmp.buf, resp->dkm.len);
	}

out:
	if (pk)
		EVP_PKEY_free(pk);
	if (ctx)
		EVP_PKEY_CTX_free(ctx);

	/*
	 * The man page for EVP_PKEY_CTX_set0_rsa_oaep_label reads:
	 *
	 * "The library takes ownership of the label so the caller should
	 * not free the original memory pointed to by label."
	 *
	 * So, this call is not needed.
	 * free_buf(&label);
	 */

	free_buf(&tmp);
	return ret;
}

static int openssl_kts_ifc_generate(struct kts_ifc_data *data,
				    flags_t parsed_flags)
{
	int ret;

	(void)parsed_flags;

	if ((parsed_flags & FLAG_OP_KAS_ROLE_INITIATOR) &&
	    (parsed_flags & FLAG_OP_AFT)) {
		CKINT(openssl_rsa_kas_ifc_encrypt_common(data, NULL));
	} else if ((parsed_flags & FLAG_OP_KAS_ROLE_RESPONDER) &&
		   (parsed_flags & FLAG_OP_AFT)) {
		CKINT(openssl_rsa_kas_ifc_decrypt_common(data, NULL));
	} else if ((parsed_flags & FLAG_OP_KAS_ROLE_INITIATOR) &&
		   (parsed_flags & FLAG_OP_VAL)) {
		struct kts_ifc_init_validation_data *init_val =
					&data->u.kts_ifc_init_validation;

		CKINT(openssl_rsa_kas_ifc_encrypt_common(data,
							 &init_val->validation_success));
	} else if ((parsed_flags & FLAG_OP_KAS_ROLE_RESPONDER) &&
		   (parsed_flags & FLAG_OP_VAL)) {
		struct kts_ifc_resp_validation_data *resp_val =
					&data->u.kts_ifc_resp_validation;

		CKINT(openssl_rsa_kas_ifc_decrypt_common(data,
							 &resp_val->validation_success));
	} else {
		logger(LOGGER_ERR, "Unknown test\n");
		ret = -EINVAL;
	}

out:
	return ret;
}

static struct kts_ifc_backend openssl_kts_ifc =
{
	openssl_kts_ifc_generate,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_kts_ifc_backend)
static void openssl_kts_ifc_backend(void)
{
	register_kts_ifc_impl(&openssl_kts_ifc);
}

/************************************************
 * ANSI X9.42 KDF interface functions
 ************************************************/

static int openssl_ansi_x942_kdf(struct ansi_x942_data *data,
				 flags_t parsed_flags)
{
	const EVP_MD *md;
	const char *cekalg;
	// At most 2 (prefix) + 256 (data) bytes for each parameter
	unsigned char acvp_info[2 + 256 + 2 + 256 + 2 + 256 + 2 + 256];
	size_t ptr;
	int use_keybits = 0;
	EVP_KDF *kdf = NULL;
	EVP_KDF_CTX *ctx = NULL;
	OSSL_PARAM params[6], *p;
	int ret = 0;

	(void)parsed_flags;

	if (strncmp((char *)data->kdf_type.buf, "DER", 3)) {
		logger(LOGGER_ERR, "Unknown KDF type\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(openssl_md_convert(data->hashalg, &md));
	switch (data->wrapalg & ACVP_SYMMASK) {
	case ACVP_AES128:
		cekalg = "AES-128-WRAP";
		break;
	case ACVP_AES192:
		cekalg = "AES-192-WRAP";
		break;
	case ACVP_AES256:
		cekalg = "AES-256-WRAP";
		break;
	default:
		logger(LOGGER_WARN, "Cipher not identified\n");
		ret = -EINVAL;
		goto out;
	}

	ptr = 0;
	if (data->party_u_info.len) {
		acvp_info[ptr++] = 0xA0;
		acvp_info[ptr++] = (unsigned char) data->party_u_info.len;
		memcpy(&acvp_info[ptr], data->party_u_info.buf,
		       data->party_u_info.len);
		ptr += data->party_u_info.len;
	}
	if (data->party_v_info.len) {
		acvp_info[ptr++] = 0xA1;
		acvp_info[ptr++] = (unsigned char) data->party_v_info.len;
		memcpy(&acvp_info[ptr], data->party_v_info.buf,
		       data->party_v_info.len);
		ptr += data->party_v_info.len;
	}
	if (data->supp_pub_info.len) {
		acvp_info[ptr++] = 0xA2;
		acvp_info[ptr++] = (unsigned char) data->supp_pub_info.len;
		memcpy(&acvp_info[ptr], data->supp_pub_info.buf,
		       data->supp_pub_info.len);
		ptr += data->supp_pub_info.len;
	}
	if (data->supp_priv_info.len) {
		acvp_info[ptr++] = 0xA3;
		acvp_info[ptr++] = (unsigned char) data->supp_priv_info.len;
		memcpy(&acvp_info[ptr], data->supp_priv_info.buf,
		       data->supp_priv_info.len);
		ptr += data->supp_priv_info.len;
	}

	kdf = EVP_KDF_fetch(NULL, "X942KDF", NULL);
	CKNULL_LOG(kdf, -EFAULT, "Cannot allocate ANSI X9.42 KDF\n");
	ctx = EVP_KDF_CTX_new(kdf);
	CKNULL_LOG(ctx, -EFAULT, "Cannot allocate ANSI X9.42 KDF context\n");

	p = params;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
						(char *)EVP_MD_name(md), 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
						 data->zz.buf, data->zz.len);
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG,
						(char *)cekalg, 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_X942_ACVPINFO,
						 acvp_info, ptr);
	*p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_X942_USE_KEYBITS,
					&use_keybits);
	*p = OSSL_PARAM_construct_end();

	CKINT(alloc_buf(data->key_len / 8, &data->derived_key));
	CKINT_O(EVP_KDF_derive(ctx, data->derived_key.buf,
			       data->derived_key.len, params));

out:
	if (kdf)
		EVP_KDF_free(kdf);
	if (ctx)
		EVP_KDF_CTX_free(ctx);
	return ret;
}


static struct ansi_x942_backend openssl_ansi_x942 =
{
	openssl_ansi_x942_kdf,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_ansi_x942_backend)
static void openssl_ansi_x942_backend(void)
{
	register_ansi_x942_impl(&openssl_ansi_x942);
}

/************************************************
 * ANSI X9.63 KDF interface functions
 ************************************************/

static int openssl_ansi_x963_kdf(struct ansi_x963_data *data,
				 flags_t parsed_flags)
{
	const EVP_MD *md;
	EVP_KDF *kdf = NULL;
	EVP_KDF_CTX *ctx = NULL;
	OSSL_PARAM params[4], *p;
	int ret = 0;

	(void)parsed_flags;

	CKINT(openssl_md_convert(data->hashalg, &md));

	kdf = EVP_KDF_fetch(NULL, "X963KDF", NULL);
	CKNULL_LOG(kdf, -EFAULT, "Cannot allocate ANSI X9.63 KDF\n");
	ctx = EVP_KDF_CTX_new(kdf);
	CKNULL_LOG(ctx, -EFAULT, "Cannot allocate ANSI X9.63 KDF context\n");

	p = params;
	*p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
						(char *)EVP_MD_name(md), 0);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
						 data->z.buf, data->z.len);
	*p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
						 data->shared_info.buf,
						 data->shared_info.len);
	*p = OSSL_PARAM_construct_end();

	CKINT(alloc_buf(data->key_data_len / 8, &data->key_data));
	CKINT_O(EVP_KDF_derive(ctx, data->key_data.buf,
			       data->key_data.len, params));

out:
	if (kdf)
		EVP_KDF_free(kdf);
	if (ctx)
		EVP_KDF_CTX_free(ctx);
	return ret;
}


static struct ansi_x963_backend openssl_ansi_x963 =
{
	openssl_ansi_x963_kdf,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_ansi_x963_backend)
static void openssl_ansi_x963_backend(void)
{
	register_ansi_x963_impl(&openssl_ansi_x963);
}
