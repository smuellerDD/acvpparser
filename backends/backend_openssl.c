/*
 * Copyright (C) 2018, Stephan Müller <smueller@chronox.de>
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
 * The code uses the interface offered by OpenSSL provided with
 * Fedora 29.
 */

#include <errno.h>
#include <openssl/aes.h>
#include <openssl/cmac.h>
#include <openssl/crypto.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/fips.h>
#include <openssl/fips_rand.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/modes.h>
#include <openssl/kdf.h>
#include <stdlib.h>
#include <string.h>

#include "backend_common.h"

#define CKINT_O(x) {							\
	ret = x;							\
	if (ret != 1) {							\
		ret = -EFAULT;						\
		goto out;						\
	}								\
}

#define CKINT_O_LOG(x, ...) {						\
	ret = x;							\
	if (ret != 1) {							\
		ret = -EFAULT;						\
		logger(LOGGER_ERR,  __VA_ARGS__);			\
		goto out;						\
	}								\
}

ACVP_DEFINE_CONSTRUCTOR(openssl_backend_init)
static void openssl_backend_init(void)
{
	FIPS_mode_set(1);
}

/************************************************
 * Symmetric cipher interface functions
 ************************************************/

static int openssl_cipher(uint64_t cipher, uint32_t keylen,
			  const EVP_CIPHER **type)
{
	int ret = 0;
	const EVP_CIPHER *l_type = NULL;
	const char *algo;

	CKINT(convert_cipher_algo(cipher, &algo));

	logger(LOGGER_DEBUG, "Key size = %u\n", keylen);
	logger(LOGGER_DEBUG, "Cipher = %s\n", algo);

	switch (cipher) {
	case ACVP_ECB:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_ecb();
			break;
		case 24:
			l_type = EVP_aes_192_ecb();
			break;
		case 32:
			l_type = EVP_aes_256_ecb();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_CBC:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_cbc();
			break;
		case 24:
			l_type = EVP_aes_192_cbc();
			break;
		case 32:
			l_type = EVP_aes_256_cbc();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_OFB:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_ofb();
			break;
		case 24:
			l_type = EVP_aes_192_ofb();
			break;
		case 32:
			l_type = EVP_aes_256_ofb();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_CFB1:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_cfb1();
			break;
		case 24:
			l_type = EVP_aes_192_cfb1();
			break;
		case 32:
			l_type = EVP_aes_256_cfb1();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_CFB8:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_cfb8();
			break;
		case 24:
			l_type = EVP_aes_192_cfb8();
			break;
		case 32:
			l_type = EVP_aes_256_cfb8();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_CFB128:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_cfb();
			break;
		case 24:
			l_type = EVP_aes_192_cfb();
			break;
		case 32:
			l_type = EVP_aes_256_cfb();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_CTR:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_ctr();
			break;
		case 24:
			l_type = EVP_aes_192_ctr();
			break;
		case 32:
			l_type = EVP_aes_256_ctr();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;

	case ACVP_GCM:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_gcm();
			break;
		case 24:
			l_type = EVP_aes_192_gcm();
			break;
		case 32:
			l_type = EVP_aes_256_gcm();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_CCM:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_ccm();
			break;
		case 24:
			l_type = EVP_aes_192_ccm();
			break;
		case 32:
			l_type = EVP_aes_256_ccm();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_XTS:
		switch (keylen) {
		case 32:
			l_type = EVP_aes_128_xts();
			break;
		case 64:
			l_type = EVP_aes_256_xts();
			break;
		case 48:
			logger(LOGGER_WARN, "Key size not supported\n");
			ret = -EINVAL;
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_TDESECB:
		l_type = EVP_des_ede3_ecb();
		break;
	case ACVP_TDESCBC:
		l_type = EVP_des_ede3_cbc();
		break;
	case ACVP_TDESCFB1:
		l_type = EVP_des_ede3_cfb1();
		break;
	case ACVP_TDESCFB8:
		l_type = EVP_des_ede3_cfb8();
		break;
	case ACVP_TDESCFB64:
		l_type = EVP_des_ede3_cfb64();
		break;
	case ACVP_TDESOFB:
		l_type = EVP_des_ede3_ofb();
		break;

	case ACVP_AESCMAC:
		switch (keylen) {
		case 16:
			l_type = EVP_aes_128_cbc();
			break;
		case 24:
			l_type = EVP_aes_192_cbc();
			break;
		case 32:
			l_type = EVP_aes_256_cbc();
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
		}
		break;
	case ACVP_TDESCMAC:
		l_type = EVP_des_ede3_cbc();
		break;
	default:
		logger(LOGGER_WARN, "Unknown cipher\n");
		ret = -EINVAL;
	}

	*type = l_type;

out:
	return ret;
}

static int openssl_md_convert(uint64_t cipher, const EVP_MD **type)
{
	int ret = 0;
	const EVP_MD *l_type = NULL;
	const char *algo;

	CKINT(convert_cipher_algo(cipher & (ACVP_HASHMASK | ACVP_HMACMASK),
				  &algo));

	logger(LOGGER_DEBUG, "SHA = %s\n", algo);

	switch (cipher & (ACVP_HASHMASK | ACVP_HMACMASK)) {
	case ACVP_HMACSHA1:
	case ACVP_SHA1:
		l_type = EVP_sha1();
		break;
	case ACVP_HMACSHA2_224:
	case ACVP_SHA224:
		l_type = EVP_sha224();
		break;
	case ACVP_HMACSHA2_256:
	case ACVP_SHA256:
		l_type = EVP_sha256();
		break;
	case ACVP_HMACSHA2_384:
	case ACVP_SHA384:
		l_type = EVP_sha384();
		break;
	case ACVP_HMACSHA2_512:
	case ACVP_SHA512:
		l_type = EVP_sha512();
		break;
	default:
		logger(LOGGER_WARN, "Unknown cipher\n");
		ret = -EINVAL;
	}

	*type = l_type;

out:
	return ret;
}

static int openssl_bn2buf(const BIGNUM *number, struct buffer *buf,
			  uint32_t bufsize)
{
	int ret;

	CKINT(alloc_buf(bufsize, buf));
	if (!BN_bn2bin(number, buf->buf + bufsize - BN_num_bytes(number)))
		return -EFAULT;

	logger_binary(LOGGER_DEBUG, buf->buf, buf->len, "bn2bin");

out:
	return ret;
}

static int openssl_bn2buffer(const BIGNUM *number, struct buffer *buf)
{
	return openssl_bn2buf(number, buf, BN_num_bytes(number));
}

static int openssl_mct_init(struct sym_data *data, flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *type = NULL;
	int ret = 0;

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	if (parsed_flags & FLAG_OP_ENC)
		ret = EVP_EncryptInit_ex(ctx, type, NULL, data->key.buf,
					 data->iv.buf);
	else
		ret = EVP_DecryptInit_ex(ctx, type, NULL, data->key.buf,
					 data->iv.buf);
	if (ret != 1) {
		logger(LOGGER_WARN, "Cipher init failed\n");
		ret = -EFAULT;
		goto out;
	}

	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");
	logger_binary(LOGGER_DEBUG, data->iv.buf, data->iv.len, "iv");

	if (data->cipher == ACVP_TDESCFB1 || data->cipher == ACVP_CFB1)
		EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS);

	data->priv = ctx;

	return 0;

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return ret;
}

#define SEMIBSIZE 8
static int openssl_mct_update(struct sym_data *data, flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) data->priv;
	size_t origlen = data->data.len;

	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      (parsed_flags & FLAG_OP_ENC) ?
		      "plaintext" : "ciphertext");

	/* For CFB-1 the data is given in bits */
	if ((data->cipher == ACVP_TDESCFB1 || data->cipher == ACVP_CFB1) &&
	    data->data_len_bits) {
		if (data->data_len_bits > (data->data.len << 3)) {
			logger(LOGGER_ERR,
			       "Data length bits (%u bits) is larger than provided data (%u bytes)\n",
			       data->data_len_bits, data->data.len);
			return -EINVAL;
		}
		origlen = data->data.len;
		data->data.len = data->data_len_bits;
	}

	if (1 != EVP_Cipher(ctx, data->data.buf, data->data.buf,
			    data->data.len)) {
		logger(LOGGER_DEBUG, "Update failed");
		return -EFAULT;
	}

	if (data->data.len != origlen)
		data->data.len = origlen;

	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      (parsed_flags & FLAG_OP_ENC) ?
		      "ciphertext" : "plaintext");

	return 0;
}

static int openssl_mct_fini(struct sym_data *data, flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) data->priv;

	(void)parsed_flags;

	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	data->priv = NULL;

	return 0;
}

static int openssl_tdes_get_last_iv(struct sym_data *data, struct buffer *iv,
				    flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = (EVP_CIPHER_CTX *) data->priv;

	(void)parsed_flags;

	if (iv->len != (uint32_t)EVP_CIPHER_CTX_iv_length(ctx)) {
		logger(LOGGER_WARN,
		       "Expected and real IV length do not match\n");
		return -EINVAL;
	}

	memcpy(iv->buf, EVP_CIPHER_CTX_iv(ctx), iv->len);

	return 0;
}

static int openssl_kw_encrypt(struct sym_data *data, flags_t parsed_flags)
{
	AES_KEY AESkey;
	BUFFER_INIT(ct);
	size_t buflen;
	int ret;

	(void)parsed_flags;

	/*
	 * Round up to the nearest AES block boundary as input data for KWP
	 * is not block-aligned.
	 */
	buflen = ((data->data.len + 15) / 16) * 16;
	buflen += SEMIBSIZE;

	CKINT(alloc_buf(buflen, &ct));

	AES_set_encrypt_key(data->key.buf, data->key.len<<3, &AESkey);

	if (data->cipher == ACVP_KW) {
		ret = CRYPTO_128_wrap(&AESkey, NULL, ct.buf,
				      data->data.buf,
				      data->data.len,
				      (block128_f)AES_encrypt);
	} else {
		ret = CRYPTO_128_wrap_pad(&AESkey, NULL, ct.buf,
					  data->data.buf,
					  data->data.len,
					  (block128_f)AES_encrypt);
	}

	free_buf(&data->data);
	copy_ptr_buf(&data->data, &ct);

	if (ret <= 0) {
		logger(LOGGER_WARN, "AES KW encrypt failed: %d\n", ret);
		ret = -EFAULT;
		goto out;
	}

	ret = 0;

out:
	return ret;
}

static int openssl_kw_decrypt(struct sym_data *data, flags_t parsed_flags)
{
	AES_KEY AESkey;
	int ret;

	(void)parsed_flags;

	AES_set_decrypt_key(data->key.buf, data->key.len<<3, &AESkey);

	if (data->cipher == ACVP_KW) {
		ret = CRYPTO_128_unwrap(&AESkey, NULL, data->data.buf,
					data->data.buf,
					data->data.len,
					(block128_f)AES_decrypt);
		/* Plaintext data block is smaller by one semiblock */
		if (data->data.len >= SEMIBSIZE)
			data->data.len -= SEMIBSIZE;
	} else {
		ret = CRYPTO_128_unwrap_pad(&AESkey, NULL, data->data.buf,
					    data->data.buf,
					    data->data.len,
					    (block128_f)AES_decrypt);

		if (ret > 0)
			data->data.len = ret;
	}

	if (ret <= 0) {
		if (data->data.len >= CIPHER_DECRYPTION_FAILED_LEN) {
			memcpy(data->data.buf, CIPHER_DECRYPTION_FAILED,
			       CIPHER_DECRYPTION_FAILED_LEN);
			data->data.len = CIPHER_DECRYPTION_FAILED_LEN;
		} else {
			logger(LOGGER_WARN, "AES KW decrypt failed\n");
			ret = -EFAULT;
			goto out;
		}
	}

	ret = 0;

out:
	return ret;
}

static int openssl_encrypt(struct sym_data *data, flags_t parsed_flags)
{
	int ret;

	if (data->cipher == ACVP_KW || data->cipher == ACVP_KWP)
		return openssl_kw_encrypt(data, parsed_flags);

	CKINT(openssl_mct_init(data, parsed_flags));

	ret = openssl_mct_update(data, parsed_flags);

	openssl_mct_fini(data, parsed_flags);

out:
	return ret;
}

static int openssl_decrypt(struct sym_data *data, flags_t parsed_flags)
{
	int ret;

	if (data->cipher == ACVP_KW || data->cipher == ACVP_KWP)
		return openssl_kw_decrypt(data, parsed_flags);

	CKINT(openssl_mct_init(data, parsed_flags));

	ret = openssl_mct_update(data, parsed_flags);

	openssl_mct_fini(data, parsed_flags);

out:
	return ret;
}

static struct sym_backend openssl_sym =
{
	openssl_encrypt,
	openssl_decrypt,
	openssl_mct_init,
	openssl_mct_update,
	openssl_mct_fini,
	openssl_tdes_get_last_iv
};

ACVP_DEFINE_CONSTRUCTOR(openssl_sym_backend)
static void openssl_sym_backend(void)
{
	register_sym_impl(&openssl_sym);
}

/************************************************
 * CMAC/HMAC cipher interface functions
 ************************************************/
static int openssl_cmac_generate(struct hmac_data *data)
{
	const EVP_CIPHER *type = NULL;
	CMAC_CTX *ctx = NULL;
	int blocklen;
	int ret = 0;

	ctx = CMAC_CTX_new();
	CKNULL(ctx, -ENOMEM);

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");

	CKINT_O_LOG(CMAC_Init(ctx, data->key.buf, data->key.len, type, NULL),
		    "CMAC_Init() failed");

	blocklen = EVP_CIPHER_block_size(type);
	CKINT_LOG(alloc_buf(blocklen, &data->mac),
		  "CMAC buffer cannot be allocated\n");

	logger(LOGGER_DEBUG, "tag length = %d", blocklen);

	CKINT_O_LOG(CMAC_Update(ctx, data->msg.buf, data->msg.len),
		    "CMAC_Update() failed\n");

	CKINT_O_LOG(CMAC_Final(ctx, data->mac.buf, (size_t *) &data->mac.len),
		    "CMAC_Final() failed\n");

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "mac");

	ret = 0;

out:
	if (ctx)
		CMAC_CTX_free(ctx);

	return ret;
}

static int openssl_hmac_generate(struct hmac_data *data)
{
	const EVP_MD *md = NULL;
	unsigned char hmac[EVP_MAX_MD_SIZE];
	unsigned int taglen = data->mac.len;
	int mdlen;
	int ret = 0;

	CKINT(openssl_md_convert(data->cipher, &md));

	mdlen = EVP_MD_size(md);

	CKINT_LOG(alloc_buf(mdlen, &data->mac),
		  "SHA buffer cannot be allocated\n");

	logger(LOGGER_DEBUG, "taglen = %d", data->mac.len);
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");
	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");

	if (!HMAC(md, data->key.buf, data->key.len,
		 data->msg.buf, data->msg.len,
		 hmac, &taglen)) {
		logger(LOGGER_WARN, "HMAC failed\n");
		ret = -EINVAL;
		goto out;
	}

	memcpy(data->mac.buf, hmac, data->mac.len);
	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "hmac");

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
 * SHA cipher interface functions
 ************************************************/
static int openssl_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	int mdlen;
	int ret;

	(void)parsed_flags;

	CKINT(openssl_md_convert(data->cipher, &md));

	mdlen = EVP_MD_size(md);

	CKINT_LOG(alloc_buf(mdlen, &data->mac),
		  "SHA buffer cannot be allocated\n");

	ctx = EVP_MD_CTX_create();
	CKNULL(ctx, -ENOMEM);

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");

	CKINT_O_LOG(EVP_DigestInit(ctx, md), "EVP_DigestInit() failed");

	CKINT_O_LOG(EVP_DigestUpdate(ctx, data->msg.buf, data->msg.len),
		    "EVP_DigestUpdate() failed");

	CKINT_O_LOG(EVP_DigestFinal(ctx, data->mac.buf,
				    (unsigned int *) &data->mac.len),
		    "EVP_DigestFinal() failed");

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "hash");

	ret = 0;

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);

	return ret;
}

static struct sha_backend openssl_sha =
{
	openssl_sha_generate,   /* hash_generate */
};

ACVP_DEFINE_CONSTRUCTOR(openssl_sha_backend)
static void openssl_sha_backend(void)
{
	register_sha_impl(&openssl_sha);
}

/************************************************
 * AEAD cipher interface functions
 ************************************************/
#define OPENSSL_USE_OFFICIAL_INTERNAL_IV_GEN
static int openssl_gcm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *type = NULL;
	uint32_t taglen = data->taglen / 8;
	uint32_t ivlen = data->ivlen / 8;
	int ret = 0;

	(void)parsed_flags;

	if (data->iv.len && data->iv.len < 12) {
		logger(LOGGER_WARN,
		       "IV length must be 12 or higher (see code for EVP_CTRL_AEAD_SET_IVLEN)\n");
		return -EINVAL;
	}

	if (!data->data.len) {
		logger(LOGGER_WARN, "Zero length input data not supported\n");
		return -EINVAL;
	}

	logger_binary(LOGGER_DEBUG, data->iv.buf, data->iv.len, "iv");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");
	logger_binary(LOGGER_DEBUG, data->assoc.buf, data->assoc.len, "AAD");
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "plaintext");

	CKINT(alloc_buf(taglen, &data->tag));

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1),
		    "EVP_CipherInit() failed\n");

	if (data->iv.len) {
		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
						data->iv.len, NULL),
			    "EVP_CIPHER_CTX_ctrl() failed to set the IV length %u\n",
			    data->iv.len);
	} else {
		if (ivlen < 4) {
			logger(LOGGER_WARN, "IV size too small\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
						ivlen, NULL),
			    "EVP_CIPHER_CTX_ctrl() failed to set the IV length %u\n",
			    data->iv.len);

		/*
		 * This code extracts the generated IV and sets it
		 * again with the EVP_CipherInit_ex. The implementation is not
		 * used by the TLS layer.
		 */
#ifndef OPENSSL_USE_OFFICIAL_INTERNAL_IV_GEN
		logger(LOGGER_DEBUG, "Internal IV generation (IV size %u)\n",
		       ivlen);
		/* 96 bit IV */
		CKINT(alloc_buf(ivlen, &data->iv));

		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
						data->iv.len, NULL),
			    "EVP_CIPHER_CTX_ctrl() failed to set the IV length %u\n",
			    data->iv.len);

		CKINT_O(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4,
					    data->iv.buf));
		memcpy(data->iv.buf, EVP_CIPHER_CTX_iv_noconst(ctx),
		       data->iv.len);
#endif
	}

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, NULL, NULL, data->key.buf,
				      data->iv.buf, 1),
		    "EVP_CipherInit_ex() failed\n");

	/*
	 * Generation of IV must come after setting key due to
	 * EVP_CTRL_GCM_IV_GEN implementation and we set a NULL buffer for IV
	 * above.
	 *
	 * This code is used by the TLS layer.
	 */
#ifdef OPENSSL_USE_OFFICIAL_INTERNAL_IV_GEN
	if (!data->iv.len) {
		logger(LOGGER_DEBUG, "Internal IV generation (IV size %u)\n",
		       ivlen);
		/* 96 bit IV */
		CKINT(alloc_buf(ivlen, &data->iv));

		CKINT_O(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4,
					    data->iv.buf));
		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN,
						0, data->iv.buf),
			    "EVP_CIPHER_CTX_ctrl() failed to generate IV %d\n",
			    ret);
	}
#endif

	if (data->assoc.len) {
		CKINT_LOG(EVP_Cipher(ctx, NULL, data->assoc.buf,
				     data->assoc.len),
			  "EVP_EncryptUpdate() AAD failed\n");
	}

	if (EVP_Cipher(ctx, data->data.buf, data->data.buf, data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_WARN,"EVP_Cipher() finaliztion failed\n");
		ret = -EFAULT;
		goto out;
	}
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "ciphertext");

	if (EVP_Cipher(ctx, NULL, NULL, 0) < 0) {
		ret = -EFAULT;
		goto out;
	}

	/* Get the tag */
	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, data->tag.len,
				        data->tag.buf),
	            "EVP_CIPHER_CTX_ctrl() failed with tag length %u\n",
		    data->tag.len);

	logger_binary(LOGGER_DEBUG, data->tag.buf, data->tag.len, "tag");

	ret = 0;

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return ret;
}

static int openssl_gcm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *type;
	int ret;

	(void)parsed_flags;

	if (data->iv.len < 12) {
		logger(LOGGER_WARN,
		       "IV length must be 12 or higher (see code for EVP_CTRL_AEAD_SET_IVLEN)\n");
		return -EINVAL;
	}

	if (!data->data.len) {
		logger(LOGGER_WARN, "Zero length input data not supported\n");
		return -EINVAL;
	}

	logger_binary(LOGGER_DEBUG, data->iv.buf, data->iv.len, "iv");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");
	logger_binary(LOGGER_DEBUG, data->tag.buf, data->tag.len, "tag");
	logger_binary(LOGGER_DEBUG, data->assoc.buf, data->assoc.len, "AAD");
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 0),
		    "EVP_CipherInit() failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
					data->iv.len, NULL),
		    "EVP_CIPHER_CTX_ctrl() for setting IV length failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
					data->tag.len, data->tag.buf),
		    "EVP_CIPHER_CTX_ctrl() for setting tag failed\n");

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, NULL, NULL, data->key.buf,
				      data->iv.buf, 0),
		    "EVP_CipherInit_ex() failed\n");

	if (data->assoc.len) {
		CKINT_LOG(EVP_Cipher(ctx, NULL, data->assoc.buf,
				     data->assoc.len),
			  "EVP_EncryptUpdate() AAD failed\n");
	}

	data->integrity_error = 0;

	if (EVP_Cipher(ctx, data->data.buf, data->data.buf, data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_DEBUG, "EVP_Cipher() finalization failed\n");
		data->integrity_error = 1;
	}

	if (EVP_Cipher(ctx, NULL, NULL, 0) < 0) {
		logger(LOGGER_DEBUG, "EVP_Cipher() finalization failed\n");
		data->integrity_error = 1;
	}

	ret = 0;

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return ret;
}

static int openssl_ccm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *type;
	uint32_t taglen = data->taglen / 8;
	int ret = 0;

	(void)parsed_flags;

	logger_binary(LOGGER_VERBOSE, data->key.buf, data->key.len, "key");
	logger_binary(LOGGER_VERBOSE, data->iv.buf, data->iv.len, "iv");
	logger_binary(LOGGER_VERBOSE, data->assoc.buf, data->assoc.len, "AAD");
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "plaintext");

	CKINT(alloc_buf(taglen, &data->tag));

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1),
		    "EVP_CipherInit_ex() failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
					data->iv.len, NULL),
		    "EVP_CTRL_CCM_SET_IVLEN failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, taglen, NULL),
		    "EVP_CTRL_CCM_SET_TAG failed (%u)\n", taglen);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, NULL, NULL, data->key.buf,
				      data->iv.buf, 1),
		    "EVP_CipherInit_ex() failed\n");

	/* Set the length as defined in the man page */
	if (EVP_Cipher(ctx, NULL, NULL, data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_WARN, "EVP_Cipher() setting length failed\n");
		ret = -EFAULT;
		goto out;
	}

	/* 
	 * Provide any AAD data. This can be called zero or more times as
	 * required
	 */
	if (data->assoc.len) {
		CKINT_LOG(EVP_Cipher(ctx, NULL, data->assoc.buf,
				     data->assoc.len),
			  "EVP_EncryptUpdate() AAD failed\n");
	}

	if (EVP_Cipher(ctx, data->data.buf, data->data.buf, data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_WARN,"EVP_Cipher() finaliztion failed\n");
		ret = -EFAULT;
		goto out;
	}

	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "ciphertext");

	/* Get the tag */
	if (0 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG,
				     data->tag.len, data->tag.buf)) {
		logger(LOGGER_WARN, "EVP_CIPHER_CTX_ctrl failed (len: %u)\n",
		       data->tag.len);
		ret = -EFAULT;
		goto out;
	}
	logger_binary(LOGGER_DEBUG, data->tag.buf, data->tag.len,
		      "Generated tag");

	ret = 0;

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	return ret;
}

static int openssl_ccm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *type;
	int ret;

	(void)parsed_flags;

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	logger_binary(LOGGER_DEBUG, data->iv.buf, data->iv.len, "iv");
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");
	logger_binary(LOGGER_DEBUG, data->tag.buf, data->tag.len, "tag");

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 0),
		    "EVP_CipherInit_ex() failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
					data->iv.len, NULL),
		    "EVP_CTRL_CCM_SET_IVLEN failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
					data->tag.len, data->tag.buf),
		    "EVP_CTRL_CCM_SET_TAG failed (%u)\n", data->tag.len);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, NULL, NULL, data->key.buf,
				       data->iv.buf, 0),
		    "EVP_CipherInit_ex() failed\n");

	/* Set the length as defined in the man page */
	if (EVP_Cipher(ctx, NULL, NULL, data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_WARN, "EVP_Cipher() setting length failed\n");
		ret = -EFAULT;
		goto out;
	}

	if (data->assoc.len != 0) {
		CKINT_LOG(EVP_Cipher(ctx, NULL, data->assoc.buf,
				     data->assoc.len),
			  "EVP_EncryptUpdate() AAD failed\n");
	}

	data->integrity_error = 0;

	if (EVP_Cipher(ctx, data->data.buf, data->data.buf, data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_DEBUG, "EVP_Cipher() finalization failed\n");
		data->integrity_error = 1;
	}

	ret = 0;

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);

	return ret;
}

static struct aead_backend openssl_aead =
{
	openssl_gcm_encrypt,    /* gcm_encrypt */
	openssl_gcm_decrypt,    /* gcm_decrypt */
	openssl_ccm_encrypt,    /* ccm_encrypt */
	openssl_ccm_decrypt,    /* ccm_decrypt */
};

ACVP_DEFINE_CONSTRUCTOR(openssl_aead_backend)
static void openssl_aead_backend(void)
{
	register_aead_impl(&openssl_aead);
}

/************************************************
 * DRBG cipher interface functions
 ************************************************/

struct openssl_test_ent {
	struct buffer *entropy;
	struct buffer *nonce;
};

static size_t openssl_entropy(DRBG_CTX *dctx, unsigned char **pout,
			      int entropy, size_t min_len, size_t max_len)
{
	(void) min_len;
	(void) max_len;
	(void) entropy;
	struct openssl_test_ent *t = FIPS_drbg_get_app_data(dctx);

	*pout = (unsigned char *) t->entropy->buf;

	return t->entropy->len;
}

static size_t openssl_nonce(DRBG_CTX *dctx, unsigned char **pout,
			    int entropy, size_t min_len, size_t max_len)
{
	(void) min_len;
	(void) max_len;
	(void) entropy;
	struct openssl_test_ent *t = FIPS_drbg_get_app_data(dctx);

	*pout = (unsigned char * )t->nonce->buf;

	return t->nonce->len;
}

static int openssl_drbg_generate(struct drbg_data *data, flags_t parsed_flags)
{
	DRBG_CTX *ctx = NULL;
	int nid = NID_undef, df = 0, ret = 0;
	struct openssl_test_ent t;

	(void)parsed_flags;

	logger(LOGGER_DEBUG, "cipher: %lu\n", data->cipher);

	if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA1) {
		nid = ((data->cipher & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				NID_hmacWithSHA1 : NID_sha1;
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA224) {
		nid = ((data->cipher & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				NID_hmacWithSHA224 : NID_sha224;
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA256) {
		nid = ((data->cipher & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				NID_hmacWithSHA256 : NID_sha256;
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA384) {
		nid = ((data->cipher & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				NID_hmacWithSHA384 : NID_sha384;
	} else if ((data->cipher & ACVP_HASHMASK) == ACVP_SHA512) {
		nid = ((data->cipher & ACVP_DRBGMASK) == ACVP_DRBGHMAC) ?
				NID_hmacWithSHA512 : NID_sha512;
	} else if ((data->cipher & ACVP_AESMASK) == ACVP_AES128) {
		nid = NID_aes_128_ctr;
	} else if ((data->cipher & ACVP_AESMASK) == ACVP_AES192) {
		nid = NID_aes_192_ctr;
	} else if ((data->cipher & ACVP_AESMASK) == ACVP_AES256) {
		nid = NID_aes_256_ctr;
	} else {
		logger(LOGGER_WARN, "DRBG with unhandled cipher detected\n");
		return -EFAULT;
	}

	if (data->df)
		df = DRBG_FLAG_CTR_USE_DF;

	ctx = FIPS_drbg_new(nid, df | DRBG_FLAG_TEST);
	CKNULL(ctx, -ENOMEM);

	logger_binary(LOGGER_DEBUG, data->entropy.buf, data->entropy.len,
		      "entropy");
	t.entropy = &data->entropy;

	logger_binary(LOGGER_DEBUG, data->nonce.buf, data->nonce.len, "nonce");
	t.nonce = &data->nonce;
	
	FIPS_drbg_set_callbacks(ctx, openssl_entropy, 0, 0, openssl_nonce, 0);
	FIPS_drbg_set_app_data(ctx, &t);

	logger_binary(LOGGER_DEBUG, data->pers.buf, data->pers.len,
		      "personalization string");

	CKINT_O(FIPS_drbg_instantiate(ctx, data->pers.buf, data->pers.len));

	if (data->entropy_reseed.buffers[0].len) {
		logger_binary(LOGGER_DEBUG,
			      data->entropy_reseed.buffers[0].buf,
			      data->entropy_reseed.buffers[0].len,
			      "entropy reseed");
		t.entropy = &data->entropy_reseed.buffers[0];

		if (data->addtl_reseed.buffers[0].len) {
			logger_binary(LOGGER_DEBUG,
				      data->addtl_reseed.buffers[0].buf,
				      data->addtl_reseed.buffers[0].len,
				      "addtl reseed");
		}
		CKINT_O(FIPS_drbg_reseed(ctx,
					 data->addtl_reseed.buffers[0].buf,
					 data->addtl_reseed.buffers[0].len));
	}

	if (data->pr) {
		logger_binary(LOGGER_DEBUG,
			      data->entropy_generate.buffers[0].buf,
			      data->entropy_generate.buffers[0].len,
			      "entropy generate 1");
		t.entropy = &data->entropy_generate.buffers[0];
	}

	logger_binary(LOGGER_DEBUG, data->addtl_generate.buffers[0].buf,
		      data->addtl_generate.buffers[0].len, "addtl generate 1");

	CKINT(alloc_buf(data->rnd_data_bits_len / 8, &data->random));

	CKINT_O_LOG(FIPS_drbg_generate(ctx, data->random.buf, data->random.len,
				       data->entropy_generate.buffers[0].len?1:0,
				       data->addtl_generate.buffers[0].buf,
				       data->addtl_generate.buffers[0].len),
		    "FIPS_drbg_generate failed\n");

	logger_binary(LOGGER_DEBUG, data->random.buf, data->random.len,
		      "random tmp");

	if (data->pr) {
		logger_binary(LOGGER_DEBUG,
			      data->entropy_generate.buffers[1].buf,
			      data->entropy_generate.buffers[1].len,
			      "entropy generate 2");
		t.entropy = &data->entropy_generate.buffers[1];
	}

	logger_binary(LOGGER_DEBUG, data->addtl_generate.buffers[1].buf,
		      data->addtl_generate.buffers[1].len, "addtl generate 2");

	CKINT_O_LOG(FIPS_drbg_generate(ctx, data->random.buf, data->random.len,
				       data->entropy_generate.buffers[1].len?1:0,
				       data->addtl_generate.buffers[1].buf,
				       data->addtl_generate.buffers[1].len),
		    "FIPS_drbg_generate failed\n");

	logger_binary(LOGGER_DEBUG, data->random.buf, data->random.len,
		      "random");

	ret = 0;

out:
	if (ctx)
		FIPS_drbg_uninstantiate(ctx);

	return ret;
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
 * TLS cipher interface functions
 ************************************************/
/* Copy from ssl/t1_enc.c */
static int tls1_PRF(const EVP_MD *md,
                    const void *seed1, int seed1_len,
                    const void *seed2, int seed2_len,
                    const void *seed3, int seed3_len,
                    const void *seed4, int seed4_len,
                    const void *seed5, int seed5_len,
                    const unsigned char *sec, int slen,
                    unsigned char *out, int olen)
{
	EVP_PKEY_CTX *pctx = NULL;
	int ret = -EFAULT;
	size_t outlen = olen;

	if (md == NULL)
		return -EINVAL;

	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
	if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
		|| EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
		|| EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, slen) <= 0)
		goto err;

	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, seed1_len) <= 0)
		goto err;
	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, seed2_len) <= 0)
		goto err;
	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, seed3_len) <= 0)
		goto err;
	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, seed4_len) <= 0)
		goto err;
	if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, seed5_len) <= 0)
		goto err;

	if (EVP_PKEY_derive(pctx, out, &outlen) <= 0)
		goto err;
	ret = 0;

err:
	EVP_PKEY_CTX_free(pctx);
	return ret;
}

static int openssl_kdf_tls_op(struct kdf_tls_data *data, flags_t parsed_flags)
{
	const EVP_MD *md;
	int ret;

	(void)parsed_flags;

	SSL_library_init();
	SSL_load_error_strings();

	CKINT(openssl_md_convert(data->hashalg, &md));

	/* Special casse */
	if ((data->hashalg & ACVP_HASHMASK) == ACVP_SHA1)
		md = EVP_get_digestbynid(NID_md5_sha1);

	CKINT(alloc_buf(data->pre_master_secret.len, &data->master_secret));

	CKINT_LOG(tls1_PRF(md,
			   TLS_MD_MASTER_SECRET_CONST,
			   TLS_MD_MASTER_SECRET_CONST_SIZE,
			   data->client_hello_random.buf,
			   data->client_hello_random.len, NULL, 0,
			   data->server_hello_random.buf,
			   data->server_hello_random.len, NULL, 0,
			   data->pre_master_secret.buf,
			   data->pre_master_secret.len,
			   data->master_secret.buf,
			   data->master_secret.len),
		  "Generation of master secret failed\n");

	logger_binary(LOGGER_DEBUG, data->master_secret.buf,
		      data->master_secret.len, "master_secret");

	CKINT(alloc_buf(data->key_block_length / 8, &data->key_block));
	CKINT_LOG(tls1_PRF(md,
			   TLS_MD_KEY_EXPANSION_CONST,
			   TLS_MD_KEY_EXPANSION_CONST_SIZE,
			   data->server_random.buf, data->server_random.len,
			   data->client_random.buf, data->client_random.len,
			   NULL, 0, NULL, 0,
			   data->master_secret.buf, data->master_secret.len,
			   data->key_block.buf, data->key_block.len),
		  "Generation of key block failed\n");

	logger_binary(LOGGER_DEBUG, data->key_block.buf, data->key_block.len,
		      "keyblock");

	ret = 0;

out:
	return (ret);
}

static struct kdf_tls_backend openssl_kdf_tls =
{
	openssl_kdf_tls_op,
};

ACVP_DEFINE_CONSTRUCTOR(openssl_kdf_tls_backend)
static void openssl_kdf_tls_backend(void)
{
	register_kdf_tls_impl(&openssl_kdf_tls);
}

/************************************************
 * RSA interface functions
 ************************************************/
static int openssl_rsa_keygen_prime(struct rsa_keygen_prime_data *data,
				    flags_t parsed_flags)
{
	BIGNUM *e = NULL, *p = NULL, *q = NULL;
	RSA *rsa = NULL;
	int ret = 0;

	(void)parsed_flags;

	if (!data->e.len) {
		logger(LOGGER_WARN, "RSA E missing\n");
		return -EINVAL;
	}

	rsa = RSA_new();
	CKNULL(rsa, -ENOMEM);

	logger_binary(LOGGER_DEBUG, data->e.buf, data->e.len, "e");
	logger_binary(LOGGER_DEBUG, data->p.buf, data->p.len, "p");
	logger_binary(LOGGER_DEBUG, data->q.buf, data->q.len, "q");

	e = BN_bin2bn((const unsigned char *) data->e.buf, data->e.len, e);
	CKNULL(e, -ENOMEM);

	p = BN_bin2bn((const unsigned char *) data->p.buf, data->p.len, p);
	CKNULL(p, -ENOMEM);
	if (BN_is_zero(p))
		BN_one(p);

	q = BN_bin2bn((const unsigned char *)data->q.buf, data->q.len, q);
	CKNULL(q, -ENOMEM);
	if (BN_is_zero(q))
		BN_one(q);

	CKINT_O_LOG(RSA_set0_factors(rsa, p, q), "P/Q cannot be set\n");

	ret = RSA_generate_key_ex(rsa, data->modulus, e, NULL);
	if (ret == 1) {
		logger(LOGGER_DEBUG, "RSA_generate_key_ex passed for RSA\n");
		data->keygen_success = 1;
		ret = 0;
	} else if (ret == 0) {
		logger(LOGGER_DEBUG, "RSA_generate_key_ex failed for RSA\n");
		data->keygen_success = 0;
	} else {
		logger(LOGGER_DEBUG,
		       "RSA_generate_key_ex general error for RSA\n");
		ret = -EFAULT;
	}

out:
	if (e)
		BN_free(e);
	if (rsa)
		RSA_free(rsa);

	return ret;
}

static int openssl_rsa_keygen_internal(struct buffer *ebuf, uint32_t modulus,
				       RSA **outkey, struct buffer *nbuf,
				       struct buffer *dbuf, struct buffer *pbuf,
				       struct buffer *qbuf)
{
	BIGNUM *e = NULL;
	const BIGNUM *egen, *n, *d, *p, *q;
	RSA *rsa = NULL;
	int ret = 0;

	if (!ebuf->len) {
		unsigned int a;
		uint8_t bitsset = 0;

		/* WARNING Buffer must be at least 3 bytes in size ! */
		CKINT(alloc_buf(sizeof(unsigned int), ebuf));

		/* generate random odd e */
		RAND_bytes(ebuf->buf, ebuf->len);
		/* make sure it is odd */
		ebuf->buf[ebuf->len - 1] |= 1;

		for (a = 0; a < ebuf->len - 2; a++)
			bitsset |= ebuf->buf[a];

		/* Make sure that value is >= 65537 */
		if (!bitsset)
			ebuf->buf[ebuf->len - 3] |= 1;
	}

	rsa = RSA_new();
	CKNULL(rsa, -ENOMEM);

	logger(LOGGER_DEBUG, "modulus: %u\n", modulus);
	logger_binary(LOGGER_DEBUG, ebuf->buf, ebuf->len, "e");

#if 1
	e = BN_bin2bn((const unsigned char *)ebuf->buf, ebuf->len, e);
	CKNULL(e, -ENOMEM);
#else
	e = BN_new();
	CKNULL(e, -ENOMEM);
	if (1 != BN_set_word(e, 65537)) {
		logger(LOGGER_WARN, "BN_set_word() failed");
		ret = -EFAULT;
		goto out;
	}
#endif

	CKINT_O_LOG(RSA_generate_key_ex(rsa, modulus, e, NULL),
		    "RSA_generate_key_ex() failed: %s\n",
		    ERR_error_string(ERR_get_error(), NULL));

	RSA_get0_key(rsa, &n, &egen, &d);
	RSA_get0_factors(rsa, &p, &q);

	free_buf(ebuf);
	CKINT(openssl_bn2buffer(egen, ebuf));

	if (nbuf)
		CKINT(openssl_bn2buffer(n, nbuf));
	if (dbuf)
		CKINT(openssl_bn2buffer(d, dbuf));
	if (pbuf)
		CKINT(openssl_bn2buffer(p, pbuf));
	if (qbuf)
		CKINT(openssl_bn2buffer(q, qbuf));

	if (outkey) {
		*outkey = rsa;
		rsa = NULL;
	}

	ret = 0;

out:
	if (e)
		BN_free(e);
	if (rsa)
		RSA_free(rsa);

	return ret;
}

static int openssl_rsa_keygen(struct rsa_keygen_data *data,
			      flags_t parsed_flags)
{
	(void)parsed_flags;

	return openssl_rsa_keygen_internal(&data->e, data->modulus, NULL,
					   &data->n, &data->d, &data->p,
					   &data->q);
}

static int openssl_rsa_keygen_en(struct buffer *ebuf, uint32_t modulus,
				 void **privkey, struct buffer *nbuf)
{
	return openssl_rsa_keygen_internal(ebuf, modulus, (RSA **)privkey, nbuf,
					   NULL, NULL, NULL);
}

static void openssl_rsa_free_key(void *privkey)
{
	RSA *rsa = (RSA *)privkey;

	if (rsa)
		RSA_free(rsa);
}

static int openssl_rsa_siggen(struct rsa_siggen_data *data,
			      flags_t parsed_flags)
{
	const EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;
	unsigned int siglen;
	int ret;

	(void)parsed_flags;

	if (!data->privkey) {
		logger(LOGGER_ERR, "Private key missing\n");
		return -EINVAL;
	}

	rsa = data->privkey;

	CKINT(openssl_md_convert(data->cipher, &md));

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");

	pk = EVP_PKEY_new();
	CKNULL(pk, -ENOMEM);

	EVP_PKEY_set1_RSA(pk, rsa);

	CKINT(alloc_buf(RSA_size(rsa), &data->sig));

	ctx = EVP_MD_CTX_create();
	CKNULL(ctx, -ENOMEM);

#if 0
	if (saltlen)
		EVP_MD_CTX_set_flags(&ctx,
                        EVP_MD_CTX_FLAG_PAD_PSS | (Saltlen << 16));

		EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_PAD_X931);
#endif

	if (!EVP_SignInit_ex(ctx, md, NULL)) {
		ret = -EFAULT;
		goto out;
	}

        if (!EVP_SignUpdate(ctx, data->msg.buf, data->msg.len)) {
		ret = -EFAULT;
		goto out;
	}

        if (!EVP_SignFinal(ctx, data->sig.buf, &siglen, pk)) {
		ret = -EFAULT;
		goto out;
	}

	logger_binary(LOGGER_DEBUG, data->sig.buf, data->sig.len, "sig");

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);
	if (pk)
		EVP_PKEY_free(pk);

	return ret;
}

static int openssl_rsa_sigver(struct rsa_sigver_data *data,
			      flags_t parsed_flags)
{
	const EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pk = NULL;
	RSA *rsa = NULL;
	BIGNUM *n = NULL, *e = NULL;
	int ret = 0;

	(void)parsed_flags;

	if (!data->n.len || !data->e.len) {
		logger(LOGGER_WARN, "RSA N or E missing\n");
		return -EINVAL;
	}

	CKINT(left_pad_buf(&data->n, data->modulus / 8));
	CKINT(left_pad_buf(&data->sig, data->modulus / 8));

	n = BN_bin2bn((const unsigned char *)data->n.buf, data->n.len, n);
	CKNULL(n, -ENOMEM);
	e = BN_bin2bn((const unsigned char *)data->e.buf, data->e.len, e);
	CKNULL(e, -ENOMEM);

	CKINT(openssl_md_convert(data->cipher, &md));

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");

	rsa = RSA_new();
	CKNULL(rsa, -ENOMEM);

	CKINT_O_LOG(RSA_set0_key(rsa, n, e, NULL),
		    "Assembly of RSA key failed\n");

	pk = EVP_PKEY_new();
	CKNULL(pk, -ENOMEM);

	EVP_PKEY_set1_RSA(pk, rsa);

	ctx = EVP_MD_CTX_create();
	CKNULL(ctx, -ENOMEM);

#if 0
	if (saltlen)
		EVP_MD_CTX_set_flags(&ctx,
                        EVP_MD_CTX_FLAG_PAD_PSS | (Saltlen << 16));

		EVP_MD_CTX_set_flags(&ctx, EVP_MD_CTX_FLAG_PAD_X931);
#endif

	if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
		ret = -EFAULT;
		goto out;
	}

        if (!EVP_VerifyUpdate(ctx, data->msg.buf, data->msg.len)) {
		ret = -EFAULT;
		goto out;
	}

	ret = EVP_VerifyFinal(ctx, data->sig.buf, data->sig.len, pk);
	if (!ret) {
		logger(LOGGER_DEBUG, "Signature verification: signature bad\n");
		data->sig_result = 0;
	} else if (ret == 1) {
		logger(LOGGER_DEBUG,
		       "Signature verification: signature good\n");
		data->sig_result = 1;
		ret = 0;
	} else {
		logger(LOGGER_WARN,
		       "Signature verification: general error\n");
		ret = -EFAULT;
	}

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);
	if (rsa)
		RSA_free(rsa);
	if (pk)
		EVP_PKEY_free(pk);
	/* n and e do not need to be freed as they belong to the RSA context. */

	return ret;
}

static struct rsa_backend openssl_rsa =
{
	openssl_rsa_keygen,     /* rsa_keygen */
	openssl_rsa_siggen,     /* rsa_siggen */
	openssl_rsa_sigver,     /* rsa_sigver */
	openssl_rsa_keygen_prime,              /* rsa_keygen_prime */
	NULL,		        /* rsa_keygen_prov_prime */
	openssl_rsa_keygen_en,
	openssl_rsa_free_key
};

ACVP_DEFINE_CONSTRUCTOR(openssl_rsa_backend)
static void openssl_rsa_backend(void)
{
	register_rsa_impl(&openssl_rsa);
}

/************************************************
 * DSA interface functions
 ************************************************/

static int _openssl_dsa_pqg_gen(struct buffer *P,
				struct buffer *Q,
				struct buffer *G,
				struct buffer *firstseed,
				uint32_t *counter,
				uint32_t L, uint32_t N, uint64_t cipher)
{
	DSA *dsa = NULL;
	int ret = 0;
	const EVP_MD *md = NULL;
	const BIGNUM *p, *q, *g;
	unsigned long h;
	unsigned char seed[1024];

	dsa = DSA_new();
	CKNULL_LOG(dsa, -ENOMEM, "DSA_new() failed");

	logger(LOGGER_DEBUG, "L = %u\n", L);
	logger(LOGGER_DEBUG, "N = %u\n", N);

	logger(LOGGER_DEBUG, "hash = %lu\n", cipher);
	CKINT(openssl_md_convert(cipher & ACVP_HASHMASK, &md));

	CKINT_O_LOG(FIPS_dsa_builtin_paramgen2(dsa, L, N, md, NULL, 0, 0, seed,
					       (int *)counter, &h, NULL),
		    "FIPS_dsa_builtin_paramgen2() failed\n");

	DSA_get0_pqg(dsa, &p, &q, &g);
	CKINT(openssl_bn2buffer(p, P));
	CKINT(openssl_bn2buffer(q, Q));
	CKINT(openssl_bn2buffer(g, G));

	if (firstseed) {
		CKINT(alloc_buf(EVP_MD_size(md), firstseed));
		memcpy(firstseed->buf, seed, firstseed->len);
	}

	logger_binary(LOGGER_DEBUG, P->buf, P->len, "P");
	logger_binary(LOGGER_DEBUG, Q->buf, Q->len, "Q");
	logger_binary(LOGGER_DEBUG, G->buf, G->len, "G");
	logger(LOGGER_DEBUG, "PQG gen counter: %u\n", *counter);

out:
	if (dsa)
		DSA_free(dsa);

	return ret;
}

static int openssl_dsa_pqggen(struct dsa_pqggen_data *data,
			      flags_t parsed_flags)
{
	DSA *dsa = NULL;
	uint32_t counter;
	int ret;

	(void)parsed_flags;
	CKINT(_openssl_dsa_pqg_gen(&data->P, &data->Q, &data->G, NULL,
				   &counter, data->L, data->N, data->cipher));

out:
	if (dsa)
		DSA_free(dsa);

	return ret;
}

static int openssl_dsa_pq_gen(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;
	return _openssl_dsa_pqg_gen(&data->P, &data->Q, &data->G,
				    &data->pq_prob_domain_param_seed,
				    &data->pq_prob_counter,
				    data->L, data->N, data->cipher);
}

static int openssl_dsa_g_gen(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	DSA *dsa = NULL;
	int ret = 0, pqg_consumed = 0;
	const EVP_MD *md = NULL;
	BIGNUM *p = NULL, *q = NULL, *g = NULL;
	const BIGNUM *g_gen;
	unsigned long h;
	int counter;
	unsigned char seed[1024];

	(void)parsed_flags;

	dsa = DSA_new();
	CKNULL_LOG(dsa, -ENOMEM, "DSA_new() failed\n");

	CKINT(left_pad_buf(&data->P, data->L / 8));
	CKINT(left_pad_buf(&data->Q, data->N / 8));

	logger(LOGGER_DEBUG, "L = %u\n", data->L);
	logger(LOGGER_DEBUG, "N = %u\n", data->N);

	logger_binary(LOGGER_DEBUG, data->P.buf, data->P.len, "P");
	logger_binary(LOGGER_DEBUG, data->Q.buf, data->Q.len, "Q");

	p = BN_bin2bn((const unsigned char *)data->P.buf, data->P.len, NULL);
	CKNULL_LOG(p, -ENOMEM, "BN_bin2bn() failed\n");

	q = BN_bin2bn((const unsigned char *)data->Q.buf, data->Q.len, NULL);
	CKNULL_LOG(q, -ENOMEM, "BN_bin2bn() failed\n");

	g = BN_new();
	CKNULL_LOG(g, -ENOMEM, "BN_new() failed\n");

	CKINT_O_LOG(DSA_set0_pqg(dsa, p, q, g), "DSA_set0_pqg failed\n");
	pqg_consumed = 1;

	logger(LOGGER_DEBUG, "hash = %lu\n", data->cipher);
	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	CKINT_O_LOG(FIPS_dsa_builtin_paramgen2(dsa, data->L, data->N, md,
					       NULL, 0, 0, seed, &counter, &h,
					       NULL),
		    "FIPS_dsa_generate_pq() failed\n");

	DSA_get0_pqg(dsa, NULL, NULL, &g_gen);
	CKINT(openssl_bn2buffer(g_gen, &data->G));

	logger_binary(LOGGER_DEBUG, data->G.buf, data->G.len, "G");

	ret = 0;

out:
	if (dsa)
		DSA_free(dsa);
	if (!pqg_consumed && p)
		BN_free(p);
	if (!pqg_consumed && q)
		BN_free(q);
	if (!pqg_consumed && g)
		BN_free(g);

	return ret;
}

static int openssl_dsa_pq_ver(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	DSA *dsa = NULL;
	int ret = 0;
	const EVP_MD *md = NULL;
	BIGNUM *p = NULL, *q = NULL, *g = NULL;
	const BIGNUM *gen_p, *gen_q, *gen_g;
	unsigned long h = 0;
	int counter = 5;
	unsigned char seed[1024];

	(void)parsed_flags;

	dsa = DSA_new();
	CKNULL_LOG(dsa, -ENOMEM, "DSA_new() failed\n");

	CKINT(left_pad_buf(&data->P, data->L / 8));
	CKINT(left_pad_buf(&data->Q, data->N / 8));
	CKINT(left_pad_buf(&data->pq_prob_domain_param_seed, data->N / 8));

	logger(LOGGER_DEBUG, "L = %u\n", data->L);
	logger(LOGGER_DEBUG, "N = %u\n", data->N);

	logger_binary(LOGGER_DEBUG, data->P.buf, data->P.len, "P");
	logger_binary(LOGGER_DEBUG, data->Q.buf, data->Q.len, "Q");
	logger_binary(LOGGER_DEBUG, data->pq_prob_domain_param_seed.buf,
		      data->pq_prob_domain_param_seed.len,
		      "Domain parameter seed");
	logger(LOGGER_DEBUG, "Counter = %u\n", data->pq_prob_counter);

	p = BN_bin2bn((const unsigned char *)data->P.buf, data->P.len, NULL);
	CKNULL_LOG(p, -ENOMEM, "BN_bin2bn() failed\n");

	q = BN_bin2bn((const unsigned char *)data->Q.buf, data->Q.len, NULL);
	CKNULL_LOG(q, -ENOMEM, "BN_bin2bn() failed\n");

	if (data->G.len)
		g = BN_bin2bn((const unsigned char *)data->G.buf, data->G.len,
			      NULL);
	else
		g = BN_new();
	CKNULL_LOG(g, -ENOMEM, "BN_bin2bn() failed\n");

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	CKINT_O_LOG(FIPS_dsa_builtin_paramgen2(dsa, data->L, data->N, md,
					data->pq_prob_domain_param_seed.buf,
					data->pq_prob_domain_param_seed.len,
					data->pq_prob_counter,
					seed, &counter, &h, NULL),
		    "FIPS_dsa_builtin_paramgen2() failed\n");

	DSA_get0_pqg(dsa, &gen_p, &gen_q, &gen_g);

	data->pqgver_success = 1;
	if (BN_cmp(gen_p, p)) {
		BUFFER_INIT(gen_p_buf);

		CKINT(openssl_bn2buffer(gen_p, &gen_p_buf));
		logger(LOGGER_DEBUG, "P comparision failed\n");
		logger_binary(LOGGER_DEBUG, gen_p_buf.buf, gen_p_buf.len,
			      "gen P");
		free_buf(&gen_p_buf);
		data->pqgver_success = 0;
	}
	if (BN_cmp(gen_q, q)) {
		BUFFER_INIT(gen_q_buf);

		CKINT(openssl_bn2buffer(gen_q, &gen_q_buf));
		logger(LOGGER_DEBUG, "Q comparision failed\n");
		logger_binary(LOGGER_DEBUG, gen_q_buf.buf, gen_q_buf.len,
			      "gen Q");
		free_buf(&gen_q_buf);
		data->pqgver_success = 0;
	}
	if (data->G.len) {
		if (BN_cmp(gen_g, g)) {
			logger(LOGGER_DEBUG, "G comparision failed\n");
			data->pqgver_success = 0;
		}
	}
	if ((uint32_t)counter != data->pq_prob_counter) {
		logger(LOGGER_DEBUG,
		       "Counter mismatch (expected %u, generated %d)\n",
		       data->pq_prob_counter, counter);
		data->pqgver_success = 0;
	}

	ret = 0;

out:
	if (dsa)
		DSA_free(dsa);
	if (p)
		BN_free(p);
	if (q)
		BN_free(q);
	if (g)
		BN_free(g);

	return ret;
}

static int openssl_dsa_pqg_ver(struct dsa_pqg_data *data, flags_t parsed_flags)
{
	DSA *dsa = NULL;
	int ret = 0, pqg_consumed = 0;
	BIGNUM *p = NULL, *q = NULL, *g = NULL;

	(void)parsed_flags;

	dsa = DSA_new();
	CKNULL_LOG(dsa, -ENOMEM, "DSA_new() failed\n");

	CKINT(left_pad_buf(&data->P, data->L / 8));
	CKINT(left_pad_buf(&data->Q, data->N / 8));
	CKINT(left_pad_buf(&data->G, data->L / 8));

	logger(LOGGER_DEBUG, "L = %u\n", data->L);
	logger(LOGGER_DEBUG, "N = %u\n", data->N);

	logger_binary(LOGGER_DEBUG, data->P.buf, data->P.len, "P");
	logger_binary(LOGGER_DEBUG, data->Q.buf, data->Q.len, "Q");
	logger_binary(LOGGER_DEBUG, data->G.buf, data->G.len, "G");

	p = BN_bin2bn((const unsigned char *)data->P.buf, data->P.len, NULL);
	CKNULL_LOG(p, -ENOMEM, "BN_bin2bn() failed\n");

	q = BN_bin2bn((const unsigned char *)data->Q.buf, data->Q.len, NULL);
	CKNULL_LOG(q, -ENOMEM, "BN_bin2bn() failed\n");

	g = BN_bin2bn((const unsigned char *)data->G.buf, data->G.len, NULL);
	CKNULL_LOG(g, -ENOMEM, "BN_bin2bn() failed\n");

	CKINT_O_LOG(DSA_set0_pqg(dsa, p, q, g), "DSA_set0_pqg failed\n");
	pqg_consumed = 1;

	if (1 == FIPS_dsa_paramgen_check_g(dsa)) {
		data->pqgver_success = 1;
		logger(LOGGER_DEBUG, "PQG verification successful\n");
	} else {
		data->pqgver_success = 0;
		logger(LOGGER_DEBUG, "PQG verification failed\n");
	}

	ret = 0;

out:
	if (dsa)
		DSA_free(dsa);
	if (!pqg_consumed && p)
		BN_free(p);
	if (!pqg_consumed && q)
		BN_free(q);
	if (!pqg_consumed && g)
		BN_free(g);

	return ret;
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
	else {
		logger(LOGGER_WARN,
		       "Unknown DSA PQG generation / verification definition (parsed flags: %lu)\n",
		       parsed_flags);
		return -EINVAL;
	}
}

#if 0
static int _openssl_dsa_pqg_gen_public_api(struct buffer *P,
					   struct buffer *Q,
					   struct buffer *G,
					   uint32_t L)
{
	DSA *dsa = NULL;
	int ret = 0;
	const BIGNUM *p, *q, *g;

	dsa = DSA_new();
	CKNULL_LOG(dsa, -ENOMEM, "DSA_new() failed\n");

	logger(LOGGER_DEBUG, "L = %u\n", L);

	/* If L >= 2048, OpenSSL applies N = 256, SHA-256 */
	if (1 != DSA_generate_parameters_ex(dsa, L, NULL, 0, NULL, NULL,
					    NULL)) {
		logger(LOGGER_WARN, "DSA_generate_parameters_ex() failed\n");
		ret = - EFAULT;
		goto out;
	}

	DSA_get0_pqg(dsa, &p, &q, &g);
	CKINT(openssl_bn2buffer(p, P));
	CKINT(openssl_bn2buffer(q, Q));
	CKINT(openssl_bn2buffer(g, G));

	//logger_binary(LOGGER_DEBUG, P->buf, P->len, "P");
	//logger_binary(LOGGER_DEBUG, Q->buf, Q->len, "Q");
	//logger_binary(LOGGER_DEBUG, G->buf, G->len, "G");

out:
	if (dsa)
		DSA_free(dsa);

	return ret;
}
#endif

static int _openssl_dsa_keygen(struct buffer *P /* [in] */,
			       struct buffer *Q /* [in] */,
			       struct buffer *G /* [in] */,
			       struct buffer *X /* [out] */,
			       struct buffer *Y /* [out] */,
			       DSA **dsa)
{
	BIGNUM *p = NULL, *q = NULL, *g = NULL;
	const BIGNUM *x, *y;
	int ret = 0, pqg_consumed = 0;

	*dsa = DSA_new();
	CKNULL_LOG(*dsa, -ENOMEM, "DSA_new() failed\n");

	p = BN_bin2bn((const unsigned char *)P->buf, P->len, NULL);
	CKNULL_LOG(p, -ENOMEM, "BN_bin2bn() failed\n");

	q = BN_bin2bn((const unsigned char *)Q->buf, Q->len, NULL);
	CKNULL_LOG(q, -ENOMEM, "BN_bin2bn() failed\n");

	g = BN_bin2bn((const unsigned char *)G->buf, G->len, NULL);
	CKNULL_LOG(g, -ENOMEM, "BN_bin2bn() failed\n");

	CKINT_O_LOG(DSA_set0_pqg(*dsa, p, q, g), "DSA_set0_pqg failed\n");
	pqg_consumed = 1;

	CKINT_O_LOG(DSA_generate_key(*dsa), "DSA_generate_key() failed\n");

	DSA_get0_key(*dsa, &y, &x);

	CKINT(openssl_bn2buffer(x, X));
	CKINT(openssl_bn2buffer(y, Y));

	//logger_binary(LOGGER_DEBUG, X->buf, X->len, "X");
	//logger_binary(LOGGER_DEBUG, Y->buf, Y->len, "Y");

	ret = 0;

out:
	if (!pqg_consumed && p)
		BN_free(p);
	if (!pqg_consumed && q)
		BN_free(q);
	if (!pqg_consumed && g)
		BN_free(g);

	return ret;
}

static int openssl_dsa_keygen(struct dsa_keygen_data *data,
			      flags_t parsed_flags)
{
	struct dsa_pqggen_data *pqg = &data->pqg;
	DSA *dsa = NULL;
	int ret;

	(void)parsed_flags;
	CKINT(_openssl_dsa_keygen(&pqg->P, &pqg->Q, &pqg->G,
				  &data->X, &data->Y, &dsa));

out:
	if (dsa)
		DSA_free(dsa);

	return ret;
}

static int openssl_dsa_sigver(struct dsa_sigver_data *data,
			      flags_t parsed_flags)
{
	struct dsa_pqggen_data *pqg = &data->pqg;
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	EVP_PKEY *pk = NULL;
	DSA *dsa = NULL;
	DSA_SIG *sig = NULL;
	BIGNUM *p = NULL, *q = NULL, *g = NULL, *y = NULL, *r = NULL, *s = NULL;
	unsigned int sig_len;
	int ret = 0, key_consumed = 0, pqg_consumed = 0, sig_consumed = 0;
	unsigned char sig_buf[1024];
	unsigned char *sig_buf_p = sig_buf;

	(void)parsed_flags;

	dsa = DSA_new();
	CKNULL_LOG(dsa, -ENOMEM, "DSA_new() failed\n");

	sig = DSA_SIG_new();
	CKNULL_LOG(sig, -ENOMEM, "DSA_SIG_new() failed\n");

	CKINT(left_pad_buf(&pqg->P, pqg->L / 8));
	CKINT(left_pad_buf(&pqg->Q, pqg->N / 8));
	CKINT(left_pad_buf(&pqg->G, pqg->L / 8));
	CKINT(left_pad_buf(&data->Y, pqg->L / 8));
	CKINT(left_pad_buf(&data->R, pqg->N / 8));
	CKINT(left_pad_buf(&data->S, pqg->N / 8));

	p = BN_bin2bn((const unsigned char *) pqg->P.buf, pqg->P.len, p);
	CKNULL(p, -ENOMEM);
	q = BN_bin2bn((const unsigned char *) pqg->Q.buf, pqg->Q.len, q);
	CKNULL(q, -ENOMEM);
	g = BN_bin2bn((const unsigned char *) pqg->G.buf, pqg->G.len, g);
	CKNULL(g, -ENOMEM);
	y = BN_bin2bn((const unsigned char *) data->Y.buf, data->Y.len, y);
	CKNULL(y, -ENOMEM);
	r = BN_bin2bn((const unsigned char *) data->R.buf, data->R.len, r);
	CKNULL(r, -ENOMEM);
	s = BN_bin2bn((const unsigned char *) data->S.buf, data->S.len, s);
	CKNULL(s, -ENOMEM);

	CKINT_O_LOG(DSA_set0_pqg(dsa, p, q, g), "DSA_set0_pqg failed\n");
	pqg_consumed = 1;

	CKINT_O_LOG(DSA_set0_key(dsa, y, NULL), "DSA_set0_key failed\n");
	key_consumed = 1;

	CKINT_O_LOG(DSA_SIG_set0(sig, r, s), "DSA_SIG_set0 failed\n");
	sig_consumed = 1;

	logger_binary(LOGGER_DEBUG, pqg->P.buf, pqg->P.len, "P");
	logger_binary(LOGGER_DEBUG, pqg->Q.buf, pqg->Q.len, "Q");
	logger_binary(LOGGER_DEBUG, pqg->G.buf, pqg->G.len, "G");
	logger_binary(LOGGER_DEBUG, data->Y.buf, data->Y.len, "Y");
	logger_binary(LOGGER_DEBUG, data->R.buf, data->R.len, "R");
	logger_binary(LOGGER_DEBUG, data->S.buf, data->S.len, "S");
	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");

	logger(LOGGER_DEBUG, "cipher = %lu\n", data->cipher);

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	pk = EVP_PKEY_new();
	CKNULL(pk, -ENOMEM);

	EVP_PKEY_set1_DSA(pk, dsa);
	sig_len = i2d_DSA_SIG(sig, &sig_buf_p);

	ctx = EVP_MD_CTX_create();
	CKNULL(ctx, -ENOMEM);

	if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
		ret = -EFAULT;
		goto out;
	}

	if (!EVP_VerifyUpdate(ctx, data->msg.buf, data->msg.len)) {
		ret = -EFAULT;
		goto out;
	}

	ret = EVP_VerifyFinal(ctx, sig_buf, sig_len, pk);
	if (!ret) {
		logger(LOGGER_DEBUG, "Signature verification: signature bad\n");
		data->sigver_success = 0;
	} else if (ret == 1) {
		logger(LOGGER_DEBUG,
		       "Signature verification: signature good\n");
		data->sigver_success = 1;
		ret = 0;
	} else {
		logger(LOGGER_WARN,
		       "Signature verification: general error\n");
		ret = -EFAULT;
	}

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);
	if (sig)
		DSA_SIG_free(sig);
	if (dsa)
		DSA_free(dsa);
	if (pk)
		EVP_PKEY_free(pk);

	if (!pqg_consumed && p)
		BN_free(p);
	if (!pqg_consumed && q)
		BN_free(q);
	if (!pqg_consumed && g)
		BN_free(g);
	if (!key_consumed && y)
		BN_free(y);
	if (!sig_consumed && r)
		BN_free(r);
	if (!sig_consumed && s)
		BN_free(s);

	return ret;
}

static int openssl_dsa_keygen_en(struct dsa_pqggen_data *pqg, struct buffer *Y,
				 void **privkey)
{
	DSA *dsa = NULL;
	BUFFER_INIT(X);
	int ret;

	//_openssl_dsa_pqg_gen_public_api(&data->P, &data->Q, &data->G,
	//				      data->L));

	CKINT(_openssl_dsa_keygen(&pqg->P, &pqg->Q, &pqg->G, &X, Y, &dsa));

	*privkey = dsa;

out:
	free_buf(&X);
	return ret;
}

static void openssl_dsa_free_key(void *privkey)
{
	DSA *key = (DSA *)privkey;

	if (key)
		DSA_free(key);
}

static int openssl_dsa_siggen(struct dsa_siggen_data *data,
			      flags_t parsed_flags)
{
	struct dsa_pqggen_data *pqg = &data->pqg;
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pk = NULL;
	const EVP_MD *md = NULL;
	DSA *dsa = NULL;
	DSA_SIG *sig = NULL;
	const BIGNUM *r, *s;
	int ret = 0;
	unsigned int sig_len;
	unsigned char sig_buf[1024];
	const unsigned char *sig_buf_p = sig_buf;

	(void)parsed_flags;

	if (!data->privkey) {
		logger(LOGGER_ERR, "Private key missing\n");
		return -EINVAL;
	}

	dsa = data->privkey;

	logger(LOGGER_DEBUG, "cipher = %lu\n", data->cipher);
	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	//logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");

	pk = EVP_PKEY_new();
	CKNULL(pk, -ENOMEM);

	EVP_PKEY_set1_DSA(pk, dsa);

	ctx = EVP_MD_CTX_create();
	CKNULL(ctx, -ENOMEM);

	if (!EVP_SignInit_ex(ctx, md, NULL)) {
		ret = -EFAULT;
		goto out;
	}

	if (!EVP_SignUpdate(ctx, data->msg.buf, data->msg.len)) {
		ret = -EFAULT;
		goto out;
	}

	if (sizeof(sig_buf) < (unsigned long)EVP_PKEY_size(pk)) {
		logger(LOGGER_ERR,
		       "Programming error, buffer size insufficient\n");
		ret = -ENOMEM;
		goto out;
	}
	if (!EVP_SignFinal(ctx, sig_buf, &sig_len, pk)) {
		ret = -EFAULT;
		goto out;
	}

	d2i_DSA_SIG(&sig, &sig_buf_p, sig_len);

	DSA_SIG_get0(sig, &r, &s);

	CKINT(openssl_bn2buf(r, &data->R, pqg->N / 8));
	CKINT(openssl_bn2buf(s, &data->S, pqg->N / 8));

#if 0
	/* There was an error at one time where the verification failed! */
	{
		struct dsa_sigver_data ver;

		ver.L = data->L;
		ver.N = data->N;
		ver.cipher = data->cipher;
		ver.msg = data->msg;
		ver.P = data->P;
		ver.Q = data->Q;
		ver.G = data->G;
		ver.Y = data->Y;
		ver.R = data->R;
		ver.S = data->S;

		CKINT(openssl_dsa_sigver(&ver, parsed_flags));

		if (!ver.sigver_success) {
			logger(LOGGER_ERR,
			       "Verification of generated signature failed!\n");

			logger_binary(LOGGER_ERR, data->P.buf, data->P.len,
				      "P");
			logger_binary(LOGGER_ERR, data->Q.buf, data->Q.len,
				      "Q");
			logger_binary(LOGGER_ERR, data->G.buf, data->G.len,
				      "G");
			logger_binary(LOGGER_ERR, data->Y.buf, data->Y.len,
				      "Y");
			logger_binary(LOGGER_ERR, data->R.buf, data->R.len,
				      "R");
			logger_binary(LOGGER_ERR, data->S.buf, data->S.len,
				      "S");

			ret = -EFAULT;
			goto out;
		}
	}
#endif

	ret = 0;

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);
	if (pk)
		EVP_PKEY_free(pk);
	if (sig)
		DSA_SIG_free(sig);

	return ret;
}

static struct dsa_backend openssl_dsa =
{
	openssl_dsa_keygen,	/* dsa_keygen */
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

static int _openssl_ecdsa_curves(uint64_t curve, int *out_nid)
{
	int nid;

	logger(LOGGER_DEBUG, "curve : %u\n", curve);

	switch(curve & ACVP_CURVEMASK) {
	case ACVP_NISTP256:
		nid = NID_X9_62_prime256v1;
		break;
	case ACVP_NISTP384:
		nid = NID_secp384r1;
		break;
	case ACVP_NISTP521:
		nid = NID_secp521r1;
		break;
	default:
		logger(LOGGER_ERR, "Unknown curve\n");
		return -EINVAL;
	}

	*out_nid = nid;

	return 0;
}

/* Internal key gen function */
static int _openssl_ecdsa_keygen(uint64_t curve, EC_KEY **out_key)
{
	EC_KEY *key = NULL;
	int ret = 0, nid = 0;

	CKINT_LOG(_openssl_ecdsa_curves(curve, &nid),
		  "Conversion of curve failed\n");

	if (!(key = EC_KEY_new_by_curve_name(nid))) {
		logger(LOGGER_ERR, "EC_KEY_new_by_curve_name() failed\n");
		ret = -EFAULT;
		goto out;
	}

	if (!EC_KEY_generate_key(key)) {
		logger(LOGGER_ERR, "EC_KEY_generate_key() failed\n");
		ret = -EFAULT;
		goto out;
	}

	*out_key = key;

out:
	return ret;
}

static int ec_get_pubkey(EC_KEY *key, BIGNUM *x, BIGNUM *y)
{
	const EC_POINT *pt;
	const EC_GROUP *grp;
	const EC_METHOD *meth;
	int rv = 0;
	BN_CTX *ctx;
	ctx = BN_CTX_new();

	if (!ctx)
		return -EFAULT;

	grp = EC_KEY_get0_group(key);
	pt = EC_KEY_get0_public_key(key);
	meth = EC_GROUP_method_of(grp);
	if (EC_METHOD_get_field_type(meth) == NID_X9_62_prime_field)
		rv = EC_POINT_get_affine_coordinates_GFp(grp, pt, x, y, ctx);
	else
#ifdef OPENSSL_NO_EC2M
	{
		fprintf(stderr, "ERROR: GF2m not supported\n");
		BN_CTX_free(ctx);
		return -EFAULT;
	}
#else
		rv = EC_POINT_get_affine_coordinates_GF2m(grp, pt, x, y, ctx);
#endif

	BN_CTX_free(ctx);

	return rv ? 0 : -EFAULT;
}

static int openssl_ecdsa_keygen(struct ecdsa_keygen_data *data,
				flags_t parsed_flags)
{
	EC_KEY *key = NULL;
	const BIGNUM *d = NULL;
	BIGNUM *Qx = NULL, *Qy = NULL;
	int ret = 0;
	size_t dbufferlen, xbufferlen, ybufferlen;

	(void)parsed_flags;

	Qx = BN_new();
	CKNULL(Qx, -ENOMEM);
	Qy = BN_new();
	CKNULL(Qy, -ENOMEM);

	CKINT(_openssl_ecdsa_keygen(data->cipher, &key));

	CKINT(ec_get_pubkey(key, Qx, Qy));

	d = EC_KEY_get0_private_key(key);

	ecdsa_get_bufferlen(data->cipher, &dbufferlen, &xbufferlen,
			    &ybufferlen);
	CKINT(alloc_buf(dbufferlen, &data->d));
	CKINT(alloc_buf(xbufferlen, &data->Qx));
	CKINT(alloc_buf(ybufferlen, &data->Qy));

	BN_bn2bin(Qx, data->Qx.buf - BN_num_bytes(Qx) + data->Qx.len);
	BN_bn2bin(Qy, data->Qy.buf - BN_num_bytes(Qy) + data->Qy.len);
	BN_bn2bin(d, data->d.buf - BN_num_bytes(d) + data->d.len);

	logger_binary(LOGGER_DEBUG, data->Qx.buf, data->Qx.len, "Qx");
	logger_binary(LOGGER_DEBUG, data->Qy.buf, data->Qy.len, "Qy");
	logger_binary(LOGGER_DEBUG, data->d.buf, data->d.len, "d");

out:
	if (key)
		EC_KEY_free(key);
	if (Qx)
		BN_free(Qx);
	if (Qy)
		BN_free(Qy);

	return ret;
}

static int openssl_ecdsa_pkvver(struct ecdsa_pkvver_data *data,
				flags_t parsed_flags)
{
	int nid = NID_undef, ret = 0;
	BIGNUM *Qx = NULL, *Qy = NULL;
	EC_KEY *key = NULL;

	(void)parsed_flags;

	logger_binary(LOGGER_DEBUG, data->Qx.buf, data->Qx.len, "Qx");
	logger_binary(LOGGER_DEBUG, data->Qy.buf, data->Qy.len, "Qy");

	Qx = BN_bin2bn((const unsigned char *)data->Qx.buf, data->Qx.len, Qx);
	CKNULL(Qx, -ENOMEM);

	Qy = BN_bin2bn((const unsigned char *)data->Qy.buf, data->Qy.len, Qy);
	CKNULL(Qy, -ENOMEM);

	CKINT(_openssl_ecdsa_curves(data->cipher, &nid));

	key = EC_KEY_new_by_curve_name(nid);
	CKNULL(key, -ENOMEM);

	if (1 == EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy)) {
		logger(LOGGER_DEBUG, "ECDSA key successfully verified\n");
		data->keyver_success = 1;
	} else {
		logger(LOGGER_DEBUG, "ECDSA key verification failed\n");
		data->keyver_success = 0;
	}

	ret = 0;

out:
	if (Qx)
		BN_free(Qx);
	if (Qy)
		BN_free(Qy);
	if (key)
		EC_KEY_free(key);

	return ret;
}

static int openssl_ecdsa_keygen_en(uint64_t curve, struct buffer *Qx_buf,
				   struct buffer *Qy_buf, void **privkey)
{
	EC_KEY *key = NULL;
	BIGNUM *Qx = NULL, *Qy = NULL;
	size_t dbufferlen, xbufferlen, ybufferlen;
	int ret;

	Qx = BN_new();
	CKNULL(Qx, -ENOMEM);
	Qy = BN_new();
	CKNULL(Qy, -ENOMEM);

	CKINT(_openssl_ecdsa_keygen(curve, &key));

	CKINT(ec_get_pubkey(key, Qx, Qy));

	ecdsa_get_bufferlen(curve, &dbufferlen, &xbufferlen, &ybufferlen);
	CKINT(alloc_buf(xbufferlen, Qx_buf));
	CKINT(alloc_buf(ybufferlen, Qy_buf));

	BN_bn2bin(Qx, Qx_buf->buf - BN_num_bytes(Qx) + Qx_buf->len);
	BN_bn2bin(Qy, Qy_buf->buf - BN_num_bytes(Qy) + Qy_buf->len);

	logger_binary(LOGGER_DEBUG, Qx_buf->buf, Qx_buf->len, "Qx");
	logger_binary(LOGGER_DEBUG, Qy_buf->buf, Qy_buf->len, "Qy");

	*privkey = key;

out:
	if (ret && key)
		EC_KEY_free(key);
	if (Qx)
		BN_free(Qx);
	if (Qy)
		BN_free(Qy);
	return ret;
}

static void openssl_ecdsa_free_key(void *privkey)
{
	EC_KEY *ecdsa = (EC_KEY *)privkey;

	if (ecdsa)
		EC_KEY_free(ecdsa);
}

static int openssl_ecdsa_siggen(struct ecdsa_siggen_data *data,
				flags_t parsed_flags)
{
	EVP_MD_CTX *ctx = NULL;
	EVP_PKEY *pk = NULL;
	const EVP_MD *md = NULL;
	ECDSA_SIG *sig = NULL;
	const BIGNUM *R, *S;
	int ret = 0;
	EC_KEY *key;
	unsigned int sig_len;
	unsigned char sig_buf[1024];
	const unsigned char *sig_buf_p = sig_buf;
	size_t dbufferlen, xbufferlen, ybufferlen;

	(void)parsed_flags;

	if (!data->privkey) {
		logger(LOGGER_ERR, "Private key missing\n");
		return -EINVAL;
	}

	key = data->privkey;

	pk = EVP_PKEY_new();
	CKNULL(pk, -ENOMEM);

	EVP_PKEY_set1_EC_KEY(pk, key);

	ctx = EVP_MD_CTX_create();
	CKNULL(ctx, -EFAULT);

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	if (!EVP_SignInit_ex(ctx, md, NULL)) {
		ret = -EFAULT;
		goto out;
	}

        if (!EVP_SignUpdate(ctx, data->msg.buf, data->msg.len)) {
		ret = -EFAULT;
		goto out;
	}

        if (!EVP_SignFinal(ctx, sig_buf, &sig_len, pk)) {
		ret = -EFAULT;
		goto out;
	}

	d2i_ECDSA_SIG(&sig, &sig_buf_p, sig_len);

	ECDSA_SIG_get0(sig, &R, &S);

	ecdsa_get_bufferlen(data->cipher, &dbufferlen, &xbufferlen,
			    &ybufferlen);
	CKINT(alloc_buf(xbufferlen, &data->R));
	CKINT(alloc_buf(xbufferlen, &data->S));

	BN_bn2bin(R,  data->R.buf -  BN_num_bytes(R) +  data->R.len);
	BN_bn2bin(S,  data->S.buf -  BN_num_bytes(S) +  data->S.len);

	logger_binary(LOGGER_DEBUG, data->R.buf, data->R.len, "R");
	logger_binary(LOGGER_DEBUG, data->S.buf, data->S.len, "S");

	ret = 0;

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);
	if (pk)
		EVP_PKEY_free(pk);
	if (sig)
		ECDSA_SIG_free(sig);

	return ret;
}

static int openssl_ecdsa_sigver(struct ecdsa_sigver_data *data,
				flags_t parsed_flags)
{
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	EVP_PKEY *pk = NULL;
	ECDSA_SIG *sig = NULL;
	BIGNUM *Qx = NULL, *Qy = NULL, *R = NULL, *S = NULL;
	int nid = NID_undef, ret = 0;
	EC_KEY *key = NULL;
	unsigned int sig_len;
	unsigned char sig_buf[1024];
	unsigned char *sig_buf_p = sig_buf;

	(void)parsed_flags;

	logger_binary(LOGGER_DEBUG, data->R.buf, data->R.len, "R");
	logger_binary(LOGGER_DEBUG, data->S.buf, data->S.len, "S");

	sig = ECDSA_SIG_new();
	CKNULL(sig, -EFAULT);

	R = BN_bin2bn((const unsigned char *) data->R.buf, data->R.len, NULL);
	CKNULL(R, -EFAULT);

	S = BN_bin2bn((const unsigned char *) data->S.buf, data->S.len, NULL);
	CKNULL(S, -EFAULT);

	if (1 != ECDSA_SIG_set0(sig, R, S)) {
		ret = -EFAULT;
		goto out;
	}

	CKINT(_openssl_ecdsa_curves(data->cipher, &nid));

	key = EC_KEY_new_by_curve_name(nid);
	CKNULL(key, -EFAULT);

	logger_binary(LOGGER_DEBUG, data->Qx.buf, data->Qx.len, "Qx");
	logger_binary(LOGGER_DEBUG, data->Qy.buf, data->Qy.len, "Qy");

	Qx = BN_bin2bn((const unsigned char *) data->Qx.buf, data->Qx.len,
		       NULL);
	CKNULL(Qx, -EFAULT);

	Qy = BN_bin2bn((const unsigned char *) data->Qy.buf, data->Qy.len,
		       NULL);
	CKNULL(Qy, -EFAULT);

	if (1 != EC_KEY_set_public_key_affine_coordinates(key, Qx, Qy)) {
		ret = -EFAULT;
		goto out;
	}

	pk = EVP_PKEY_new();
	CKNULL(pk, -ENOMEM);

	EVP_PKEY_set1_EC_KEY(pk, key);

	sig_len = i2d_ECDSA_SIG(sig, &sig_buf_p);

	ctx = EVP_MD_CTX_create();
	CKNULL(ctx, -ENOMEM);

	CKINT(openssl_md_convert(data->cipher & ACVP_HASHMASK, &md));

	if (!EVP_VerifyInit_ex(ctx, md, NULL)) {
		ret = -EFAULT;
		goto out;
	}

        if (!EVP_VerifyUpdate(ctx, data->msg.buf, data->msg.len)) {
		ret = -EFAULT;
		goto out;
	}

	ret = EVP_VerifyFinal(ctx, sig_buf, sig_len, pk);
	if (!ret) {
		logger(LOGGER_DEBUG, "Signature verification: signature bad\n");
		data->sigver_success = 0;
	} else if (ret == 1) {
		logger(LOGGER_DEBUG,
		       "Signature verification: signature good\n");
		data->sigver_success = 1;
		ret = 0;
	} else {
		logger(LOGGER_WARN,
		       "Signature verification: general error\n");
		ret = -EFAULT;
	}

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);
	if (sig)
		ECDSA_SIG_free(sig);
	if (key)
		EC_KEY_free(key);
	if (pk)
		EVP_PKEY_free(pk);
	if (Qx)
		BN_free(Qx);
	if (Qy)
		BN_free(Qy);

	return ret;
}

static struct ecdsa_backend openssl_ecdsa =
{
	openssl_ecdsa_keygen,   /* ecdsa_keygen_testing */
	NULL,
	openssl_ecdsa_pkvver,   /* ecdsa_pkvver */
	openssl_ecdsa_siggen,   /* ecdsa_siggen */
	openssl_ecdsa_sigver,   /* ecdsa_sigver */
	openssl_ecdsa_keygen_en,
	openssl_ecdsa_free_key

};

ACVP_DEFINE_CONSTRUCTOR(openssl_ecdsa_backend)
static void openssl_ecdsa_backend(void)
{
	register_ecdsa_impl(&openssl_ecdsa);
}

/************************************************
 * DH interface functions
 ************************************************/
static int openssl_hash_ss(uint64_t cipher, struct buffer *ss,
			   struct buffer *hashzz)
{
	const EVP_MD *md = NULL;
	EVP_MD_CTX *ctx = NULL;
	int ret = 0;

	if (cipher & ACVP_HASHMASK) {
		unsigned char hashzz_tmp[64];
		unsigned int hashlen;
		unsigned int compare = 0;

		CKINT(openssl_md_convert(cipher & ACVP_HASHMASK, &md));

		if (hashzz->len) {
			compare = 1;
		} else {
			CKINT_LOG(alloc_buf(EVP_MD_size(md), hashzz),
				  "Cannot allocate hashzz buffer\n");
			logger(LOGGER_DEBUG,
			       "Hash buffer of size %u allocated\n",
			       hashzz->len);
		}

		ctx = EVP_MD_CTX_create();
		CKNULL(ctx, -ENOMEM);

		CKINT_O_LOG(EVP_DigestInit(ctx, md), "EVP_DigestInit() failed");
		CKINT_O_LOG(EVP_DigestUpdate(ctx, ss->buf, ss->len),
			    "EVP_DigestUpdate() failed");
		CKINT_O_LOG(EVP_DigestFinal(ctx, hashzz_tmp, &hashlen),
			    "EVP_DigestFinal() failed");

		logger_binary(LOGGER_DEBUG, hashzz_tmp, hashlen,
			      "shared secret hash");

		if (compare) {
			logger_binary(LOGGER_DEBUG, hashzz->buf, hashzz->len,
				      "expexted shared secret hash");
			if (memcmp(hashzz->buf, hashzz_tmp, hashzz->len))
				ret = -ENOENT;
			else
				ret = 0;
		} else {
			memcpy(hashzz->buf, &hashzz_tmp, hashzz->len);
		}
	} else {
		hashzz->buf = ss->buf;
		hashzz->len = ss->len;

		/* ensure that free_buf does not free the buffer */
		ss->buf = NULL;
		ss->len = 0;

		logger_binary(LOGGER_DEBUG, hashzz->buf, hashzz->len,
				      "Shared secret");
	}

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);

	return ret;
}

static int openssl_dh_ss_common(uint64_t cipher,
				struct buffer *P,
				struct buffer *Q,
				struct buffer *G,
				struct buffer *Yrem,
				struct buffer *Xloc,
				struct buffer *Yloc,
				struct buffer *hashzz)
{
	DH *dh = NULL;
	BIGNUM *p = NULL, *q = NULL, *g = NULL, *bn_Yrem = NULL,
	       *bn_Xloc = NULL, *bn_Yloc = NULL;
	BUFFER_INIT(ss);
	unsigned int pqg_consumed = 0, localkey_consumed = 0;
	int ret = 0;

	/* Generate the parameters to be used */
	dh = DH_new();
	CKNULL_LOG(dh, -ENOMEM, "DH_new() failed");

	logger_binary(LOGGER_DEBUG, P->buf, P->len, "P");
	logger_binary(LOGGER_DEBUG, Q->buf, Q->len, "Q");
	logger_binary(LOGGER_DEBUG, G->buf, G->len, "G");

	p = BN_bin2bn((const unsigned char *)P->buf, P->len, NULL);
	CKNULL_LOG(p, -ENOMEM, "BN_bin2bn() failed\n");

	q = BN_bin2bn((const unsigned char *)Q->buf, Q->len, NULL);
	CKNULL_LOG(q, -ENOMEM, "BN_bin2bn() failed\n");

	g = BN_bin2bn((const unsigned char *)G->buf, G->len, NULL);
	CKNULL_LOG(g, -ENOMEM, "BN_bin2bn() failed\n");

	if (1 != DH_set0_pqg(dh, p, q, g)) {
		logger(LOGGER_WARN, "DH_set0_pqg failed\n");
		ret = -EFAULT;
		goto out;
	}
	pqg_consumed = 1;

	logger_binary(LOGGER_DEBUG, Yrem->buf, Yrem->len, "Yrem");
	bn_Yrem = BN_bin2bn((const unsigned char *)Yrem->buf, Yrem->len, NULL);
	CKNULL_LOG(bn_Yrem, -ENOMEM, "BN_bin2bn() failed\n");

	if (!Xloc->len || !Yloc->len) {
		const BIGNUM *bn_Yloc, *bn_Xloc;
		CKINT_O_LOG(DH_generate_key(dh), "DH_generate_key failed\n");

		DH_get0_key(dh, &bn_Yloc, &bn_Xloc);

		CKINT(openssl_bn2buffer(bn_Yloc, Yloc));
		logger_binary(LOGGER_DEBUG, Yloc->buf, Yloc->len,
			      "generated Yloc");
	} else {
		logger_binary(LOGGER_DEBUG, Xloc->buf, Xloc->len, "used Xloc");
		bn_Xloc = BN_bin2bn((const unsigned char *)Xloc->buf, Xloc->len,
				    NULL);
		CKNULL_LOG(bn_Xloc, -ENOMEM, "BN_bin2bn() failed\n");

		CKINT_O_LOG(DH_set0_key(dh, NULL, bn_Xloc),
			    "DH_set0_key failed\n");
		localkey_consumed = 1;
	}

	CKINT_LOG(alloc_buf(P->len, &ss), "Cannot allocate ss\n");

	/* Compute the shared secret */
	if (0 > DH_compute_key_padded(ss.buf, bn_Yrem, dh)) {
		logger(LOGGER_DEBUG, "Cannot generate shared secret\n");

		/*
		 * This error may be possible if the key does not match PQG.
		 * In this case, the test is successful nonetheless.
		 */
		ret = -EOPNOTSUPP;
		goto out;
	}
	logger_binary(LOGGER_DEBUG, ss.buf, ss.len, "Generated shared secret");

	/* We do not use CKINT here, because -ENOENT is no real error */
	ret = openssl_hash_ss(cipher, &ss, hashzz);

out:
	if (dh)
		DH_free(dh);
	if (!pqg_consumed && p)
		BN_free(p);
	if (!pqg_consumed && q)
		BN_free(q);
	if (!pqg_consumed && g)
		BN_free(g);

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

	return openssl_dh_ss_common(data->cipher, &data->P, &data->Q, &data->G,
				    &data->Yrem,
				    &data->Xloc, &data->Yloc,
				    &data->hashzz);
}

static int openssl_dh_ss_ver(struct dh_ss_ver_data *data,
			       flags_t parsed_flags)
{
	int ret = openssl_dh_ss_common(data->cipher, &data->P, &data->Q,
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

	EC_KEY *local_key = NULL;
	EC_POINT *remote_pubkey = NULL;
	BN_CTX *c = NULL;
	size_t dbufferlen, xbufferlen, ybufferlen;
	const BIGNUM *d = NULL;
	BIGNUM *Qx = NULL, *Qy = NULL, *localQx = NULL, *localQy = NULL,
	       *locald = NULL;
	EC_GROUP *group = NULL;
	BUFFER_INIT(ss);
	int nid = 0, ret = 0;

	ecdsa_get_bufferlen(cipher, &dbufferlen, &xbufferlen,
			    &ybufferlen);

	CKINT_LOG(_openssl_ecdsa_curves(cipher, &nid),
		  "Conversion of curve failed\n");

	Qx = BN_bin2bn((const unsigned char *)Qxrem->buf, Qxrem->len, Qx);
	CKNULL(Qx, -ENOMEM);

	Qy = BN_bin2bn((const unsigned char *)Qyrem->buf, Qyrem->len, Qy);
	CKNULL(Qy, -ENOMEM);

	/* Generate point of remote public key */
	group = EC_GROUP_new_by_curve_name(nid);
	CKNULL(group, -ENOMEM);

	remote_pubkey = EC_POINT_new(group);
	CKNULL_LOG(remote_pubkey, -ENOMEM, "EC_POINT_new() failed\n");
	c = BN_CTX_new();
	CKNULL_LOG(c, -ENOMEM, "BN_CTX_new failed\n");

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group))
	    == NID_X9_62_prime_field) {
		CKINT_O(EC_POINT_set_affine_coordinates_GFp(group, remote_pubkey,
							  Qx, Qy, c));
	} else {
#ifdef OPENSSL_NO_EC2M
		logger(LOGGER_WARN, "GF2m not supported\n");
		ret = -EFAULT;
		goto out;
#else
		CKINT_O(EC_POINT_set_affine_coordinates_GF2m(group,
							     remote_pubkey,
							     Qx, Qy, c));
#endif
	}

	local_key = EC_KEY_new_by_curve_name(nid);
	CKNULL_LOG(local_key, -ENOMEM, "EC_KEY_new_by_curve_name() failed\n");

	if (!privloc->len || !Qxloc->len || !Qyloc->len) {
		/* Create our own local key */

		if (!privloc->len)
			CKINT(alloc_buf(dbufferlen, privloc));

		if (!Qxloc->len)
			CKINT(alloc_buf(xbufferlen, Qxloc));

		if (!Qyloc->len)
			CKINT(alloc_buf(ybufferlen, Qyloc));

		CKINT_O_LOG(EC_KEY_generate_key(local_key),
			    "Cannot generate local key\n");

		localQx = BN_new();
		CKNULL(localQx, -ENOMEM);
		localQy = BN_new();
		CKNULL(localQy, -ENOMEM);

		CKINT(ec_get_pubkey(local_key, localQx, localQy));

		BN_bn2bin(localQx,
			  Qxloc->buf - BN_num_bytes(localQx) + Qxloc->len);
		BN_bn2bin(localQy,
			  Qyloc->buf - BN_num_bytes(localQy) + Qyloc->len);

		d = EC_KEY_get0_private_key(local_key);

		BN_bn2bin(d, privloc->buf - BN_num_bytes(d) + privloc->len);

		logger_binary(LOGGER_DEBUG, Qxloc->buf, Qxloc->len,
			      "generated local Qx");
		logger_binary(LOGGER_DEBUG, Qyloc->buf, Qyloc->len,
			      "generated local Qy");
		logger_binary(LOGGER_DEBUG, privloc->buf, privloc->len,
			      "generated local private key");
	} else {
		/* Use existing local key */

		localQx = BN_bin2bn((const unsigned char *)Qxloc->buf,
				    Qxloc->len, localQx);
		CKNULL(localQx, -ENOMEM);

		localQy = BN_bin2bn((const unsigned char *)Qyloc->buf,
				    Qyloc->len, localQy);
		CKNULL(localQy, -ENOMEM);

		locald = BN_bin2bn((const unsigned char *)privloc->buf,
				    privloc->len, locald);
		CKNULL(localQy, -ENOMEM);

		ret = EC_KEY_set_private_key(local_key, locald);
		if (ret != 1) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		ret = EC_KEY_set_public_key_affine_coordinates(local_key,
							       localQx,
							       localQy);
		if (ret != 1) {
			ret = -EOPNOTSUPP;
			goto out;
		}
	}

	/* Create buffer for shared secret */
	CKINT(alloc_buf((EC_GROUP_get_degree(group) + 7)/8, &ss));

	if (0 == ECDH_compute_key(ss.buf, ss.len, remote_pubkey,
				  local_key, NULL)) {
		logger(LOGGER_DEBUG, "Cannot generate shared secret\n");

		/*
		 * This error may be possible if the point is not on the curve.
		 * In this case, the test is successful nonetheless.
		 */
		ret = -EOPNOTSUPP;
		goto out;
	}
	logger_binary(LOGGER_DEBUG, ss.buf, ss.len, "Generated shared secret");

	/* We do not use CKINT here, because -ENOENT is no real error */
	ret = openssl_hash_ss(cipher, &ss, hashzz);

out:
	if (c)
		BN_CTX_free(c);
	if (remote_pubkey)
		EC_POINT_free(remote_pubkey);
	if (Qx)
		BN_free(Qx);
	if (Qy)
		BN_free(Qy);
	if (localQx)
		BN_free(localQx);
	if (localQy)
		BN_free(localQy);
	if (locald)
		BN_free(locald);
	if (local_key)
		EC_KEY_free(local_key);
	if (group)
		EC_GROUP_free(group);

	free_buf(&ss);

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
