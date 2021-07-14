/*
 * Copyright (C) 2018 - 2021, Stephan Müller <smueller@chronox.de>
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
 * The code uses the interface offered by OpenSSL provided with
 * Fedora 29.
 */

#include "backend_openssl_common.h"

/************************************************
 * General helper functions
 ************************************************/
int openssl_bn2buf(const BIGNUM *number, struct buffer *buf, uint32_t bufsize)
{
	int ret;

	CKINT(alloc_buf(bufsize, buf));
	if (!BN_bn2bin(number, buf->buf + bufsize - BN_num_bytes(number)))
		return -EFAULT;

	logger_binary(LOGGER_DEBUG, buf->buf, buf->len, "bn2bin");

out:
	return ret;
}

int openssl_bn2buffer(const BIGNUM *number, struct buffer *buf)
{
	return openssl_bn2buf(number, buf, (uint32_t)BN_num_bytes(number));
}

int openssl_cipher(uint64_t cipher, size_t keylen, const EVP_CIPHER **type)
{
	uint64_t mask;
	int ret = 0;
	const EVP_CIPHER *l_type = NULL;
	const char *algo;

	switch (cipher) {
	case ACVP_ECB:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		}
		break;
	case ACVP_CBC:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		}
		break;
	case ACVP_OFB:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		}
		break;
	case ACVP_CFB1:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		}
		break;
	case ACVP_CFB8:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		}
		break;
	case ACVP_CFB128:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		}
		break;
	case ACVP_CTR:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		}
		break;

	case ACVP_GMAC:
	case ACVP_GCM:
		mask = ACVP_CIPHERTYPE_AEAD;
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
			goto out;
		}
		break;
	case ACVP_CCM:
		mask = ACVP_CIPHERTYPE_AEAD;
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
			goto out;
		}
		break;
	case ACVP_XTS:
		mask = ACVP_CIPHERTYPE_AES;
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
			goto out;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
			goto out;
		}
		break;
	case ACVP_TDESECB:
		mask = ACVP_CIPHERTYPE_TDES;
		l_type = EVP_des_ede3_ecb();
		break;
	case ACVP_TDESCBC:
		mask = ACVP_CIPHERTYPE_TDES;
		l_type = EVP_des_ede3_cbc();
		break;
	case ACVP_TDESCFB1:
		mask = ACVP_CIPHERTYPE_TDES;
		l_type = EVP_des_ede3_cfb1();
		break;
	case ACVP_TDESCFB8:
		mask = ACVP_CIPHERTYPE_TDES;
		l_type = EVP_des_ede3_cfb8();
		break;
	case ACVP_TDESCFB64:
		mask = ACVP_CIPHERTYPE_TDES;
		l_type = EVP_des_ede3_cfb64();
		break;
	case ACVP_TDESOFB:
		mask = ACVP_CIPHERTYPE_TDES;
		l_type = EVP_des_ede3_ofb();
		break;

	case ACVP_AESCMAC:
		mask = ACVP_CIPHERTYPE_CMAC;
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
			goto out;
		}
		break;
	case ACVP_TDESCMAC:
		mask = ACVP_CIPHERTYPE_CMAC;
		l_type = EVP_des_ede3_cbc();
		break;
#ifdef OPENSSL_30X
	case ACVP_CBC_CS1:
	case ACVP_CBC_CS2:
	case ACVP_CBC_CS3:
		printf("EVP_CIPHER_fetch\n");
		mask = ACVP_CIPHERTYPE_AES;
		switch (keylen) {
		case 16:
			l_type = EVP_CIPHER_fetch(NULL, "AES-128-CBC-CTS", NULL);;
			break;
		case 24:
			l_type = EVP_CIPHER_fetch(NULL, "AES-192-CBC-CTS", NULL);;
			break;
		case 32:
			l_type = EVP_CIPHER_fetch(NULL, "AES-256-CBC-CTS", NULL);;
			break;
		default:
			logger(LOGGER_WARN, "Unknown key size\n");
			ret = -EINVAL;
			goto out;
		}
		break;
#endif
	default:
		logger(LOGGER_WARN, "Unknown cipher\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(convert_cipher_algo(cipher, mask, &algo));

	logger(LOGGER_DEBUG, "Key size = %zu\n", keylen);
	logger(LOGGER_DEBUG, "Cipher = %s\n", algo);


	*type = l_type;

out:
	return ret;
}

int openssl_md_convert(uint64_t cipher, const EVP_MD **type)
{
	int ret = 0;
	const EVP_MD *l_type = NULL;
	const char *algo;

	CKINT(convert_cipher_algo(cipher & (ACVP_HASHMASK | ACVP_HMACMASK |
					    ACVP_SHAKEMASK),
				  ACVP_CIPHERTYPE_HASH | ACVP_CIPHERTYPE_HMAC | ACVP_CIPHERTYPE_XOF,
				  &algo));

	logger(LOGGER_DEBUG, "SHA = %s\n", algo);

	switch (cipher & (ACVP_HASHMASK | ACVP_HMACMASK | ACVP_SHAKEMASK)) {
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
#ifdef OPENSSL_30X
	case ACVP_HMACSHA2_512224:
	case ACVP_SHA512224:
			l_type = EVP_sha512_224();
			break;
	case ACVP_HMACSHA2_512256:
	case ACVP_SHA512256:
			l_type = EVP_sha512_256();
			break;
#endif
#ifdef OPENSSL_SSH_SHA3
	case ACVP_HMACSHA3_224:
	case ACVP_SHA3_224:
		l_type = EVP_sha3_224();
		break;
	case ACVP_HMACSHA3_256:
	case ACVP_SHA3_256:
		l_type = EVP_sha3_256();
		break;
	case ACVP_HMACSHA3_384:
	case ACVP_SHA3_384:
		l_type = EVP_sha3_384();
		break;
	case ACVP_HMACSHA3_512:
	case ACVP_SHA3_512:
		l_type = EVP_sha3_512();
		break;

	case ACVP_SHAKE128:
		l_type = EVP_shake128();
		break;
	case ACVP_SHAKE256:
		l_type = EVP_shake256();
		break;
#endif

	default:
		logger(LOGGER_WARN, "Unknown cipher\n");
		ret = -EINVAL;
	}

	*type = l_type;

out:
	return ret;
}

int openssl_hash_ss(uint64_t cipher, struct buffer *ss, struct buffer *hashzz)
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
			CKINT_LOG(alloc_buf((size_t)EVP_MD_size(md), hashzz),
					"Cannot allocate hashzz buffer\n");
			logger(LOGGER_DEBUG,
					"Hash buffer of size %zu allocated\n",
					hashzz->len);
		}

		ctx = EVP_MD_CTX_create();
		CKNULL(ctx, -ENOMEM);

		CKINT_O_LOG(EVP_DigestInit(ctx, md),
				"EVP_DigestInit() failed\n");
		CKINT_O_LOG(EVP_DigestUpdate(ctx, ss->buf, ss->len),
				"EVP_DigestUpdate() failed\n");
		CKINT_O_LOG(EVP_DigestFinal(ctx, hashzz_tmp, &hashlen),
				"EVP_DigestFinal() failed\n");

		logger_binary(LOGGER_DEBUG, hashzz_tmp, hashlen,
				"shared secret hash");

		if (compare) {
			logger_binary(LOGGER_DEBUG, hashzz->buf, hashzz->len,
					"expected shared secret hash");
			if (memcmp(hashzz->buf, hashzz_tmp, hashzz->len))
				ret = -ENOENT;
			else
				ret = 0;
		} else {
			memcpy(hashzz->buf, &hashzz_tmp, hashzz->len);
		}
	} else {
		if (hashzz->len) {
			if (ss->len != hashzz->len) {
				logger(LOGGER_ERR, "expected shared secret length is different from calculated shared secret\n");
				ret = -ENOENT;
				goto out;
			}
			logger_binary(LOGGER_DEBUG, hashzz->buf, hashzz->len,
					"expexted shared secret hash");
			if (memcmp(hashzz->buf, ss->buf, hashzz->len))
				ret = -ENOENT;
			else
				ret = 0;
		} else {
			hashzz->buf = ss->buf;
			hashzz->len = ss->len;

			/* ensure that free_buf does not free the buffer */
			ss->buf = NULL;
			ss->len = 0;

			logger_binary(LOGGER_DEBUG, hashzz->buf, hashzz->len,
					"Shared secret");
		}
	}

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);

	return ret;
}

int _openssl_ecdsa_curves(uint64_t curve, int *out_nid, char *digest)
{
	int nid;
	char dgst[50];
	logger(LOGGER_DEBUG, "curve : %" PRIu64 "\n", curve);

	switch (curve & ACVP_CURVEMASK) {
		case ACVP_NISTB163:
			nid = NID_sect163r2;
			strcpy(dgst, "B-163");
			break;
		case ACVP_NISTK163:
			nid = NID_sect163k1;
			strcpy(dgst, "K-163");
			break;
		case ACVP_NISTB233:
			nid = NID_sect233r1;
			strcpy(dgst, "B-233");
			break;
		case ACVP_NISTK233:
			nid = NID_sect233k1;
			strcpy(dgst, "K-233");
			break;
		case ACVP_NISTB283:
			nid = NID_sect283r1;
			strcpy(dgst, "B-283");
			break;
		case ACVP_NISTK283:
			nid = NID_sect283k1;
			strcpy(dgst, "K-283");
			break;
		case ACVP_NISTB409:
			nid = NID_sect409r1;
			strcpy(dgst, "B-409");
			break;
		case ACVP_NISTK409:
			nid = NID_sect409k1;
			strcpy(dgst, "K-409");
			break;
		case ACVP_NISTB571:
			nid = NID_sect571r1;
			strcpy(dgst, "B-571");
			break;
		case ACVP_NISTK571:
			nid = NID_sect571k1;
			strcpy(dgst, "K-571");
			break;
		case ACVP_NISTP192:
			nid = NID_X9_62_prime192v1;
			strcpy(dgst, "P-192");
			break;
		case ACVP_NISTP224:
			nid = NID_secp224r1;
			strcpy(dgst, "P-224");
			break;
		case ACVP_NISTP256:
			nid = NID_X9_62_prime256v1;
			strcpy(dgst, "P-256");
			break;
		case ACVP_NISTP384:
			nid = NID_secp384r1;
			strcpy(dgst, "P-384");
			break;
		case ACVP_NISTP521:
			nid = NID_secp521r1;
			strcpy(dgst, "P-521");
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
			return -EINVAL;
	}

	*out_nid = nid;
	if(digest != NULL){
		strcpy(digest, dgst);
	}
	return 0;
}

#ifdef OPENSSL_SSH_SHA3
static int openssl_shake_cb(EVP_MD_CTX *ctx, unsigned char *md, size_t size)
{
	return EVP_DigestFinalXOF(ctx, md, size);
}
#else
static int openssl_shake_cb(EVP_MD_CTX *ctx, unsigned char *md, size_t size)
{
	(void)ctx;
	(void)md;
	(void)size;
	return -EOPNOTSUPP;
}
#endif

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
		    "EVP_CipherInit() during first call failed\n");

	if (data->iv.len) {
		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
						(int)data->iv.len, NULL),
			    "EVP_CIPHER_CTX_ctrl() failed to set the IV length %zu\n",
			    data->iv.len);
	} else {
		if (ivlen < 4) {
			logger(LOGGER_WARN, "IV size too small\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
						(int)ivlen, NULL),
			    "EVP_CIPHER_CTX_ctrl() failed to set the IV length %zu\n",
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
		    "EVP_CipherInit_ex() during second call failed (%s)\n",
		    ERR_error_string(ERR_get_error(), NULL));

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

		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4,
						data->iv.buf),
			    "EVP_CTRL_GCM_SET_IV_FIXED setting fixed value failed\n");
		CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_IV_GEN,
						0, data->iv.buf),
			    "EVP_CIPHER_CTX_ctrl() failed to generate IV %d\n",
			    ret);
	}
#endif

	if (data->assoc.len) {
		CKINT_LOG(EVP_Cipher(ctx, NULL, data->assoc.buf,
				     (unsigned int)data->assoc.len),
			  "EVP_EncryptUpdate() AAD failed\n");
	}

	if (data->data.len) {
		if (EVP_Cipher(ctx, data->data.buf, data->data.buf,
			       (unsigned int)data->data.len) !=
		    (int)data->data.len) {
			logger(LOGGER_WARN,"EVP_Cipher() finaliztion failed\n");
			ret = -EFAULT;
			goto out;
		}
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
			      "ciphertext");
	}

	if (EVP_Cipher(ctx, NULL, NULL, 0) < 0) {
		logger(LOGGER_ERR, "EVP_Cipher failed %s\n",
		       ERR_error_string(ERR_get_error(), NULL));
		ret = -EFAULT;
		goto out;
	}

	/* Get the tag */
	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
					(int)data->tag.len, data->tag.buf),
		    "EVP_CIPHER_CTX_ctrl() failed with tag length %zu\n",
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
					(int)data->iv.len, NULL),
		    "EVP_CIPHER_CTX_ctrl() for setting IV length failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
					(int)data->tag.len, data->tag.buf),
		    "EVP_CIPHER_CTX_ctrl() for setting tag failed\n");

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, NULL, NULL, data->key.buf,
				      data->iv.buf, 0),
		    "EVP_CipherInit_ex() failed\n");

	if (data->assoc.len) {
		CKINT_LOG(EVP_Cipher(ctx, NULL, data->assoc.buf,
				     (unsigned int)data->assoc.len),
			  "EVP_EncryptUpdate() AAD failed\n");
	}

	data->integrity_error = 0;

	if (data->data.len) {
		if (EVP_Cipher(ctx, data->data.buf, data->data.buf,
			       (unsigned int)data->data.len) !=
		    (int)data->data.len) {
			logger(LOGGER_DEBUG, "EVP_Cipher() finalization failed\n");
			data->integrity_error = 1;
		}
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

	if (!data->data.len) {
		CKINT(alloc_buf(1, &data->data));
		data->data.len = 0;
	}

	CKINT(openssl_cipher(data->cipher, data->key.len, &type));

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1),
		    "EVP_CipherInit_ex() failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
					(int)data->iv.len, NULL),
		    "EVP_CTRL_CCM_SET_IVLEN failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, (int)taglen,
					NULL),
		    "EVP_CTRL_CCM_SET_TAG failed (%u)\n", taglen);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, NULL, NULL, data->key.buf,
				      data->iv.buf, 1),
		    "EVP_CipherInit_ex() failed\n");

	/* Set the length as defined in the man page */
	if (EVP_Cipher(ctx, NULL, NULL, (unsigned int)data->data.len) !=
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
				     (unsigned int)data->assoc.len),
			  "EVP_EncryptUpdate() encrypt AAD failed\n");
	}

	if (EVP_Cipher(ctx, data->data.buf, data->data.buf,
		       (unsigned int)data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_WARN,"EVP_Cipher() finaliztion failed\n");
		ret = -EFAULT;
		goto out;
	}

	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "ciphertext");

	/* Get the tag */
	if (0 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG,
				     (int)data->tag.len, data->tag.buf)) {
		logger(LOGGER_WARN, "EVP_CIPHER_CTX_ctrl failed (len: %zu)\n",
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
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "ciphertext");
	logger_binary(LOGGER_DEBUG, data->tag.buf, data->tag.len, "tag");

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 0),
		    "EVP_CipherInit_ex() failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
					(int)data->iv.len, NULL),
		    "EVP_CTRL_CCM_SET_IVLEN failed\n");

	CKINT_O_LOG(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
					(int)data->tag.len, data->tag.buf),
		    "EVP_CTRL_CCM_SET_TAG failed (%zu)\n", data->tag.len);

	CKINT_O_LOG(EVP_CipherInit_ex(ctx, NULL, NULL, data->key.buf,
				       data->iv.buf, 0),
		    "EVP_CipherInit_ex() failed\n");

	/* Set the length as defined in the man page */
	if (EVP_Cipher(ctx, NULL, NULL, (unsigned int)data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_WARN, "EVP_Cipher() setting length failed\n");
		ret = -EFAULT;
		goto out;
	}

	if (data->assoc.len != 0) {
		CKINT_LOG(EVP_Cipher(ctx, NULL, data->assoc.buf,
				     (unsigned int)data->assoc.len),
			  "EVP_EncryptUpdate() decrypt AAD failed\n");
	}

	data->integrity_error = 0;

	if (EVP_Cipher(ctx, data->data.buf, data->data.buf,
		       (unsigned int)data->data.len) !=
	    (int)data->data.len) {
		logger(LOGGER_DEBUG, "EVP_Cipher() finalization failed\n");
        free_buf(&data->data);
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
 * SHA cipher interface functions
 ************************************************/
static int openssl_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
	EVP_MD_CTX *ctx = NULL;
	const EVP_MD *md = NULL;
	unsigned int maclen = 0;
	int mdlen;
	int ret;

	(void)parsed_flags;

	CKINT(openssl_md_convert(data->cipher, &md));

	if (data->cipher & ACVP_SHAKEMASK)
		mdlen = data->outlen / 8;
	else
		mdlen = EVP_MD_size(md);

	CKINT_LOG(alloc_buf((size_t)mdlen, &data->mac),
		  "SHA buffer cannot be allocated\n");

	ctx = EVP_MD_CTX_create();
	CKNULL_LOG(ctx, -ENOMEM, "MD context not created\n");
	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len, "msg");

	CKINT_O_LOG(EVP_DigestInit(ctx, md), "EVP_DigestInit() failed %s\n",
		    ERR_error_string(ERR_get_error(), NULL));

	CKINT_O_LOG(EVP_DigestUpdate(ctx, data->msg.buf, data->msg.len),
		    "EVP_DigestUpdate() failed\n");

	if (data->cipher & ACVP_SHAKEMASK) {
		CKINT_O_LOG(openssl_shake_cb(ctx, data->mac.buf,
					     data->mac.len),
			    "EVP_DigestFinalXOF() failed\n");
	} else {
		CKINT_O_LOG(EVP_DigestFinal(ctx, data->mac.buf,
					    &maclen),
			    "EVP_DigestFinal() failed\n");
		data->mac.len = (size_t)maclen;
	}

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "hash");

	ret = 0;

out:
	if (ctx)
		EVP_MD_CTX_destroy(ctx);

	return ret;
}

/*
 * Example for SHA MCT inner loop handling in backend
 *
 * This code is meant to be an example - it is meaningless for OpenSSL (but it
 * works!), but when having, say, an HSM where ACVP handling code invoking the
 * HSM crypto code is also found within the HSM, moving this function into that
 * HSM handling code reduces the round trip between the host executing the ACVP
 * parser code and the HSM executing the ACVP handling code a 1000-fold.
 *
 * This code should be invoked with the hash_mct_inner_loop function pointer.
 */
#if 0
#include "parser_sha_mct_helper.h"

static int openssl_hash_inner_loop(struct sha_data *data, flags_t parsed_flags)
{
	switch (data->cipher & (ACVP_HASHMASK |
				ACVP_HMACMASK |
				ACVP_SHAKEMASK)) {
	case ACVP_SHA1:
	case ACVP_SHA224:
	case ACVP_SHA256:
	case ACVP_SHA384:
	case ACVP_SHA512:
		return parser_sha2_inner_loop(data, parsed_flags,
					      openssl_sha_generate);

	case ACVP_SHA3_224:
	case ACVP_SHA3_256:
	case ACVP_SHA3_384:
	case ACVP_SHA3_512:
		return parser_sha3_inner_loop(data, parsed_flags,
					      openssl_sha_generate);

	case ACVP_SHAKE128:
	case ACVP_SHAKE256:
		return parser_shake_inner_loop(data, parsed_flags,
					       openssl_sha_generate);

	default:
		return -EOPNOTSUPP;
	}
}
#endif

static struct sha_backend openssl_sha =
{
	openssl_sha_generate,   /* hash_generate */
	NULL,			/* or use openssl_hash_inner_loop */
};

ACVP_DEFINE_CONSTRUCTOR(openssl_sha_backend)
static void openssl_sha_backend(void)
{
	register_sha_impl(&openssl_sha);
}
