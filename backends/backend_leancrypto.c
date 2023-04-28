/* Backend for leancrypto
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
 */

#include <strings.h>

#include <leancrypto/lc_aes.h>
#include <leancrypto/lc_cshake.h>
#include <leancrypto/lc_hash_drbg.h>
#include <leancrypto/lc_hkdf.h>
#include <leancrypto/lc_hmac.h>
#include <leancrypto/lc_hmac_drbg_sha512.h>
#include <leancrypto/lc_kdf_ctr.h>
#include <leancrypto/lc_kdf_dpi.h>
#include <leancrypto/lc_kdf_fb.h>
#include <leancrypto/lc_kmac.h>
#include <leancrypto/lc_pbkdf2.h>
#include <leancrypto/lc_sha256.h>
#include <leancrypto/lc_sha3.h>
#include <leancrypto/lc_sha512.h>

#include "backend_common.h"
#include "parser_sha_mct_helper.h"

#include "sha3_arm8_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_c.h"
#include "shake_4x_avx2.h"

/************************************************
 * Symmetric cipher interface functions
 ************************************************/
static int lc_cipher_convert(struct sym_data *data, const struct lc_sym **impl)
{
	switch(data->cipher) {
	case ACVP_CBC:
		*impl = lc_aes_cbc;
		break;
	case ACVP_CTR:
		*impl = lc_aes_ctr;
		break;
	case ACVP_KW:
		*impl = lc_aes_kw;
		break;
// 	case ACVP_ECB:
// 		*impl = lc_aes_ecb;
// 		break;
	default:
		return -EINVAL;
	}

	return 0;
}


static int lc_kw_encrypt(struct sym_data *data, flags_t parsed_flags)
{
	LC_SYM_CTX_ON_STACK(aes_kw, lc_aes_kw);
	BUFFER_INIT(ct);
	int ret;

	(void)parsed_flags;

	CKINT(alloc_buf(data->data.len + 8, &ct));

	lc_sym_init(aes_kw);
	CKINT(lc_sym_setkey(aes_kw, data->key.buf, data->key.len));

	/* Output: First 8 bytes are IV, remainder is CT */
	lc_aes_kw_encrypt(aes_kw, data->data.buf, ct.buf, data->data.len);

	free_buf(&data->data);
	copy_ptr_buf(&data->data, &ct);
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "ciphertext");

out:
	return ret;
}

static int lc_kw_decrypt(struct sym_data *data, flags_t parsed_flags)
{
	LC_SYM_CTX_ON_STACK(aes_kw, lc_aes_kw);
	int ret;

	(void)parsed_flags;

	if (data->data.len < 8)
		return -EINVAL;

	lc_sym_init(aes_kw);
	CKINT(lc_sym_setkey(aes_kw, data->key.buf, data->key.len));

	/* Input: First 8 bytes are IV, remainder is CT */
	ret = lc_aes_kw_decrypt(aes_kw, data->data.buf, data->data.buf,
				data->data.len);
	data->data.len -= 8;
	if (ret) {
		if (data->data.len >= CIPHER_DECRYPTION_FAILED_LEN) {
			memcpy(data->data.buf, CIPHER_DECRYPTION_FAILED,
			       CIPHER_DECRYPTION_FAILED_LEN);
			data->data.len = CIPHER_DECRYPTION_FAILED_LEN;
			ret = 0;
			goto out;
		} else {
			logger(LOGGER_WARN, "AES KW encrypt update failed\n");
			ret = -EFAULT;
			goto out;
		}
	} else {
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
			      "plaintext");
	}

out:
	return ret;
}

static int lc_mct_init(struct sym_data *data, flags_t parsed_flags)
{
	const struct lc_sym *impl;
	struct lc_sym_ctx *ctx = NULL;
	int ret;

	(void)parsed_flags;

	CKINT(lc_cipher_convert(data, &impl));

	CKINT(lc_sym_alloc(impl, &ctx));
	lc_sym_init(ctx);
	CKINT(lc_sym_setkey(ctx, data->key.buf, data->key.len));
	logger_binary(LOGGER_DEBUG, data->key.buf, data->key.len, "key");

	if (data->iv.len)
		CKINT(lc_sym_setiv(ctx, data->iv.buf, data->iv.len));

	data->priv = ctx;

	return 0;

out:
	lc_sym_zero_free(ctx);
	return ret;
}

static int lc_mct_update(struct sym_data *data, flags_t parsed_flags)
{
	struct lc_sym_ctx *ctx = (struct lc_sym_ctx *)data->priv;

	if (parsed_flags & FLAG_OP_ENC) {
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
			      "plaintext" );
		lc_sym_encrypt(ctx, data->data.buf, data->data.buf,
			       data->data.len);
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
			      "ciphertext");
	} else {
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
			      "ciphertext" );
		lc_sym_decrypt(ctx, data->data.buf, data->data.buf,
			       data->data.len);
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
			      "plaintext");
	}

	return 0;
}

static int lc_mct_fini(struct sym_data *data, flags_t parsed_flags)
{
	struct lc_sym_ctx *ctx = (struct lc_sym_ctx *)data->priv;

	(void)parsed_flags;

	lc_sym_zero_free(ctx);
	data->priv = NULL;

	return 0;
}

static int lc_crypt(struct sym_data *data, flags_t parsed_flags)
{
	int ret;

	if (data->cipher == ACVP_KW) {
		if (parsed_flags & FLAG_OP_ENC)
			return lc_kw_encrypt(data, parsed_flags);
		else
			return lc_kw_decrypt(data, parsed_flags);
	}

	CKINT(lc_mct_init(data, parsed_flags));

	ret = lc_mct_update(data, parsed_flags);

	lc_mct_fini(data, parsed_flags);

out:
	return ret;
}

static struct sym_backend lc_sym =
{
	lc_crypt,		/* encrypt */
	lc_crypt,		/* decrypt */
	lc_mct_init,		/* mct_init */
	lc_mct_update,		/* mct_update */
	lc_mct_fini,		/* mct_fini */
};

ACVP_DEFINE_CONSTRUCTOR(lc_sym_backend)
static void lc_sym_backend(void)
{
	register_sym_impl(&lc_sym);
}

/************************************************
 * SHA cipher interface functions
 ************************************************/
static int lc_get_hash(uint64_t cipher, const struct lc_hash **lc_hash)
{
	char *envstr = getenv("LC_SHA3");

	switch (cipher) {
	case ACVP_HMACSHA2_256:
	case ACVP_SHA256:
		*lc_hash = lc_sha256;
		return 0;
	case ACVP_HMACSHA2_512:
	case ACVP_SHA512:
		*lc_hash = lc_sha512;
		return 0;
	}

	//printf("Test leancrypto SHA3 %s implementation\n",
	//       envstr ? envstr : "default");

	if (envstr && !strncasecmp(envstr, "C", 1)) {
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_c;
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_c;
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_c;
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_c;
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_c;
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_c;
			break;
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_c;
			break;
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_c;
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else if (envstr && !strncasecmp(envstr, "AVX2", 4)) {
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_avx2;
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_avx2;
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_avx2;
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_avx2;
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_avx2;
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_avx2;
			break;
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_avx2;
			break;
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_avx2;
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else if (envstr && !strncasecmp(envstr, "AVX512", 6)) {
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_avx512;
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_avx512;
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_avx512;
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_avx512;
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_avx512;
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_avx512;
			break;
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_avx512;
			break;
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_avx512;
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else if (envstr && !strncasecmp(envstr, "ARM_NEON", 6)) {
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_arm_neon;
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_arm_neon;
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_arm_neon;
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_arm_neon;
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_arm_neon;
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_arm_neon;
			break;
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_arm_neon;
			break;
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_arm_neon;
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else {
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224;
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256;
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384;
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512;
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128;
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256;
			break;
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128;
			break;
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256;
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	}

	return 0;
}

/************************************************
 * SHA cipher interface functions
 ************************************************/
#ifdef __x86_64__
static int lc_shake4x_generate(struct sha_data *data)
{
	int ret;
	size_t outbytes = data->outlen / 8;
	uint8_t *outbuf0, *outbuf1 = NULL, *outbuf2 = NULL, *outbuf3 = NULL;

	if (!(data->cipher & ACVP_SHAKE128) &&
	    !(data->cipher & ACVP_SHAKE256)) {
		printf("SHAKE4X requires SHAKE test vector\n");
		return -EOPNOTSUPP;
	}

	ret = -posix_memalign((void *)&outbuf0, 32, outbytes);
	if (ret)
		goto out;
	memset(outbuf0, 0, outbytes);
	data->mac.buf = outbuf0;
	data->mac.len = outbytes;

	ret = -posix_memalign((void *)&outbuf1, 32, outbytes);
	if (ret)
		goto out;
	ret = -posix_memalign((void *)&outbuf2, 32, outbytes);
	if (ret)
		goto out;
	ret = -posix_memalign((void *)&outbuf3, 32, outbytes);
	if (ret)
		goto out;

	uint8_t *out0 = outbuf0;
	uint8_t *out1 = outbuf1;
	uint8_t *out2 = outbuf2;
	uint8_t *out3 = outbuf3;

	const uint8_t *in0 = data->msg.buf;
	const uint8_t *in1 = data->msg.buf;
	const uint8_t *in2 = data->msg.buf;
	const uint8_t *in3 = data->msg.buf;
	if (data->cipher == ACVP_SHAKE128) {
		shake128x4(out0, out1, out2, out3, outbytes,
			   in0, in1, in2, in3, data->msg.len);
	} else {
		shake256x4(out0, out1, out2, out3, outbytes,
			   in0, in1, in2, in3, data->msg.len);
	}

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "data read");

	if (memcmp(outbuf0, outbuf1, outbytes)) {
		logger(LOGGER_ERR, "SHAKE lane 1 mismatch with lane 0\n");
		ret = -EFAULT;
	}
	if (memcmp(outbuf0, outbuf2, outbytes)) {
		logger(LOGGER_ERR, "SHAKE lane 2 mismatch with lane 0\n");
		ret = -EFAULT;
	}
	if (memcmp(outbuf0, outbuf3, outbytes)) {
		logger(LOGGER_ERR, "SHAKE lane 3 mismatch with lane 0\n");
		ret = -EFAULT;
	}

out:
	if (outbuf1)
		free(outbuf1);
	if (outbuf2)
		free(outbuf2);
	if (outbuf3)
		free(outbuf3);
	return ret;

}
#else
static int lc_shake4x_generate(struct sha_data *data)
{
	(void)data;
	return -EOPNOTSUPP;
}
#endif

static int lc_hash_generate(struct sha_data *data, flags_t parsed_flags)
{
	char *envstr = getenv("LC_SHAKE");
	const struct lc_hash *lc_hash;
	BUFFER_INIT(msg_p);
	int ret;

	(void)parsed_flags;

	/* Special handling */
	if (envstr && !strncasecmp(envstr, "AVX2-4X", 7))
		return lc_shake4x_generate(data);

	ret = lc_get_hash(data->cipher, &lc_hash);
	if (ret)
		return ret;

	LC_HASH_CTX_ON_STACK(hash, lc_hash);

	CKINT(sha_ldt_helper(data, &msg_p));

	if (data->cipher & ACVP_SHAKEMASK) {
		CKINT_LOG(alloc_buf(data->outlen / 8, &data->mac),
			  "SHA buffer cannot be allocated\n");
	} else {
		CKINT_LOG(alloc_buf(lc_hash_digestsize(hash), &data->mac),
			  "SHA buffer cannot be allocated\n");
	}

	lc_hash_init(hash);
	if (data->cipher & ACVP_SHAKEMASK)
		lc_hash_set_digestsize(hash, data->mac.len);
	lc_hash_update(hash, msg_p.buf, msg_p.len);
	lc_hash_final(hash, data->mac.buf);
	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "data read");

out:
	lc_hash_zero(hash);
	sha_ldt_clear_buf(data, &msg_p);
	return ret;

}

static struct sha_backend lc_sha =
{
	lc_hash_generate,	/* hash_generate */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(lc_sha_backend)
static void lc_sha_backend(void)
{
	register_sha_impl(&lc_sha);
}

/************************************************
 * cSHAKE cipher interface functions
 ************************************************/

static int lc_cshake_generate(struct cshake_data *data, flags_t parsed_flags)
{
	const struct lc_hash *lc_hash;
	int ret;

	(void)parsed_flags;

	ret = lc_get_hash(data->cipher, &lc_hash);
	if (ret)
		return ret;

	LC_HASH_CTX_ON_STACK(cshake, lc_hash);

	CKINT_LOG(alloc_buf(data->outlen >> 3, &data->mac),
		  "Cannot allocate buffer\n");

	lc_cshake_init(cshake,
		       data->function_name.buf, data->function_name.len,
		       data->customization.buf, data->customization.len);
	lc_hash_set_digestsize(cshake, data->mac.len);
	lc_hash_update(cshake, data->msg.buf, data->msg.len);
	lc_hash_final(cshake, data->mac.buf);

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "data read");

out:
	lc_hash_zero(cshake);
	return ret;
}

static struct cshake_backend lc_cshake_backend =
{
	lc_cshake_generate,	/* cshake_generate */
};

ACVP_DEFINE_CONSTRUCTOR(lc_cshake_backend_c)
static void lc_cshake_backend_c(void)
{
	register_cshake_impl(&lc_cshake_backend);
}

/************************************************
 * HMAC cipher interface functions
 ************************************************/

static int lc_hmac_generate(struct hmac_data *data, flags_t parsed_flags)
{
	const struct lc_hash *lc_hash;
	int ret;

	(void)parsed_flags;

	ret = lc_get_hash(data->cipher, &lc_hash);
	if (ret)
		return ret;

	LC_HMAC_CTX_ON_STACK(hmac, lc_hash);

	CKINT_LOG(alloc_buf(lc_hmac_macsize(hmac), &data->mac),
		  "Cannot allocate buffer\n");
	lc_hmac_init(hmac, data->key.buf, data->key.len);
	lc_hmac_update(hmac, data->msg.buf, data->msg.len);
	lc_hmac_final(hmac, data->mac.buf);

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "data read");

out:
	lc_hmac_zero(hmac);
	return ret;
}

static struct hmac_backend lc_hmac_backend =
{
	lc_hmac_generate,	/* hmac_generate */
};

ACVP_DEFINE_CONSTRUCTOR(lc_hmac_backend_c)
static void lc_hmac_backend_c(void)
{
	register_hmac_impl(&lc_hmac_backend);
}

/************************************************
 * KMAC cipher interface functions
 ************************************************/

static int lc_kmac_internal(struct kmac_data *data, int verify)
{
	LC_KMAC_CTX_ON_STACK(kmac256, lc_cshake256);
	LC_KMAC_CTX_ON_STACK(kmac128, lc_cshake128);
	struct lc_kmac_ctx *kmac = (data->cipher == ACVP_KMAC256) ? kmac256 :
								    kmac128;
	BUFFER_INIT(mac);
	int ret;

	if (!verify) {
		CKINT_LOG(alloc_buf(data->maclen >> 3, &data->mac),
			  "Cannot allocate buffer\n");
		mac.buf = data->mac.buf;
		mac.len = data->mac.len;
	} else {
		CKINT_LOG(alloc_buf(data->maclen >> 3, &mac),
			  "Cannot allocate buffer\n");
	}

	lc_kmac_init(kmac, data->key.buf, data->key.len,
		     data->customization.buf, data->customization.len);
	lc_kmac_update(kmac, data->msg.buf, data->msg.len);
	if (data->xof_enabled)
		lc_kmac_final_xof(kmac, mac.buf, mac.len);
	else
		lc_kmac_final(kmac, mac.buf, mac.len);

	logger_binary(LOGGER_DEBUG, mac.buf, mac.len, "data read");

	if (verify) {
		if (mac.len == data->mac.len &&
		    !memcmp(mac.buf, data->mac.buf, mac.len))
			data->verify_result = 1;
		else
			data->verify_result = 0;

		free_buf(&mac);
	}

out:
	lc_kmac_zero(kmac);
	return ret;
}

static int lc_kmac_generate(struct kmac_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;
	return lc_kmac_internal(data, 0);
}

static int lc_kmac_verify(struct kmac_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;
	return lc_kmac_internal(data, 1);
}

static struct kmac_backend lc_kmac_backend =
{
	lc_kmac_generate,	/* kmac_generate */
	lc_kmac_verify
};

ACVP_DEFINE_CONSTRUCTOR(lc_kmac_backend_c)
static void lc_kmac_backend_c(void)
{
	register_kmac_impl(&lc_kmac_backend);
}

/************************************************
 * DRBG cipher interface functions
 ************************************************/

static int lc_drbg_do_test(struct drbg_data *data, struct lc_rng_ctx *drbg)
{
	BUFFER_INIT(tmpentropy);
	int ret = 0;

	/* concatenate entropy and nonce */
	CKINT(alloc_buf(data->entropy.len + data->nonce.len, &tmpentropy));
	memcpy(tmpentropy.buf, data->entropy.buf, data->entropy.len);
	memcpy(tmpentropy.buf + data->entropy.len, data->nonce.buf,
	       data->nonce.len);

	CKINT(alloc_buf(data->rnd_data_bits_len / 8, &data->random));

	CKINT_LOG(lc_rng_seed(drbg, tmpentropy.buf, tmpentropy.len,
			      data->pers.buf, data->pers.len),
		  "DRBG seeding failed\n");

	if (data->entropy_reseed.buffers[0].len) {
		logger_binary(LOGGER_DEBUG,
			      data->entropy_reseed.buffers[0].buf,
			      data->entropy_reseed.buffers[0].len,
			      "entropy reseed");
		CKINT_LOG(lc_rng_seed(drbg,
				      data->entropy_reseed.buffers[0].buf,
				      data->entropy_reseed.buffers[0].len,
				      data->addtl_reseed.buffers[0].buf,
				      data->addtl_reseed.buffers[0].len),
			  "DRBG reseeding failed\n");
	}

	CKINT(lc_rng_generate(drbg,
			      data->addtl_generate.buffers[0].buf,
			      data->addtl_generate.buffers[0].len,
			      data->random.buf, data->random.len));

	CKINT(lc_rng_generate(drbg,
			      data->addtl_generate.buffers[1].buf,
			      data->addtl_generate.buffers[1].len,
			      data->random.buf, data->random.len));

out:
	lc_rng_zero(drbg);
	free_buf(&tmpentropy);
	return ret;
}

static int lc_drbg_test(struct drbg_data *data, flags_t parsed_flags)
{
	int ret;

	(void)parsed_flags;

 	if ((data->type & ACVP_DRBGMASK) == ACVP_DRBGHMAC) {
 		LC_DRBG_HMAC_CTX_ON_STACK(drbg);
 		ret = lc_drbg_do_test(data, drbg);
 	} else {
		LC_DRBG_HASH_CTX_ON_STACK(drbg);
		ret = lc_drbg_do_test(data, drbg);
	}

	return ret;
}

static struct drbg_backend lc_drbg =
{
	lc_drbg_test,	/* drbg_generate */
};

ACVP_DEFINE_CONSTRUCTOR(lc_drbg_backend)
static void lc_drbg_backend(void)
{
	register_drbg_impl(&lc_drbg);
}

/************************************************
 * SP800-108 KDF cipher interface functions
 ************************************************/
static int lc_kdf_108_generate(struct kdf_108_data *data, flags_t parsed_flags)
{
	const struct lc_hash *lc_hash;
	uint32_t derived_key_bytes = data->derived_key_length / 8;
	int ret;

	(void)parsed_flags;

	if (data->derived_key_length % 8) {
		logger(LOGGER_WARN, "Derived key must be byte-aligned\n");
		return-EINVAL;
	}

	if (!(data->mac & ACVP_HMACMASK) && !(data->mac & ACVP_CMACMASK)) {
		logger(LOGGER_WARN, "HMAC or CMAC required (%" PRIu64 ")\n",
		       data->mac);
		return -EINVAL;
	}

	ret = lc_get_hash(data->mac, &lc_hash);
	if (ret)
		return ret;

	LC_HMAC_CTX_ON_STACK(hmac, lc_hash);

	CKINT(alloc_buf(derived_key_bytes, &data->derived_key));

	/* Generate the arbitrary fixed data buffer */
	if (!data->fixed_data.len) {
		CKINT(alloc_buf(lc_hmac_macsize(hmac),
				&data->fixed_data));
		//TODO: fill fixed data with random numbers?
		logger(LOGGER_DEBUG, "Generated fixed data of size %zu\n",
		       data->fixed_data.len);
	}

	if (convert_cipher_match(data->kdfmode, ACVP_KDF_108_DOUBLE_PIPELINE,
				 ACVP_CIPHERTYPE_KDF)) {
		CKINT(lc_kdf_dpi_init(hmac, data->key.buf, data->key.len));
		CKINT_LOG(lc_kdf_dpi_generate(hmac,
					      data->fixed_data.buf,
					      data->fixed_data.len,
					      data->derived_key.buf,
					      data->derived_key.len),
		      "KDF DPI failed\n");
	} else if (convert_cipher_match(data->kdfmode, ACVP_KDF_108_FEEDBACK,
					ACVP_CIPHERTYPE_KDF)) {
		if (data->iv.len < lc_hmac_macsize(hmac)) {
			logger(LOGGER_WARN,
			       "Feedback KDF IV too small (present size %zu, expected minimum %zu)\n",
			       data->fixed_data.len,
			       lc_hmac_macsize(hmac));
			ret = -EINVAL;
			goto out;
		}

		CKINT(lc_kdf_fb_init(hmac, data->key.buf, data->key.len));
		CKINT_LOG(lc_kdf_fb_generate(hmac,
					     data->iv.buf, data->iv.len,
					     data->fixed_data.buf,
					     data->fixed_data.len,
					     data->derived_key.buf,
					     data->derived_key.len),
		      "KDF FB failed\n");
	} else if (convert_cipher_match(data->kdfmode, ACVP_KDF_108_COUNTER,
					ACVP_CIPHERTYPE_KDF)) {
		CKINT(lc_kdf_ctr_init(hmac, data->key.buf, data->key.len));
		CKINT_LOG(lc_kdf_ctr_generate(hmac,
					      data->fixed_data.buf,
					      data->fixed_data.len,
					      data->derived_key.buf,
					      data->derived_key.len),
		      "KDF CTR failed\n");
	} else {
		logger(LOGGER_WARN, "Unknown KDF type\n");
		ret = -EINVAL;
		goto out;
	}

	if (ret > 0)
		ret = 0;

out:
	lc_hmac_zero(hmac);

	return ret;
}


static struct kdf_108_backend lc_108 =
{
	lc_kdf_108_generate,
};

ACVP_DEFINE_CONSTRUCTOR(lc_108_backend)
static void lc_108_backend(void)
{
	register_kdf_108_impl(&lc_108);
}

/************************************************
 * SP800-132 PBKDF cipher interface functions
 ************************************************/
static int lc_pbkdf_generate(struct pbkdf_data *data, flags_t parsed_flags)
{
	const struct lc_hash *lc_hash;
	uint32_t derived_key_bytes = data->derived_key_length / 8;
	int ret;

	(void)parsed_flags;

	if (data->derived_key_length % 8) {
		logger(LOGGER_WARN, "Derived key must be byte-aligned\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(lc_get_hash(data->hash, &lc_hash));

	CKINT(alloc_buf(derived_key_bytes, &data->derived_key));

	CKINT_LOG(lc_pbkdf2(lc_hash,
			    data->password.buf, data->password.len,
			    data->salt.buf, data->salt.len,
			    data->iteration_count,
			    data->derived_key.buf, data->derived_key.len),
		  "PKBDF2 failed\n");

out:
	return ret;
}


static struct pbkdf_backend lc_pbkdf =
{
	lc_pbkdf_generate,
};

ACVP_DEFINE_CONSTRUCTOR(lc_pbkdf_backend)
static void lc_pbkdf_backend(void)
{
	register_pbkdf_impl(&lc_pbkdf);
}

/************************************************
 * RFC5869 HKDF cipher interface functions
 ************************************************/
static int lc_hkdf_generate(struct hkdf_data *data, flags_t parsed_flags)
{
	BUFFER_INIT(local_dkm);
	const struct lc_hash *lc_hash;
	uint32_t derived_key_bytes = data->dkmlen / 8;
	int ret;

	(void)parsed_flags;

	if (data->dkmlen % 8) {
		logger(LOGGER_WARN, "Derived key must be byte-aligned\n");
		return -EINVAL;
	}

	ret = lc_get_hash(data->hash, &lc_hash);
	if (ret)
		return ret;
	LC_HKDF_CTX_ON_STACK(hkdf, lc_hash);

	if (data->dkm.buf && data->dkm.len) {
		CKINT(alloc_buf(derived_key_bytes, &local_dkm));
	} else {
		CKINT(alloc_buf(derived_key_bytes, &data->dkm));
	}

	/* Extract phase */
	CKINT_LOG(lc_hkdf_extract(hkdf,
				  data->z.buf, data->z.len,
				  data->salt.buf, data->salt.len),
		  "HKDF extract failed\n");

	if (local_dkm.buf && local_dkm.len) {
		CKINT_LOG(lc_hkdf_expand(hkdf,
					 data->info.buf, data->info.len,
					 local_dkm.buf, local_dkm.len),
			  "HKDF expand failed\n");

		if (local_dkm.len != data->dkm.len ||
		    memcmp(local_dkm.buf, data->dkm.buf, local_dkm.len)) {
			logger(LOGGER_DEBUG, "HKDF validation result: fail\n");
			data->validity_success = 0;
		} else {
			data->validity_success = 1;
		}
	} else {
		CKINT_LOG(lc_hkdf_expand(hkdf,
					 data->info.buf, data->info.len,
					 data->dkm.buf, data->dkm.len),
			  "HKDF expand failed\n");
	}

out:
	lc_hkdf_zero(hkdf);
	free_buf(&local_dkm);

	return ret;
}


static struct hkdf_backend lc_hkdf_back =
{
	lc_hkdf_generate,
};

ACVP_DEFINE_CONSTRUCTOR(lc_hkdf_backend)
static void lc_hkdf_backend(void)
{
	register_hkdf_impl(&lc_hkdf_back);
}
