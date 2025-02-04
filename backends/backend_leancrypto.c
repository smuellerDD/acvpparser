/* Backend for leancrypto
 *
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

/* required for posix memalign */
#define _GNU_SOURCE

#include "frontend_headers.h"

#include <leancrypto.h>

#include "backend_common.h"
#include "parser_sha_mct_helper.h"

#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_c.h"
#include "aes_riscv64.h"

#include "dilithium_signature_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_c.h"
#include "sha3_riscv_asm.h"

#include "sha256_arm_ce.h"
#include "sha256_arm_neon.h"
#include "sha256_avx2.h"
#include "sha256_c.h"
#include "sha256_riscv.h"
#include "sha256_riscv_zbb.h"
#include "sha256_shani.h"

#include "sha512_arm_ce.h"
#include "sha512_arm_neon.h"
#include "sha512_avx2.h"
#include "sha512_c.h"
#include "sha512_riscv.h"
#include "sha512_riscv_zbb.h"
#include "sha512_shani.h"

#ifdef __x86_64__
#include "shake_4x_avx2.h"
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
#include "shake_2x_armv8.h"
#endif

/************************************************
 * Symmetric cipher interface functions
 ************************************************/
static void lc_cipher_check_c(const struct lc_sym *selected,
			      const struct lc_sym *c,
			      const char *log)
{
	if (selected == c)
		logger(LOGGER_ERR,
		       "Cipher selection %s uses C implementation!\n", log);
}

static int lc_cipher_convert(struct sym_data *data, const struct lc_sym **impl)
{
	const char *envstr = getenv("LC_AES");

	if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "AES implementation: C\n");
		switch(data->cipher) {
		case ACVP_CBC:
			*impl = lc_aes_cbc_c;
			break;
		case ACVP_CTR:
			*impl = lc_aes_ctr_c;
			break;
		case ACVP_KW:
			*impl = lc_aes_kw_c;
			break;
		default:
			return -EINVAL;
		}
	} else if (envstr && !strncasecmp(envstr, "AESNI", 5)) {
		logger(LOGGER_VERBOSE, "AES implementation: AESNI\n");
		switch(data->cipher) {
		case ACVP_CBC:
			*impl = lc_aes_cbc_aesni;
			lc_cipher_check_c(*impl, lc_aes_cbc_c, "AESNI CBC");
			break;
		case ACVP_CTR:
			*impl = lc_aes_ctr_aesni;
			lc_cipher_check_c(*impl, lc_aes_ctr_c, "AESNI CTR");
			break;
		case ACVP_KW:
			*impl = lc_aes_kw_aesni;
			lc_cipher_check_c(*impl, lc_aes_kw_c, "AESNI KW");
			break;
		default:
			return -EINVAL;
		}
	} else if (envstr && !strncasecmp(envstr, "ARM_CE", 6)) {
		logger(LOGGER_VERBOSE, "AES implementation: ARM CE\n");
		switch(data->cipher) {
		case ACVP_CBC:
			*impl = lc_aes_cbc_armce;
			lc_cipher_check_c(*impl, lc_aes_cbc_c, "ARM CE CBC");
			break;
		case ACVP_CTR:
			*impl = lc_aes_ctr_armce;
			lc_cipher_check_c(*impl, lc_aes_ctr_c, "ARM CE CTR");
			break;
		case ACVP_KW:
			*impl = lc_aes_kw_armce;
			lc_cipher_check_c(*impl, lc_aes_kw_c, "ARM CE KW");
			break;
		default:
			return -EINVAL;
		}
	} else if (envstr && !strncasecmp(envstr, "RISCV64", 7)) {
		logger(LOGGER_VERBOSE, "AES implementation: RISC-V 64\n");
		switch(data->cipher) {
		case ACVP_CBC:
			*impl = lc_aes_cbc_riscv64;
			lc_cipher_check_c(*impl, lc_aes_cbc_c, "RISC-V 64 CBC");
			break;
		case ACVP_CTR:
			*impl = lc_aes_ctr_riscv64;
			lc_cipher_check_c(*impl, lc_aes_ctr_c, "RISC-V 64 CTR");
			break;
		case ACVP_KW:
			*impl = lc_aes_kw_riscv64;
			lc_cipher_check_c(*impl, lc_aes_kw_c, "RISC-V 64 KW");
			break;
		default:
			return -EINVAL;
		}
	} else {
		logger(LOGGER_ERR, "AES implementation: default\n");
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
static void __attribute__((unused))
lc_hash_check_c(const struct lc_hash *selected, const struct lc_hash *c,
		const char *log)
{
	if (selected == c)
		logger(LOGGER_ERR,
		       "Hash selection %s uses C implementation!\n", log);
}


static int lc_get_hash(uint64_t cipher, const struct lc_hash **lc_hash)
{
	const char *envstr = getenv("LC_SHA3");

	if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "SHA-2 implementation: C\n");
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256_c;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384_c;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512_c;
			return 0;
		}
#ifdef __amd64
	} else if (envstr && !strncasecmp(envstr, "AVX2", 4)) {
		logger(LOGGER_VERBOSE, "SHA-2 implementation: AVX2\n");
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256_avx2;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384_avx2;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512_avx2;
			return 0;
		}
	} else if (envstr && !strncasecmp(envstr, "AESNI", 4)) {
		logger(LOGGER_VERBOSE, "SHA-2 implementation: SHA-NI\n");
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256_shani;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384_shani;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512_shani;
			return 0;
		}
#elif (defined(__arm__) || defined(__aarch64__))
	} else if (envstr && !strncasecmp(envstr, "ARM_NEON", 8)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: ARM NEON\n");
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256_arm_neon;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384_arm_neon;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512_arm_neon;
			return 0;
		}
	} else if (envstr && !strncasecmp(envstr, "ARM_CE", 6)) {
		logger(LOGGER_VERBOSE, "SHA-2 implementation: ARM CE\n");
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256_arm_ce;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384_arm_ce;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512_arm_ce;
			return 0;
		}
#endif
	} else if (envstr && !strncasecmp(envstr, "RISCV64", 7)) {
		logger(LOGGER_VERBOSE, "SHA-2 implementation: RISC-V 64\n");
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256_riscv;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384_riscv;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512_riscv;
			return 0;
		}
	} else if (envstr && !strncasecmp(envstr, "RISCV64_ZBB", 11)) {
		logger(LOGGER_VERBOSE, "SHA-2 implementation: RISC-V 64 Zbb assembler\n");
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256_riscv_zbb;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384_riscv_zbb;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512_riscv_zbb;
			return 0;
		}

	} else {
		switch (cipher) {
		case ACVP_HMACSHA2_256:
		case ACVP_SHA256:
			*lc_hash = lc_sha256;
			return 0;
		case ACVP_HMACSHA2_384:
		case ACVP_SHA384:
			*lc_hash = lc_sha384;
			return 0;
		case ACVP_HMACSHA2_512:
		case ACVP_SHA512:
			*lc_hash = lc_sha512;
			return 0;
		}
	}

	//printf("Test leancrypto SHA3 %s implementation\n",
	//       envstr ? envstr : "default");

	if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: C\n");
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
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_c;
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_c;
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
#ifdef __amd64
	} else if (envstr && !strncasecmp(envstr, "AVX2", 4)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: AVX2\n");
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_avx2;
			lc_hash_check_c(*lc_hash, lc_sha3_224_c, "AVX2 SHA3-224");
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_avx2;
			lc_hash_check_c(*lc_hash, lc_sha3_256_c, "AVX2 SHA3-256");
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_avx2;
			lc_hash_check_c(*lc_hash, lc_sha3_384_c, "AVX2 SHA3-384");
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_avx2;
			lc_hash_check_c(*lc_hash, lc_sha3_512_c, "AVX2 SHA3-512");
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_avx2;
			lc_hash_check_c(*lc_hash, lc_shake128_c, "AVX2 SHAKE-128");
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_avx2;
			lc_hash_check_c(*lc_hash, lc_shake256_c, "AVX2 SHAKE-256");
			break;
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_avx2;
			lc_hash_check_c(*lc_hash, lc_cshake128_c, "AVX2 cSHAKE-128");
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_avx2;
			lc_hash_check_c(*lc_hash, lc_cshake256_c, "AVX2 cSHAKE-256");
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else if (envstr && !strncasecmp(envstr, "AVX512", 6)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: AVX-512\n");
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_avx512;
			lc_hash_check_c(*lc_hash, lc_sha3_224_c, "AVX512 SHA3-224");
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_avx512;
			lc_hash_check_c(*lc_hash, lc_sha3_256_c, "AVX512 SHA3-256");
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_avx512;
			lc_hash_check_c(*lc_hash, lc_sha3_384_c, "AVX512 SHA3-384");
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_avx512;
			lc_hash_check_c(*lc_hash, lc_sha3_512_c, "AVX512 SHA3-512");
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_avx512;
			lc_hash_check_c(*lc_hash, lc_shake128_c, "AVX512 SHAKE-128");
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_avx512;
			lc_hash_check_c(*lc_hash, lc_shake256_c, "AVX512 SHAKE-256");
			break;
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_avx512;
			lc_hash_check_c(*lc_hash, lc_cshake128_c, "AVX512 cSHAKE-128");
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_avx512;
			lc_hash_check_c(*lc_hash, lc_cshake256_c, "AVX512 cSHAKE-256");
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
#elif (defined(__arm__) || defined(__aarch64__))
	} else if (envstr && !strncasecmp(envstr, "ARM_NEON", 8)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: ARM NEON\n");
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_arm_neon;
			lc_hash_check_c(*lc_hash, lc_sha3_224_c, "ARM NEON SHA3-224");
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_arm_neon;
			lc_hash_check_c(*lc_hash, lc_sha3_256_c, "ARM NEON SHA3-256");
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_arm_neon;
			lc_hash_check_c(*lc_hash, lc_sha3_384_c, "ARM NEON SHA3-384");
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_arm_neon;
			lc_hash_check_c(*lc_hash, lc_sha3_512_c, "ARM NEON SHA3-512");
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_arm_neon;
			lc_hash_check_c(*lc_hash, lc_shake128_c, "ARM NEON SHAKE-128");
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_arm_neon;
			lc_hash_check_c(*lc_hash, lc_shake256_c, "ARM NEON SHAKE-256");
			break;
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_arm_neon;
			lc_hash_check_c(*lc_hash, lc_cshake128_c, "ARM NEON cSHAKE-128");
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_arm_neon;
			lc_hash_check_c(*lc_hash, lc_cshake256_c, "ARM NEON cSHAKE-256");
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
#ifdef __aarch64__
	} else if (envstr && !strncasecmp(envstr, "ARM_ASM", 6)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: ARM assembler\n");
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_arm_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_224_c, "ARM assembler SHA3-224");
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_arm_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_256_c, "ARM assembler SHA3-256");
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_arm_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_384_c, "ARM assembler SHA3-384");
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_arm_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_512_c, "ARM assembler SHA3-512");
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_arm_asm;
			lc_hash_check_c(*lc_hash, lc_shake128_c, "ARM assembler SHAKE-128");
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_arm_asm;
			lc_hash_check_c(*lc_hash, lc_shake256_c, "ARM assembler SHAKE-256");
			break;
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_arm_asm;
			lc_hash_check_c(*lc_hash, lc_cshake128_c, "ARM assembler cSHAKE-128");
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_arm_asm;
			lc_hash_check_c(*lc_hash, lc_cshake256_c, "ARM assembler cSHAKE-256");
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else if (envstr && !strncasecmp(envstr, "ARM_CE", 6)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: ARM CE\n");
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_arm_ce;
			lc_hash_check_c(*lc_hash, lc_sha3_224_c, "ARM CE SHA3-224");
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_arm_ce;
			lc_hash_check_c(*lc_hash, lc_sha3_256_c, "ARM CE SHA3-256");
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_arm_ce;
			lc_hash_check_c(*lc_hash, lc_sha3_384_c, "ARM CE SHA3-384");
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_arm_ce;
			lc_hash_check_c(*lc_hash, lc_sha3_512_c, "ARM CE SHA3-512");
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_arm_ce;
			lc_hash_check_c(*lc_hash, lc_shake128_c, "ARM CE SHAKE-128");
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_arm_ce;
			lc_hash_check_c(*lc_hash, lc_shake256_c, "ARM CE SHAKE-256");
			break;
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_arm_ce;
			lc_hash_check_c(*lc_hash, lc_cshake128_c, "ARM CE cSHAKE-128");
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_arm_ce;
			lc_hash_check_c(*lc_hash, lc_cshake256_c, "ARM CE cSHAKE-256");
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
#endif
#endif
	} else if (envstr && !strncasecmp(envstr, "RISCV64", 7)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: RISC-V 64\n");
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_224_c, "RISCV64 assembler SHA3-224");
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_256_c, "RISCV64 assembler SHA3-256");
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_384_c, "RISCV64 assembler SHA3-384");
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_sha3_512_c, "RISCV64 assembler SHA3-512");
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_shake128_c, "RISCV64 assembler SHAKE-128");
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_shake256_c, "RISCV64 assembler SHAKE-256");
			break;
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_cshake128_c, "RISCV64 assembler cSHAKE-128");
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_riscv_asm;
			lc_hash_check_c(*lc_hash, lc_cshake256_c, "RISCV64 assembler cSHAKE-256");
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else if (envstr && !strncasecmp(envstr, "RISCV64_ZBB", 11)) {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: RISC-V 64 Zbb assembler\n");
		switch (cipher) {
		case ACVP_HMACSHA3_224:
		case ACVP_SHA3_224:
			*lc_hash = lc_sha3_224_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_sha3_224_c, "RISCV64 Zbb assembler SHA3-224");
			break;
		case ACVP_HMACSHA3_256:
		case ACVP_SHA3_256:
			*lc_hash = lc_sha3_256_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_sha3_256_c, "RISCV64 Zbb assembler SHA3-256");
			break;
		case ACVP_HMACSHA3_384:
		case ACVP_SHA3_384:
			*lc_hash = lc_sha3_384_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_sha3_384_c, "RISCV64 Zbb assembler SHA3-384");
			break;
		case ACVP_HMACSHA3_512:
		case ACVP_SHA3_512:
			*lc_hash = lc_sha3_512_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_sha3_512_c, "RISCV64 Zbb assembler SHA3-512");
			break;
		case ACVP_SHAKE128:
			*lc_hash = lc_shake128_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_shake128_c, "RISCV64 Zbb assembler SHAKE-128");
			break;
		case ACVP_SHAKE256:
			*lc_hash = lc_shake256_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_shake256_c, "RISCV64 Zbb assembler SHAKE-256");
			break;
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_cshake128_c, "RISCV64 Zbb assembler cSHAKE-128");
			break;
		case ACVP_KMAC256:
		case ACVP_CSHAKE256:
			*lc_hash = lc_cshake256_riscv_asm_zbb;
			lc_hash_check_c(*lc_hash, lc_cshake256_c, "RISCV64 Zbb assembler cSHAKE-256");
			break;
		default:
			logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
			cipher);
			return -EOPNOTSUPP;
		}
	} else {
		logger(LOGGER_VERBOSE, "SHA-3 implementation: default\n");
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
		case ACVP_KMAC128:
		case ACVP_CSHAKE128:
			*lc_hash = lc_cshake128;
			break;
		case ACVP_KMAC256:
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

static int lc_get_common_hash(uint64_t cipher, const struct lc_hash **lc_hash)
{
	switch (cipher) {
	case ACVP_HMACSHA2_256:
	case ACVP_SHA256:
		*lc_hash = lc_sha256;
		return 0;
	case ACVP_HMACSHA2_384:
	case ACVP_SHA384:
		*lc_hash = lc_sha384;
		return 0;
	case ACVP_HMACSHA2_512:
	case ACVP_SHA512:
		*lc_hash = lc_sha512;
		return 0;
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
	case ACVP_KMAC128:
	case ACVP_CSHAKE128:
		*lc_hash = lc_cshake128;
		break;
	case ACVP_KMAC256:
	case ACVP_CSHAKE256:
		*lc_hash = lc_cshake256;
		break;
	default:
		logger(LOGGER_ERR, "Cipher %" PRIu64 " not implemented\n",
		cipher);
		return -EOPNOTSUPP;
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

#if defined(__aarch64__) || defined(_M_ARM64)
static int lc_shake_armv8_2x_generate(struct sha_data *data)
{
	int ret;
	size_t outbytes = data->outlen / 8;
	uint8_t *outbuf0, *outbuf1 = NULL;

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

	uint8_t *out0 = outbuf0;
	uint8_t *out1 = outbuf1;

	const uint8_t *in0 = data->msg.buf;
	const uint8_t *in1 = data->msg.buf;
	if (data->cipher == ACVP_SHAKE128) {
		shake128x2_armv8(out0, out1, outbytes, in0, in1, data->msg.len);
	} else {
		shake256x2_armv8(out0, out1, outbytes, in0, in1, data->msg.len);
	}

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "data read");

	if (memcmp(outbuf0, outbuf1, outbytes)) {
		logger(LOGGER_ERR, "SHAKE lane 1 mismatch with lane 0\n");
		ret = -EFAULT;
	}

out:
	if (outbuf1)
		free(outbuf1);
	return ret;
}
#else
static int lc_shake_armv8_2x_generate(struct sha_data *data)
{
	(void)data;
	return -EOPNOTSUPP;
}
#endif

static int lc_hash_generate(struct sha_data *data, flags_t parsed_flags)
{
	const char *envstr = getenv("LC_SHAKE");
	const struct lc_hash *lc_hash;
	BUFFER_INIT(msg_p);
	int ret;

	(void)parsed_flags;

	/* Special handling */
	if (envstr && !strncasecmp(envstr, "AVX2-4X", 7))
		return lc_shake4x_generate(data);
	else if (envstr && !strncasecmp(envstr, "ARM-2X", 6))
		return lc_shake_armv8_2x_generate(data);

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
	NULL,
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
	const struct lc_hash *lc_hash;
	BUFFER_INIT(mac);
	int ret;

	ret = lc_get_hash(data->cipher, &lc_hash);
	if (ret)
		return ret;

	LC_KMAC_CTX_ON_STACK(kmac, lc_hash);


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
	NULL,
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

/************************************************
 * Dilithium
 ************************************************/
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct static_rng {
	const uint8_t *seed;
	size_t seedlen;
};

static int lc_static_rng_gen(void *_state, const uint8_t *addtl_input,
			     size_t addtl_input_len, uint8_t *out,
			     size_t outlen)
{
	struct static_rng *state = _state;

	(void)addtl_input;
	(void)addtl_input_len;

	if (outlen != state->seedlen)
		return -EINVAL;

	memcpy(out, state->seed, outlen);

	return 0;
}

static int lc_static_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			      const uint8_t *persbuf, size_t perslen)
{
	(void)_state;
	(void)seed;
	(void)seedlen;
	(void)persbuf;
	(void)perslen;
	return 0;
}

static void lc_static_rng_zero(void *_state)
{
	(void)_state;
}

static const struct lc_rng lc_static_drng = {
	.generate = lc_static_rng_gen,
	.seed = lc_static_rng_seed,
	.zero = lc_static_rng_zero,
};

/************************************************
 * EDDSA interface functions
 ************************************************/
static int lc_eddsa_keygen(struct eddsa_keygen_data *data, flags_t parsed_flags)
{
	struct lc_ed25519_pk pk;
	struct lc_ed25519_sk sk;
	int ret = 0;

	/*
	 * The secret key buffer holds d || q and thus is twice the size of
	 * q. As we only want the private key in data->d, set the length
	 * appropriately.
	 */
#define LC_ED25519_PURE_SECRETKEYBYTES (LC_ED25519_SECRETKEYBYTES - 32)

	(void)parsed_flags;

	if (!(data->cipher & ACVP_ED25519)) {
		logger(LOGGER_ERR, "Curve 25519 only supported\n");
		return -EINVAL;
	}

	CKINT(alloc_buf(LC_ED25519_PUBLICKEYBYTES, &data->q));
	CKINT(alloc_buf(LC_ED25519_PURE_SECRETKEYBYTES, &data->d));

	CKINT(lc_ed25519_keypair(&pk, &sk, lc_seeded_rng));

	memcpy(data->q.buf, pk.pk, LC_ED25519_PUBLICKEYBYTES);
	memcpy(data->d.buf, sk.sk, LC_ED25519_PURE_SECRETKEYBYTES);

out:
	return ret;
}

static int lc_eddsa_keygen_en(struct buffer *qbuf, uint64_t curve,
			      void **privkey)
{
	struct lc_ed25519_pk pk;
	struct lc_ed25519_sk *sk = NULL;
	int ret;

	if (!(curve & ACVP_ED25519)) {
		logger(LOGGER_ERR, "Curve 25519 only supported\n");
		return -EINVAL;
	}

	CKINT(alloc_buf(LC_ED25519_PUBLICKEYBYTES, qbuf));

	sk = calloc(1, sizeof(struct lc_ed25519_sk));
	CKNULL(sk, -ENOMEM);

	CKINT(lc_ed25519_keypair(&pk, sk, lc_seeded_rng));
	memcpy(qbuf->buf, pk.pk, LC_ED25519_PUBLICKEYBYTES);

	*privkey = sk;

out:
	if (ret && sk)
		free(sk);
	return ret;
}

static void lc_eddsa_free_key(void *privkey)
{
	if (privkey)
		free(privkey);
}

static int lc_eddsa_siggen(struct eddsa_siggen_data *data, flags_t parsed_flags)
{
	struct lc_ed25519_sig sig;
	struct lc_ed25519_sk *sk = (struct lc_ed25519_sk *)data->privkey;
	int ret;

	(void)parsed_flags;

	if (!(data->cipher & ACVP_ED25519)) {
		logger(LOGGER_ERR, "Curve 25519 only supported\n");
		return -EINVAL;
	}

	CKNULL(sk, -EINVAL);

	CKINT(alloc_buf(LC_ED25519_SIGBYTES, &data->signature));
	if (data->prehash) {
		uint8_t digest[LC_SHA512_SIZE_DIGEST];

		lc_hash(lc_sha512, data->msg.buf, data->msg.len, digest);
		CKINT(lc_ed25519ph_sign(&sig, digest, sizeof(digest), sk,
					lc_seeded_rng));
	} else {
		CKINT(lc_ed25519_sign(&sig, data->msg.buf, data->msg.len, sk,
				      lc_seeded_rng));
	}

	/* extract signature */

	memcpy(data->signature.buf, sig.sig, data->signature.len);

out:
	return ret;
}

static int lc_eddsa_sigver(struct eddsa_sigver_data *data,
				  flags_t parsed_flags)
{
	struct lc_ed25519_sig sig;
	struct lc_ed25519_pk pk;
	int ret;

	(void)parsed_flags;

	if (!(data->cipher & ACVP_ED25519)) {
		logger(LOGGER_ERR, "Curve 25519 only supported\n");
		return -EINVAL;
	}

	if (data->signature.len > LC_ED25519_SIGBYTES) {
		logger(LOGGER_ERR, "Signature unexpected size %zu\n",
		       data->signature.len);
		return -EINVAL;
	}

	if (data->q.len != LC_ED25519_PUBLICKEYBYTES) {
		logger(LOGGER_ERR, "Wrong key size\n");
		return -EINVAL;
	}

	memcpy(sig.sig, data->signature.buf, data->signature.len);
	memcpy(pk.pk, data->q.buf, data->q.len);

	if (data->prehash) {
		uint8_t digest[LC_SHA512_SIZE_DIGEST];

		lc_hash(lc_sha512, data->msg.buf, data->msg.len, digest);
		ret = lc_ed25519ph_verify(&sig, digest, sizeof(digest), &pk);
	} else {
		ret = lc_ed25519_verify(&sig, data->msg.buf, data->msg.len,
					&pk);
	}

	if (!ret) {
		logger(LOGGER_DEBUG, "EDDSA signature successfully verified\n");
		data->sigver_success = 1;
	} else if (ret == -EBADMSG) {
		logger(LOGGER_DEBUG,
		       "EDDSA signature verification with bad signature\n");
		data->sigver_success = 0;
	} else {
		logger(LOGGER_DEBUG, "Signature verification failed");
		data->sigver_success = 0;
		/* do not fail here, because that is an expected error */
	}

	return 0;
}

static struct eddsa_backend lc_eddsa =
{
	lc_eddsa_keygen,
	NULL,
	lc_eddsa_siggen,
	lc_eddsa_sigver,
	lc_eddsa_keygen_en,
	lc_eddsa_free_key
};

ACVP_DEFINE_CONSTRUCTOR(lc_eddsa_backend)
static void lc_eddsa_backend(void)
{
	register_eddsa_impl(&lc_eddsa);
}

/************************************************
 * ML-DSA interface functions
 ************************************************/

/* TODO roll in */
#if 0
	const char *envstr = getenv("LC_DILITHIUM");

	if (!envstr || (envstr && !strncasecmp(envstr, "common", 6)) ||
	    (envstr && !strncasecmp(envstr, "riscv64_rvv", 11))) {
		logger(LOGGER_VERBOSE, "Dilithium-87 implementation: common\n");
		funcs->dilithium_keypair_from_seed =
			lc_dilithium_87_keypair_from_seed;
		funcs->dilithium_sign = lc_dilithium_87_sign_ctx;
		funcs->dilithium_verify = lc_dilithium_87_verify_ctx;
	} else if (envstr ||
		   (envstr && !strncasecmp(envstr, "riscv64_asm", 11))) {
		logger(LOGGER_VERBOSE,
		       "Dilithium-87 implementation: RISCV64 ASM\n");
#endif

extern void lc_cpu_feature_disable(void);
extern void lc_cpu_feature_enable(void);
static void lc_ml_set_impl(void)
{
	const char *envstr = getenv("LC_DILTHIUM");

	if (envstr && !strncasecmp(envstr, "C", 1))
		lc_cpu_feature_disable();
}

static void lc_ml_reset_impl(void)
{
	const char *envstr = getenv("LC_DILTHIUM");

	if (envstr && !strncasecmp(envstr, "C", 1))
		lc_cpu_feature_enable();
}

static int lc_ml_type(uint64_t cipher, enum lc_dilithium_type *type)
{
	lc_ml_set_impl();

	switch (cipher) {
	case ACVP_ML_DSA_44:
		*type = LC_DILITHIUM_44;
		break;
	case ACVP_ML_DSA_65:
		*type = LC_DILITHIUM_65;
		break;
	case ACVP_ML_DSA_87:
		*type = LC_DILITHIUM_87;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_dsa_keygen(struct ml_dsa_keygen_data *data,
			    flags_t parsed_flags)
{
	struct lc_dilithium_pk lc_pk;
	struct lc_dilithium_sk lc_sk;
	enum lc_dilithium_type type;
	size_t len;
	uint8_t *ptr;
	int ret;

	(void)parsed_flags;

	CKINT(lc_ml_type(data->cipher, &type));

	CKINT(lc_dilithium_keypair_from_seed(&lc_pk, &lc_sk, data->seed.buf,
					     data->seed.len, type));

	CKINT(lc_dilithium_pk_ptr(&ptr, &len, &lc_pk));
	CKINT(alloc_buf(len, &data->pk));
	memcpy(data->pk.buf, ptr, len);

	CKINT(lc_dilithium_sk_ptr(&ptr, &len, &lc_sk));
	CKINT(alloc_buf(len, &data->sk));
	memcpy(data->sk.buf, ptr, len);

out:
	lc_ml_reset_impl();
	return ret;
}

static int lc_ml_dsa_siggen(struct ml_dsa_siggen_data *data,
			    flags_t parsed_flags)
{
	struct lc_dilithium_sk sk;
	struct lc_dilithium_sig *sig = NULL;
	enum lc_dilithium_type type;
	size_t len;
	uint8_t *ptr;
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	int ret;

	CKINT(lc_ml_type(data->cipher, &type));

	CKINT(lc_dilithium_sk_load(&sk, data->sk.buf, data->sk.len));

	CKINT(-posix_memalign((void **)&sig, 8,
			      sizeof(struct lc_dilithium_sig)));

	/* Set ML-DSA.Sign_internal */
	if (!strncasecmp((char *)data->interface.buf, "internal", 8))
		lc_dilithium_ctx_internal(ctx);

	/* This call also covers the NULL buffer */
	lc_dilithium_ctx_userctx(ctx, data->context.buf, data->context.len);

	if (data->hashalg) {
		BUFFER_INIT(tmp);
		const struct lc_hash *hash_alg;

		CKINT(lc_get_common_hash(data->hashalg, &hash_alg));
		lc_dilithium_ctx_hash(ctx, hash_alg);

		/* Calculate the digest */
		LC_HASH_CTX_ON_STACK(hash_ctx, hash_alg);
		lc_hash_init(hash_ctx);

		if (hash_alg == lc_shake256)
			lc_hash_set_digestsize(hash_ctx, 64);

		CKINT(alloc_buf(lc_hash_digestsize(hash_ctx), &tmp));
		lc_hash_update(hash_ctx, data->msg.buf, data->msg.len);
		lc_hash_final(hash_ctx, tmp.buf);

		lc_hash_zero(hash_ctx);
		free_buf(&data->msg);
		copy_ptr_buf(&data->msg, &tmp);
	}

	if (data->rnd.len) {
		/* random data is provided by test vector */

		struct static_rng s_rng_state;
		struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
					     .rng_state = &s_rng_state };

		s_rng_state.seed = data->rnd.buf;
		s_rng_state.seedlen = data->rnd.len;

		CKINT(lc_dilithium_sign_ctx(sig, ctx, data->msg.buf,
					    data->msg.len, &sk, &s_drng));
	} else if ((parsed_flags & FLAG_OP_ML_DSA_TYPE_MASK) ==
		   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC) {
		/* Module is required to generate random data */

		CKINT(lc_dilithium_sign_ctx(sig, ctx, data->msg.buf,
					    data->msg.len, &sk, lc_seeded_rng));
	} else {
		/* Module is required to perform deterministic operation */

		CKINT(lc_dilithium_sign_ctx(sig, ctx, data->msg.buf,
					    data->msg.len, &sk, NULL));
	}

	CKINT(lc_dilithium_sig_ptr(&ptr, &len, sig));
	CKINT(alloc_buf(len, &data->sig));
	memcpy(data->sig.buf, ptr, len);

#if 0
	struct lc_dilithium_pk pk;

	if (sizeof(pk.pk) == data->pk.len) {
		memcpy(pk.pk, data->pk.buf, data->pk.len);

		CKINT(funcs.dilithium_verify(&sig, data->msg.buf,
					     data->msg.len, &pk));
	}
#endif

out:
	if (sig)
		free(sig);
	lc_ml_reset_impl();
	return ret;
}

static int lc_ml_dsa_sigver(struct ml_dsa_sigver_data *data,
			    flags_t parsed_flags)
{
	struct lc_dilithium_pk pk;
	struct lc_dilithium_sig *sig = NULL;
	enum lc_dilithium_type type;
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	int ret;

	(void)parsed_flags;

	CKINT(lc_ml_type(data->cipher, &type));
	CKINT(-posix_memalign((void **)&sig, 8,
			      sizeof(struct lc_dilithium_sig)));

	CKINT(lc_dilithium_pk_load(&pk, data->pk.buf, data->pk.len));
	ret = lc_dilithium_sig_load(sig, data->sig.buf, data->sig.len);
	if (ret) {
		if (ret == -EINVAL) {
			logger(LOGGER_DEBUG,
			       "Signature has invalid size (expected %u, actual %zu)\n",
			       lc_dilithium_sig_size(type), data->sig.len);
			ret = 0;
			data->sigver_success = 0;
		}
		goto out;
	}

	/* Set ML-DSA.Sign_internal */
	if (!strncasecmp((char *)data->interface.buf, "internal", 8))
		lc_dilithium_ctx_internal(ctx);

	/* This call also covers the NULL buffer */
	lc_dilithium_ctx_userctx(ctx, data->context.buf, data->context.len);

	if (data->hashalg) {
		BUFFER_INIT(tmp);
		const struct lc_hash *hash_alg;

		CKINT(lc_get_common_hash(data->hashalg, &hash_alg));
		lc_dilithium_ctx_hash(ctx, hash_alg);

		/* Calculate the digest */
		LC_HASH_CTX_ON_STACK(hash_ctx, hash_alg);
		lc_hash_init(hash_ctx);

		if (hash_alg == lc_shake256)
			lc_hash_set_digestsize(hash_ctx, 64);

		CKINT(alloc_buf(lc_hash_digestsize(hash_ctx), &tmp));
		lc_hash_update(hash_ctx, data->msg.buf, data->msg.len);
		lc_hash_final(hash_ctx, tmp.buf);

		lc_hash_zero(hash_ctx);
		free_buf(&data->msg);
		copy_ptr_buf(&data->msg, &tmp);
	}

	ret = lc_dilithium_verify_ctx(sig, ctx, data->msg.buf, data->msg.len,
				      &pk);

	if (ret == -EBADMSG) {
		logger(LOGGER_DEBUG, "Signature verification: signature bad\n");
		data->sigver_success = 0;
	} else if (!ret) {
		logger(LOGGER_DEBUG,
		       "Signature verification: signature good\n");
		data->sigver_success = 1;
	} else {
		/* This can happen when data is wrong */
		logger(LOGGER_WARN, "Signature verification: general error\n");
		data->sigver_success = 0;
	}

	ret = 0;

out:
	if (sig)
		free(sig);
	lc_ml_reset_impl();
	return ret;
}

static int lc_ml_dsa_keygen_en(uint64_t cipher, struct buffer *pk,
			       void **sk)
{
	struct lc_dilithium_pk lc_pk;
	struct lc_dilithium_sk *lc_sk;
	enum lc_dilithium_type type;
	uint8_t *ptr;
	size_t len;
	int ret;

	CKINT(lc_ml_type(cipher, &type));

	lc_sk = calloc(1, sizeof(struct lc_dilithium_sk));
	CKNULL(lc_sk, -ENOMEM);

	CKINT(lc_dilithium_keypair(&lc_pk, lc_sk, lc_seeded_rng, type));

	CKINT(lc_dilithium_pk_ptr(&ptr, &len, &lc_pk));
	CKINT(alloc_buf(len, pk));
	memcpy(pk->buf, ptr, len);

	*sk = lc_sk;

out:
	return ret;
}

static void lc_ml_dsa_free_key(void *privkey)
{
	if (privkey)
		free(privkey);
}

static struct ml_dsa_backend lc_ml_dsa =
{
	lc_ml_dsa_keygen,
	lc_ml_dsa_siggen,
	lc_ml_dsa_sigver,
	lc_ml_dsa_keygen_en,
	lc_ml_dsa_free_key
};

ACVP_DEFINE_CONSTRUCTOR(lc_ml_dsa_backend)
static void lc_ml_dsa_backend(void)
{
	register_ml_dsa_impl(&lc_ml_dsa);
}

/************************************************
 * ML-KEM interface functions
 ************************************************/
static void lc_ml_kem_set_impl(void)
{
	const char *envstr = getenv("LC_KYBER");

	if (envstr && !strncasecmp(envstr, "C", 1))
		lc_cpu_feature_disable();
}

static void lc_ml_kem_reset_impl(void)
{
	const char *envstr = getenv("LC_KYBER");

	if (envstr && !strncasecmp(envstr, "C", 1))
		lc_cpu_feature_enable();
}

static int lc_ml_kem_type(uint64_t cipher, enum lc_kyber_type *type)
{
	lc_ml_kem_set_impl();

	switch (cipher) {
	case ACVP_ML_KEM_1024:
		*type = LC_KYBER_1024;
		break;
	case ACVP_ML_KEM_768:
		*type = LC_KYBER_768;
		break;
	case ACVP_ML_KEM_512:
		*type = LC_KYBER_512;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_kem_keygen(struct ml_kem_keygen_data *data,
			    flags_t parsed_flags)
{
	struct lc_kyber_pk pk;
	struct lc_kyber_sk sk;
	enum lc_kyber_type type;
	uint8_t buf[64];
	size_t len;
	uint8_t *ptr;
	int ret;

	(void)parsed_flags;

	CKINT(lc_ml_kem_type(data->cipher, &type));

	if (data->d.len + data->z.len != sizeof(buf))
		return -EINVAL;
	memcpy(buf, data->d.buf, data->d.len);
	memcpy(buf + data->d.len, data->z.buf, data->z.len);

	CKINT(lc_kyber_keypair_from_seed(&pk, &sk, buf, sizeof(buf), type));

	CKINT(lc_kyber_pk_ptr(&ptr, &len, &pk));
	CKINT(alloc_buf(len, &data->ek));
	memcpy(data->ek.buf, ptr, len);

	CKINT(lc_kyber_sk_ptr(&ptr, &len, &sk));
	CKINT(alloc_buf(len, &data->dk));
	memcpy(data->dk.buf, ptr, len);

out:
	lc_ml_kem_reset_impl();
	return ret;
}

static int lc_ml_kem_encapsulation(struct ml_kem_encapsulation_data *data,
				   flags_t parsed_flags)
{
	struct lc_kyber_pk pk;
	struct lc_kyber_ct ct;
	struct lc_kyber_ss ss;
	enum lc_kyber_type type;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	size_t len;
	uint8_t *ptr;
	int ret;

	(void)parsed_flags;

	CKINT(lc_ml_kem_type(data->cipher, &type));

	CKINT(lc_kyber_pk_load(&pk, data->ek.buf, data->ek.len));

	s_rng_state.seed = data->msg.buf;
	s_rng_state.seedlen = data->msg.len;

	/* Set seeded RNG with the pre-defined seed data */
	CKINT(lc_rng_set_seeded(&s_drng));

	CKINT(lc_kyber_enc(&ct, &ss, &pk));

	/* Unset seeded RNG using the standard seeded RNG */
	CKINT(lc_rng_set_seeded(NULL));

	CKINT(lc_kyber_ct_ptr(&ptr, &len, &ct));
	CKINT(alloc_buf(len, &data->c));
	memcpy(data->c.buf, ptr, len);

	CKINT(lc_kyber_ss_ptr(&ptr, &len, &ss));
	CKINT(alloc_buf(len, &data->ss));
	memcpy(data->ss.buf, ptr, len);

out:
	lc_ml_kem_reset_impl();
	return ret;
}

static int lc_ml_kem_decapsulation(struct ml_kem_decapsulation_data *data,
				   flags_t parsed_flags)
{
	struct lc_kyber_sk sk;
	struct lc_kyber_ct ct;
	struct lc_kyber_ss ss;
	enum lc_kyber_type type;
	size_t len;
	uint8_t *ptr;
	int ret;

	(void)parsed_flags;

	CKINT(lc_ml_kem_type(data->cipher, &type));

	CKINT(lc_kyber_sk_load(&sk, data->dk.buf, data->dk.len));
	CKINT(lc_kyber_ct_load(&ct, data->c.buf, data->c.len));

	CKINT(lc_kyber_dec(&ss, &ct, &sk));

	CKINT(lc_kyber_ss_ptr(&ptr, &len, &ss));
	CKINT(alloc_buf(len, &data->ss));
	memcpy(data->ss.buf, ptr, len);

out:
	lc_ml_kem_reset_impl();
	return ret;
}

static struct ml_kem_backend lc_ml_kem =
{
	lc_ml_kem_keygen,
	lc_ml_kem_encapsulation,
	lc_ml_kem_decapsulation,
};

ACVP_DEFINE_CONSTRUCTOR(lc_ml_kem_backend)
static void lc_ml_kem_backend(void)
{
	register_ml_kem_impl(&lc_ml_kem);
}

/************************************************
 * SLH-DSA interface functions
 ************************************************/

extern void lc_cpu_feature_disable(void);
extern void lc_cpu_feature_enable(void);
static void lc_slh_set_impl(void)
{
	const char *envstr = getenv("LC_SPHINCS");

	if (envstr && !strncasecmp(envstr, "C", 1))
		lc_cpu_feature_disable();
}

static void lc_slh_reset_impl(void)
{
	const char *envstr = getenv("LC_SPHINCS");

	if (envstr && !strncasecmp(envstr, "C", 1))
		lc_cpu_feature_enable();
}


static int lc_slh_type(uint64_t cipher, enum lc_sphincs_type *type, uint8_t *n)
{
	lc_slh_set_impl();

	switch (cipher) {
	case ACVP_SLH_DSA_SHAKE_128F:
		*type = LC_SPHINCS_SHAKE_128f;
		*n = 16;
		break;
	case ACVP_SLH_DSA_SHAKE_128S:
		*type = LC_SPHINCS_SHAKE_128s;
		*n = 16;
		break;
	case ACVP_SLH_DSA_SHAKE_192F:
		*type = LC_SPHINCS_SHAKE_192f;
		*n = 24;
		break;
	case ACVP_SLH_DSA_SHAKE_192S:
		*type = LC_SPHINCS_SHAKE_192s;
		*n = 24;
		break;
	case ACVP_SLH_DSA_SHAKE_256F:
		*type = LC_SPHINCS_SHAKE_256f;
		*n = 32;
		break;
	case ACVP_SLH_DSA_SHAKE_256S:
		*type = LC_SPHINCS_SHAKE_256s;
		*n = 32;
		break;
	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_slh_dsa_keygen(struct slh_dsa_keygen_data *data,
			     flags_t parsed_flags)
{
	struct lc_sphincs_pk lc_pk;
	struct lc_sphincs_sk lc_sk;
	uint8_t seed[3 * 32], n;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	enum lc_sphincs_type type;
	size_t len;
	uint8_t *ptr;
	int ret;

	(void)parsed_flags;

	CKINT(lc_slh_type(data->cipher, &type, &n));

	if (data->sk_seed.len != n || data->sk_prf.len != n ||
	    data->pk_seed.len != n) {
		    logger(LOGGER_ERR, "Input data unexpected\n");
		    ret = -EOPNOTSUPP;
		    goto out;
	}

	memcpy(seed, data->sk_seed.buf, n);
	memcpy(seed + n, data->sk_prf.buf, n);
	memcpy(seed + 2 * n, data->pk_seed.buf, n);
	s_rng_state.seed = seed;
	s_rng_state.seedlen = 3 * n;

	CKINT(lc_sphincs_keypair(&lc_pk, &lc_sk, &s_drng, type));

	CKINT(lc_sphincs_pk_ptr(&ptr, &len, &lc_pk));
	CKINT(alloc_buf(len, &data->pk));
	memcpy(data->pk.buf, ptr, len);

	CKINT(lc_sphincs_sk_ptr(&ptr, &len, &lc_sk));
	CKINT(alloc_buf(len, &data->sk));
	memcpy(data->sk.buf, ptr, len);

out:
	lc_slh_reset_impl();
	return ret;
}

static int lc_slh_dsa_siggen(struct slh_dsa_siggen_data *data,
			     flags_t parsed_flags)
{
	struct lc_sphincs_sk sk;
	struct lc_sphincs_sig *sig = NULL;
	enum lc_sphincs_type type;
	size_t len;
	uint8_t *ptr;
	int ret;
	uint8_t n;
	LC_SPHINCS_CTX_ON_STACK(ctx);

	CKINT(lc_slh_type(data->cipher, &type, &n));

	CKINT(lc_sphincs_sk_load(&sk, data->sk.buf, data->sk.len));
	switch (data->cipher) {
	case ACVP_SLH_DSA_SHAKE_128F:
	case ACVP_SLH_DSA_SHAKE_192F:
	case ACVP_SLH_DSA_SHAKE_256F:
		lc_sphincs_sk_set_keytype_fast(&sk);
		break;

	case ACVP_SLH_DSA_SHAKE_128S:
	case ACVP_SLH_DSA_SHAKE_192S:
	case ACVP_SLH_DSA_SHAKE_256S:
		lc_sphincs_sk_set_keytype_small(&sk);
		break;

	default:
		return -EOPNOTSUPP;
	}

	CKINT(-posix_memalign((void **)&sig, 8, sizeof(struct lc_sphincs_sig)));

	/* Set SLH-DSA.Sign_internal */
	if (!strncasecmp((char *)data->interface.buf, "internal", 8))
		lc_sphincs_ctx_internal(ctx);

	/* This call also covers the NULL buffer */
	lc_sphincs_ctx_userctx(ctx, data->context.buf, data->context.len);

	if (data->hashalg) {
		BUFFER_INIT(tmp);
		const struct lc_hash *hash_alg;

		CKINT(lc_get_common_hash(data->hashalg, &hash_alg));
		lc_sphincs_ctx_hash(ctx, hash_alg);

		/* Calculate the digest */
		LC_HASH_CTX_ON_STACK(hash_ctx, hash_alg);
		lc_hash_init(hash_ctx);

		if (hash_alg == lc_shake256)
			lc_hash_set_digestsize(hash_ctx, 64);

		CKINT(alloc_buf(lc_hash_digestsize(hash_ctx), &tmp));
		lc_hash_update(hash_ctx, data->msg.buf, data->msg.len);
		lc_hash_final(hash_ctx, tmp.buf);

		lc_hash_zero(hash_ctx);
		free_buf(&data->msg);
		copy_ptr_buf(&data->msg, &tmp);
	}

	if (data->rnd.len) {
		/* random data is provided by test vector */

		struct static_rng s_rng_state;
		struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
					     .rng_state = &s_rng_state };

		s_rng_state.seed = data->rnd.buf;
		s_rng_state.seedlen = data->rnd.len;

		CKINT(lc_sphincs_sign_ctx(sig, ctx, data->msg.buf,
					  data->msg.len, &sk, &s_drng));
	} else if ((parsed_flags & FLAG_OP_ML_DSA_TYPE_MASK) ==
		   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC) {
		/* Module is required to generate random data */

		CKINT(lc_sphincs_sign_ctx(sig, ctx, data->msg.buf,
					  data->msg.len, &sk, lc_seeded_rng));
	} else {
		/* Module is required to perform deterministic operation */

		CKINT(lc_sphincs_sign_ctx(sig, ctx, data->msg.buf,
					  data->msg.len, &sk, NULL));
	}

	CKINT(lc_sphincs_sig_ptr(&ptr, &len, sig));
	CKINT(alloc_buf(len, &data->sig));
	memcpy(data->sig.buf, ptr, len);

out:
	if (sig)
		free(sig);
	lc_slh_reset_impl();
	return ret;
}

static int lc_slg_dsa_sigver(struct slh_dsa_sigver_data *data,
			     flags_t parsed_flags)
{
	struct lc_sphincs_pk pk;
	struct lc_sphincs_sig *sig = NULL;
	enum lc_sphincs_type type;
	int ret;
	uint8_t n;
	LC_SPHINCS_CTX_ON_STACK(ctx);

	(void)parsed_flags;

	CKINT(lc_slh_type(data->cipher, &type, &n));

	CKINT(-posix_memalign((void **)&sig, 8, sizeof(struct lc_sphincs_sig)));

	CKINT(lc_sphincs_pk_load(&pk, data->pk.buf, data->pk.len));
	ret = lc_sphincs_sig_load(sig, data->sig.buf, data->sig.len);
	if (ret) {
		if (ret == -EINVAL) {
			logger(LOGGER_DEBUG,
			       "Signature has invalid size (expected %u, actual %zu)\n",
			       lc_sphincs_sig_size(type), data->sig.len);
			ret = 0;
			data->sigver_success = 0;
		}
		goto out;
	}
	switch (data->cipher) {
	case ACVP_SLH_DSA_SHAKE_128F:
	case ACVP_SLH_DSA_SHAKE_192F:
	case ACVP_SLH_DSA_SHAKE_256F:
		lc_sphincs_pk_set_keytype_fast(&pk);
		break;

	case ACVP_SLH_DSA_SHAKE_128S:
	case ACVP_SLH_DSA_SHAKE_192S:
	case ACVP_SLH_DSA_SHAKE_256S:
		lc_sphincs_pk_set_keytype_small(&pk);
		break;

	default:
		return -EOPNOTSUPP;
	}

	/* Set SLH-DSA.Sign_internal */
	if (!strncasecmp((char *)data->interface.buf, "internal", 8))
		lc_sphincs_ctx_internal(ctx);

	/* This call also covers the NULL buffer */
	lc_sphincs_ctx_userctx(ctx, data->context.buf, data->context.len);

	if (data->hashalg) {
		BUFFER_INIT(tmp);
		const struct lc_hash *hash_alg;

		CKINT(lc_get_common_hash(data->hashalg, &hash_alg));
		lc_sphincs_ctx_hash(ctx, hash_alg);

		/* Calculate the digest */
		LC_HASH_CTX_ON_STACK(hash_ctx, hash_alg);
		lc_hash_init(hash_ctx);

		if (hash_alg == lc_shake256)
			lc_hash_set_digestsize(hash_ctx, 64);

		CKINT(alloc_buf(lc_hash_digestsize(hash_ctx), &tmp));
		lc_hash_update(hash_ctx, data->msg.buf, data->msg.len);
		lc_hash_final(hash_ctx, tmp.buf);

		lc_hash_zero(hash_ctx);
		free_buf(&data->msg);
		copy_ptr_buf(&data->msg, &tmp);
	}

	ret = lc_sphincs_verify_ctx(sig, ctx, data->msg.buf, data->msg.len,
				    &pk);

	if (ret == -EBADMSG) {
		logger(LOGGER_DEBUG, "Signature verification: signature bad\n");
		data->sigver_success = 0;
	} else if (!ret) {
		logger(LOGGER_DEBUG,
		       "Signature verification: signature good\n");
		data->sigver_success = 1;
	} else {
		/* This can happen when data is wrong */
		logger(LOGGER_WARN, "Signature verification: general error\n");
		data->sigver_success = 0;
	}

	ret = 0;

out:
	if (sig)
		free(sig);
	lc_slh_reset_impl();
	return ret;
}

static struct slh_dsa_backend lc_slh_dsa =
{
	lc_slh_dsa_keygen,
	lc_slh_dsa_siggen,
	lc_slg_dsa_sigver
};

ACVP_DEFINE_CONSTRUCTOR(lc_slh_dsa_backend)
static void lc_slh_dsa_backend(void)
{
	register_slh_dsa_impl(&lc_slh_dsa);
}


#ifdef __KERNEL__
void __init linux_kernel_constructor(void)
{
	_init_lc_sym_backend();
	_init_lc_sha_backend();
	_init_lc_cshake_backend_c();
	_init_lc_hmac_backend_c();
	_init_lc_kmac_backend_c();
	_init_lc_drbg_backend();
	_init_lc_108_backend();
	_init_lc_pbkdf_backend();
	_init_lc_hkdf_backend();
	_init_lc_eddsa_backend();
	_init_lc_ml_dsa_backend();
	_init_lc_ml_kem_backend();
	_init_lc_slh_dsa_backend();
}
#endif
