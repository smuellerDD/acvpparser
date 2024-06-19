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
#include "kyber_kem_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_c.h"
#include "sha3_riscv_asm.h"
#ifdef __x86_64__
#include "shake_4x_avx2.h"
#include "kyber_kem_avx2.h"
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
#include "shake_2x_armv8.h"
#include "kyber_kem_armv8.h"
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

#if 0
#include <getopt.h>

static int lc_compare(const uint8_t *act, const uint8_t *exp,
		      const size_t len, const char *info)
{
	if (memcmp(act, exp, len)) {
		unsigned int i;

		printf("Expected %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(exp + i));

		printf("\n");

		printf("Actual %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(act + i));

		printf("\n");

		return 1;
	}

	return 0;
}

#include "dilithium_tester_vectors_level2_hex.h"
static int lc_dilithium_one(const struct dilithium_testvector_hex *vector)
{
	struct lc_dilithium_pk d_pk;
	struct lc_dilithium_sk d_sk;
	struct lc_dilithium_sig d_sig;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	int ret = 0;

	s_rng_state.seed = vector->seed;
	s_rng_state.seedlen = sizeof(vector->seed);

	CKINT(lc_dilithium_keypair_c(&d_pk, &d_sk, &s_drng));
	CKINT(lc_dilithium_sign_c(&d_sig, vector->msg, 8, &d_sk, NULL));

	ret += lc_compare(d_pk.pk, vector->pk, LC_DILITHIUM_PUBLICKEYBYTES,
			  "Dilithium PK");
	ret += lc_compare(d_sk.sk, vector->sk, LC_DILITHIUM_SECRETKEYBYTES,
			  "Dilithium SK");
	ret += lc_compare(d_sig.sig, vector->sig, LC_DILITHIUM_CRYPTO_BYTES,
			  "Dilithium Sig");

	if (lc_dilithium_verify_c(&d_sig, vector->msg, 8, &d_pk))
		printf("Signature verification failed!\n");

out:
	return ret;
}

static int lc_dilithium_gen_one(unsigned int err)
{
	struct lc_dilithium_pk d_pk;
	struct lc_dilithium_sk d_sk;
	struct lc_dilithium_sig d_sig;
	struct static_rng s_rng_state;
	uint8_t msg[4096] = { 0 };
	size_t msg_len;
	uint8_t seed[32];
	uint32_t errorlocation = 0;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	int ret = 0;

	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, msg, sizeof(msg)));

	/* msg_len is defined by the first 12 bits of the msg buf */
	msg_len = (size_t)msg[0];
	msg_len |= (((size_t)msg[1]) & 7) << 8;

	if (msg_len > sizeof(msg)) {
		printf("msg_len generation failure %zu %zu\n", msg_len,
		       sizeof(msg));
		return -EFAULT;
	}

	memcpy(&errorlocation, msg, sizeof(errorlocation));

	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, seed, sizeof(seed)));
	s_rng_state.seed = seed;
	s_rng_state.seedlen = sizeof(seed);

	CKINT(lc_dilithium_keypair_c(&d_pk, &d_sk, &s_drng));
	CKINT(lc_dilithium_sign_c(&d_sig, msg, msg_len, &d_sk, NULL));

	switch (err) {
	case 1:
		printf("error added: in signature\n");
		errorlocation &= (sizeof(d_sig.sig) - 1);
		d_sig.sig[errorlocation] = (d_sig.sig[errorlocation] + 1) & 0xff;
		break;
	case 2:
		printf("error added: in pk\n");
		errorlocation &= (sizeof(d_pk.pk) - 1);
		d_pk.pk[errorlocation] = (d_pk.pk[errorlocation] + 1) & 0xff;
		break;
	case 3:
		printf("error added: in sk\n");
		errorlocation &= (sizeof(d_sk.sk) - 1);
		d_sk.sk[errorlocation] = (d_sk.sk[errorlocation] + 1) & 0xff;
		break;
	default:
		break;
	}

#if LC_DILITHIUM_MODE == 2
	printf("parameter set: ML-DSA-44\n");
#elif LC_DILITHIUM_MODE == 3
	printf("parameter set: ML-DSA-65\n");
#else
	printf("parameter set: ML-DSA-87\n");
#endif

	bin2print(seed, sizeof(seed), stdout, "seed");
	bin2print(d_pk.pk, sizeof(d_pk.pk), stdout, "pk");
	bin2print(d_sk.sk, sizeof(d_sk.sk), stdout, "sk");
	printf("deterministic signature: true\n");
	bin2print(msg, msg_len, stdout, "message");
	bin2print(d_sig.sig, sizeof(d_sig.sig), stdout, "sig");

	printf("\n");

out:
	return ret;
}

static int lc_dilithium_gen_all(void)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < 10; i++) {
		ret += lc_dilithium_gen_one(0);
	}

	ret += lc_dilithium_gen_one(1);
	ret += lc_dilithium_gen_one(2);
	ret += lc_dilithium_gen_one(3);

	return ret;
}

static int lc_dilithium_all(void)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(dilithium_testvectors_cavp_data); i++) {
		ret += lc_dilithium_one(&dilithium_testvectors_cavp_data[i]);
	}

	return ret;
}

/************************************************
 * Kyber
 ************************************************/

static int lc_kyber_gen_one(unsigned int err)
{
	struct lc_kyber_pk d_pk;
	struct lc_kyber_sk d_sk;
	struct lc_kyber_ss d_ss;
	struct lc_kyber_ct d_ct;
	struct static_rng s_rng_state;
	uint8_t seed[32];
	uint32_t errorlocation = 0;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	int ret = 0;

	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, (void *)&errorlocation,
			      sizeof(errorlocation)));

	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, seed, sizeof(seed)));
	s_rng_state.seed = seed;
	s_rng_state.seedlen = sizeof(seed);

	CKINT(lc_kyber_keypair_c(&d_pk, &d_sk, &s_drng));
	CKINT(lc_kyber_enc_c(&d_ct, &d_ss, &d_pk, &s_drng));

	switch (err) {
	case 1:
		printf("error added: in shared secret\n");
		errorlocation &= (sizeof(d_ss.ss) - 1);
		d_ss.ss[errorlocation] = (d_ss.ss[errorlocation] + 1) & 0xff;
		break;
	case 2:
		printf("error added: in pk\n");
		errorlocation &= (sizeof(d_pk.pk) - 1);
		d_pk.pk[errorlocation] = (d_pk.pk[errorlocation] + 1) & 0xff;
		break;
	case 3:
		printf("error added: in sk\n");
		errorlocation &= (sizeof(d_sk.sk) - 1);
		d_sk.sk[errorlocation] = (d_sk.sk[errorlocation] + 1) & 0xff;
		break;
	case 4:
		printf("error added: in ciphertext\n");
		errorlocation &= (sizeof(d_ct.ct) - 1);
		d_ct.ct[errorlocation] = (d_ct.ct[errorlocation] + 1) & 0xff;
		break;
	default:
		break;
	}

#if LC_KYBER_K == 2
	printf("parameter set: ML-KEM-512\n");
#elif LC_KYBER_K == 3
	printf("parameter set: ML-KEM-768\n");
#else
	printf("parameter set: ML-KEM-1024\n");
#endif

	bin2print(seed, sizeof(seed), stdout, "seed");
	bin2print(d_pk.pk, sizeof(d_pk.pk), stdout, "pk");
	bin2print(d_sk.sk, sizeof(d_sk.sk), stdout, "sk");
	bin2print(d_ct.ct, sizeof(d_ct.ct), stdout, "ct");
	bin2print(d_ss.ss, sizeof(d_ss.ss), stdout, "ss");

	printf("\n");

out:
	return ret;
}

static int lc_kyber_gen_all(void)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < 10; i++) {
		ret += lc_kyber_gen_one(0);
	}

	ret += lc_kyber_gen_one(1);
	ret += lc_kyber_gen_one(2);
	ret += lc_kyber_gen_one(3);
	ret += lc_kyber_gen_one(4);

	return ret;
}

/************************************************
 * Specific calls
 ************************************************/
static void lc_fips_usage(void)
{
	fprintf(stderr, "Additional options:\n");
	fprintf(stderr, "\t-t --dilithium_test\tPerform testing\n");
	fprintf(stderr, "\t-g --dilithium_generate\tGenerate vectors\n");
}

static int lc_main(int argc, char *argv[])
{
	int ret = 0, c = 0;

	optind = 0;

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{"dilithium_test",	no_argument,  0, 'd'},
			{"dilithium_generate",	no_argument,  0, 'g'},
			{"kyber_test",		no_argument,  0, 'k'},
			{"kyber_generate",	no_argument,  0, 'i'},

			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "dgki", options, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				return lc_dilithium_all();
			case 1:
				return lc_dilithium_gen_all();

			case 2:
				/* TODO */
				return lc_kyber_gen_all();
			case 3:
				return lc_kyber_gen_all();

			default:
				return -EINVAL;
			}
			break;

		case 'd':
			return lc_dilithium_all();
		case 'g':
			return lc_dilithium_gen_all();

		case 'k':
			/* TODO */
			return lc_kyber_gen_all();
		case 'i':
			return lc_kyber_gen_all();

		default:
			return -EINVAL;
		}
	}

	return ret;
}

struct main_extension lc_main_extension_def = {
	lc_main,
	lc_fips_usage,
};

ACVP_DEFINE_CONSTRUCTOR(lc_main_extension)
static void lc_main_extension(void)
{
	register_main_extension(&lc_main_extension_def);
}
#endif

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
	CKINT(lc_ed25519_sign(&sig, data->msg.buf, data->msg.len, sk,
			      lc_seeded_rng));

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

	ret = lc_ed25519_verify(&sig, data->msg.buf, data->msg.len, &pk);

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

/******************************** Dilithium 87 ********************************/

struct dilithium_87_funcs {
	int (*dilithium_keypair)(struct lc_dilithium_pk *pk,
				 struct lc_dilithium_sk *sk,
				 struct lc_rng_ctx *rng_ctx);
	int (*dilithium_sign)(struct lc_dilithium_sig *sig,
			      const uint8_t *m, size_t mlen,
			      const struct lc_dilithium_sk *sk,
			      struct lc_rng_ctx *rng_ctx);
	int (*dilithium_verify)(const struct lc_dilithium_sig *sig,
				const uint8_t *m, size_t mlen,
				const struct lc_dilithium_pk *pk);
};

static int lc_get_dilithium_87(struct dilithium_87_funcs *funcs)
{
	const char *envstr = getenv("LC_DILITHIUM");

	if (!envstr || (envstr && !strncasecmp(envstr, "common", 6))) {
		logger(LOGGER_VERBOSE, "Dilithium-87 implementation: common\n");
		funcs->dilithium_keypair = lc_dilithium_keypair;
		funcs->dilithium_sign = lc_dilithium_sign;
		funcs->dilithium_verify = lc_dilithium_verify;
	} else if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "Dilithium-87 implementation: C\n");
		funcs->dilithium_keypair = lc_dilithium_keypair_c;
		funcs->dilithium_sign = lc_dilithium_sign_c;
		funcs->dilithium_verify = lc_dilithium_verify_c;
	} else {
		logger(LOGGER_ERR, "Unknown Dilithium-87 implementation %s\n", envstr);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_dsa_87_keygen(struct ml_dsa_keygen_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_87_funcs funcs;
	struct lc_dilithium_pk lc_pk;
	struct lc_dilithium_sk lc_sk;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };

	int ret;

	(void)parsed_flags;

	CKINT(lc_get_dilithium_87(&funcs));

	s_rng_state.seed = data->seed.buf;
	s_rng_state.seedlen = data->seed.len;
	CKINT(funcs.dilithium_keypair(&lc_pk, &lc_sk, &s_drng));

	CKINT(alloc_buf(sizeof(lc_pk.pk), &data->pk));
	memcpy(data->pk.buf, lc_pk.pk, sizeof(lc_pk.pk));

	CKINT(alloc_buf(sizeof(lc_sk.sk), &data->sk));
	memcpy(data->sk.buf, lc_sk.sk, sizeof(lc_sk.sk));

out:
	return ret;
}

static int lc_ml_dsa_87_siggen(struct ml_dsa_siggen_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_87_funcs funcs;
	struct lc_dilithium_sk sk;
	struct lc_dilithium_sig sig;
	int ret;

	CKINT(lc_get_dilithium_87(&funcs));

	if (data->sk.len) {
		if (data->sk.len != sizeof(sk.sk))
			return -EFAULT;
		memcpy(sk.sk, data->sk.buf, data->sk.len);
	} else if (data->privkey) {
		struct lc_dilithium_sk *tmp = data->privkey;

		memcpy(sk.sk, tmp->sk, lc_dilithium_sk_size());
	} else
		return -EOPNOTSUPP;

	if (data->rnd.len) {
		/* random data is provided by test vector */

		struct static_rng s_rng_state;
		struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
					     .rng_state = &s_rng_state };

		s_rng_state.seed = data->rnd.buf;
		s_rng_state.seedlen = data->rnd.len;

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, &s_drng));
	} else if ((parsed_flags & FLAG_OP_ML_DSA_TYPE_MASK) ==
		   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC) {
		/* Module is required to generate random data */

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, lc_seeded_rng));
	} else {
		/* Module is required to perform deterministic operation */

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, NULL));
	}

	CKINT(alloc_buf(sizeof(sig.sig), &data->sig));
	memcpy(data->sig.buf, sig.sig, sizeof(sig.sig));

#if 0
	struct lc_dilithium_pk pk;

	if (sizeof(pk.pk) == data->pk.len) {
		memcpy(pk.pk, data->pk.buf, data->pk.len);

		CKINT(funcs.dilithium_verify(&sig, data->msg.buf,
					     data->msg.len, &pk));
	}
#endif

out:
	return ret;
}

static int lc_ml_dsa_87_sigver(struct ml_dsa_sigver_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_87_funcs funcs;
	struct lc_dilithium_pk pk;
	struct lc_dilithium_sig sig;
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_dilithium_87(&funcs));

	if (sizeof(pk.pk) != data->pk.len)
		return -EOPNOTSUPP;
	memcpy(pk.pk, data->pk.buf, data->pk.len);

	if (sizeof(sig.sig) != data->sig.len)
		return -EOPNOTSUPP;
	memcpy(sig.sig, data->sig.buf, data->sig.len);

	ret = funcs.dilithium_verify(&sig, data->msg.buf, data->msg.len, &pk);

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
	return ret;
}

static int lc_ml_dsa_87_keygen_en(uint64_t cipher, struct buffer *pk,
				  void **sk)
{
	struct lc_dilithium_pk lc_pk;
	struct lc_dilithium_sk *lc_sk;
	int ret;

	(void)cipher;

	lc_sk = calloc(1, sizeof(struct lc_dilithium_sk));
	CKNULL(lc_sk, -ENOMEM);

	CKINT(lc_dilithium_keypair(&lc_pk, lc_sk, lc_seeded_rng));

	CKINT(alloc_buf(sizeof(lc_pk.pk), pk));
	memcpy(pk->buf, lc_pk.pk, sizeof(lc_pk.pk));

	*sk = lc_sk;

out:
	return ret;
}

/******************************** Dilithium 65 ********************************/

struct dilithium_65_funcs {
	int (*dilithium_keypair)(struct lc_dilithium_65_pk *pk,
				 struct lc_dilithium_65_sk *sk,
				 struct lc_rng_ctx *rng_ctx);
	int (*dilithium_sign)(struct lc_dilithium_65_sig *sig,
			      const uint8_t *m, size_t mlen,
			      const struct lc_dilithium_65_sk *sk,
			      struct lc_rng_ctx *rng_ctx);
	int (*dilithium_verify)(const struct lc_dilithium_65_sig *sig,
				const uint8_t *m, size_t mlen,
				const struct lc_dilithium_65_pk *pk);
};

static int lc_get_dilithium_65(struct dilithium_65_funcs *funcs)
{
	const char *envstr = getenv("LC_DILITHIUM");

	if (!envstr || (envstr && !strncasecmp(envstr, "common", 6))) {
		logger(LOGGER_VERBOSE, "Dilithium-65 implementation: common\n");
		funcs->dilithium_keypair = lc_dilithium_65_keypair;
		funcs->dilithium_sign = lc_dilithium_65_sign;
		funcs->dilithium_verify = lc_dilithium_65_verify;
	} else if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "Dilithium-87 implementation: C\n");
		funcs->dilithium_keypair = lc_dilithium_65_keypair_c;
		funcs->dilithium_sign = lc_dilithium_65_sign_c;
		funcs->dilithium_verify = lc_dilithium_65_verify_c;
	} else {
		logger(LOGGER_ERR, "Unknown Dilithium-65 implementation %s\n", envstr);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_dsa_65_keygen(struct ml_dsa_keygen_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_65_funcs funcs;
	struct lc_dilithium_65_pk lc_pk;
	struct lc_dilithium_65_sk lc_sk;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };

	int ret;

	(void)parsed_flags;

	CKINT(lc_get_dilithium_65(&funcs));

	s_rng_state.seed = data->seed.buf;
	s_rng_state.seedlen = data->seed.len;
	CKINT(funcs.dilithium_keypair(&lc_pk, &lc_sk, &s_drng));

	CKINT(alloc_buf(sizeof(lc_pk.pk), &data->pk));
	memcpy(data->pk.buf, lc_pk.pk, sizeof(lc_pk.pk));

	CKINT(alloc_buf(sizeof(lc_sk.sk), &data->sk));
	memcpy(data->sk.buf, lc_sk.sk, sizeof(lc_sk.sk));

out:
	return ret;
}

static int lc_ml_dsa_65_siggen(struct ml_dsa_siggen_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_65_funcs funcs;
	struct lc_dilithium_65_sk sk;
	struct lc_dilithium_65_sig sig;
	int ret;

	CKINT(lc_get_dilithium_65(&funcs));

	if (data->sk.len) {
		if (data->sk.len != sizeof(sk.sk))
			return -EFAULT;
		memcpy(sk.sk, data->sk.buf, data->sk.len);
	} else if (data->privkey) {
		struct lc_dilithium_65_sk *tmp = data->privkey;

		memcpy(sk.sk, tmp->sk, lc_dilithium_65_sk_size());
	} else
		return -EOPNOTSUPP;

	if (data->rnd.len) {
		/* random data is provided by test vector */

		struct static_rng s_rng_state;
		struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
					     .rng_state = &s_rng_state };

		s_rng_state.seed = data->rnd.buf;
		s_rng_state.seedlen = data->rnd.len;

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, &s_drng));
	} else if ((parsed_flags & FLAG_OP_ML_DSA_TYPE_MASK) ==
		   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC) {
		/* Module is required to generate random data */

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, lc_seeded_rng));
	} else {
		/* Module is required to perform deterministic operation */

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, NULL));
	}

	CKINT(alloc_buf(sizeof(sig.sig), &data->sig));
	memcpy(data->sig.buf, sig.sig, sizeof(sig.sig));

#if 0
	struct lc_dilithium_65_pk pk;

	if (sizeof(pk.pk) == data->pk.len) {
		memcpy(pk.pk, data->pk.buf, data->pk.len);

		CKINT(funcs.dilithium_verify(&sig, data->msg.buf,
					     data->msg.len, &pk));
	}
#endif

out:
	return ret;
}

static int lc_ml_dsa_65_sigver(struct ml_dsa_sigver_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_65_funcs funcs;
	struct lc_dilithium_65_pk pk;
	struct lc_dilithium_65_sig sig;
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_dilithium_65(&funcs));

	if (sizeof(pk.pk) != data->pk.len)
		return -EOPNOTSUPP;
	memcpy(pk.pk, data->pk.buf, data->pk.len);

	if (sizeof(sig.sig) != data->sig.len)
		return -EOPNOTSUPP;
	memcpy(sig.sig, data->sig.buf, data->sig.len);

	ret = funcs.dilithium_verify(&sig, data->msg.buf, data->msg.len, &pk);

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
	return ret;
}

static int lc_ml_dsa_65_keygen_en(uint64_t cipher, struct buffer *pk,
				  void **sk)
{
	struct lc_dilithium_65_pk lc_pk;
	struct lc_dilithium_65_sk *lc_sk = NULL;
	int ret;

	(void)cipher;

	lc_sk = calloc(1, sizeof(struct lc_dilithium_65_sk));
	CKNULL(lc_sk, -ENOMEM);

	CKINT_LOG(lc_dilithium_65_keypair(&lc_pk, lc_sk, lc_seeded_rng),
		  "ML-DSA-65 keygen failed %d\n", ret);

	CKINT(alloc_buf(sizeof(lc_pk.pk), pk));
	memcpy(pk->buf, lc_pk.pk, sizeof(lc_pk.pk));

	*sk = lc_sk;

out:
	return ret;
}

/******************************** Dilithium 44 ********************************/

struct dilithium_44_funcs {
	int (*dilithium_keypair)(struct lc_dilithium_44_pk *pk,
				 struct lc_dilithium_44_sk *sk,
				 struct lc_rng_ctx *rng_ctx);
	int (*dilithium_sign)(struct lc_dilithium_44_sig *sig,
			      const uint8_t *m, size_t mlen,
			      const struct lc_dilithium_44_sk *sk,
			      struct lc_rng_ctx *rng_ctx);
	int (*dilithium_verify)(const struct lc_dilithium_44_sig *sig,
				const uint8_t *m, size_t mlen,
				const struct lc_dilithium_44_pk *pk);
};

static int lc_get_dilithium_44(struct dilithium_44_funcs *funcs)
{
	const char *envstr = getenv("LC_DILITHIUM");

	if (!envstr || (envstr && !strncasecmp(envstr, "common", 6))) {
		logger(LOGGER_VERBOSE, "Dilithium-44 implementation: common\n");
		funcs->dilithium_keypair = lc_dilithium_44_keypair;
		funcs->dilithium_sign = lc_dilithium_44_sign;
		funcs->dilithium_verify = lc_dilithium_44_verify;
	} else if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "Dilithium implementation: C\n");
		funcs->dilithium_keypair = lc_dilithium_44_keypair_c;
		funcs->dilithium_sign = lc_dilithium_44_sign_c;
		funcs->dilithium_verify = lc_dilithium_44_verify_c;
	} else {
		logger(LOGGER_ERR, "Unknown Dilithium-44 implementation %s\n", envstr);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_dsa_44_keygen(struct ml_dsa_keygen_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_44_funcs funcs;
	struct lc_dilithium_44_pk lc_pk;
	struct lc_dilithium_44_sk lc_sk;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };

	int ret;

	(void)parsed_flags;

	CKINT(lc_get_dilithium_44(&funcs));

	s_rng_state.seed = data->seed.buf;
	s_rng_state.seedlen = data->seed.len;
	CKINT(funcs.dilithium_keypair(&lc_pk, &lc_sk, &s_drng));

	CKINT(alloc_buf(sizeof(lc_pk.pk), &data->pk));
	memcpy(data->pk.buf, lc_pk.pk, sizeof(lc_pk.pk));

	CKINT(alloc_buf(sizeof(lc_sk.sk), &data->sk));
	memcpy(data->sk.buf, lc_sk.sk, sizeof(lc_sk.sk));

out:
	return ret;
}

static int lc_ml_dsa_44_siggen(struct ml_dsa_siggen_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_44_funcs funcs;
	struct lc_dilithium_44_sk sk;
	struct lc_dilithium_44_sig sig;
	int ret;

	CKINT(lc_get_dilithium_44(&funcs));

	if (data->sk.len) {
		if (data->sk.len != sizeof(sk.sk))
			return -EFAULT;
		memcpy(sk.sk, data->sk.buf, data->sk.len);
	} else if (data->privkey) {
		struct lc_dilithium_44_sk *tmp = data->privkey;

		memcpy(sk.sk, tmp->sk, lc_dilithium_44_sk_size());
	} else
		return -EOPNOTSUPP;

	if (data->rnd.len) {
		/* random data is provided by test vector */

		struct static_rng s_rng_state;
		struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
					     .rng_state = &s_rng_state };

		s_rng_state.seed = data->rnd.buf;
		s_rng_state.seedlen = data->rnd.len;

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, &s_drng));
	} else if ((parsed_flags & FLAG_OP_ML_DSA_TYPE_MASK) ==
		   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC) {
		/* Module is required to generate random data */

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, lc_seeded_rng));
	} else {
		/* Module is required to perform deterministic operation */

		CKINT(funcs.dilithium_sign(&sig, data->msg.buf, data->msg.len,
					   &sk, NULL));
	}

	CKINT(alloc_buf(sizeof(sig.sig), &data->sig));
	memcpy(data->sig.buf, sig.sig, sizeof(sig.sig));

#if 0
	struct lc_dilithium_44_pk pk;

	if (sizeof(pk.pk) == data->pk.len) {
		memcpy(pk.pk, data->pk.buf, data->pk.len);

		CKINT(funcs.dilithium_verify(&sig, data->msg.buf,
					     data->msg.len, &pk));
	}
#endif

out:
	return ret;
}

static int lc_ml_dsa_44_sigver(struct ml_dsa_sigver_data *data,
			       flags_t parsed_flags)
{
	struct dilithium_44_funcs funcs;
	struct lc_dilithium_44_pk pk;
	struct lc_dilithium_44_sig sig;
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_dilithium_44(&funcs));

	if (sizeof(pk.pk) != data->pk.len)
		return -EOPNOTSUPP;
	memcpy(pk.pk, data->pk.buf, data->pk.len);

	if (sizeof(sig.sig) != data->sig.len)
		return -EOPNOTSUPP;
	memcpy(sig.sig, data->sig.buf, data->sig.len);

	ret = funcs.dilithium_verify(&sig, data->msg.buf, data->msg.len, &pk);

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
	return ret;
}

static int lc_ml_dsa_44_keygen_en(uint64_t cipher, struct buffer *pk,
				  void **sk)
{
	struct lc_dilithium_44_pk lc_pk;
	struct lc_dilithium_44_sk *lc_sk = NULL;
	int ret;

	(void)cipher;

	lc_sk = calloc(1, sizeof(struct lc_dilithium_44_sk));
	CKNULL(lc_sk, -ENOMEM);

	CKINT(lc_dilithium_44_keypair(&lc_pk, lc_sk, lc_seeded_rng));

	CKINT(alloc_buf(sizeof(lc_pk.pk), pk));
	memcpy(pk->buf, lc_pk.pk, sizeof(lc_pk.pk));

	*sk = lc_sk;

out:
	return ret;
}

/******************************** Common Code *********************************/

static int lc_ml_dsa_keygen(struct ml_dsa_keygen_data *data,
			       flags_t parsed_flags)
{
	if (data->cipher == ACVP_ML_DSA_44)
		return lc_ml_dsa_44_keygen(data, parsed_flags);
	if (data->cipher == ACVP_ML_DSA_65)
		return lc_ml_dsa_65_keygen (data, parsed_flags);
	if (data->cipher == ACVP_ML_DSA_87)
		return lc_ml_dsa_87_keygen(data, parsed_flags);
	return -EOPNOTSUPP;
}

static int lc_ml_dsa_siggen(struct ml_dsa_siggen_data *data,
			       flags_t parsed_flags)
{
	if (data->cipher == ACVP_ML_DSA_44)
		return lc_ml_dsa_44_siggen(data, parsed_flags);
	if (data->cipher == ACVP_ML_DSA_65)
		return lc_ml_dsa_65_siggen (data, parsed_flags);
	if (data->cipher == ACVP_ML_DSA_87)
		return lc_ml_dsa_87_siggen(data, parsed_flags);
	return -EOPNOTSUPP;
}

static int lc_ml_dsa_sigver(struct ml_dsa_sigver_data *data,
			    flags_t parsed_flags)
{
	if (data->cipher == ACVP_ML_DSA_44)
		return lc_ml_dsa_44_sigver(data, parsed_flags);
	if (data->cipher == ACVP_ML_DSA_65)
		return lc_ml_dsa_65_sigver(data, parsed_flags);
	if (data->cipher == ACVP_ML_DSA_87)
		return lc_ml_dsa_87_sigver(data, parsed_flags);
	return -EOPNOTSUPP;
}

static int lc_ml_dsa_keygen_en(uint64_t cipher, struct buffer *pk,
			       void **sk)
{
	if (cipher == ACVP_ML_DSA_44)
		return lc_ml_dsa_44_keygen_en(cipher, pk, sk);
	if (cipher == ACVP_ML_DSA_65)
		return lc_ml_dsa_65_keygen_en(cipher, pk, sk);
	if (cipher == ACVP_ML_DSA_87)
		return lc_ml_dsa_87_keygen_en(cipher, pk, sk);
	return -EOPNOTSUPP;
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

struct kyber_rng {
	const uint8_t *d;
	size_t dlen;
	const uint8_t *z;
	size_t zlen;

	const uint8_t *ptr;
	size_t *ptr_len;
};

static int lc_kyber_rng_gen(void *_state, const uint8_t *addtl_input,
			    size_t addtl_input_len, uint8_t *out,
			    size_t outlen)
{
	struct kyber_rng *state = _state;

	(void)addtl_input;
	(void)addtl_input_len;

	if (outlen != *state->ptr_len)
		return -EINVAL;

	memcpy(out, state->ptr, outlen);

	/* Flip-flop between seed values */
	if (state->ptr == state->d) {
		state->ptr = state->z;
		state->ptr_len = &state->zlen;
	} else {
		state->ptr = state->d;
		state->ptr_len = &state->dlen;
	}

	return 0;
}

static int lc_kyber_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			      const uint8_t *persbuf, size_t perslen)
{
	(void)_state;
	(void)seed;
	(void)seedlen;
	(void)persbuf;
	(void)perslen;
	return 0;
}

static void lc_kyber_rng_zero(void *_state)
{
	(void)_state;
}

static const struct lc_rng lc_kyber_drng = {
	.generate = lc_kyber_rng_gen,
	.seed = lc_kyber_rng_seed,
	.zero = lc_kyber_rng_zero,
};

/********************************* Kyber 1024 *********************************/

struct kyber_funcs {
	int (*kyber_keypair)(struct lc_kyber_pk *pk,
			     struct lc_kyber_sk *sk,
			     struct lc_rng_ctx *rng_ctx);
	int (*kyber_enc_int)(struct lc_kyber_ct *ct,
			     struct lc_kyber_ss *ss,
			     const struct lc_kyber_pk *pk,
			     struct lc_rng_ctx *rng_ctx);
	int (*kyber_dec)(struct lc_kyber_ss *ss,
			 const struct lc_kyber_ct *ct,
			 const struct lc_kyber_sk *sk);
};

static int lc_get_kyber(struct kyber_funcs *funcs)
{
	const char *envstr = getenv("LC_KYBER");

	if (!envstr || (envstr && !strncasecmp(envstr, "common", 6))) {
		logger(LOGGER_VERBOSE, "Kyber-1024 implementation: common\n");
#ifdef __x86_64__
		funcs->kyber_keypair = lc_kyber_keypair_avx;
		funcs->kyber_enc_int = lc_kyber_enc_avx;
		funcs->kyber_dec = lc_kyber_dec_avx;
#elif defined(__aarch64__) || defined(_M_ARM64)
		funcs->kyber_keypair = lc_kyber_keypair_armv8;
		funcs->kyber_enc_int = lc_kyber_enc_armv8;
		funcs->kyber_dec = lc_kyber_dec_armv8;
#else
		funcs->kyber_keypair = lc_kyber_keypair;
		funcs->kyber_enc_int = lc_kyber_enc_c;
		funcs->kyber_dec = lc_kyber_dec;
#endif

	} else if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "Kyber implementation: C\n");
		funcs->kyber_keypair = lc_kyber_keypair_c;
		funcs->kyber_enc_int = lc_kyber_enc_c;
		funcs->kyber_dec = lc_kyber_dec_c;
	} else {
		logger(LOGGER_ERR, "Unknown Kyber implementation %s\n", envstr);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_kem_1024_keygen(struct ml_kem_keygen_data *data,
				 flags_t parsed_flags)
{
	struct kyber_funcs funcs;
	struct lc_kyber_pk pk;
	struct lc_kyber_sk sk;
	struct kyber_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_kyber_drng,
				     .rng_state = &s_rng_state };
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber(&funcs));

	s_rng_state.d = data->d.buf;
	s_rng_state.dlen = data->d.len;
	s_rng_state.z = data->z.buf;
	s_rng_state.zlen = data->z.len;

	/* The d value is the first random number to be supplied */
	s_rng_state.ptr = s_rng_state.d;
	s_rng_state.ptr_len = &s_rng_state.dlen;

	CKINT(funcs.kyber_keypair(&pk, &sk, &s_drng));

	CKINT(alloc_buf(sizeof(pk.pk), &data->ek));
	memcpy(data->ek.buf, pk.pk, sizeof(pk.pk));

	CKINT(alloc_buf(sizeof(sk.sk), &data->dk));
	memcpy(data->dk.buf, sk.sk, sizeof(sk.sk));

out:
	return ret;
}

static int lc_ml_kem_1024_encapsulation(struct ml_kem_encapsulation_data *data,
					flags_t parsed_flags)
{
	struct kyber_funcs funcs;
	struct lc_kyber_pk pk;
	struct lc_kyber_ct ct;
	struct lc_kyber_ss ss;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber(&funcs));

	if (sizeof(pk.pk) != data->ek.len) {
		logger(LOGGER_ERR,
		       "Kyber EK does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(pk.pk), data->ek.len);
		return -EOPNOTSUPP;
	}
	memcpy(pk.pk, data->ek.buf, data->ek.len);

	s_rng_state.seed = data->msg.buf;
	s_rng_state.seedlen = data->msg.len;

	if (funcs.kyber_enc_int) {
		CKINT(funcs.kyber_enc_int(&ct, &ss, &pk, &s_drng));
	} else {
		ret = -EOPNOTSUPP;
		goto out;
	}

	CKINT(alloc_buf(sizeof(ct.ct), &data->c));
	memcpy(data->c.buf, ct.ct, sizeof(ct.ct));

	CKINT(alloc_buf(sizeof(ss.ss), &data->ss));
	memcpy(data->ss.buf, ss.ss, sizeof(ss.ss));

out:
	return ret;
}

static int lc_ml_kem_1024_decapsulation(struct ml_kem_decapsulation_data *data,
					flags_t parsed_flags)
{
	struct kyber_funcs funcs;
	struct lc_kyber_sk sk;
	struct lc_kyber_ct ct;
	struct lc_kyber_ss ss;
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber(&funcs));

	if (sizeof(sk.sk) != data->dk.len) {
		logger(LOGGER_ERR,
		       "Kyber DK does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(sk.sk), data->dk.len);
		return -EFAULT;
	}
	memcpy(sk.sk, data->dk.buf, data->dk.len);

	if (sizeof(ct.ct) != data->c.len) {
		logger(LOGGER_ERR,
		       "Kyber CT does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(ct.ct), data->c.len);
		return -EFAULT;
	}
	memcpy(ct.ct, data->c.buf, data->c.len);

	CKINT(funcs.kyber_dec(&ss, &ct, &sk));

	CKINT(alloc_buf(sizeof(ss.ss), &data->ss));
	memcpy(data->ss.buf, ss.ss, sizeof(ss.ss));

out:
	return ret;
}

/********************************* Kyber 768 **********************************/

struct kyber_768_funcs {
	int (*kyber_768_keypair)(struct lc_kyber_768_pk *pk,
			     struct lc_kyber_768_sk *sk,
			     struct lc_rng_ctx *rng_ctx);
	int (*kyber_768_enc_int)(struct lc_kyber_768_ct *ct,
			     struct lc_kyber_768_ss *ss,
			     const struct lc_kyber_768_pk *pk,
			     struct lc_rng_ctx *rng_ctx);
	int (*kyber_768_dec)(struct lc_kyber_768_ss *ss,
			 const struct lc_kyber_768_ct *ct,
			 const struct lc_kyber_768_sk *sk);
};

static int lc_get_kyber_768(struct kyber_768_funcs *funcs)
{
	const char *envstr = getenv("LC_KYBER");

	if (!envstr || (envstr && !strncasecmp(envstr, "common", 6))) {
		logger(LOGGER_VERBOSE, "Kyber-768 implementation: common\n");
#ifdef __x86_64__
		funcs->kyber_768_keypair = lc_kyber_768_keypair_avx;
		funcs->kyber_768_enc_int = lc_kyber_768_enc_avx;
		funcs->kyber_768_dec = lc_kyber_768_dec_avx;
#elif defined(__aarch64__) || defined(_M_ARM64)
		funcs->kyber_768_keypair = lc_kyber_768_keypair_armv8;
		funcs->kyber_768_enc_int = lc_kyber_768_enc_armv8;
		funcs->kyber_768_dec = lc_kyber_768_dec_armv8;
#else
		funcs->kyber_768_keypair = lc_kyber_768_keypair;
		funcs->kyber_768_enc_int = lc_kyber_768_enc;
		funcs->kyber_768_dec = lc_kyber_768_dec;
#endif

	} else if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "Kyber-768 implementation: C\n");
		funcs->kyber_768_keypair = lc_kyber_768_keypair_c;
		funcs->kyber_768_enc_int = lc_kyber_768_enc_c;
		funcs->kyber_768_dec = lc_kyber_768_dec_c;
	} else {
		logger(LOGGER_ERR, "Unknown Kyber implementation %s\n", envstr);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_kem_768_keygen(struct ml_kem_keygen_data *data,
				flags_t parsed_flags)
{
	struct kyber_768_funcs funcs;
	struct lc_kyber_768_pk pk;
	struct lc_kyber_768_sk sk;
	struct kyber_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_kyber_drng,
				     .rng_state = &s_rng_state };
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber_768(&funcs));

	s_rng_state.d = data->d.buf;
	s_rng_state.dlen = data->d.len;
	s_rng_state.z = data->z.buf;
	s_rng_state.zlen = data->z.len;

	/* The d value is the first random number to be supplied */
	s_rng_state.ptr = s_rng_state.d;
	s_rng_state.ptr_len = &s_rng_state.dlen;

	CKINT(funcs.kyber_768_keypair(&pk, &sk, &s_drng));

	CKINT(alloc_buf(sizeof(pk.pk), &data->ek));
	memcpy(data->ek.buf, pk.pk, sizeof(pk.pk));

	CKINT(alloc_buf(sizeof(sk.sk), &data->dk));
	memcpy(data->dk.buf, sk.sk, sizeof(sk.sk));

out:
	return ret;
}

static int lc_ml_kem_768_encapsulation(struct ml_kem_encapsulation_data *data,
				       flags_t parsed_flags)
{
	struct kyber_768_funcs funcs;
	struct lc_kyber_768_pk pk;
	struct lc_kyber_768_ct ct;
	struct lc_kyber_768_ss ss;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber_768(&funcs));

	if (sizeof(pk.pk) != data->ek.len) {
		logger(LOGGER_ERR,
		       "Kyber EK does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(pk.pk), data->ek.len);
		return -EOPNOTSUPP;
	}
	memcpy(pk.pk, data->ek.buf, data->ek.len);

	s_rng_state.seed = data->msg.buf;
	s_rng_state.seedlen = data->msg.len;

	if (funcs.kyber_768_enc_int) {
		CKINT(funcs.kyber_768_enc_int(&ct, &ss, &pk, &s_drng));
	} else {
		ret = -EOPNOTSUPP;
		goto out;
	}

	CKINT(alloc_buf(sizeof(ct.ct), &data->c));
	memcpy(data->c.buf, ct.ct, sizeof(ct.ct));

	CKINT(alloc_buf(sizeof(ss.ss), &data->ss));
	memcpy(data->ss.buf, ss.ss, sizeof(ss.ss));

out:
	return ret;
}

static int lc_ml_kem_768_decapsulation(struct ml_kem_decapsulation_data *data,
				       flags_t parsed_flags)
{
	struct kyber_768_funcs funcs;
	struct lc_kyber_768_sk sk;
	struct lc_kyber_768_ct ct;
	struct lc_kyber_768_ss ss;
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber_768(&funcs));

	if (sizeof(sk.sk) != data->dk.len) {
		logger(LOGGER_ERR,
		       "Kyber DK does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(sk.sk), data->dk.len);
		return -EFAULT;
	}
	memcpy(sk.sk, data->dk.buf, data->dk.len);

	if (sizeof(ct.ct) != data->c.len) {
		logger(LOGGER_ERR,
		       "Kyber CT does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(ct.ct), data->c.len);
		return -EFAULT;
	}
	memcpy(ct.ct, data->c.buf, data->c.len);

	CKINT(funcs.kyber_768_dec(&ss, &ct, &sk));

	CKINT(alloc_buf(sizeof(ss.ss), &data->ss));
	memcpy(data->ss.buf, ss.ss, sizeof(ss.ss));

out:
	return ret;
}

/********************************* Kyber 512 **********************************/

struct kyber_512_funcs {
	int (*kyber_512_keypair)(struct lc_kyber_512_pk *pk,
			     struct lc_kyber_512_sk *sk,
			     struct lc_rng_ctx *rng_ctx);
	int (*kyber_512_enc_int)(struct lc_kyber_512_ct *ct,
			     struct lc_kyber_512_ss *ss,
			     const struct lc_kyber_512_pk *pk,
			     struct lc_rng_ctx *rng_ctx);
	int (*kyber_512_dec)(struct lc_kyber_512_ss *ss,
			 const struct lc_kyber_512_ct *ct,
			 const struct lc_kyber_512_sk *sk);
};

static int lc_get_kyber_512(struct kyber_512_funcs *funcs)
{
	const char *envstr = getenv("LC_KYBER");

	if (!envstr || (envstr && !strncasecmp(envstr, "common", 6))) {
		logger(LOGGER_VERBOSE, "Kyber-512 implementation: common, but using C\n");
		funcs->kyber_512_keypair = lc_kyber_512_keypair_c;
		funcs->kyber_512_enc_int = lc_kyber_512_enc_c;
		funcs->kyber_512_dec = lc_kyber_512_dec_c;
	} else if (envstr && !strncasecmp(envstr, "C", 1)) {
		logger(LOGGER_VERBOSE, "Kyber-512 implementation: C\n");
		funcs->kyber_512_keypair = lc_kyber_512_keypair_c;
		funcs->kyber_512_enc_int = lc_kyber_512_enc_c;
		funcs->kyber_512_dec = lc_kyber_512_dec_c;
	} else {
		logger(LOGGER_ERR, "Unknown Kyber implementation %s\n", envstr);
		return -EOPNOTSUPP;
	}

	return 0;
}

static int lc_ml_kem_512_keygen(struct ml_kem_keygen_data *data,
				flags_t parsed_flags)
{
	struct kyber_512_funcs funcs;
	struct lc_kyber_512_pk pk;
	struct lc_kyber_512_sk sk;
	struct kyber_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_kyber_drng,
				     .rng_state = &s_rng_state };
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber_512(&funcs));

	s_rng_state.d = data->d.buf;
	s_rng_state.dlen = data->d.len;
	s_rng_state.z = data->z.buf;
	s_rng_state.zlen = data->z.len;

	/* The d value is the first random number to be supplied */
	s_rng_state.ptr = s_rng_state.d;
	s_rng_state.ptr_len = &s_rng_state.dlen;

	CKINT(funcs.kyber_512_keypair(&pk, &sk, &s_drng));

	CKINT(alloc_buf(sizeof(pk.pk), &data->ek));
	memcpy(data->ek.buf, pk.pk, sizeof(pk.pk));

	CKINT(alloc_buf(sizeof(sk.sk), &data->dk));
	memcpy(data->dk.buf, sk.sk, sizeof(sk.sk));

out:
	return ret;
}

static int lc_ml_kem_512_encapsulation(struct ml_kem_encapsulation_data *data,
				       flags_t parsed_flags)
{
	struct kyber_512_funcs funcs;
	struct lc_kyber_512_pk pk;
	struct lc_kyber_512_ct ct;
	struct lc_kyber_512_ss ss;
	struct static_rng s_rng_state;
	struct lc_rng_ctx s_drng = { .rng = &lc_static_drng,
				     .rng_state = &s_rng_state };
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber_512(&funcs));

	if (sizeof(pk.pk) != data->ek.len) {
		logger(LOGGER_ERR,
		       "Kyber EK does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(pk.pk), data->ek.len);
		return -EOPNOTSUPP;
	}
	memcpy(pk.pk, data->ek.buf, data->ek.len);

	s_rng_state.seed = data->msg.buf;
	s_rng_state.seedlen = data->msg.len;

	if (funcs.kyber_512_enc_int) {
		CKINT(funcs.kyber_512_enc_int(&ct, &ss, &pk, &s_drng));
	} else {
		ret = -EOPNOTSUPP;
		goto out;
	}

	CKINT(alloc_buf(sizeof(ct.ct), &data->c));
	memcpy(data->c.buf, ct.ct, sizeof(ct.ct));

	CKINT(alloc_buf(sizeof(ss.ss), &data->ss));
	memcpy(data->ss.buf, ss.ss, sizeof(ss.ss));

out:
	return ret;
}

static int lc_ml_kem_512_decapsulation(struct ml_kem_decapsulation_data *data,
				       flags_t parsed_flags)
{
	struct kyber_512_funcs funcs;
	struct lc_kyber_512_sk sk;
	struct lc_kyber_512_ct ct;
	struct lc_kyber_512_ss ss;
	int ret;

	(void)parsed_flags;

	CKINT(lc_get_kyber_512(&funcs));

	if (sizeof(sk.sk) != data->dk.len) {
		logger(LOGGER_ERR,
		       "Kyber DK does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(sk.sk), data->dk.len);
		return -EFAULT;
	}
	memcpy(sk.sk, data->dk.buf, data->dk.len);

	if (sizeof(ct.ct) != data->c.len) {
		logger(LOGGER_ERR,
		       "Kyber CT does not match expected size (expected %zu, actual %zu)\n",
		       sizeof(ct.ct), data->c.len);
		return -EFAULT;
	}
	memcpy(ct.ct, data->c.buf, data->c.len);

	CKINT(funcs.kyber_512_dec(&ss, &ct, &sk));

	CKINT(alloc_buf(sizeof(ss.ss), &data->ss));
	memcpy(data->ss.buf, ss.ss, sizeof(ss.ss));

out:
	return ret;
}

/******************************** Common Code *********************************/

static int lc_ml_kem_keygen(struct ml_kem_keygen_data *data,
			    flags_t parsed_flags)
{
	if (data->cipher == ACVP_ML_KEM_512)
		return lc_ml_kem_512_keygen(data, parsed_flags);
	else if (data->cipher == ACVP_ML_KEM_768)
		return lc_ml_kem_768_keygen(data, parsed_flags);
	else if (data->cipher == ACVP_ML_KEM_1024)
		return lc_ml_kem_1024_keygen(data, parsed_flags);
	else
		return -EOPNOTSUPP;
}

static int lc_ml_kem_encapsulation(struct ml_kem_encapsulation_data *data,
				   flags_t parsed_flags)
{
	if (data->cipher == ACVP_ML_KEM_512)
		return lc_ml_kem_512_encapsulation(data, parsed_flags);
	else if (data->cipher == ACVP_ML_KEM_768)
		return lc_ml_kem_768_encapsulation(data, parsed_flags);
	else if (data->cipher == ACVP_ML_KEM_1024)
		return lc_ml_kem_1024_encapsulation(data, parsed_flags);
	else
		return -EOPNOTSUPP;
}

static int lc_ml_kem_decapsulation(struct ml_kem_decapsulation_data *data,
				   flags_t parsed_flags)
{
	if (data->cipher == ACVP_ML_KEM_512)
		return lc_ml_kem_512_decapsulation(data, parsed_flags);
	else if (data->cipher == ACVP_ML_KEM_768)
		return lc_ml_kem_768_decapsulation(data, parsed_flags);
	else if (data->cipher == ACVP_ML_KEM_1024)
		return lc_ml_kem_1024_decapsulation(data, parsed_flags);
	else
		return -EOPNOTSUPP;
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
}
#endif
