/*
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "kcapi.h"

#include "backend_common.h"
#include "logger.h"
#include "parser_sha_mct_helper.h"
#include "stringhelper.h"

/************************************************
 * Symmetric cipher interface functions
 ************************************************/

static int libkcapi_rawciphername(uint64_t cipher, char **cipherstring)
{
	char *outstr = NULL;

	outstr = calloc(1, 128);
	if (!outstr)
		return -EFAULT;
	switch (cipher) {
	case ACVP_ECB:
		sprintf(outstr, "ecb(aes)");
		break;
	case ACVP_CBC:
		sprintf(outstr, "cbc(aes)");
		break;
	case ACVP_CTR:
		sprintf(outstr, "ctr(aes)");
		break;
	case ACVP_CFB8:
		sprintf(outstr, "cfb(aes)");
		break;
	case ACVP_CFB128:
		sprintf(outstr, "cfb(aes)");
		break;
	case ACVP_XTS:
		sprintf(outstr, "xts(aes)");
		break;
	case ACVP_KW:
		sprintf(outstr, "kw(aes)");
		break;

	case ACVP_TDESECB:
		sprintf(outstr, "ecb(des3_ede)");
		break;
	case ACVP_TDESCBC:
		sprintf(outstr, "cbc(des3_ede)");
		break;
	case ACVP_TDESCTR:
		sprintf(outstr, "ctr(des3_ede)");
		break;
	case ACVP_TDESCFB8:
		sprintf(outstr, "cfb(des3_ede)");
		break;
	case ACVP_TDESCFB64:
		sprintf(outstr, "cfb(des3_ede)");
		break;

	case ACVP_GMAC:
	case ACVP_GCM:
		sprintf(outstr, "gcm(aes)");
		break;
	case ACVP_CCM:
		sprintf(outstr, "ccm(aes)");
		break;

	case ACVP_AESCMAC:
		sprintf(outstr, "cmac(aes)");
		break;
	case ACVP_TDESCMAC:
		sprintf(outstr, "cmac(des3_ede)");
		break;
	case ACVP_HMACSHA1:
		sprintf(outstr, "hmac(sha1)");
		break;
	case ACVP_HMACSHA2_224:
		sprintf(outstr, "hmac(sha224)");
		break;
	case ACVP_HMACSHA2_256:
		sprintf(outstr, "hmac(sha256)");
		break;
	case ACVP_HMACSHA2_384:
		sprintf(outstr, "hmac(sha384)");
		break;
	case ACVP_HMACSHA2_512:
		sprintf(outstr, "hmac(sha512)");
		break;
	case ACVP_HMACSHA3_224:
		sprintf(outstr, "hmac(sha3-224)");
		break;
	case ACVP_HMACSHA3_256:
		sprintf(outstr, "hmac(sha3-256)");
		break;
	case ACVP_HMACSHA3_384:
		sprintf(outstr, "hmac(sha3-384)");
		break;
	case ACVP_HMACSHA3_512:
		sprintf(outstr, "hmac(sha3-512)");
		break;

	case ACVP_SHA1:
		sprintf(outstr, "sha1");
		break;
	case ACVP_SHA224:
		sprintf(outstr, "sha224");
		break;
	case ACVP_SHA256:
		sprintf(outstr, "sha256");
		break;
	case ACVP_SHA384:
		sprintf(outstr, "sha384");
		break;
	case ACVP_SHA512:
		sprintf(outstr, "sha512");
		break;
	case ACVP_SHA3_224:
		sprintf(outstr, "sha3-224");
		break;
	case ACVP_SHA3_256:
		sprintf(outstr, "sha3-256");
		break;
	case ACVP_SHA3_384:
		sprintf(outstr, "sha3-384");
		break;
	case ACVP_SHA3_512:
		sprintf(outstr, "sha3-512");
		break;

	case ACVP_ECDH:
		sprintf(outstr, "ecdh");
		break;

	case ACVP_DH2048224:
	case ACVP_DH2048256:
		sprintf(outstr, "dh");
		break;

	default:
		logger(LOGGER_WARN, "Unknown cipher\n");
		free(outstr);
		return -EFAULT;
	}

	*cipherstring = outstr;

	return 0;
}

static int libkcapi_ciphername(uint64_t cipher, char **cipherstring)
{
	char *envstr = NULL;
	char *outstr = NULL;

	switch (cipher) {
	case ACVP_ECB:
		envstr = secure_getenv("KCAPI_ECB_AES");
		break;
	case ACVP_CBC:
		envstr = secure_getenv("KCAPI_CBC_AES");
		break;
	case ACVP_XTS:
		envstr = secure_getenv("KCAPI_XTS_AES");
		break;
	case ACVP_CTR:
		envstr = secure_getenv("KCAPI_CTR_AES");
		break;
	case ACVP_CFB8:
		envstr = secure_getenv("KCAPI_CFB8_AES");
		break;
	case ACVP_CFB128:
		envstr = secure_getenv("KCAPI_CFB128_AES");
		break;
	case ACVP_KW:
		envstr = secure_getenv("KCAPI_KW_AES");
		break;

	case ACVP_TDESECB:
		envstr = secure_getenv("KCAPI_ECB_TDES");
		break;
	case ACVP_TDESCBC:
		envstr = secure_getenv("KCAPI_CBC_TDES");
		break;
	case ACVP_TDESCTR:
		envstr = secure_getenv("KCAPI_CTR_TDES");
		break;
	case ACVP_TDESCFB8:
		envstr = secure_getenv("KCAPI_CFB8_TDES");
		break;
	case ACVP_TDESCFB64:
		envstr = secure_getenv("KCAPI_CFB64_TDES");
		break;

	case ACVP_GMAC:
	case ACVP_GCM:
		envstr = secure_getenv("KCAPI_GCM_AES");
		break;
	case ACVP_CCM:
		envstr = secure_getenv("KCAPI_CCM_AES");
		break;

	case ACVP_AESCMAC:
		envstr = secure_getenv("KCAPI_CMAC_AES");
		break;
	case ACVP_TDESCMAC:
		envstr = secure_getenv("KCAPI_CMAC_TDES");
		break;

	case ACVP_HMACSHA1:
		envstr = secure_getenv("KCAPI_HMAC_SHA1");
		break;
	case ACVP_HMACSHA2_224:
		envstr = secure_getenv("KCAPI_HMAC_SHA224");
		break;
	case ACVP_HMACSHA2_256:
		envstr = secure_getenv("KCAPI_HMAC_SHA256");
		break;
	case ACVP_HMACSHA2_384:
		envstr = secure_getenv("KCAPI_HMAC_SHA384");
		break;
	case ACVP_HMACSHA2_512:
		envstr = secure_getenv("KCAPI_HMAC_SHA512");
		break;
	case ACVP_HMACSHA3_224:
		envstr = secure_getenv("KCAPI_HMAC_SHA3_224");
		break;
	case ACVP_HMACSHA3_256:
		envstr = secure_getenv("KCAPI_HMAC_SHA3_256");
		break;
	case ACVP_HMACSHA3_384:
		envstr = secure_getenv("KCAPI_HMAC_SHA3_384");
		break;
	case ACVP_HMACSHA3_512:
		envstr = secure_getenv("KCAPI_HMAC_SHA3_512");
		break;

	case ACVP_SHA1:
		envstr = secure_getenv("KCAPI_SHA1");
		break;
	case ACVP_SHA224:
		envstr = secure_getenv("KCAPI_SHA224");
		break;
	case ACVP_SHA256:
		envstr = secure_getenv("KCAPI_SHA256");
		break;
	case ACVP_SHA384:
		envstr = secure_getenv("KCAPI_SHA384");
		break;
	case ACVP_SHA512:
		envstr = secure_getenv("KCAPI_SHA512");
		break;
	case ACVP_SHA3_224:
		envstr = secure_getenv("KCAPI_SHA3_224");
		break;
	case ACVP_SHA3_256:
		envstr = secure_getenv("KCAPI_SHA3_256");
		break;
	case ACVP_SHA3_384:
		envstr = secure_getenv("KCAPI_SHA3_384");
		break;
	case ACVP_SHA3_512:
		envstr = secure_getenv("KCAPI_SHA3_512");
		break;

	case ACVP_ECDH:
		envstr = secure_getenv("KCAPI_ECDH");
		break;

	case ACVP_DH2048224:
	case ACVP_DH2048256:
		envstr = secure_getenv("KCAPI_DH");
		break;

	default:
		logger(LOGGER_ERR, "Unknown cipher\n");
		return -EFAULT;
	}

	if (envstr) {
		outstr = strdup(envstr);
		if (!outstr)
			return -EFAULT;
		*cipherstring = outstr;
		return 0;
	} else {
		return libkcapi_rawciphername(cipher, cipherstring);
	}
}

static int libkcapi_setupcipher(struct sym_data *data)
{
	char *ciphername = NULL;
	int ret;
	struct kcapi_handle *handle = NULL;

	CKINT(libkcapi_ciphername(data->cipher, &ciphername));

	CKINT_LOG(kcapi_cipher_init(&handle, ciphername, 0),
		  "Allocation of %s cipher failed\n", ciphername);

	logger(LOGGER_VERBOSE, "name = %s\n", ciphername);

	if (data->key.len) {
		CKINT_LOG(kcapi_cipher_setkey(handle, data->key.buf,
					      (uint32_t)data->key.len),
			  "Symmetric cipher setkey failed\n");
	}
	logger_binary(LOGGER_VERBOSE, data->key.buf, data->key.len, "key");

	data->priv = handle;

	ret = 0;

out:
	if (ret && handle)
		kcapi_cipher_destroy(handle);

	if (ciphername)
		free(ciphername);
	return ret;
}

static int libkcapi_mct_init(struct sym_data *data, flags_t parsed_flags)
{
	int ret = 0;
	struct kcapi_handle *handle = NULL;

	CKINT(libkcapi_setupcipher(data));

	handle = (struct kcapi_handle *)data->priv;
	if (parsed_flags & FLAG_OP_ENC) {
		logger(LOGGER_DEBUG, "Initiating encrypt operation\n");
		CKINT(kcapi_cipher_stream_init_enc(handle, data->iv.buf,
						   NULL, 0));
	} else {
		logger(LOGGER_DEBUG, "Initiating decrypt operation\n");
		CKINT(kcapi_cipher_stream_init_dec(handle, data->iv.buf,
						   NULL, 0));
	}

out:
	return ret;
}

static int libkcapi_mct_update(struct sym_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = (struct kcapi_handle *)data->priv;

	(void)parsed_flags;

	if (data->data.len) {
		struct iovec iov;
		int32_t ret;

		iov.iov_base = data->data.buf;
		iov.iov_len = data->data.len;
		//TODO use kcapi_cipher_stream_update_last
		ret = kcapi_cipher_stream_update(handle, &iov, 1);
		if (ret != (int32_t)data->data.len) {
			logger(LOGGER_WARN, "Cipher write failed\n");
			return -EFAULT;
		}
		ret = kcapi_cipher_stream_op(handle, &iov, 1);
		if (ret != (int32_t)data->data.len) {
			logger(LOGGER_WARN, "Cipher read failed\n");
			return -EFAULT;
		}
	}

	return 0;
}

static int libkcapi_mct_fini(struct sym_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = (struct kcapi_handle *)data->priv;

	(void)parsed_flags;

	logger(LOGGER_DEBUG, "Freeing cipher handle\n");
	kcapi_cipher_destroy(handle);
	data->priv = NULL;

	return 0;
}

static int libkcapi_encrypt(struct sym_data *data, flags_t parsed_flags)
{
	int ret;
	struct kcapi_handle *handle = NULL;

	(void)parsed_flags;

	CKINT(libkcapi_setupcipher(data));

	handle = (struct kcapi_handle *)data->priv;

	if (data->iv.len != kcapi_cipher_ivsize(handle)) {
		logger(LOGGER_ERR,
		       "Unexpeted IV size (expected %u, actual %zu)\n",
		       kcapi_cipher_ivsize(handle), data->iv.len);
		ret = -EINVAL;
		goto out;
	}

	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "data to be written");
	if (data->data.len) {
		int32_t rc = kcapi_cipher_encrypt(handle,
						  data->data.buf,
						  (uint32_t)data->data.len,
						  data->iv.buf,
						  data->data.buf,
						  (uint32_t)data->data.len, 0);
		if (rc != (int32_t)data->data.len) {
			logger(LOGGER_WARN, "Encryption failed\n");
			ret = -EFAULT;
			goto out;
		}
	}
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "data read");

	ret = 0;

out:
	kcapi_cipher_destroy(handle);

	return ret;
}

static int libkcapi_decrypt(struct sym_data *data, flags_t parsed_flags)
{
	int ret;
	struct kcapi_handle *handle = NULL;

	(void)parsed_flags;

	CKINT(libkcapi_setupcipher(data));

	handle = (struct kcapi_handle *)data->priv;

	if (data->iv.len != kcapi_cipher_ivsize(handle)) {
		logger(LOGGER_ERR,
		       "Unexpeted IV size (expected %u, actual %zu)\n",
		       kcapi_cipher_ivsize(handle), data->iv.len);
		ret = -EFAULT;
		goto out;
	}

	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "data to be written");
	if (data->data.len) {
		int32_t rc = kcapi_cipher_decrypt(handle, data->data.buf,
						  (uint32_t)data->data.len,
						  data->iv.buf,
						  data->data.buf,
						  (uint32_t)data->data.len, 0);
		if (rc != (int32_t)data->data.len) {
			logger(LOGGER_WARN, "Decryption failed\n");
			ret = -EFAULT;
			goto out;
		}
	}
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
		      "data read");

	ret = 0;

out:
	kcapi_cipher_destroy(handle);

	return ret;
}

static struct sym_backend libkcapi_sym =
{
	libkcapi_encrypt,		/* encrypt */
	libkcapi_decrypt,		/* decrypt */
	libkcapi_mct_init,		/* mct_init */
	libkcapi_mct_update,		/* mct_update */
	libkcapi_mct_fini,		/* mct_fini */
};

ACVP_DEFINE_CONSTRUCTOR(libkcapi_sym_backend)
static void libkcapi_sym_backend(void)
{
	register_sym_impl(&libkcapi_sym);
}

/************************************************
 * SHA cipher interface functions
 ************************************************/

static int libkcapi_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
	char *ciphername = NULL;
	BUFFER_INIT(msg_p);
	int ret;
	ssize_t rc = 0;
	struct kcapi_handle *handle = NULL;

	(void)parsed_flags;

	CKINT(sha_ldt_helper(data, &msg_p));

	CKINT(libkcapi_ciphername(data->cipher, &ciphername));

	CKINT_LOG(kcapi_md_init(&handle, ciphername, 0),
		  "Allocation of %s cipher failed\n", ciphername);

	logger(LOGGER_VERBOSE, "name = %s\n", ciphername);

	CKINT_LOG(alloc_buf(kcapi_md_digestsize(handle), &data->mac),
		  "Cannot allocate buffer\n");

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len,
		      "data written");


	rc = kcapi_md_update(handle, msg_p.buf, msg_p.len);
	if (rc < 0) {
		ret = (int)rc;
		goto out;
	}

	rc = kcapi_md_final(handle, data->mac.buf, data->mac.len);
	if (rc < 0) {
		ret = (int)rc;
		goto out;
	}
	if ((size_t)rc != data->mac.len) {
		logger(LOGGER_WARN, "SHA output size mismatch\n");
		ret = -EFAULT;
		goto out;
	}
	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "data read");

	ret = 0;

out:
	sha_ldt_clear_buf(data, &msg_p);
	if (ciphername)
		free(ciphername);
	kcapi_md_destroy(handle);
	return ret;
}

static struct sha_backend libkcapi_sha =
{
	libkcapi_sha_generate,	/* hash_generate */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(libkcapi_sha_backend)
static void libkcapi_sha_backend(void)
{
	register_sha_impl(&libkcapi_sha);
}

/************************************************
 * HMAC cipher interface functions
 ************************************************/

static int libkcapi_hmac_generate(struct hmac_data *data, flags_t parsed_flags)
{
	char *ciphername = NULL;
	int ret;
	int32_t rc = 0;
	struct kcapi_handle *handle = NULL;

	(void)parsed_flags;

	CKINT(libkcapi_ciphername(data->cipher, &ciphername));

	CKINT_LOG(kcapi_md_init(&handle, ciphername, 0),
		  "Allocation of %s cipher failed\n", ciphername);
	logger(LOGGER_VERBOSE, "name = %s\n", ciphername);

	CKINT(kcapi_md_setkey(handle, data->key.buf, (uint32_t)data->key.len));
	logger_binary(LOGGER_VERBOSE, data->key.buf, data->key.len, "key");

	CKINT_LOG(alloc_buf(kcapi_md_digestsize(handle), &data->mac),
		  "Cannot allocate buffer\n");

	logger_binary(LOGGER_DEBUG, data->msg.buf, data->msg.len,
		      "data written");
	rc = kcapi_md_digest(handle, data->msg.buf, (uint32_t)data->msg.len,
			     data->mac.buf, (uint32_t)data->mac.len);
	if (rc != (int32_t)data->mac.len) {
		logger(LOGGER_WARN, "SHA output size mismatch\n");
		ret = -EFAULT;
		goto out;
	}
	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "data read");

	ret = 0;

out:
	if (ciphername)
		free(ciphername);
	kcapi_md_destroy(handle);
	return ret;
}

static struct hmac_backend libkcapi_hmac =
{
	libkcapi_hmac_generate,	/* hmac_generate */
};

ACVP_DEFINE_CONSTRUCTOR(libkcapi_hmac_backend)
static void libkcapi_hmac_backend(void)
{
	register_hmac_impl(&libkcapi_hmac);
}

/************************************************
 * AEAD cipher interface functions
 ************************************************/

static int libkcapi_aead_setupcipher(struct aead_data *data)
{
	char *ciphername = NULL;
	int ret;
	struct kcapi_handle *handle = NULL;
	uint32_t taglen = data->taglen / 8;

	CKINT(libkcapi_ciphername(data->cipher, &ciphername));

	/*
	 * RFC4106 special handling: append the first 4 bytes of the IV to
	 * the key. If IV is NULL, append NULL string (i.e. the fixed field is
	 * zero in case of internal IV generation). The first 4 bytes of
	 * the IV must be removed from the IV string.
	 */
	logger_binary(LOGGER_VERBOSE, data->key.buf, data->key.len, "key");
	if (strcasestr(ciphername, "rfc4106")) {
		BUFFER_INIT(rfc);

		CKINT(alloc_buf(data->key.len + 4, &rfc));

		memcpy(rfc.buf, data->key.buf, data->key.len);
		if (data->iv.len >= 4) {
			uint32_t i = 0;

			memcpy(rfc.buf + data->key.len, data->iv.buf, 4);

			/* move remaining bytes to the front */
			for (i = 0; i < (data->iv.len - 4); i++)
				data->iv.buf[i] = data->iv.buf[(i + 4)];
			data->iv.len -= 4;
		}
		free_buf(&data->key);
		copy_ptr_buf(&data->key, &rfc);
	}

	CKINT_LOG(kcapi_aead_init(&handle, ciphername, 0),
		  "Allocation of %s cipher failed\n", ciphername);
	logger(LOGGER_VERBOSE, "name = %s\n", ciphername);

	/* Setting the tag length */
	CKINT_LOG(kcapi_aead_settaglen(handle, taglen),
		  "Setting of authentication tag length failed\n");

	kcapi_aead_setassoclen(handle, (uint32_t)data->assoc.len);
	logger(LOGGER_DEBUG, "AAD size %zu\n", data->assoc.len);

	if (data->key.len) {
		CKINT_LOG(kcapi_aead_setkey(handle, data->key.buf,
					    (uint32_t)data->key.len),
			  "Symmetric cipher setkey failed\n");
	}
	logger_binary(LOGGER_VERBOSE, data->key.buf, data->key.len, "key");

	data->priv = handle;

out:
	if (ret && handle)
		kcapi_cipher_destroy(handle);

	if (ciphername)
		free(ciphername);
	return ret;
}

static int libkcapi_aead_encrypt(struct aead_data *data, struct buffer *iv)
{
	struct kcapi_handle *handle = NULL;
	struct iovec iov[3];
	int ret;
	uint32_t taglen = data->taglen / 8;

	handle = (struct kcapi_handle *)data->priv;

	CKINT_LOG(kcapi_aead_stream_init_enc(handle, iv->buf, NULL, 0),
		  "AEAD initialization failed\n");

	logger_binary(LOGGER_DEBUG, data->assoc.buf, data->assoc.len, "AAD");
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "PT");
	logger_binary(LOGGER_DEBUG, data->iv.buf, data->iv.len, "IV");

	iov[0].iov_base = data->assoc.buf;
	iov[0].iov_len = data->assoc.len;
	iov[1].iov_base = data->data.buf;
	iov[1].iov_len = data->data.len;
	CKINT_LOG(kcapi_aead_stream_update_last(handle, iov, 2),
		  "AEAD update failed\n");

	CKINT(alloc_buf(taglen, &data->tag));

	iov[2].iov_base = data->tag.buf;
	iov[2].iov_len = data->tag.len;

	CKINT_LOG(kcapi_aead_stream_op(handle, iov, 3), "AEAD final failed\n");

	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "CT");
	logger_binary(LOGGER_DEBUG, data->tag.buf, data->tag.len,
		      "Generated tag");

out:
	return ret;
}

static int libkcapi_aead_decrypt(struct aead_data *data, struct buffer *iv)
{
	struct kcapi_handle *handle = NULL;
	struct iovec iov[3];
	unsigned int i = 0, j = 0;
	int ret;

	handle = (struct kcapi_handle *)data->priv;

	CKINT_LOG(kcapi_aead_stream_init_dec(handle, iv->buf, NULL, 0),
		  "AEAD initialization failed\n");

	logger_binary(LOGGER_DEBUG, data->assoc.buf, data->assoc.len, "AAD");
	logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "CT");
	logger_binary(LOGGER_DEBUG, data->tag.buf, data->tag.len, "Tag");

	if (data->assoc.len) {
		iov[i].iov_base = data->assoc.buf;
		iov[i].iov_len = data->assoc.len;
		i++;
		j++;
	}

	if (data->data.len) {
		iov[i].iov_base = data->data.buf;
		iov[i].iov_len = data->data.len;
		i++;
		j++;
	}

	if (data->tag.len) {
		iov[i].iov_base = data->tag.buf;
		iov[i].iov_len = data->tag.len;
		i++;
		/* No increment of j as the tag is not returned */
	}

	if (!i) {
		logger(LOGGER_WARN, "No input data\n");
		ret = -EINVAL;
		goto out;
	}

	/*
	 * We know that i contains at least one backend buffer, We "hijack"
	 * it for GMAC testing as no return data will ever be coming back
	 * from the kernel. Yet, we need to set a buffer as otherwise the kernel
	 * will not perform the cipher operation.
	 */
	if (!j)
		j++;

	CKINT_LOG(kcapi_aead_stream_update_last(handle, iov, i),
		  "AEAD update failed\n");

	ret = kcapi_aead_stream_op(handle, iov, j);
	if (ret < 0) {
		if (ret != -EBADMSG) {
			logger(LOGGER_WARN, "Decryption failed: %d\n", ret);
			goto out;
		}
		/* decryption error */
		data->integrity_error = 1;
		logger(LOGGER_DEBUG,
		       "Decryption failed due to integrity error\n");
		ret = 0;
		free_buf(&data->data);
	} else {
		ret = 0;
		data->integrity_error = 0;
		logger(LOGGER_DEBUG, "Decryption successful\n");
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len,
			      "PT");
	}

	if (data->ptlen / 8 < data->data.len)
		data->data.len = data->ptlen / 8;

out:
	return ret;
}

static int libkcapi_gcm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	BUFFER_INIT(newiv);
	int ret;

	(void)parsed_flags;

	if (data->ivlen && !data->iv.len) {
		logger(LOGGER_ERR,
		       "AEAD encryption with internal IV generation not implemented for KCAPI\n");
		return -EINVAL;
	}

	CKINT(libkcapi_aead_setupcipher(data));

	handle = (struct kcapi_handle *)data->priv;

	CKINT(kcapi_pad_iv(handle, data->iv.buf, (uint32_t)data->iv.len,
			   &newiv.buf, (uint32_t *)&newiv.len));

	CKINT(libkcapi_aead_encrypt(data, &newiv));

out:
	kcapi_cipher_destroy(handle);
	free_buf(&newiv);

	return ret;
}

static int libkcapi_gcm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	BUFFER_INIT(newiv);
	int ret;

	(void)parsed_flags;

	if (data->ivlen && !data->iv.len) {
		logger(LOGGER_ERR,
		       "AEAD decryption with internal IV generation not implemented for KCAPI\n");
		return -EINVAL;
	}

	CKINT(libkcapi_aead_setupcipher(data));

	handle = (struct kcapi_handle *)data->priv;

	CKINT_LOG(kcapi_pad_iv(handle, data->iv.buf, (uint32_t)data->iv.len,
			       &newiv.buf, (uint32_t *)&newiv.len),
		  "IV padding failed\n");

	CKINT(libkcapi_aead_decrypt(data, &newiv));

out:
	kcapi_cipher_destroy(handle);
	free_buf(&newiv);

	return ret;
}

static int libkcapi_ccm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	BUFFER_INIT(newiv);
	int ret;

	(void)parsed_flags;

	CKINT(libkcapi_aead_setupcipher(data));

	handle = (struct kcapi_handle *)data->priv;

	CKINT_LOG(kcapi_aead_ccm_nonce_to_iv(data->iv.buf,
					     (uint32_t)data->iv.len,
					     &newiv.buf,
					     (uint32_t *)&newiv.len),
		  "CCM nonce conversion failed\n");

	logger_binary(LOGGER_DEBUG, newiv.buf, newiv.len,
		     "CCM generated IV from nonce");

	CKINT(libkcapi_aead_encrypt(data, &newiv));
	free_buf(&data->iv);
	copy_ptr_buf(&data->iv, &newiv);

out:
	kcapi_cipher_destroy(handle);

	return ret;
}

static int libkcapi_ccm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	BUFFER_INIT(newiv);
	int ret;

	(void)parsed_flags;

	CKINT_LOG(kcapi_aead_ccm_nonce_to_iv(data->iv.buf,
					     (uint32_t)data->iv.len,
					     &newiv.buf,
					     (uint32_t *)&newiv.len),
		  "CCM nonce conversion failed\n");
	logger_binary(LOGGER_DEBUG, newiv.buf, newiv.len,
		     "CCM generated IV from nonce");

	CKINT(libkcapi_aead_setupcipher(data));

	handle = (struct kcapi_handle *)data->priv;

	CKINT(libkcapi_aead_decrypt(data, &newiv));

out:
	kcapi_cipher_destroy(handle);
	free_buf(&newiv);

	return ret;
}

static struct aead_backend libkcapi_aead =
{
	libkcapi_gcm_encrypt,	/* gcm_encrypt */
	libkcapi_gcm_decrypt,	/* gcm_decrypt */
	libkcapi_ccm_encrypt,	/* ccm_encrypt */
	libkcapi_ccm_decrypt,	/* ccm_decrypt */
};

ACVP_DEFINE_CONSTRUCTOR(libkcapi_aead_backend)
static void libkcapi_aead_backend(void)
{
	register_aead_impl(&libkcapi_aead);
}

/************************************************
 * SP800-108 KDF cipher interface functions
 ************************************************/
static int libkcapi_kdf_108_generate(struct kdf_108_data *data,
				     flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	uint32_t derived_key_bytes = data->derived_key_length / 8;
	int ret;
	char *ciphername = NULL;

	(void)parsed_flags;

	if (data->derived_key_length % 8) {
		logger(LOGGER_WARN, "Derived key must be byte-aligned\n");
		ret = -EINVAL;
		goto out;
	}

	if (!(data->mac & ACVP_HMACMASK) && !(data->mac & ACVP_CMACMASK)) {
		logger(LOGGER_WARN, "HMAC or CMAC required (%" PRIu64 ")\n", data->mac);
		ret = -EINVAL;
		goto out;
	}

	CKINT(alloc_buf(derived_key_bytes, &data->derived_key));

	CKINT_LOG(libkcapi_ciphername(data->mac, &ciphername),
		  "Converation to cipher name failed\n");

	CKINT_LOG(kcapi_md_init(&handle, ciphername, 0),
		  "Allocation of KDF hash %s failed\n", ciphername);

	CKINT_LOG(kcapi_md_setkey(handle, data->key.buf,
				  (uint32_t)data->key.len),
		  "KDF MAC setkey failed\n");

	/* Generate the arbitrary fixed data buffer */
	if (!data->fixed_data.len) {
		CKINT(alloc_buf(kcapi_md_digestsize(handle),
				&data->fixed_data));
		CKINT_LOG(kcapi_rng_get_bytes(data->fixed_data.buf,
					      (uint32_t)data->fixed_data.len),
			  "Getting random numbers failed\n");
		logger(LOGGER_DEBUG, "Generated fixed data of size %zu\n",
		       data->fixed_data.len);
	}

	if (convert_cipher_match(data->kdfmode, ACVP_KDF_108_DOUBLE_PIPELINE,
				 ACVP_CIPHERTYPE_KDF)) {
		ret = kcapi_kdf_dpi(handle, data->fixed_data.buf,
				    (uint32_t)data->fixed_data.len,
				    data->derived_key.buf,
				    (uint32_t)data->derived_key.len);
	} else if (convert_cipher_match(data->kdfmode, ACVP_KDF_108_FEEDBACK,
					ACVP_CIPHERTYPE_KDF)) {
		BUFFER_INIT(input);

		if (data->iv.len < kcapi_md_digestsize(handle)) {
			logger(LOGGER_WARN,
			       "Feedback KDF IV too small (present size %zu, expected minimum %u)\n",
			       data->fixed_data.len,
			       kcapi_md_digestsize(handle));
			ret = -EINVAL;
			goto out;
		}

		CKINT(alloc_buf(data->iv.len + data->fixed_data.len, &input));
		memcpy(input.buf, data->iv.buf, data->iv.len);
		memcpy(input.buf + data->iv.len, data->fixed_data.buf,
		       data->fixed_data.len);
		ret = kcapi_kdf_fb(handle,  input.buf, (uint32_t)input.len,
				   data->derived_key.buf,
				   (uint32_t)data->derived_key.len);
		free_buf(&input);
	} else if (convert_cipher_match(data->kdfmode, ACVP_KDF_108_COUNTER,
					ACVP_CIPHERTYPE_KDF)) {
		ret = kcapi_kdf_ctr(handle,  data->fixed_data.buf,
				    (uint32_t)data->fixed_data.len,
				    data->derived_key.buf,
				    (uint32_t)data->derived_key.len);
	} else {
		logger(LOGGER_WARN, "Unknown KDF type\n");
		ret = -EINVAL;
		goto out;
	}

	if (ret > 0)
		ret = 0;

out:
	kcapi_md_destroy(handle);
	if (ciphername)
		free(ciphername);
	return ret;
}


static struct kdf_108_backend libkcapi_108 =
{
	libkcapi_kdf_108_generate,
	NULL,
};

ACVP_DEFINE_CONSTRUCTOR(libkcapi_108_backend)
static void libkcapi_108_backend(void)
{
	register_kdf_108_impl(&libkcapi_108);
}

/************************************************
 * SP800-132 PBKDF cipher interface functions
 ************************************************/
static int libkcapi_pbkdf_generate(struct pbkdf_data *data,
				   flags_t parsed_flags)
{
	uint32_t derived_key_bytes = data->derived_key_length / 8;
	int ret;
	char *ciphername = NULL, hmacname[128];

	(void)parsed_flags;

	if (data->derived_key_length % 8) {
		logger(LOGGER_WARN, "Derived key must be byte-aligned\n");
		ret = -EINVAL;
		goto out;
	}

	if (!(data->hash & ACVP_HASHMASK)) {
		logger(LOGGER_WARN, "Hash required (%" PRIu64 ")\n", data->hash);
		ret = -EINVAL;
		goto out;
	}

	CKINT(alloc_buf(derived_key_bytes, &data->derived_key));

	CKINT_LOG(libkcapi_ciphername(data->hash, &ciphername),
		  "Converation to cipher name failed\n");
	snprintf(hmacname, sizeof(hmacname), "hmac(%s)", ciphername);

	CKINT_LOG(kcapi_pbkdf(hmacname,
			      data->password.buf,
			      (uint32_t)data->password.len,
			      data->salt.buf, (uint32_t)data->salt.len,
			      data->iteration_count,
			      data->derived_key.buf,
		       (uint32_t)data->derived_key.len),
		  "PBKDF with hash %s failed\n", hmacname);

out:
	if (ciphername)
		free(ciphername);
	return ret;
}


static struct pbkdf_backend libkcapi_pbkdf =
{
	libkcapi_pbkdf_generate,
};

ACVP_DEFINE_CONSTRUCTOR(libkcapi_pbkdf_backend)
static void libkcapi_pbkdf_backend(void)
{
	register_pbkdf_impl(&libkcapi_pbkdf);
}

/************************************************
 * RFC5869 HKDF cipher interface functions
 ************************************************/
static int libkcapi_hkdf_generate(struct hkdf_data *data,
				  flags_t parsed_flags)
{
	BUFFER_INIT(local_dkm);
	uint32_t derived_key_bytes = data->dkmlen / 8;
	int ret;
	char *ciphername = NULL, ciphername2[256];

	(void)parsed_flags;

	if (data->dkmlen % 8) {
		logger(LOGGER_WARN, "Derived key must be byte-aligned\n");
		ret = -EINVAL;
		goto out;
	}

	if (data->dkm.buf && data->dkm.len) {
		CKINT(alloc_buf(derived_key_bytes, &local_dkm));
	} else {
		CKINT(alloc_buf(derived_key_bytes, &data->dkm));
	}

	CKINT_LOG(libkcapi_ciphername(data->hash, &ciphername),
		  "Converation to cipher name failed\n");
	snprintf(ciphername2, sizeof(ciphername2), "hmac(%s)", ciphername);

	if (local_dkm.buf && local_dkm.len) {
		CKINT_LOG(kcapi_hkdf(ciphername2,
				     data->z.buf, (uint32_t)data->z.len,
				     data->salt.buf, (uint32_t)data->salt.len,
				     data->info.buf, (uint32_t)data->info.len,
				     local_dkm.buf, (uint32_t)local_dkm.len),
			  "HKDF with hash %s failed\n", ciphername);

		if (local_dkm.len != data->dkm.len ||
		    memcmp(local_dkm.buf, data->dkm.buf, local_dkm.len)) {
			logger(LOGGER_DEBUG, "HKDF validation result: fail\n");
			data->validity_success = 0;
		} else {
			data->validity_success = 1;
		}
	} else {
		CKINT_LOG(kcapi_hkdf(ciphername2,
				     data->z.buf, (uint32_t)data->z.len,
				     data->salt.buf, (uint32_t)data->salt.len,
				     data->info.buf, (uint32_t)data->info.len,
				     data->dkm.buf, (uint32_t)data->dkm.len),
			  "HKDF with hash %s failed\n", ciphername);
	}

out:
	if (ciphername)
		free(ciphername);
	free_buf(&local_dkm);

	return ret;
}


static struct hkdf_backend libkcapi_hkdf =
{
	libkcapi_hkdf_generate,
};

ACVP_DEFINE_CONSTRUCTOR(libkcapi_hkdf_backend)
static void libkcapi_hkdf_backend(void)
{
	register_hkdf_impl(&libkcapi_hkdf);
}
