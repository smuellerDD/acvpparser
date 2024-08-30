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

/************************************************
 * RSA interface functions
 ************************************************/
#ifdef LIBKCAPI_RSA_ENABLED
#define CIPHERMAXNAME 63

extern char n1[];
extern char e1[];
extern char d1[];
extern char p1[];
extern char q1[];
extern char dp1[];
extern char dq1[];
extern char qinv1[];
extern char n2[];
extern char e2[];
extern char d2[];
extern char p2[];
extern char q2[];
extern char dp2[];
extern char dq2[];
extern char qinv2[];
extern char n3[];
extern char e3[];
extern char d3[];
extern char p3[];
extern char q3[];
extern char dp3[];
extern char dq3[];
extern char qinv3[];
extern char n4[];
extern char e4[];
extern char d4[];
extern char p4[];
extern char q4[];
extern char dp4[];
extern char dq4[];
extern char qinv4[];

unsigned char * write_field(unsigned char *ptr, unsigned char *src, unsigned short int len)
{
	/* actual length of a field = 0x02 and len */
	unsigned char *tmp;
	tmp = (unsigned char *)(&len);
	ptr[0] = 0x02;
	if(len <= 127)
	{
		if(tmp)
			memcpy(ptr + 1, tmp, 1);
		ptr = ptr + 2;
	}
	else if(len > 127 && len <=255)
	{
		ptr[1] = 0x81;
		if(tmp)
			memcpy(ptr + 2, tmp, 1);
		ptr = ptr + 3;
	}
	else if(len > 255)
	{
		ptr[1] = 0x82;
		if(tmp)
		{
			memcpy(ptr + 2, tmp + 1, 1);
			memcpy(ptr + 3, tmp, 1);
		}
		ptr = ptr + 4;
	}

	if(src)
		memcpy(ptr, src, len);
	ptr = ptr + len;
	return ptr;
}

extern int rsa_private_key_ber_encode(struct rsa_siggen_data *data, struct buffer *d,
				      struct buffer *p, struct buffer *q, struct buffer *dp,
				      struct buffer *dq, struct buffer *qinv,
				      struct buffer *pk);

int rsa_public_key_ber_encode(struct rsa_sigver_data *data, struct buffer *pk) {
	/*
	 *        BER encoding for public key
	 *        1. Calculate total length of Public key
	 *
	 *        Metadata for complete key = 0x30 and sum of length of all fields
	 *
	 *        2. BER encoding the length of any field
	 *        actual length of a field = 0x02 and len
	 *
	 *        if length <= 127 - 1 byte (actual length)
	 *        if length > 127 and length <= 255 - 2 bytes (Byte1 = 0x81, Byte2 = actual length)
	 *        if length > 255 - 3 bytes (Byte1 = 0x82, Byte2 and Byte3 = actual length)
	 */

	unsigned short int nlen;
	unsigned short int elen, total=0, extra;
	unsigned char *ptr;
	unsigned char *tmp;
	int ret = 0;

	if(!data)
	{
		logger(LOGGER_ERR, "rsa: rsa_sigver_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}

	nlen = data->n.len;
	elen = data->e.len;
	total =  nlen;
	if(nlen <= 127)
		total = total + 2;
	else if(nlen >= 128 && nlen <= 255)
		total = total + 3;
	else
		total = total + 4;
	total = total + elen;

	if(elen <= 127)
		total = total + 2;
	else if(elen >= 128 && elen <= 255)
		total = total + 3;
	else
		total = total + 4;

	if(total <= 127)
		extra = 2;
	else if(total >= 128 && total <= 255)
		extra = 3;
	else
		extra = 4;

	/*Calculated total length and extra bytes*/
	/*Start Prepare buffer*/
	CKINT_LOG(alloc_buf(total + extra + 1, pk), "rsa: public key buffer could not be allocated\n");
	ptr = pk->buf;
	ptr[0] = 0x30;
	if(extra == 2)
		memcpy(ptr + 1, &total, 1);
	if(extra == 3)
	{
		ptr[1] = 0x81;
		memcpy(ptr + 2, &total, 1);
	}
	if(extra == 4)
	{
		tmp =(unsigned char*)(&total);
		ptr[1] = 0x82;
		memcpy(ptr + 2, tmp + 1, 1);
		memcpy(ptr + 3, tmp , 1);
	}
	ptr = ptr + extra;
	ptr = write_field(ptr, data->n.buf, nlen);
	ptr = write_field(ptr, data->e.buf, elen);
	out:
	return ret;
}

static int rsa_sigver(struct rsa_sigver_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	char cipher[CIPHERMAXNAME];
	struct kcapi_handle *handle1 = NULL;
	char cipher1[CIPHERMAXNAME];
	int ret = 0;
	int ret1 = 0;
	struct buffer pk;
	struct buffer dgst;
	struct buffer mac;
	struct buffer in;
	int dgst_len=0;
	pk.len = 0;
	pk.buf = NULL;
	dgst.len = 0;
	dgst.buf = NULL;
	mac.len = 0;
	mac.buf = NULL;
	in.len = 0;
	in.buf = NULL;

	if(!data)
	{
		logger(LOGGER_ERR,"rsa: rsa_sigver_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}
	(void)parsed_flags;

	if(!(parsed_flags & FLAG_OP_RSA_SIG_PKCS15))
	{
		logger(LOGGER_ERR, "rsa: invalid cipher\n");
		return -EFAULT;
	}
	strcpy(cipher,"pkcs1pad(rsa,");
	switch(data->cipher & ACVP_HASHMASK)
	{
		case ACVP_SHA1:
			strcat(cipher, "sha1)");
			strcpy(cipher1, "sha1");
			dgst_len = 20;
			break;
		case ACVP_SHA224:
			strcat(cipher, "sha224)");
			strcpy(cipher1, "sha224");
			dgst_len = 28;
			break;
		case ACVP_SHA256:
			strcat(cipher, "sha256)");
			strcpy(cipher1, "sha256");
			dgst_len = 32;
			break;
		case ACVP_SHA384:
			strcat(cipher, "sha384)");
			strcpy(cipher1, "sha384");
			dgst_len = 48;
			break;
		case ACVP_SHA512:
			strcat(cipher, "sha512)");
			strcpy(cipher1, "sha512");
			dgst_len = 64;
			break;
	}

	if (kcapi_akcipher_init(&handle, cipher, 0))
	{
		logger(LOGGER_ERR, "rsa: allocation of %s cipher failed\n", cipher);
		return -EFAULT;
	}
	if (kcapi_md_init(&handle1, cipher1, 0))
	{
		logger(LOGGER_ERR, "rsa: allocation of hash %s failed\n", cipher);
		kcapi_akcipher_destroy(handle1);
		ret = -EFAULT;
	}

	CKINT_LOG(alloc_buf(dgst_len, &mac), "rsa: mac buffer could not be allocated\n");
	ret = kcapi_md_digest(handle1, data->msg.buf, data->msg.len, mac.buf, mac.len);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "rsa: message digest generation failed\n");
		goto out;
	}

	if(rsa_public_key_ber_encode(data, &pk) < 0)
	{
		logger(LOGGER_ERR, "rsa: BER encoding of public key failed\n");
		ret = -EFAULT;
		goto out;
	}

	ret1 = kcapi_akcipher_setpubkey(handle, pk.buf, pk.len);
	if (ret1 <= 0)
	{
		logger(LOGGER_ERR, "rsa: public key setting failed\n");
		ret = -EFAULT;
		goto out;
	}

	CKINT_LOG(alloc_buf(ret, &dgst), "rsa: digest buffer could not be allocated\n");
	CKINT_LOG(alloc_buf(data->sig.len + mac.len, &in), "rsa: in buffer could not be allocated\n");

	if(data->sig.buf)
		memcpy(in.buf, data->sig.buf, data->sig.len);

	if(mac.buf)
		memcpy(in.buf + data->sig.len, mac.buf, mac.len);

	ret1 = kcapi_akcipher_verify(handle,
				     in.buf, in.len,
			      dgst.buf, dgst.len, 0);

	if(ret1 < 0)
	{
		logger(LOGGER_ERR, "rsa: signature verification failed with error = %d\n", ret1);
		data->sig_result = 0;
		goto out;
	}
	data->sig_result = 1;

	out:
	if(dgst.buf)
		free_buf(&dgst);
	if(in.buf)
		free_buf(&in);
	if(pk.buf)
		free_buf(&pk);
	if(mac.buf)
		free_buf(&mac);

	kcapi_akcipher_destroy(handle);
	kcapi_md_destroy(handle1);
	return ret;
}

static int rsa_siggen(struct rsa_siggen_data *data,
		      flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	char cipher[CIPHERMAXNAME];
	struct kcapi_handle *handle1 = NULL;
	char cipher1[CIPHERMAXNAME];
	int ret = 0;
	int ret1 = 0;
	char *n_ptr;
	char *e_ptr;
	char *d_ptr;
	char *p_ptr;
	char *q_ptr;
	char *dp_ptr;
	char *dq_ptr;
	char *qinv_ptr;
	struct buffer d;
	struct buffer p;
	struct buffer q;
	struct buffer dp;
	struct buffer dq;
	struct buffer qinv;
	struct buffer pk;
	struct buffer dgst;
	struct buffer mac;
	int dgst_len=0;
	pk.len = 0;
	pk.buf = NULL;
	dgst.len = 0;
	dgst.buf = NULL;
	mac.len = 0;
	mac.buf = NULL;
	d.len = 0;
	d.buf = NULL;
	p.len = 0;
	p.buf = NULL;
	q.len = 0;
	q.buf = NULL;
	dp.len = 0;
	dp.buf = NULL;
	dq.len = 0;
	dq.buf = NULL;
	qinv.len = 0;
	qinv.buf = NULL;

	if(!data)
	{
		logger(LOGGER_ERR, "rsa: rsa_siggen_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}
	(void)parsed_flags;

	if(!(parsed_flags & FLAG_OP_RSA_SIG_PKCS15))
	{
		logger(LOGGER_ERR, "rsa: invalid cipher\n");
		return -EFAULT;
	}

	strcpy(cipher,"pkcs1pad(rsa,");
	switch(data->cipher & ACVP_HASHMASK)
	{
		case ACVP_SHA1:
			strcat(cipher, "sha1)");
			strcpy(cipher1, "sha1");
			dgst_len = 20;
			break;
		case ACVP_SHA224:
			strcat(cipher, "sha224)");
			strcpy(cipher1, "sha224");
			dgst_len = 28;
			break;
		case ACVP_SHA256:
			strcat(cipher, "sha256)");
			strcpy(cipher1, "sha256");
			dgst_len = 32;
			break;
		case ACVP_SHA384:
			strcat(cipher, "sha384)");
			strcpy(cipher1, "sha384");
			dgst_len = 48;
			break;
		case ACVP_SHA512:
			strcat(cipher, "sha512)");
			strcpy(cipher1, "sha512");
			dgst_len = 64;
			break;
	}

	if (kcapi_akcipher_init(&handle, cipher, 0))
	{
		logger(LOGGER_ERR, "rsa: allocation of %s cipher failed\n", cipher);
		return -EFAULT;
	}
	if (kcapi_md_init(&handle1, cipher1, 0))
	{
		logger(LOGGER_ERR, "rsa: allocation of hash %s failed\n", cipher1);
		kcapi_akcipher_destroy(handle1);
		ret = -EFAULT;
	}

	CKINT_LOG(alloc_buf(dgst_len, &mac), "rsa: mac buffer cannot be allocated\n");
	ret = kcapi_md_digest(handle1, data->msg.buf, data->msg.len, mac.buf, mac.len);

	if (ret < 0)
	{
		logger(LOGGER_ERR, "rsa: message digest generation failed\n");
		goto out;
	}

	/*
	 *        definition for the array n1, n1[] = "n = 00b67b1cee2ff9f99f94478a23200816e0449845....."
	 *        the actual value that is needed is starting from index 4
	 *        therefore, we do n1 + 4
	 *        the same logic is followed for the other attributes
	 */

	if(data->modulus == 1024)
	{
		n_ptr = n1 + 4;
		e_ptr = e1 + 4;
		d_ptr = d1 + 4;
		p_ptr = p1 + 4;
		q_ptr = q1 + 4;
		dp_ptr = dp1 + 5;
		dq_ptr = dq1 + 5;
		qinv_ptr = qinv1 + 7;
	}
	if(data->modulus == 2048)
	{
		n_ptr = n2 + 4;
		e_ptr = e2 + 4;
		d_ptr = d2 + 4;
		p_ptr = p2 + 4;
		q_ptr = q2 + 4;
		dp_ptr = dp2 + 5;
		dq_ptr = dq2 + 5;
		qinv_ptr = qinv2 + 7;
	}
	if(data->modulus == 3072)
	{
		n_ptr = n3 + 4;
		e_ptr = e3 + 4;
		d_ptr = d3 + 4;
		p_ptr = p3 + 4;
		q_ptr = q3 + 4;
		dp_ptr = dp3 + 5;
		dq_ptr = dq3 + 5;
		qinv_ptr = qinv3 + 7;
	}
	if(data->modulus == 4096)
	{
		n_ptr = n4 + 4;
		e_ptr = e4 + 4;
		d_ptr = d4 + 4;
		p_ptr = p4 + 4;
		q_ptr = q4 + 4;
		dp_ptr = dp4 + 5;
		dq_ptr = dq4 + 5;
		qinv_ptr = qinv4 + 7;
	}

	hex2bin_alloc((char*)n_ptr, strlen(n_ptr), &data->n.buf, &data->n.len);
	hex2bin_alloc((char*)e_ptr, strlen(e_ptr), &data->e.buf, &data->e.len);
	hex2bin_alloc((char*)d_ptr, strlen(d_ptr), &d.buf, &d.len);
	hex2bin_alloc((char*)p_ptr, strlen(p_ptr), &p.buf, &p.len);
	hex2bin_alloc((char*)q_ptr, strlen(q_ptr), &q.buf, &q.len);
	hex2bin_alloc((char*)dp_ptr, strlen(dp_ptr), &dp.buf, &dp.len);
	hex2bin_alloc((char*)dq_ptr, strlen(dq_ptr), &dq.buf, &dq.len);
	hex2bin_alloc((char*)qinv_ptr, strlen(qinv_ptr), &qinv.buf, &qinv.len);

	if(rsa_private_key_ber_encode(data, &d, &p, &q, &dp, &dq, &qinv, &pk) < 0)
	{
		logger(LOGGER_ERR, "rsa: BER encoding of private key failed\n");
		ret = -EFAULT;
		goto out;
	}

	ret1 = kcapi_akcipher_setkey(handle, pk.buf, pk.len);
	if (ret1 <= 0)
	{
		logger(LOGGER_ERR, "rsa: pivate key setting failed with error = %d\n", ret1);
		ret = -EFAULT;
		goto out;
	}

	CKINT_LOG(alloc_buf(ret1, &(data->sig)), "rsa: signature buffer could not be allocated\n");
	ret = kcapi_akcipher_sign(handle,
				  mac.buf, mac.len,
			   data->sig.buf, data->sig.len, 0);
	out:
	if(dgst.buf)
		free_buf(&dgst);
	if(pk.buf)
		free_buf(&pk);
	if(mac.buf)
		free_buf(&mac);
	if(d.buf)
		free_buf(&d);
	if(p.buf)
		free_buf(&p);
	if(q.buf)
		free_buf(&q);
	if(dp.buf)
		free_buf(&dp);
	if(dq.buf)
		free_buf(&dq);
	if(qinv.buf)
		free_buf(&qinv);

	kcapi_akcipher_destroy(handle);
	kcapi_md_destroy(handle1);
	return ret;
}

static struct rsa_backend kcapi_rsa =
{
	NULL,
	rsa_siggen,
	rsa_sigver,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_rsa_backend)
static void kcapi_rsa_backend(void)
{
	register_rsa_impl(&kcapi_rsa);
}
#endif /* LIBKCAPI_RSA_ENABLED */

/************************************************
 * ECDSA interface functions
 ************************************************/

#ifdef LIBKCAPI_ECDSA_ENABLED

#define ECDH_CURVE_STR_P192 "ecdh-nist-p192"
#define ECDH_CURVE_STR_P256 "ecdh-nist-p256"
#define ECDH_CURVE_STR_P384 "ecdh-nist-p384"
#define ECDH_CURVE_ID_P192 1
#define ECDH_CURVE_ID_P256 2
#define ECDH_CURVE_ID_P384 3
#define ECDH_CURVE_NUM_P192 192
#define ECDH_CURVE_NUM_P256 256
#define ECDH_CURVE_NUM_P384 384

static int ecdsa_keygen(struct ecdsa_keygen_extra_data *data, flags_t parsed_flags)
{
	if(!data)
	{
		logger(LOGGER_ERR, "ecdsa: ecdsa_keygen_extra_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}
	(void)parsed_flags;

	struct kcapi_handle *handle = NULL;
	struct kcapi_handle *ecdh = NULL;
	struct buffer key;
	size_t dlen, qxlen, qylen;
	int ret=0;
	char *curve_str = NULL;
	int curve_num = 0;
	int curve_id = 0;

	if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
	{
		curve_str = ECDH_CURVE_STR_P384;
		curve_num = ECDH_CURVE_NUM_P384;
		curve_id = ECDH_CURVE_ID_P384;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
	{
		curve_str = ECDH_CURVE_STR_P256;
		curve_num = ECDH_CURVE_NUM_P256;
		curve_id = ECDH_CURVE_ID_P256;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
	{
		curve_str = ECDH_CURVE_STR_P192;
		curve_num = ECDH_CURVE_NUM_P192;
		curve_id = ECDH_CURVE_ID_P192;
	}
	else
	{
		logger(LOGGER_ERR, "ecdsa: curve is not supported\n");
		return -EINVAL;
	}

	key.len = 0;
	key.buf = NULL;

	if (kcapi_ecc_init(&handle, curve_str))
	{
		ret = -EINVAL;
		logger(LOGGER_ERR, "ecdsa: allocation of cipher failed\n");
		goto out;
	}

	if(curve_num == 384)
		ecdsa_get_bufferlen(ACVP_NISTP384, &dlen, &qxlen, &qylen);
	else
		ecdsa_get_bufferlen(ACVP_NISTP256, &dlen, &qxlen, &qylen);

	CKINT_LOG(alloc_buf(qxlen, &data->Qx), "ecdsa: Qx could not be allocated\n");
	CKINT_LOG(alloc_buf(qylen, &data->Qy), "ecdsa: Qy could not be allocated\n");
	CKINT_LOG(alloc_buf(dlen, &data->d), "ecdaa: private Key buffer could not be allocated\n");
	ret = kcapi_ecc_keygen(handle, curve_num, data->d.buf, data->d.len, data->Qx.buf,
			       data->Qx.len, data->Qy.buf, data->Qy.len);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdsa: key generation failed with error = %d\n", ret);
		goto out;
	}

	if (kcapi_kpp_init(&ecdh, curve_str, 0))
	{
		ret = -EINVAL;
		logger(LOGGER_ERR, "ecdh: allocation of cipher failed\n");
		goto out;
	}

	ret = kcapi_kpp_ecdh_setcurve(ecdh, curve_id);

	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: curve setting failed with error: %d\n", ret);
		goto out;
	}

	ret = kcapi_kpp_setkey(ecdh, data->d.buf, data->d.len);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: key setting failed with error: %d\n", ret);
		goto out;
	}

	CKINT_LOG(alloc_buf(qxlen + qylen, &key), "ecdh: local public Key buffer could not be allocated\n");

	ret = kcapi_kpp_keygen(ecdh, key.buf, key.len, 0);
	if(ret < 0)
	{
		ret = -EINVAL;
		logger(LOGGER_ERR, "ecdsa: public keygen failed\n");
		goto out;
	}
	else if(memcmp(data->Qx.buf, key.buf, qxlen) == 0 && memcmp(data->Qy.buf, key.buf+qxlen, qylen) == 0)
	{
		logger(LOGGER_DEBUG, "ecdsa: public keygen success\n");
	}
	else
	{
		logger(LOGGER_ERR, "ecdsa: public keygen failed\n");
		ret = -EINVAL;
		goto out;
	}

out:
	kcapi_kpp_destroy(ecdh);
	kcapi_ecc_destroy(handle);
	if(key.buf)
		free_buf(&key);
	return ret;
}

static int ecdsa_keyver(struct ecdsa_pkvver_data *data, flags_t parsed_flags)
{
	if(!data)
	{
		logger(LOGGER_ERR, "ecdsa: ecdsa_pkvver_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}

	struct kcapi_handle *handle = NULL;
	int ret =0 , re;
	char *curve_str = NULL;
	int curve_num = 0;
	(void) parsed_flags;

	if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
	{
		curve_str = ECDH_CURVE_STR_P384;
		curve_num = ECDH_CURVE_NUM_P384;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
	{
		curve_str = ECDH_CURVE_STR_P256;
		curve_num = ECDH_CURVE_NUM_P256;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
	{
		curve_str = ECDH_CURVE_STR_P192;
		curve_num = ECDH_CURVE_NUM_P192;
	}
	else
	{
		logger(LOGGER_ERR, "ecdsa: curve is not supported.\n");
		return -EINVAL;
	}

	if (kcapi_ecc_init(&handle, curve_str))
	{
		logger(LOGGER_ERR, "ecdsa: allocation of cipher failed\n");
		ret = -EINVAL;
		goto out;
	}
	re = kcapi_ecc_verify(handle, curve_num, data->Qx.buf,
			      data->Qx.len, data->Qy.buf, data->Qy.len);
	if(re < 0)
	{
		logger(LOGGER_ERR, "ecdsa: public keyver failed\n");
		data->keyver_success = 0;
	}
	else
	{
		logger(LOGGER_DEBUG, "ecdsa: public keyVer success\n");
		data->keyver_success = 1;
	}
out:
	kcapi_ecc_destroy(handle);
	return ret;
}

static int ecdsa_sigver(struct ecdsa_sigver_data *data, flags_t parsed_flags)
{
	if(!data)
	{
		logger(LOGGER_ERR, "ecdsa: ecdsa_sigver_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}

	struct kcapi_handle *handle = NULL, *hash_handle = NULL;
	int ret = 0, rc = 0;
	size_t len = 0;
	char *curve_str = NULL;
	(void) parsed_flags;

	if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
	{
		curve_str = "ecdsa-nist-p384";
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
	{
		curve_str = "ecdsa-nist-p256";
	}
	else
	{
		logger(LOGGER_ERR, "ecdsa: curve not FIPS supported.\n");
		return -EINVAL;
	}

	if(!data->component)
	{
		/* We need to generate the msg hash */
		struct buffer msg = data->msg;
		data->msg.buf = NULL;
		data->msg.len = 0;
		char cipher[CIPHERMAXNAME];

		if(sha_mac_cipher(cipher, data->cipher & ACVP_HASHMASK, &len))
		{
			return -EINVAL;
		}

		if (kcapi_md_init(&hash_handle, cipher, 0))
		{
			logger(LOGGER_ERR, "ecdsa: allocation of hash %s failed\n", cipher);
			return 1;
		}

		CKINT_LOG(alloc_buf(len, &data->msg), "ecdsa: msg hash buffer could not be allocated\n");
		rc = kcapi_md_digest(hash_handle, msg.buf, msg.len, data->msg.buf, data->msg.len);
		if (rc < 0)
		{
			logger(LOGGER_ERR, "ecdsa: message digest generation failed\n");
			kcapi_md_destroy(hash_handle);
			return 1;
		}

		kcapi_md_destroy(hash_handle);
		if(msg.buf)
			free_buf(&msg);
	}

	if (kcapi_akcipher_init(&handle, curve_str, 0))
	{
		logger(LOGGER_ERR, "ecdsa: allocation of %s cipher failed\n", curve_str);
		return -EFAULT;
	}

	/* Encoding and setting public key */
	struct buffer pk;
	unsigned char *ptr;
	pk.len = 0;
	pk.buf = NULL;

	CKINT_LOG(alloc_buf(data->Qx.len + data->Qy.len + 1, &pk), "ecdsa: public key buffer could not be allocated\n");
	ptr = (&pk)->buf;

	ptr[0] = 0x04;
	ptr = ptr + 1;

	if(data->Qx.buf)
		memcpy(ptr, data->Qx.buf, data->Qx.len);
	ptr = ptr + data->Qx.len;

	if(data->Qy.buf)
		memcpy(ptr, data->Qy.buf, data->Qy.len);

	ret = kcapi_akcipher_setpubkey(handle, pk.buf, pk.len);
	if (ret <= 0)
	{
		logger(LOGGER_ERR, "ecdsa: asymmetric cipher set public key failed\n");
		ret = -EFAULT;
		goto out;
	}

	/* BER Encoding signature */
	struct buffer in;
	struct buffer dgst;
	unsigned short int rlen;
	unsigned short int slen;
	unsigned short int total = 0, extra;
	unsigned char *tmp;

	in.len = 0;
	in.buf = NULL;
	dgst.len = 0;
	dgst.buf = NULL;
	ptr = NULL;

	CKINT_LOG(alloc_buf(rc, &dgst), "ecdsa: dgst buffer could not be allocated\n");

	rlen = data->R.len;
	slen = data->S.len;

	/*
	 *        Metadata for complete key = 0x30 and sum of length of all fields
	 *
	 *        BER encoding the length of any field
	 *        actual length of a field = 0x02 and len
	 *
	 *        if length <= 127 - 1 byte (actual length)
	 *        if length > 127 and length <= 255 - 2 bytes (Byte1 = 0x81, Byte2 = actual length)
	 *        if length > 255 - 3 bytes (Byte1 = 0x82, Byte2 and Byte3 = actual length)
	 */


	total = rlen;
	if(rlen <= 127)
		total = total + 2;
	else if(rlen >= 128 && rlen <= 255)
		total = total + 3;
	else
		total = total + 4;

	total = total + slen;
	if(slen <= 127)
		total = total + 2;
	else if(slen >= 128 && slen <= 255)
		total = total + 3;
	else
		total = total + 4;

	if(total <= 127)
		extra = 2;
	else if(total >= 128 && total <= 255)
		extra = 3;
	else
		extra = 4;

	CKINT_LOG(alloc_buf(total + extra + data->msg.len + 1, &in), "ecdsa: in buffer could not be allocated\n");
	ptr = (&in)->buf;
	ptr[0] = 0x30;
	if(extra == 2)
		memcpy(ptr + 1, &total, 1);
	if(extra == 3)
	{
		ptr[1] = 0x81;
		memcpy(ptr + 2, &total, 1);
	}
	if(extra == 4)
	{
		tmp =(unsigned char*) (&total);
		ptr[1] = 0x82;
		memcpy(ptr + 2, tmp + 1, 1);
		memcpy(ptr + 3, tmp , 1);
	}

	ptr = ptr + extra;
	ptr = write_field(ptr, data->R.buf, rlen);
	ptr = write_field(ptr, data->S.buf, slen);

	if(data->msg.buf)
		memcpy(ptr + 1, data->msg.buf, data->msg.len);

	ret = kcapi_akcipher_verify(handle, in.buf, in.len, dgst.buf, dgst.len, 0);

	if(ret < 0)
	{
		data->sigver_success = 0;
		logger(LOGGER_ERR, "ecdsa: SigVer Failed\n");
	}
	else
	{
		data->sigver_success = 1;
		logger(LOGGER_DEBUG, "ecdsa: SigVer Success\n");
	}
	ret = 0;

out:
	kcapi_akcipher_destroy(handle);
	if(in.buf)
		free_buf(&in);
	if(dgst.buf)
		free_buf(&dgst);
	if(pk.buf)
		free_buf(&pk);
	return ret;
}

static struct ecdsa_backend kcapi_ecdsa =
{
	NULL,
	ecdsa_keygen,
	ecdsa_keyver,
	NULL,
	ecdsa_sigver,
	NULL,
	NULL
};
ACVP_DEFINE_CONSTRUCTOR(kcapi_ecdsa_backend)
static void kcapi_ecdsa_backend(void)
{
	register_ecdsa_impl(&kcapi_ecdsa);
}

#endif /* LIBKCAPI_ECDSA_ENABLED */

/************************************************
 * ECDH interface functions
 ************************************************/

#ifdef LIBKCAPI_ECDH_ENABLED

#define ECDH_SS_KEYLEN_P192 24
#define ECDH_SS_KEYLEN_P256 32
#define ECDH_SS_KEYLEN_P384 48

static int ecdh_ss_ver(struct ecdh_ss_ver_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	int ret = 0;
	struct buffer key;       //IUT Public Key
	struct buffer rkey;      //Remote Public Key
	struct buffer secret;    //Shared Secret
	char *curve;
	int curve_id, ss_key_len;

	if(!data)
	{
		logger(LOGGER_ERR, "ecdh: ecdh_ss_ver_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}
	(void)parsed_flags;

	key.len = 0;
	key.buf = NULL;
	rkey.len = 0;
	rkey.buf = NULL;
	secret.len = 0;
	secret.buf = NULL;

	if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
	{
		curve = ECDH_CURVE_STR_P384;
		curve_id = ECDH_CURVE_ID_P384;
		ss_key_len = ECDH_SS_KEYLEN_P384;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
	{
		curve = ECDH_CURVE_STR_P256;
		curve_id = ECDH_CURVE_ID_P256;
		ss_key_len = ECDH_SS_KEYLEN_P256;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
	{
		curve = ECDH_CURVE_STR_P192;
		curve_id = ECDH_CURVE_ID_P192;
		ss_key_len = ECDH_SS_KEYLEN_P192;
	}
	else
	{
		logger(LOGGER_ERR, "ecdh: curve not supported\n");
		return -EINVAL;
	}

	if (kcapi_kpp_init(&handle, curve, 0))
	{
		ret = -EINVAL;
		logger(LOGGER_ERR, "ecdh: allocation of cipher failed\n");
		goto out1;
	}

	ret = kcapi_kpp_ecdh_setcurve(handle, curve_id);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: setting ecdh curve failed with error: %d\n", ret);
		goto out1;
	}

	ret = kcapi_kpp_setkey(handle, data->privloc.buf, data->privloc.len);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: kernel keys generation failed with error: %d\n", ret);
		goto out;
	}

	CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &key), "ecdh: local pub Key buffer could not be allocated\n");
	ret = kcapi_kpp_keygen(handle, key.buf, key.len, 0);
	if(ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: public keygen failed\n");
		goto out;
	}
	if(memcmp(data->Qxloc.buf, key.buf, data->Qxrem.len))
	{
		logger(LOGGER_ERR, "ecdh: key not matching\n");
		data->validity_success=0;
		goto out;
	}
	if(memcmp(data->Qyloc.buf, key.buf + data->Qxrem.len, data->Qyrem.len))
	{
		logger(LOGGER_ERR, "ecdh: key not matching\n");
		data->validity_success=0;
		goto out;
	}

	CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &rkey), "ecdh: remote key buffer could not be allocated\n");

	if(data->Qxrem.buf)
		memcpy(rkey.buf, data->Qxrem.buf, data->Qxrem.len);

	if(data->Qyrem.buf)
		memcpy(rkey.buf + data->Qxrem.len, data->Qyrem.buf, data->Qyrem.len);

	CKINT_LOG(alloc_buf(ss_key_len * 2, &secret), "ecdh: shared secret buffer could not be allocated\n");
	ret = kcapi_kpp_ssgen(handle, rkey.buf, rkey.len, secret.buf, ss_key_len * 2, 0);
	if(ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: ssgen failed\n");
		goto out;
	}

	if(memcmp(data->hashzz.buf, secret.buf, ss_key_len))
	{
		logger(LOGGER_ERR, "ecdh: ssver failed\n");
		data->validity_success=0;
	}
	else
	{
		data->validity_success=1;
	}
out:
	if(key.buf)
		free_buf(&key);
	if(rkey.buf)
		free_buf(&rkey);
	if(secret.buf)
		free_buf(&secret);
out1:
	kcapi_kpp_destroy(handle);
	return ret;
}

static int ecdh_ss(struct ecdh_ss_data *data, flags_t parsed_flags)
{
	struct kcapi_handle *handle = NULL;
	int ret = 0;
	char *curve;
	int curve_id, ss_key_len;
	struct buffer key;       //IUT Pub Key
	struct buffer rkey;      //Remote Pub Key
	struct buffer pkey;      //Private Key
	struct buffer secret;    //Shared Secret

	if(!data)
	{
		logger(LOGGER_ERR, "ecdh: ecdh_ss_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}
	(void)parsed_flags;

	key.len = 0;
	key.buf = NULL;
	pkey.len = 0;
	pkey.buf = NULL;
	rkey.len = 0;
	rkey.buf = NULL;
	secret.len = 0;
	secret.buf = NULL;

	if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
	{
		curve = ECDH_CURVE_STR_P384;
		curve_id = ECDH_CURVE_ID_P384;
		ss_key_len = ECDH_SS_KEYLEN_P384;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
	{
		curve = ECDH_CURVE_STR_P256;
		curve_id = ECDH_CURVE_ID_P256;
		ss_key_len = ECDH_SS_KEYLEN_P256;
	}
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
	{
		curve = ECDH_CURVE_STR_P192;
		curve_id = ECDH_CURVE_ID_P192;
		ss_key_len = ECDH_SS_KEYLEN_P192;
	}
	else
	{
		logger(LOGGER_ERR, "ecdh: curve not supported\n");
		return -EINVAL;
	}

	if (kcapi_kpp_init(&handle, curve, 0))
	{
		ret = -EINVAL;
		logger(LOGGER_ERR, "ecdh: allocation of cipher failed\n");
		goto out1;
	}

	ret = kcapi_kpp_ecdh_setcurve(handle, curve_id);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: setting ecdh curve failed: %d\n", ret);
		goto out1;
	}

	CKINT_LOG(alloc_buf(ss_key_len, &pkey), "ecdh: private key buffer could not be allocated\n");
	ret = kcapi_rng_get_bytes(pkey.buf, ss_key_len);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: get RNG failed with error: %d\n", ret);
		goto out;
	}

	ret = kcapi_kpp_setkey(handle, pkey.buf, ss_key_len);
	if (ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: private key setting failed with error: %d\n", ret);
		goto out;
	}

	CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &key), "ecdh: local public key buffer could not be allocated\n");
	ret = kcapi_kpp_keygen(handle, key.buf, key.len, 0);
	if(ret<0)
	{
		logger(LOGGER_ERR, "ecdh: public keygen failed\n");
		goto out;
	}

	CKINT_LOG(alloc_buf(data->Qxrem.len , &data->Qxloc), "ecdh: local x key buffer could not be allocated\n");
	CKINT_LOG(alloc_buf(data->Qyrem.len , &data->Qyloc), "ecdh: local y key buffer could not be allocated\n");

	if(key.buf)
		memcpy(data->Qxloc.buf, key.buf, data->Qxrem.len);

	if(key.buf)
		memcpy(data->Qyloc.buf, key.buf + data->Qxrem.len, data->Qyrem.len);

	CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &rkey), "ecdh: remote key buffer could not be allocated\n");

	if(data->Qxrem.buf)
		memcpy(rkey.buf, data->Qxrem.buf, data->Qxrem.len);

	if(data->Qyrem.buf)
		memcpy(rkey.buf + data->Qxrem.len, data->Qyrem.buf, data->Qyrem.len);

	CKINT_LOG(alloc_buf(ss_key_len * 2, &secret), "ecdh: shared secret buffer could not be allocated\n");
	ret = kcapi_kpp_ssgen(handle, rkey.buf, rkey.len, secret.buf, ss_key_len * 2, 0);
	if(ret < 0)
	{
		logger(LOGGER_ERR, "ecdh: siggen failed\n");
		goto out;
	}

	CKINT_LOG(alloc_buf(ss_key_len, &data->hashzz), "ecdh: shared secret buffer could not be allocated\n");

	if(secret.buf)
		memcpy(data->hashzz.buf, secret.buf, ss_key_len);
out:
	if(key.buf)
		free_buf(&key);
	if(pkey.buf)
		free_buf(&pkey);
	if(rkey.buf)
		free_buf(&rkey);
	if(secret.buf)
		free_buf(&secret);
out1:
	kcapi_kpp_destroy(handle);
	return ret;
}

static struct ecdh_backend kcapi_ecdh =
{
	ecdh_ss,
	ecdh_ss_ver,
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_ecdh_backend)
static void kcapi_ecdh_backend(void)
{
	register_ecdh_impl(&kcapi_ecdh);
}

#endif /* LIBKCAPI_ECDH_ENABLED */

/************************************************
 * DRBG interface functions
 ************************************************/

#ifdef LIBKCAPI_DRBG_ENABLED

static int drbg_cipher(uint64_t acvp_cipher, uint64_t type, uint32_t pr, char* cipher)
{
	if(pr)
		strcpy(cipher, "drbg_pr");
	else
		strcpy(cipher, "drbg_nopr");

	switch(acvp_cipher & ACVP_HASHMASK)
	{
		case ACVP_SHA1:
			if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
				strcat(cipher, "_hmac");
		strcat(cipher, "_sha1");
		break;
		case ACVP_SHA224:
			if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
				strcat(cipher, "_hmac");
		strcat(cipher, "_sha224");
		break;
		case ACVP_SHA256:
			if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
				strcat(cipher, "_hmac");
		strcat(cipher, "_sha256");
		break;
		case ACVP_SHA384:
			if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
				strcat(cipher, "_hmac");
		strcat(cipher, "_sha384");
		break;
		case ACVP_SHA512:
			if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
				strcat(cipher, "_hmac");
		strcat(cipher, "_sha512");
		break;
	}

	switch(acvp_cipher & ACVP_AESMASK)
	{
		case ACVP_AES128:
			strcat(cipher, "_ctr_aes128");
			break;
		case ACVP_AES192:
			strcat(cipher, "_ctr_aes192");
			break;
		case ACVP_AES256:
			strcat(cipher, "_ctr_aes256");
			break;
	}
	return 0;
}

static int drbg_generate(struct drbg_data *data, flags_t parsed_flags)
{
	char cipher[CIPHERMAXNAME];
	int ret = 0;
	unsigned int i;
	static struct kcapi_handle *rng = NULL;
	struct buffer ent = {NULL, 0};

	if(!data)
	{
		logger(LOGGER_ERR, "drbg: drbg_data is empty, returning -EINVAL...\n");
		return -EINVAL;
	}
	(void)parsed_flags;

	drbg_cipher(data->cipher, data->type, data->pr, cipher);

	ret = kcapi_rng_init(&rng, cipher, 0);
	if (ret)
		return ret;

	CKINT_LOG(alloc_buf(data->entropy.len + data->nonce.len, &ent), "drbg: entropy buffer could not be allocated\n");

	if(data->entropy.buf)
		memcpy(ent.buf, data->entropy.buf, data->entropy.len);

	if(data->nonce.buf)
		memcpy(ent.buf + data->entropy.len, data->nonce.buf, data->nonce.len);

	ret = kcapi_rng_set_entropy(rng, ent.buf, ent.len);
	if(ret)
		logger(LOGGER_ERR, "drbg: setting entropy failed with error = %d\n", ret);

	ret = kcapi_rng_seed(rng, data->pers.buf, data->pers.len);
	if (ret)
		goto out;
	CKINT_LOG(alloc_buf(data->rnd_data_bits_len/8, &data->random), "drbg: data->random buffer could not be allocated\n");

	for(i = 1; i <= data->entropy_reseed.arraysize; i++)
	{
		unsigned char *addn =  data->addtl_reseed.buffers[i-1].buf;
		int len = data->addtl_reseed.buffers[i-1].len;
		struct buffer ent1;
		ent1.buf = data->entropy_reseed.buffers[i-1].buf;
		ent1.len = data->entropy_reseed.buffers[i-1].len;
		ret = kcapi_rng_set_entropy(rng, ent1.buf, ent1.len);

		if(ret < 0)
		{
			logger(LOGGER_ERR, "drbg: entropy setting failed with error = %d \n", ret);
			goto out;
		}

		ret = kcapi_rng_seed(rng, addn, len);
		if (ret)
		{
			logger(LOGGER_ERR, "drbg: reseed failed with error = %d\n",ret);
			goto out;
		}
	}

	for(i = 1; i <= data->addtl_generate.arraysize; i++)
	{
		// calling generate twice is not the same as calling it with 2 * num_bytes
		unsigned char *addn =  data->addtl_generate.buffers[i-1].buf;
		int len = data->addtl_generate.buffers[i-1].len;

		if(data->pr)
		{
			struct buffer ent1;
			ent1.buf = data->entropy_generate.buffers[i-1].buf;
			ent1.len = data->entropy_generate.buffers[i-1].len;
			ret = kcapi_rng_set_entropy(rng, ent1.buf, ent1.len);
			if(ret < 0)
			{
				logger(LOGGER_ERR, "drbg: entropy set failed with error = %d\n", ret);
				goto out;
			}
		}

		ret = kcapi_rng_send_addtl(rng, addn, len);
		if (ret < 0)
		{
			logger(LOGGER_ERR, "drbg: setting additional data failed with error = %d\n", ret);
			goto out;
		}

		ret = kcapi_rng_generate(rng, data->random.buf, data->random.len);
		if (ret < 0)
		{
			logger(LOGGER_ERR, "drbg: generation failed with error = %d\n", ret);
			goto out;
		}
	}
out:
	if (rng)
		kcapi_rng_destroy(rng);
	if(ent.buf)
		free_buf(&ent);
	return ret;
}

static struct drbg_backend kcapi_drbg =
{
	drbg_generate,
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_drbg_backend)
static void kcapi_drbg_backend(void)
{
	register_drbg_impl(&kcapi_drbg);
}

#endif /* LIBKCAPI_DRBG_ENABLED */
