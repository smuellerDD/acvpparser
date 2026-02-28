/* OpenSSH backend
 *
 * Copyright (C) 2025, Joachim Vandersmissen <joachim.vandersmissen@atsec.com>
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

#include "backend_common.h"
#include "openssh_shim.c"

static int openssh_digest_convert(uint64_t cipher, int *alg, size_t *out_len)
{
	switch (cipher & (ACVP_HASHMASK | ACVP_HMACMASK | ACVP_SHAKEMASK)) {
	case ACVP_HMACSHA1:
	case ACVP_SHA1:
		*alg = SSH_DIGEST_SHA1;
		*out_len = 20;
		break;
	case ACVP_HMACSHA2_256:
	case ACVP_SHA256:
		*alg = SSH_DIGEST_SHA256;
		*out_len = 32;
		break;
	case ACVP_HMACSHA2_384:
	case ACVP_SHA384:
		*alg = SSH_DIGEST_SHA384;
		*out_len = 48;
		break;
	case ACVP_HMACSHA2_512:
	case ACVP_SHA512:
		*alg = SSH_DIGEST_SHA512;
		*out_len = 64;
		break;
	default:
		logger(LOGGER_WARN, "Unknown cipher\n");
		return -EINVAL;
	}

	return 0;
}

/************************************************
 * HMAC cipher interface functions
 ************************************************/
static int openssh_hmac_generate(struct hmac_data *data, flags_t parsed_flags)
{
	struct ssh_hmac_ctx *ctx = NULL;
	int ret = 0;
	int alg;
	size_t out_len;

	(void)parsed_flags;

	CKINT(openssh_digest_convert(data->cipher, &alg, &out_len));
	CKINT(alloc_buf(out_len, &data->mac));

	ctx = ssh_hmac_start(alg);
	CKNULL_LOG(ctx, -EFAULT, "ssh_hmac_start failed\n");
	CKINT_LOG(ssh_hmac_init(ctx, data->key.buf, data->key.len),
		  "ssh_hmac_init failed: %d\n", ret)
	CKINT_LOG(ssh_hmac_update(ctx, data->msg.buf, data->msg.len),
		  "ssh_hmac_update failed: %d\n", ret);
	CKINT_LOG(ssh_hmac_final(ctx, data->mac.buf, data->mac.len),
		  "ssh_hmac_final failed: %d\n", ret);

out:
	if (ctx)
		ssh_hmac_free(ctx);
	return ret;
}

static struct hmac_backend openssh_hmac =
{
	openssh_hmac_generate,
	NULL,
};

ACVP_DEFINE_CONSTRUCTOR(openssh_hmac_backend)
static void openssh_hmac_backend(void)
{
	register_hmac_impl(&openssh_hmac);
}

/************************************************
 * SSH KDF interface functions
 ************************************************/
static int openssh_kdf_ssh_internal(struct kdf_ssh_data *data, char id, int alg,
				    size_t out_len, struct buffer *out)
{
	struct ssh ssh;
	struct kex kex;
	struct sshbuf *shared_secret = NULL;
	int ret;

	ssh.kex = &kex;

	kex.session_id = sshbuf_from(data->session_id.buf, data->session_id.len);
	CKNULL_LOG(kex.session_id, -EFAULT, "sshbuf_from failed\n");
	kex.hash_alg = alg;

	shared_secret = sshbuf_from(data->k.buf, data->k.len);

	ret = derive_key(&ssh, id, out_len, data->h.buf, data->h.len,
			 shared_secret, &out->buf);
	if (ret != 0) {
		logger(LOGGER_ERR, "derive_key failed: %d\n",
		       ret);
		goto out;
	}

	out->len = out_len;

out:
	if (kex.session_id)
		sshbuf_free(kex.session_id);
	if (shared_secret)
		sshbuf_free(shared_secret);
	return ret;
}

static int openssh_kdf_ssh(struct kdf_ssh_data *data, flags_t parsed_flags)
{
	int alg;
	size_t ivlen, enclen, maclen;
	int ret;

	(void)parsed_flags;

	CKINT(openssh_digest_convert(data->cipher, &alg, &maclen));

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

	CKINT(openssh_kdf_ssh_internal(data,  'A' + 0, alg, ivlen,
				       &data->initial_iv_client));
	CKINT(openssh_kdf_ssh_internal(data,  'A' + 1, alg, ivlen,
				       &data->initial_iv_server));
	CKINT(openssh_kdf_ssh_internal(data,  'A' + 2, alg, enclen,
				       &data->encryption_key_client));
	CKINT(openssh_kdf_ssh_internal(data,  'A' + 3, alg, enclen,
				       &data->encryption_key_server));
	CKINT(openssh_kdf_ssh_internal(data,  'A' + 4, alg, maclen,
				       &data->integrity_key_client));
	CKINT(openssh_kdf_ssh_internal(data,  'A' + 5, alg, maclen,
				       &data->integrity_key_server));

out:
	return ret;
}

static struct kdf_ssh_backend openssh_kdf =
{
	openssh_kdf_ssh,
};

ACVP_DEFINE_CONSTRUCTOR(openssh_kdf_ssh_backend)
static void openssh_kdf_ssh_backend(void)
{
	register_kdf_ssh_impl(&openssh_kdf);
}

/************************************************
 * EdDSA cipher interface functions
 ************************************************/
static int openssh_eddsa_keygen(struct eddsa_keygen_data *data,
				flags_t parsed_flags)
{
	unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_ed25519_SECRETKEYBYTES];
	int ret = 0;

	(void)parsed_flags;

	ret = crypto_sign_ed25519_keypair(pk, sk);
	if (ret != 0) {
		logger(LOGGER_ERR, "crypto_sign_ed25519_keypair failed: %d\n",
		       ret);
		goto out;
	}

	// sk also contains the public key, we don't want that.
	CKINT(alloc_buf(crypto_sign_ed25519_SECRETKEYBYTES - crypto_sign_ed25519_PUBLICKEYBYTES,
			&data->d));
	memcpy(data->d.buf, sk, data->d.len);

	CKINT(alloc_buf(crypto_sign_ed25519_PUBLICKEYBYTES, &data->q));
	memcpy(data->q.buf, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	logger_binary(LOGGER_DEBUG, data->d.buf, data->d.len, "d");
	logger_binary(LOGGER_DEBUG, data->q.buf, data->q.len, "Q");

out:
	return ret;
}

static int openssh_eddsa_siggen(struct eddsa_siggen_data *data,
				flags_t parsed_flags)
{
	BUFFER_INIT(sm);
	unsigned long long smlen;
	const unsigned char *sk;
	int ret = 0;

	(void)parsed_flags;

	if (!data->privkey) {
		logger(LOGGER_ERR, "Private key missing\n");
		return -EINVAL;
	}

	sk = (const unsigned char *)data->privkey;

	CKINT(alloc_buf(crypto_sign_ed25519_BYTES + data->msg.len, &sm));

	ret = crypto_sign_ed25519(sm.buf, &smlen, data->msg.buf, data->msg.len,
				  sk);
	if (ret != 0) {
		logger(LOGGER_ERR, "crypto_sign_ed25519 failed: %d\n",
		       ret);
		goto out;
	}

	// sm also contains the message, we don't want that.
	CKINT(alloc_buf(crypto_sign_ed25519_BYTES, &data->signature));
	memcpy(data->signature.buf, sm.buf, crypto_sign_ed25519_BYTES);

out:
	free_buf(&sm);
	return ret;
}

static int openssh_eddsa_sigver(struct eddsa_sigver_data *data,
				flags_t parsed_flags)
{
	BUFFER_INIT(m);
	BUFFER_INIT(sm);
	unsigned long long mlen;
	int ret = 0;

	(void)parsed_flags;

	CKINT(alloc_buf(crypto_sign_ed25519_BYTES + data->msg.len, &m));

	CKINT(alloc_buf(crypto_sign_ed25519_BYTES + data->msg.len, &sm));
	memcpy(sm.buf, data->signature.buf, crypto_sign_ed25519_BYTES);
	memcpy(&sm.buf[crypto_sign_ed25519_BYTES], data->msg.buf, data->msg.len);

	ret = crypto_sign_ed25519_open(m.buf, &mlen, sm.buf, sm.len,
				       data->q.buf);
	if (ret != 0) {
		logger(LOGGER_DEBUG, "Signature verification: signature bad\n");
		data->sigver_success = 0;
	} else {
		logger(LOGGER_DEBUG,
		       "Signature verification: signature good\n");
		data->sigver_success = 1;
	}

	ret = 0;

out:
	free_buf(&sm);
	free_buf(&m);
	return ret;
}

static int openssh_eddsa_keygen_en(struct buffer *qbuf, uint64_t curve,
				   void **privkey)
{
	unsigned char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	unsigned char *sk;
	int ret;

	(void)curve;

	sk = calloc(1, crypto_sign_ed25519_SECRETKEYBYTES);
	CKNULL(sk, -ENOMEM);

	ret = crypto_sign_ed25519_keypair(pk, sk);
	if (ret != 0) {
		logger(LOGGER_ERR, "crypto_sign_ed25519_keypair failed: %d\n",
		       ret);
		goto out;
	}

	CKINT(alloc_buf(crypto_sign_ed25519_PUBLICKEYBYTES, qbuf));
	memcpy(qbuf->buf, pk, crypto_sign_ed25519_PUBLICKEYBYTES);

	logger_binary(LOGGER_DEBUG, qbuf->buf, qbuf->len, "Q");

	*privkey = sk;

out:
	if (ret && sk)
		free(sk);
	return ret;
}

static void openssh_eddsa_free_key(void *privkey)
{
	unsigned char *sk = (unsigned char *)privkey;

	if (sk) {
		free(sk);
	}
}

static struct eddsa_backend openssh_eddsa =
{
	openssh_eddsa_keygen,   /* eddsa_keygen */
	NULL,
	openssh_eddsa_siggen,   /* eddsa_siggen */
	openssh_eddsa_sigver,   /* eddsa_sigver */
	openssh_eddsa_keygen_en,
	openssh_eddsa_free_key,
};

ACVP_DEFINE_CONSTRUCTOR(openssh_eddsa_backend)
static void openssh_eddsa_backend(void)
{
	register_eddsa_impl(&openssh_eddsa);
}
