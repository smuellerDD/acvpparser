/*
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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

#include <stdlib.h>

#include <hash.h>
#include <hmac.h>

#include "backend_common.h"

/************************************************
 * SHA cipher interface functions
 ************************************************/

static int acvpproxy_convert(uint64_t cipher, hash_type *hash)
{
	switch (cipher) {
	case ACVP_SHA1:
	case ACVP_HMACSHA1:
		*hash = HASH_TYPE_SHA1;
		break;
	case ACVP_SHA224:
	case ACVP_HMACSHA2_224:
		*hash = HASH_TYPE_SHA224;
		break;
	case ACVP_SHA256:
	case ACVP_HMACSHA2_256:
		*hash = HASH_TYPE_SHA256;
		break;
	case ACVP_SHA384:
	case ACVP_HMACSHA2_384:
		*hash = HASH_TYPE_SHA384;
		break;
	case ACVP_SHA512:
	case ACVP_HMACSHA2_512:
		*hash = HASH_TYPE_SHA512;
		break;
	default:
		logger(LOGGER_WARN, "Unknown cipher\n");
		return -EINVAL;
	}
	return 0;
}

static int acvpproxy_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
	const hash_spec *spec;
	hash_ctx *ctx = NULL;
	hash_type hash;
	int ret = 0;

	(void)parsed_flags;

	CKINT(acvpproxy_convert(data->cipher, &hash));

	spec = hash_spec_get(hash);
	CKNULL_LOG(spec, -EINVAL, "Cannot find hash implementation\n");

	CKINT_LOG(alloc_buf(spec->hash, &data->mac),
			    "SHA buffer cannot be allocated\n");

	ctx = malloc(spec->ctx);
	CKNULL_LOG(ctx, -ENOMEM, "Cannot allocate hash context\n");

	spec->init(ctx);
	spec->update(ctx, data->msg.buf, data->msg.len);
	spec->finish(ctx, data->mac.buf);

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "hash");

out:
	if (ctx)
		free(ctx);
	return ret;
}

static struct sha_backend acvpproxy_sha =
{
	acvpproxy_sha_generate,   /* hash_generate */
};

ACVP_DEFINE_CONSTRUCTOR(acvpproxy_sha_backend)
static void acvpproxy_sha_backend(void)
{
	register_sha_impl(&acvpproxy_sha);
}

/************************************************
 * HMAC cipher interface functions
 ************************************************/
static int acvpproxy_mac_generate(struct hmac_data *data, flags_t parsed_flags)
{
	hash_type hash;
	int ret = 0;

	(void)parsed_flags;

	CKINT(acvpproxy_convert(data->cipher, &hash));

	ret = hmac(hash, data->key.buf, data->key.len,
		   data->msg.buf, data->msg.len,
		   &data->mac.buf, &data->mac.len);
	if (!ret) {
		logger(LOGGER_WARN, "Cannot generate HMAC\n");
		ret = EFAULT;
		goto out;
	}

	logger_binary(LOGGER_DEBUG, data->mac.buf, data->mac.len, "HMAC");

out:
	return ret;
}

static struct hmac_backend acvpproxy_mac =
{
	acvpproxy_mac_generate,
};

ACVP_DEFINE_CONSTRUCTOR(acvpproxy_mac_backend)
static void acvpproxy_mac_backend(void)
{
	register_hmac_impl(&acvpproxy_mac);
}
