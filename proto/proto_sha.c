/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "frontend_headers.h"

#include "cipher_definitions.h"
#include "constructor.h"
#include "sha.pb-c.h"
#include "parser_sha.h"
#include "parser_sha_mct_helper.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct sha_backend *sha_backend = NULL;

static int _proto_sha_tester(struct buffer *in, struct buffer *out,
			     flags_t parsed_flags, int mct)
{
	ShaDataMsg ShaDataMsg_send = SHA_DATA_MSG__INIT;
	struct sha_data data = { 0 };
	ShaDataMsg *ShaDataMsg_recv = NULL;
	int ret;

	CKNULL(sha_backend, -EINVAL);

	ShaDataMsg_recv = sha_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(ShaDataMsg_recv, -EBADMSG);

	data.msg.buf = ShaDataMsg_recv->msg.data;
	data.msg.len = ShaDataMsg_recv->msg.len;
	data.bitlen = ShaDataMsg_recv->bitlen;
	data.ldt_expansion_size = ShaDataMsg_recv->ldt_expansion_size;
	data.outlen = ShaDataMsg_recv->outlen;
	data.minoutlen = ShaDataMsg_recv->minoutlen;
	data.maxoutlen = ShaDataMsg_recv->maxoutlen;
	data.cipher = ShaDataMsg_recv->cipher;

	if (mct) {
		if (sha_backend->hash_mct_inner_loop) {
			CKINT(sha_backend->hash_mct_inner_loop(&data,
							       parsed_flags));
		} else {
			CKNULL(sha_backend->hash_generate, -EINVAL);

			switch (data.cipher & (ACVP_HASHMASK |
					       ACVP_SHAKEMASK)) {
			case ACVP_SHA3_224:
			case ACVP_SHA3_256:
			case ACVP_SHA3_384:
			case ACVP_SHA3_512:
				CKINT(parser_sha3_inner_loop(
					&data, parsed_flags,
					sha_backend->hash_generate));
				break;

			case ACVP_SHAKE128:
			case ACVP_SHAKE256:
				CKINT(parser_shake_inner_loop(
					&data, parsed_flags,
					sha_backend->hash_generate));
				break;

			default:
				CKINT(parser_sha2_inner_loop(
					&data, parsed_flags,
					sha_backend->hash_generate));
				break;
			}
		}
	} else {
		CKNULL(sha_backend->hash_generate, -EINVAL);
		CKINT(sha_backend->hash_generate(&data, parsed_flags));
	}

	ShaDataMsg_send.mac.data = data.mac.buf;
	ShaDataMsg_send.mac.len = data.mac.len;
	ShaDataMsg_send.outlen = data.outlen;

	CKINT(proto_alloc_comm_buf(
		out, sha_data_msg__get_packed_size(&ShaDataMsg_send)));
	sha_data_msg__pack(&ShaDataMsg_send, out->buf);

out:
	free_buf(&data.mac);

	if (ShaDataMsg_recv)
		sha_data_msg__free_unpacked(ShaDataMsg_recv, NULL);

	return ret;
}

static int proto_sha_tester(struct buffer *in, struct buffer *out,
			    flags_t parsed_flags)
{
	return _proto_sha_tester(in, out, parsed_flags, 0);
}

static struct proto_tester proto_sha =
{
	PB_SHA,
	proto_sha_tester,	/* process_req */
	NULL
};

static int proto_sha_mct_inner_loop_tester(struct buffer *in,
					   struct buffer *out,
					   flags_t parsed_flags)
{
	return _proto_sha_tester(in, out, parsed_flags, 1);
}

static struct proto_tester proto_sha_mct_inner_loop =
{
	PB_SHA_MCP_INNER_LOOP,
	proto_sha_mct_inner_loop_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_sha)
static void register_proto_sha(void)
{
	proto_register_tester(&proto_sha, "SHA");
	proto_register_tester(&proto_sha_mct_inner_loop, "SHA Inner Loop");
}

void register_sha_impl(struct sha_backend *implementation)
{
	register_backend(sha_backend, implementation, "SHA");
}
