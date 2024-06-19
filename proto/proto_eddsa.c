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

#include "frontend_headers.h"

#include "constructor.h"
#include "eddsa.pb-c.h"
#include "parser_eddsa.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct eddsa_backend *eddsa_backend = NULL;

static int proto_eddsa_keygen_tester(struct buffer *in, struct buffer *out,
				   flags_t parsed_flags)
{
	EddsaKeygenDataMsg EddsaKeygenDataMsg_send =
		EDDSA_KEYGEN_DATA_MSG__INIT;
	struct eddsa_keygen_data data = { 0 };
	EddsaKeygenDataMsg *EddsaKeygenDataMsg_recv = NULL;
	int ret;

	CKNULL(eddsa_backend, -EINVAL);
	CKNULL(eddsa_backend->eddsa_keygen, -EINVAL);

	EddsaKeygenDataMsg_recv = eddsa_keygen_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(EddsaKeygenDataMsg_recv, -EBADMSG);

	data.cipher = EddsaKeygenDataMsg_recv->cipher;

	CKINT(eddsa_backend->eddsa_keygen(&data, parsed_flags));

	EddsaKeygenDataMsg_send.d.data = data.d.buf;
	EddsaKeygenDataMsg_send.d.len = data.d.len;
	EddsaKeygenDataMsg_send.q.data = data.q.buf;
	EddsaKeygenDataMsg_send.q.len = data.q.len;

	CKINT(proto_alloc_comm_buf(
		out,
		eddsa_keygen_data_msg__get_packed_size(&EddsaKeygenDataMsg_send)));
	eddsa_keygen_data_msg__pack(&EddsaKeygenDataMsg_send, out->buf);

out:
	free_buf(&data.q);
	free_buf(&data.d);

	if (EddsaKeygenDataMsg_recv)
		eddsa_keygen_data_msg__free_unpacked(EddsaKeygenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_eddsa_keygen =
{
	PB_EDDSA_KEYGEN,
	proto_eddsa_keygen_tester,	/* process_req */
	NULL
};

static int proto_eddsa_keyver_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	EddsaKeyverDataMsg EddsaKeyverDataMsg_send =
		EDDSA_KEYVER_DATA_MSG__INIT;
	struct eddsa_keyver_data data = { 0 };
	EddsaKeyverDataMsg *EddsaKeyverDataMsg_recv = NULL;
	int ret;

	CKNULL(eddsa_backend, -EINVAL);
	CKNULL(eddsa_backend->eddsa_keyver, -EINVAL);

	EddsaKeyverDataMsg_recv = eddsa_keyver_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(EddsaKeyverDataMsg_recv, -EBADMSG);

	data.cipher = EddsaKeyverDataMsg_recv->cipher;
	data.q.buf = EddsaKeyverDataMsg_recv->q.data;
	data.q.len = EddsaKeyverDataMsg_recv->q.len;

	CKINT(eddsa_backend->eddsa_keyver(&data, parsed_flags));

	EddsaKeyverDataMsg_send.keyver_success = data.keyver_success;

	CKINT(proto_alloc_comm_buf(
		out,
		eddsa_keyver_data_msg__get_packed_size(&EddsaKeyverDataMsg_send)));
	eddsa_keyver_data_msg__pack(&EddsaKeyverDataMsg_send, out->buf);

out:
	if (EddsaKeyverDataMsg_recv)
		eddsa_keyver_data_msg__free_unpacked(EddsaKeyverDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_eddsa_keyver =
{
	PB_EDDSA_KEYVER,
	proto_eddsa_keyver_tester,	/* process_req */
	NULL
};

struct proto_eddsa_privkey {
	uint32_t ref;
	void *privkey;
};

static struct proto_eddsa_privkey proto_eddsa_privkey = { 0, NULL };

static int proto_eddsa_siggen_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	EddsaSiggenDataMsg EddsaSiggenDataMsg_send =
		EDDSA_SIGGEN_DATA_MSG__INIT;
	struct eddsa_siggen_data data = { 0 };
	EddsaSiggenDataMsg *EddsaSiggenDataMsg_recv = NULL;
	int ret;

	CKNULL(eddsa_backend, -EINVAL);
	CKNULL(eddsa_backend->eddsa_siggen, -EINVAL);

	EddsaSiggenDataMsg_recv =
		eddsa_siggen_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EddsaSiggenDataMsg_recv, -EBADMSG);

	if (EddsaSiggenDataMsg_recv->privkey != proto_eddsa_privkey.ref) {
		ret = -ENOKEY;
		goto out;
	}

	data.msg.buf = EddsaSiggenDataMsg_recv->msg.data;
	data.msg.len = EddsaSiggenDataMsg_recv->msg.len;
	data.context.buf = EddsaSiggenDataMsg_recv->context.data;
	data.context.len = EddsaSiggenDataMsg_recv->context.len;
	data.cipher = EddsaSiggenDataMsg_recv->cipher;
	data.prehash = EddsaSiggenDataMsg_recv->prehash;
	data.privkey = proto_eddsa_privkey.privkey;

	CKINT(eddsa_backend->eddsa_siggen(&data, parsed_flags));

	EddsaSiggenDataMsg_send.signature.data = data.signature.buf;
	EddsaSiggenDataMsg_send.signature.len = data.signature.len;

	CKINT(proto_alloc_comm_buf(
		out,
		eddsa_siggen_data_msg__get_packed_size(
			&EddsaSiggenDataMsg_send)));
	eddsa_siggen_data_msg__pack(&EddsaSiggenDataMsg_send, out->buf);

out:
	free_buf(&data.signature);

	if (EddsaSiggenDataMsg_recv)
		eddsa_siggen_data_msg__free_unpacked(
			EddsaSiggenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_eddsa_siggen =
{
	PB_EDDSA_SIGGEN,
	proto_eddsa_siggen_tester,	/* process_req */
	NULL
};

static int proto_eddsa_sigver_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	EddsaSigverDataMsg EddsaSigverDataMsg_send = EDDSA_SIGVER_DATA_MSG__INIT;
	struct eddsa_sigver_data data = { 0 };
	EddsaSigverDataMsg *EddsaSigverDataMsg_recv = NULL;
	int ret;

	CKNULL(eddsa_backend, -EINVAL);
	CKNULL(eddsa_backend->eddsa_sigver, -EINVAL);

	EddsaSigverDataMsg_recv =
		eddsa_sigver_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EddsaSigverDataMsg_recv, -EBADMSG);

	data.msg.buf = EddsaSigverDataMsg_recv->msg.data;
	data.msg.len = EddsaSigverDataMsg_recv->msg.len;
	data.q.buf = EddsaSigverDataMsg_recv->q.data;
	data.q.len = EddsaSigverDataMsg_recv->q.len;
	data.signature.buf = EddsaSigverDataMsg_recv->signature.data;
	data.signature.len = EddsaSigverDataMsg_recv->signature.len;
	data.cipher = EddsaSigverDataMsg_recv->cipher;
	data.prehash = EddsaSigverDataMsg_recv->prehash;

	CKINT(eddsa_backend->eddsa_sigver(&data, parsed_flags));

	EddsaSigverDataMsg_send.sigver_success = data.sigver_success;

	CKINT(proto_alloc_comm_buf(
		out,
		eddsa_sigver_data_msg__get_packed_size(
			&EddsaSigverDataMsg_send)));
	eddsa_sigver_data_msg__pack(&EddsaSigverDataMsg_send, out->buf);

out:
	/* not needed as covered below: free_buf(&data.mac); */

	if (EddsaSigverDataMsg_recv)
		eddsa_sigver_data_msg__free_unpacked(
			EddsaSigverDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_eddsa_sigver =
{
	PB_EDDSA_SIGVER,
	proto_eddsa_sigver_tester,	/* process_req */
	NULL
};

static int proto_eddsa_keygen_en_tester(struct buffer *in, struct buffer *out,
					flags_t parsed_flags)
{
	EddsaKeygenEnMsg EddsaKeygenEnMsg_send = EDDSA_KEYGEN_EN_MSG__INIT;
	EddsaKeygenEnMsg *EddsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(qbuf)
	static uint32_t ref = 1;
	int ret;

	(void)parsed_flags;

	CKNULL(eddsa_backend, -EINVAL);
	CKNULL(eddsa_backend->eddsa_keygen_en, -EINVAL);

	EddsaKeygenEnMsg_recv = eddsa_keygen_en_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EddsaKeygenEnMsg_recv, -EBADMSG);

	if (proto_eddsa_privkey.privkey) {
		ret = -EEXIST;
		goto out;
	}

	CKINT(eddsa_backend->eddsa_keygen_en(&qbuf,
					     EddsaKeygenEnMsg_recv->curve,
					     &proto_eddsa_privkey.privkey));

	proto_eddsa_privkey.ref = ref++;

	EddsaKeygenEnMsg_send.qbuf.data = qbuf.buf;
	EddsaKeygenEnMsg_send.qbuf.len = qbuf.len;
	EddsaKeygenEnMsg_send.privkey = proto_eddsa_privkey.ref;

	CKINT(proto_alloc_comm_buf(
		out,
		eddsa_keygen_en_msg__get_packed_size(&EddsaKeygenEnMsg_send)));
	eddsa_keygen_en_msg__pack(&EddsaKeygenEnMsg_send, out->buf);

out:
	free_buf(&qbuf);

	if (EddsaKeygenEnMsg_recv)
		eddsa_keygen_en_msg__free_unpacked(EddsaKeygenEnMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_eddsa_keygen_en =
{
	PB_EDDSA_KEYGEN_EN,
	proto_eddsa_keygen_en_tester,	/* process_req */
	NULL
};

static int proto_eddsa_free_key_tester(struct buffer *in, struct buffer *out,
				       flags_t parsed_flags)
{
	EddsaFreeKeyMsg EddsaFreeKeyMsg_send = EDDSA_FREE_KEY_MSG__INIT;
	EddsaFreeKeyMsg *EddsaFreeKeyMsg_recv = NULL;
	int ret;

	(void)parsed_flags;

	CKNULL(eddsa_backend, -EINVAL);
	CKNULL(eddsa_backend->eddsa_free_key, -EINVAL);

	EddsaFreeKeyMsg_recv = eddsa_free_key_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EddsaFreeKeyMsg_recv, -EBADMSG);

	if (!proto_eddsa_privkey.privkey ||
	    proto_eddsa_privkey.ref != EddsaFreeKeyMsg_recv->privkey) {
		ret = -ENOKEY;
		goto out;
	}

	eddsa_backend->eddsa_free_key(proto_eddsa_privkey.privkey);
	proto_eddsa_privkey.privkey = NULL;
	proto_eddsa_privkey.ref = 0;

	CKINT(proto_alloc_comm_buf(
		out,
		eddsa_free_key_msg__get_packed_size(&EddsaFreeKeyMsg_send)));
	eddsa_free_key_msg__pack(&EddsaFreeKeyMsg_send, out->buf);

out:
	if (EddsaFreeKeyMsg_recv)
		eddsa_free_key_msg__free_unpacked(EddsaFreeKeyMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_eddsa_free_key =
{
	PB_EDDSA_FREE_KEY,
	proto_eddsa_free_key_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_eddsa)
static void register_proto_eddsa(void)
{
	proto_register_tester(&proto_eddsa_keygen, "EDDSA Keygen");
	proto_register_tester(&proto_eddsa_keyver, "EDDSA PKV Ver");
	proto_register_tester(&proto_eddsa_siggen, "EDDSA Siggen");
	proto_register_tester(&proto_eddsa_sigver, "EDDSA Sigver");
	proto_register_tester(&proto_eddsa_keygen_en, "EDDSA Keygen En");
	proto_register_tester(&proto_eddsa_free_key, "EDDSA Free Key");
}

void register_eddsa_impl(struct eddsa_backend *implementation)
{
	register_backend(eddsa_backend, implementation, "EDDSA");
}
