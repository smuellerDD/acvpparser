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
#include "ml-dsa.pb-c.h"
#include "parser_ml_dsa.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct ml_dsa_backend *ml_dsa_backend = NULL;

static int proto_ml_dsa_keygen_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	MlDsaKeygenDataMsg MlDsaKeygenDataMsg_send =
		ML_DSA_KEYGEN_DATA_MSG__INIT;
	struct ml_dsa_keygen_data data = { 0 };
	MlDsaKeygenDataMsg *MlDsaKeygenDataMsg_recv = NULL;
	int ret;

	CKNULL(ml_dsa_backend, -EINVAL);
	CKNULL(ml_dsa_backend->ml_dsa_keygen, -EINVAL);

	MlDsaKeygenDataMsg_recv = ml_dsa_keygen_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(MlDsaKeygenDataMsg_recv, -EBADMSG);

	data.cipher = MlDsaKeygenDataMsg_recv->cipher;
	data.seed.buf = MlDsaKeygenDataMsg_recv->seed.data;
	data.seed.len = MlDsaKeygenDataMsg_recv->seed.len;

	CKINT(ml_dsa_backend->ml_dsa_keygen(&data, parsed_flags));

	MlDsaKeygenDataMsg_send.pk.data = data.pk.buf;
	MlDsaKeygenDataMsg_send.pk.len = data.pk.len;
	MlDsaKeygenDataMsg_send.sk.data = data.sk.buf;
	MlDsaKeygenDataMsg_send.sk.len = data.sk.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_dsa_keygen_data_msg__get_packed_size(&MlDsaKeygenDataMsg_send)));
	ml_dsa_keygen_data_msg__pack(&MlDsaKeygenDataMsg_send, out->buf);

out:
	free_buf(&data.pk);
	free_buf(&data.sk);

	if (MlDsaKeygenDataMsg_recv)
		ml_dsa_keygen_data_msg__free_unpacked(MlDsaKeygenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_dsa_keygen =
{
	PB_ML_DSA_KEYGEN,
	proto_ml_dsa_keygen_tester,	/* process_req */
	NULL
};

struct proto_ml_dsa_privkey {
	uint32_t ref;
	void *privkey;
};

static struct proto_ml_dsa_privkey proto_ml_dsa_privkey = { 0, NULL };

static int proto_ml_dsa_siggen_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	MlDsaSiggenDataMsg MlDsaSiggenDataMsg_send =
		ML_DSA_SIGGEN_DATA_MSG__INIT;
	struct ml_dsa_siggen_data data = { 0 };
	MlDsaSiggenDataMsg *MlDsaSiggenDataMsg_recv = NULL;
	int ret;

	CKNULL(ml_dsa_backend, -EINVAL);
	CKNULL(ml_dsa_backend->ml_dsa_siggen, -EINVAL);

	MlDsaSiggenDataMsg_recv =
		ml_dsa_siggen_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(MlDsaSiggenDataMsg_recv, -EBADMSG);

	if (MlDsaSiggenDataMsg_recv->privkey != proto_ml_dsa_privkey.ref) {
		ret = -ENOKEY;
		goto out;
	}

	data.msg.buf = MlDsaSiggenDataMsg_recv->msg.data;
	data.msg.len = MlDsaSiggenDataMsg_recv->msg.len;
	data.mu.buf = MlDsaSiggenDataMsg_recv->mu.data;
	data.mu.len = MlDsaSiggenDataMsg_recv->mu.len;
	data.rnd.buf = MlDsaSiggenDataMsg_recv->rnd.data;
	data.rnd.len = MlDsaSiggenDataMsg_recv->rnd.len;
	data.sk.buf = MlDsaSiggenDataMsg_recv->sk.data;
	data.sk.len = MlDsaSiggenDataMsg_recv->sk.len;
	data.context.buf = MlDsaSiggenDataMsg_recv->context.data;
	data.context.len = MlDsaSiggenDataMsg_recv->context.len;
	data.interface.buf = MlDsaSiggenDataMsg_recv->interface.data;
	data.interface.len = MlDsaSiggenDataMsg_recv->interface.len;
	data.cipher = MlDsaSiggenDataMsg_recv->cipher;
	data.hashalg = MlDsaSiggenDataMsg_recv->hashalg;
	data.privkey = proto_ml_dsa_privkey.privkey;

	CKINT(ml_dsa_backend->ml_dsa_siggen(&data, parsed_flags));

	MlDsaSiggenDataMsg_send.sig.data = data.sig.buf;
	MlDsaSiggenDataMsg_send.sig.len = data.sig.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_dsa_siggen_data_msg__get_packed_size(
			&MlDsaSiggenDataMsg_send)));
	ml_dsa_siggen_data_msg__pack(&MlDsaSiggenDataMsg_send, out->buf);

out:
	free_buf(&data.sig);

	if (MlDsaSiggenDataMsg_recv)
		ml_dsa_siggen_data_msg__free_unpacked(
			MlDsaSiggenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_dsa_siggen =
{
	PB_ML_DSA_SIGGEN,
	proto_ml_dsa_siggen_tester,	/* process_req */
	NULL
};

static int proto_ml_dsa_sigver_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	MlDsaSigverDataMsg MlDsaSigverDataMsg_send = ML_DSA_SIGVER_DATA_MSG__INIT;
	struct ml_dsa_sigver_data data = { 0 };
	MlDsaSigverDataMsg *MlDsaSigverDataMsg_recv = NULL;
	int ret;

	CKNULL(ml_dsa_backend, -EINVAL);
	CKNULL(ml_dsa_backend->ml_dsa_sigver, -EINVAL);

	MlDsaSigverDataMsg_recv =
		ml_dsa_sigver_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(MlDsaSigverDataMsg_recv, -EBADMSG);

	data.msg.buf = MlDsaSigverDataMsg_recv->msg.data;
	data.msg.len = MlDsaSigverDataMsg_recv->msg.len;
	data.mu.buf = MlDsaSigverDataMsg_recv->mu.data;
	data.mu.len = MlDsaSigverDataMsg_recv->mu.len;
	data.sig.buf = MlDsaSigverDataMsg_recv->sig.data;
	data.sig.len = MlDsaSigverDataMsg_recv->sig.len;
	data.pk.buf = MlDsaSigverDataMsg_recv->pk.data;
	data.pk.len = MlDsaSigverDataMsg_recv->pk.len;
	data.context.buf = MlDsaSigverDataMsg_recv->context.data;
	data.context.len = MlDsaSigverDataMsg_recv->context.len;
	data.interface.buf = MlDsaSigverDataMsg_recv->interface.data;
	data.interface.len = MlDsaSigverDataMsg_recv->interface.len;
	data.cipher = MlDsaSigverDataMsg_recv->cipher;
	data.hashalg = MlDsaSigverDataMsg_recv->hashalg;

	CKINT(ml_dsa_backend->ml_dsa_sigver(&data, parsed_flags));

	MlDsaSigverDataMsg_send.sigver_success = data.sigver_success;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_dsa_sigver_data_msg__get_packed_size(
			&MlDsaSigverDataMsg_send)));
	ml_dsa_sigver_data_msg__pack(&MlDsaSigverDataMsg_send, out->buf);

out:
	if (MlDsaSigverDataMsg_recv)
		ml_dsa_sigver_data_msg__free_unpacked(
			MlDsaSigverDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_dsa_sigver =
{
	PB_ML_DSA_SIGVER,
	proto_ml_dsa_sigver_tester,	/* process_req */
	NULL
};

static int proto_ml_dsa_keygen_en_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	MlDsaKeygenEnMsg MlDsaKeygenEnMsg_send = ML_DSA_KEYGEN_EN_MSG__INIT;
	MlDsaKeygenEnMsg *MlDsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(pk)
	static uint32_t ref = 1;
	int ret;

	(void)parsed_flags;

	CKNULL(ml_dsa_backend, -EINVAL);
	CKNULL(ml_dsa_backend->ml_dsa_keygen_en, -EINVAL);

	MlDsaKeygenEnMsg_recv = ml_dsa_keygen_en_msg__unpack(NULL, in->len,
							     in->buf);
	CKNULL(MlDsaKeygenEnMsg_recv, -EBADMSG);

	if (proto_ml_dsa_privkey.privkey) {
		ret = -EEXIST;
		goto out;
	}

	CKINT(ml_dsa_backend->ml_dsa_keygen_en(MlDsaKeygenEnMsg_recv->cipher,
					       &pk,
					       &proto_ml_dsa_privkey.privkey));

	proto_ml_dsa_privkey.ref = ref++;

	MlDsaKeygenEnMsg_send.pk.data = pk.buf;
	MlDsaKeygenEnMsg_send.pk.len = pk.len;
	MlDsaKeygenEnMsg_send.privkey = proto_ml_dsa_privkey.ref;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_dsa_keygen_en_msg__get_packed_size(&MlDsaKeygenEnMsg_send)));
	ml_dsa_keygen_en_msg__pack(&MlDsaKeygenEnMsg_send, out->buf);

out:
	free_buf(&pk);

	if (MlDsaKeygenEnMsg_recv)
		ml_dsa_keygen_en_msg__free_unpacked(MlDsaKeygenEnMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_dsa_keygen_en =
{
	PB_ML_DSA_KEYGEN_EN,
	proto_ml_dsa_keygen_en_tester,	/* process_req */
	NULL
};

static int proto_ml_dsa_free_key_tester(struct buffer *in, struct buffer *out,
				       flags_t parsed_flags)
{
	MlDsaFreeKeyMsg MlDsaFreeKeyMsg_send = ML_DSA_FREE_KEY_MSG__INIT;
	MlDsaFreeKeyMsg *MlDsaFreeKeyMsg_recv = NULL;
	int ret;

	(void)parsed_flags;

	CKNULL(ml_dsa_backend, -EINVAL);
	CKNULL(ml_dsa_backend->ml_dsa_free_key, -EINVAL);

	MlDsaFreeKeyMsg_recv = ml_dsa_free_key_msg__unpack(NULL, in->len, in->buf);
	CKNULL(MlDsaFreeKeyMsg_recv, -EBADMSG);

	if (!proto_ml_dsa_privkey.privkey ||
	    proto_ml_dsa_privkey.ref != MlDsaFreeKeyMsg_recv->privkey) {
		ret = -ENOKEY;
		goto out;
	}

	ml_dsa_backend->ml_dsa_free_key(proto_ml_dsa_privkey.privkey);
	proto_ml_dsa_privkey.privkey = NULL;
	proto_ml_dsa_privkey.ref = 0;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_dsa_free_key_msg__get_packed_size(&MlDsaFreeKeyMsg_send)));
	ml_dsa_free_key_msg__pack(&MlDsaFreeKeyMsg_send, out->buf);

out:
	if (MlDsaFreeKeyMsg_recv)
		ml_dsa_free_key_msg__free_unpacked(MlDsaFreeKeyMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_dsa_free_key =
{
	PB_ML_DSA_FREE_KEY,
	proto_ml_dsa_free_key_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_ml_dsa)
static void register_proto_ml_dsa(void)
{
	proto_register_tester(&proto_ml_dsa_keygen, "ML_DSA Keygen");
	proto_register_tester(&proto_ml_dsa_siggen, "ML_DSA Siggen");
	proto_register_tester(&proto_ml_dsa_sigver, "ML_DSA Sigver");
	proto_register_tester(&proto_ml_dsa_keygen_en, "ML_DSA Keygen En");
	proto_register_tester(&proto_ml_dsa_free_key, "ML_DSA Free Key");
}

void register_ml_dsa_impl(struct ml_dsa_backend *implementation)
{
	register_backend(ml_dsa_backend, implementation, "ML_DSA");
}
