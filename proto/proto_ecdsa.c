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
#include "ecdsa.pb-c.h"
#include "parser_ecdsa.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct ecdsa_backend *ecdsa_backend = NULL;

static int proto_ecdsa_keygen_tester(struct buffer *in, struct buffer *out,
				   flags_t parsed_flags)
{
	EcdsaKeygenDataMsg EcdsaKeygenDataMsg_send = ECDSA_KEYGEN_DATA_MSG__INIT;
	struct ecdsa_keygen_data data = { 0 };
	EcdsaKeygenDataMsg *EcdsaKeygenDataMsg_recv = NULL;
	int ret;

	CKNULL(ecdsa_backend, -EINVAL);
	CKNULL(ecdsa_backend->ecdsa_keygen, -EINVAL);

	EcdsaKeygenDataMsg_recv = ecdsa_keygen_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(EcdsaKeygenDataMsg_recv, -EBADMSG);

	data.cipher = EcdsaKeygenDataMsg_recv->cipher;

	CKINT(ecdsa_backend->ecdsa_keygen(&data, parsed_flags));

	EcdsaKeygenDataMsg_send.d.data = data.d.buf;
	EcdsaKeygenDataMsg_send.d.len = data.d.len;
	EcdsaKeygenDataMsg_send.qx.data = data.Qx.buf;
	EcdsaKeygenDataMsg_send.qx.len = data.Qx.len;
	EcdsaKeygenDataMsg_send.qy.data = data.Qy.buf;
	EcdsaKeygenDataMsg_send.qy.len = data.Qy.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ecdsa_keygen_data_msg__get_packed_size(&EcdsaKeygenDataMsg_send)));
	ecdsa_keygen_data_msg__pack(&EcdsaKeygenDataMsg_send, out->buf);

out:
	free_buf(&data.Qx);
	free_buf(&data.Qy);
	free_buf(&data.d);

	if (EcdsaKeygenDataMsg_recv)
		ecdsa_keygen_data_msg__free_unpacked(EcdsaKeygenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdsa_keygen =
{
	PB_ECDSA_KEYGEN,
	proto_ecdsa_keygen_tester,	/* process_req */
	NULL
};

static int proto_ecdsa_keygen_extra_tester(struct buffer *in,
					   struct buffer *out,
					   flags_t parsed_flags)
{
	EcdsaKeygenExtraDataMsg EcdsaKeygenExtraDataMsg_send =
		ECDSA_KEYGEN_EXTRA_DATA_MSG__INIT;
	struct ecdsa_keygen_extra_data data = { 0 };
	EcdsaKeygenExtraDataMsg *EcdsaKeygenExtraDataMsg_recv = NULL;
	int ret;

	CKNULL(ecdsa_backend, -EINVAL);
	CKNULL(ecdsa_backend->ecdsa_keygen_extra, -EINVAL);

	EcdsaKeygenExtraDataMsg_recv =
		ecdsa_keygen_extra_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EcdsaKeygenExtraDataMsg_recv, -EBADMSG);

	data.cipher = EcdsaKeygenExtraDataMsg_recv->cipher;

	CKINT(ecdsa_backend->ecdsa_keygen_extra(&data, parsed_flags));

	EcdsaKeygenExtraDataMsg_send.d.data = data.d.buf;
	EcdsaKeygenExtraDataMsg_send.d.len = data.d.len;
	EcdsaKeygenExtraDataMsg_send.qx.data = data.Qx.buf;
	EcdsaKeygenExtraDataMsg_send.qx.len = data.Qx.len;
	EcdsaKeygenExtraDataMsg_send.qy.data = data.Qy.buf;
	EcdsaKeygenExtraDataMsg_send.qy.len = data.Qy.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ecdsa_keygen_extra_data_msg__get_packed_size(
			&EcdsaKeygenExtraDataMsg_send)));
	ecdsa_keygen_extra_data_msg__pack(&EcdsaKeygenExtraDataMsg_send,
					  out->buf);

out:
	free_buf(&data.Qx);
	free_buf(&data.Qy);
	free_buf(&data.d);

	if (EcdsaKeygenExtraDataMsg_recv)
		ecdsa_keygen_extra_data_msg__free_unpacked(EcdsaKeygenExtraDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdsa_keygen_extra =
{
	PB_ECDSA_KEYGEN_EXTRA,
	proto_ecdsa_keygen_extra_tester,	/* process_req */
	NULL
};

static int proto_ecdsa_pkvver_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	EcdsaPkvverDataMsg EcdsaPkvverDataMsg_send =
		ECDSA_PKVVER_DATA_MSG__INIT;
	struct ecdsa_pkvver_data data = { 0 };
	EcdsaPkvverDataMsg *EcdsaPkvverDataMsg_recv = NULL;
	int ret;

	CKNULL(ecdsa_backend, -EINVAL);
	CKNULL(ecdsa_backend->ecdsa_pkvver, -EINVAL);

	EcdsaPkvverDataMsg_recv = ecdsa_pkvver_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(EcdsaPkvverDataMsg_recv, -EBADMSG);

	data.cipher = EcdsaPkvverDataMsg_recv->cipher;
	data.Qx.buf = EcdsaPkvverDataMsg_recv->qx.data;
	data.Qx.len = EcdsaPkvverDataMsg_recv->qx.len;
	data.Qy.buf = EcdsaPkvverDataMsg_recv->qy.data;
	data.Qy.len = EcdsaPkvverDataMsg_recv->qy.len;

	CKINT(ecdsa_backend->ecdsa_pkvver(&data, parsed_flags));

	EcdsaPkvverDataMsg_send.keyver_success = data.keyver_success;

	CKINT(proto_alloc_comm_buf(
		out,
		ecdsa_pkvver_data_msg__get_packed_size(&EcdsaPkvverDataMsg_send)));
	ecdsa_pkvver_data_msg__pack(&EcdsaPkvverDataMsg_send, out->buf);

out:
	if (EcdsaPkvverDataMsg_recv)
		ecdsa_pkvver_data_msg__free_unpacked(EcdsaPkvverDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdsa_pkvver =
{
	PB_ECDSA_PKVVER,
	proto_ecdsa_pkvver_tester,	/* process_req */
	NULL
};

struct proto_ecdsa_privkey {
	uint32_t ref;
	void *privkey;
};

static struct proto_ecdsa_privkey proto_ecdsa_privkey = { 0, NULL };

static int proto_ecdsa_siggen_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	EcdsaSiggenDataMsg EcdsaSiggenDataMsg_send = ECDSA_SIGGEN_DATA_MSG__INIT;
	struct ecdsa_siggen_data data = { 0 };
	EcdsaSiggenDataMsg *EcdsaSiggenDataMsg_recv = NULL;
	int ret;

	CKNULL(ecdsa_backend, -EINVAL);
	CKNULL(ecdsa_backend->ecdsa_siggen, -EINVAL);

	EcdsaSiggenDataMsg_recv =
		ecdsa_siggen_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EcdsaSiggenDataMsg_recv, -EBADMSG);

	if (EcdsaSiggenDataMsg_recv->privkey != proto_ecdsa_privkey.ref) {
		ret = -ENOKEY;
		goto out;
	}

	data.msg.buf = EcdsaSiggenDataMsg_recv->msg.data;
	data.msg.len = EcdsaSiggenDataMsg_recv->msg.len;
	data.Qx.buf = EcdsaSiggenDataMsg_recv->qx.data;
	data.Qx.len = EcdsaSiggenDataMsg_recv->qx.len;
	data.Qy.buf = EcdsaSiggenDataMsg_recv->qy.data;
	data.Qy.len = EcdsaSiggenDataMsg_recv->qy.len;
	data.component = EcdsaSiggenDataMsg_recv->component;
	data.cipher = EcdsaSiggenDataMsg_recv->cipher;
	data.privkey = proto_ecdsa_privkey.privkey;

	CKINT(ecdsa_backend->ecdsa_siggen(&data, parsed_flags));

	EcdsaSiggenDataMsg_send.qx.data = data.Qx.buf;
	EcdsaSiggenDataMsg_send.qx.len = data.Qx.len;
	EcdsaSiggenDataMsg_send.qy.data = data.Qy.buf;
	EcdsaSiggenDataMsg_send.qy.len = data.Qy.len;
	EcdsaSiggenDataMsg_send.r.data = data.R.buf;
	EcdsaSiggenDataMsg_send.r.len = data.R.len;
	EcdsaSiggenDataMsg_send.s.data = data.S.buf;
	EcdsaSiggenDataMsg_send.s.len = data.S.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ecdsa_siggen_data_msg__get_packed_size(
			&EcdsaSiggenDataMsg_send)));
	ecdsa_siggen_data_msg__pack(&EcdsaSiggenDataMsg_send, out->buf);

out:
	if (EcdsaSiggenDataMsg_recv->qx.data != data.Qx.buf)
		free_buf(&data.Qx);
	if (EcdsaSiggenDataMsg_recv->qy.data != data.Qy.buf)
		free_buf(&data.Qy);
	free_buf(&data.R);
	free_buf(&data.S);

	if (EcdsaSiggenDataMsg_recv)
		ecdsa_siggen_data_msg__free_unpacked(
			EcdsaSiggenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdsa_siggen =
{
	PB_ECDSA_SIGGEN,
	proto_ecdsa_siggen_tester,	/* process_req */
	NULL
};

static int proto_ecdsa_sigver_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	EcdsaSigverDataMsg EcdsaSigverDataMsg_send = ECDSA_SIGVER_DATA_MSG__INIT;
	struct ecdsa_sigver_data data = { 0 };
	EcdsaSigverDataMsg *EcdsaSigverDataMsg_recv = NULL;
	int ret;

	CKNULL(ecdsa_backend, -EINVAL);
	CKNULL(ecdsa_backend->ecdsa_sigver, -EINVAL);

	EcdsaSigverDataMsg_recv =
		ecdsa_sigver_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EcdsaSigverDataMsg_recv, -EBADMSG);

	data.msg.buf = EcdsaSigverDataMsg_recv->msg.data;
	data.msg.len = EcdsaSigverDataMsg_recv->msg.len;
	data.Qx.buf = EcdsaSigverDataMsg_recv->qx.data;
	data.Qx.len = EcdsaSigverDataMsg_recv->qx.len;
	data.Qy.buf = EcdsaSigverDataMsg_recv->qy.data;
	data.Qy.len = EcdsaSigverDataMsg_recv->qy.len;
	data.R.buf = EcdsaSigverDataMsg_recv->r.data;
	data.R.len = EcdsaSigverDataMsg_recv->r.len;
	data.S.buf = EcdsaSigverDataMsg_recv->s.data;
	data.S.len = EcdsaSigverDataMsg_recv->s.len;
	data.component = EcdsaSigverDataMsg_recv->component;
	data.cipher = EcdsaSigverDataMsg_recv->cipher;

	CKINT(ecdsa_backend->ecdsa_sigver(&data, parsed_flags));

	EcdsaSigverDataMsg_send.sigver_success = data.sigver_success;

	CKINT(proto_alloc_comm_buf(
		out,
		ecdsa_sigver_data_msg__get_packed_size(
			&EcdsaSigverDataMsg_send)));
	ecdsa_sigver_data_msg__pack(&EcdsaSigverDataMsg_send, out->buf);

out:
	/* not needed as covered below: free_buf(&data.mac); */

	if (EcdsaSigverDataMsg_recv)
		ecdsa_sigver_data_msg__free_unpacked(
			EcdsaSigverDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdsa_sigver =
{
	PB_ECDSA_SIGVER,
	proto_ecdsa_sigver_tester,	/* process_req */
	NULL
};

static int proto_ecdsa_keygen_en_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	EcdsaKeygenEnMsg EcdsaKeygenEnMsg_send = ECDSA_KEYGEN_EN_MSG__INIT;
	EcdsaKeygenEnMsg *EcdsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(qx)
	BUFFER_INIT(qy);
	static uint32_t ref = 1;
	int ret;

	(void)parsed_flags;

	CKNULL(ecdsa_backend, -EINVAL);
	CKNULL(ecdsa_backend->ecdsa_keygen_en, -EINVAL);

	EcdsaKeygenEnMsg_recv = ecdsa_keygen_en_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EcdsaKeygenEnMsg_recv, -EBADMSG);

	if (proto_ecdsa_privkey.privkey) {
		ret = -EEXIST;
		goto out;
	}

	CKINT(ecdsa_backend->ecdsa_keygen_en(EcdsaKeygenEnMsg_recv->curve,
					     &qx, &qy,
					     &proto_ecdsa_privkey.privkey));

	proto_ecdsa_privkey.ref = ref++;

	EcdsaKeygenEnMsg_send.qx.data = qx.buf;
	EcdsaKeygenEnMsg_send.qx.len = qx.len;
	EcdsaKeygenEnMsg_send.qy.data = qy.buf;
	EcdsaKeygenEnMsg_send.qy.len = qy.len;
	EcdsaKeygenEnMsg_send.privkey = proto_ecdsa_privkey.ref;

	CKINT(proto_alloc_comm_buf(
		out,
		ecdsa_keygen_en_msg__get_packed_size(&EcdsaKeygenEnMsg_send)));
	ecdsa_keygen_en_msg__pack(&EcdsaKeygenEnMsg_send, out->buf);

out:
	free_buf(&qx);
	free_buf(&qy);

	if (EcdsaKeygenEnMsg_recv)
		ecdsa_keygen_en_msg__free_unpacked(EcdsaKeygenEnMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdsa_keygen_en =
{
	PB_ECDSA_KEYGEN_EN,
	proto_ecdsa_keygen_en_tester,	/* process_req */
	NULL
};

static int proto_ecdsa_free_key_tester(struct buffer *in, struct buffer *out,
				       flags_t parsed_flags)
{
	EcdsaFreeKeyMsg EcdsaFreeKeyMsg_send = ECDSA_FREE_KEY_MSG__INIT;
	EcdsaFreeKeyMsg *EcdsaFreeKeyMsg_recv = NULL;
	int ret;

	(void)parsed_flags;

	CKNULL(ecdsa_backend, -EINVAL);
	CKNULL(ecdsa_backend->ecdsa_free_key, -EINVAL);

	EcdsaFreeKeyMsg_recv = ecdsa_free_key_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EcdsaFreeKeyMsg_recv, -EBADMSG);

	if (!proto_ecdsa_privkey.privkey ||
	    proto_ecdsa_privkey.ref != EcdsaFreeKeyMsg_recv->privkey) {
		ret = -ENOKEY;
		goto out;
	}

	ecdsa_backend->ecdsa_free_key(proto_ecdsa_privkey.privkey);
	proto_ecdsa_privkey.privkey = NULL;
	proto_ecdsa_privkey.ref = 0;

	CKINT(proto_alloc_comm_buf(
		out,
		ecdsa_free_key_msg__get_packed_size(&EcdsaFreeKeyMsg_send)));
	ecdsa_free_key_msg__pack(&EcdsaFreeKeyMsg_send, out->buf);

out:
	if (EcdsaFreeKeyMsg_recv)
		ecdsa_free_key_msg__free_unpacked(EcdsaFreeKeyMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdsa_free_key =
{
	PB_ECDSA_FREE_KEY,
	proto_ecdsa_free_key_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_ecdsa)
static void register_proto_ecdsa(void)
{
	proto_register_tester(&proto_ecdsa_keygen, "ECDSA Keygen");
	proto_register_tester(&proto_ecdsa_keygen_extra, "ECDSA Keygen Extra");
	proto_register_tester(&proto_ecdsa_pkvver, "ECDSA PKV Ver");
	proto_register_tester(&proto_ecdsa_siggen, "ECDSA Siggen");
	proto_register_tester(&proto_ecdsa_sigver, "ECDSA Sigver");
	proto_register_tester(&proto_ecdsa_keygen_en, "ECDSA Keygen En");
	proto_register_tester(&proto_ecdsa_free_key, "ECDSA Free Key");
}

void register_ecdsa_impl(struct ecdsa_backend *implementation)
{
	register_backend(ecdsa_backend, implementation, "ECDSA");
}
