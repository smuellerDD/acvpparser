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
#include "ml-kem.pb-c.h"
#include "parser_ml_kem.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct ml_kem_backend *ml_kem_backend = NULL;

static int proto_ml_kem_keygen_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	MlKemKeygenDataMsg MlKemKeygenDataMsg_send =
		ML_KEM_KEYGEN_DATA_MSG__INIT;
	struct ml_kem_keygen_data data = { 0 };
	MlKemKeygenDataMsg *MlKemKeygenDataMsg_recv = NULL;
	int ret;

	CKNULL(ml_kem_backend, -EINVAL);
	CKNULL(ml_kem_backend->ml_kem_keygen, -EINVAL);

	MlKemKeygenDataMsg_recv = ml_kem_keygen_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(MlKemKeygenDataMsg_recv, -EBADMSG);

	data.cipher = MlKemKeygenDataMsg_recv->cipher;
	data.d.buf = MlKemKeygenDataMsg_recv->d.data;
	data.d.len = MlKemKeygenDataMsg_recv->d.len;
	data.z.buf = MlKemKeygenDataMsg_recv->z.data;
	data.z.len = MlKemKeygenDataMsg_recv->z.len;

	CKINT(ml_kem_backend->ml_kem_keygen(&data, parsed_flags));

	MlKemKeygenDataMsg_send.ek.data = data.ek.buf;
	MlKemKeygenDataMsg_send.ek.len = data.ek.len;
	MlKemKeygenDataMsg_send.dk.data = data.dk.buf;
	MlKemKeygenDataMsg_send.dk.len = data.dk.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_kem_keygen_data_msg__get_packed_size(&MlKemKeygenDataMsg_send)));
	ml_kem_keygen_data_msg__pack(&MlKemKeygenDataMsg_send, out->buf);

out:
	free_buf(&data.ek);
	free_buf(&data.dk);

	if (MlKemKeygenDataMsg_recv)
		ml_kem_keygen_data_msg__free_unpacked(MlKemKeygenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_kem_keygen =
{
	PB_ML_KEM_KEYGEN,
	proto_ml_kem_keygen_tester,	/* process_req */
	NULL
};

static int proto_ml_kem_encap_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	MlKemEncapDataMsg MlKemEncapDataMsg_send =
		ML_KEM_ENCAP_DATA_MSG__INIT;
	struct ml_kem_encapsulation_data data = { 0 };
	MlKemEncapDataMsg *MlKemEncapDataMsg_recv = NULL;
	int ret;

	CKNULL(ml_kem_backend, -EINVAL);
	CKNULL(ml_kem_backend->ml_kem_encapsulation, -EINVAL);

	MlKemEncapDataMsg_recv =
		ml_kem_encap_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(MlKemEncapDataMsg_recv, -EBADMSG);

	data.msg.buf = MlKemEncapDataMsg_recv->msg.data;
	data.msg.len = MlKemEncapDataMsg_recv->msg.len;
	data.ek.buf = MlKemEncapDataMsg_recv->ek.data;
	data.ek.len = MlKemEncapDataMsg_recv->ek.len;
	data.cipher = MlKemEncapDataMsg_recv->cipher;

	CKINT(ml_kem_backend->ml_kem_encapsulation(&data, parsed_flags));

	MlKemEncapDataMsg_send.c.data = data.c.buf;
	MlKemEncapDataMsg_send.c.len = data.c.len;
	MlKemEncapDataMsg_send.ss.data = data.ss.buf;
	MlKemEncapDataMsg_send.ss.len = data.ss.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_kem_encap_data_msg__get_packed_size(
			&MlKemEncapDataMsg_send)));
	ml_kem_encap_data_msg__pack(&MlKemEncapDataMsg_send, out->buf);

out:
	free_buf(&data.c);
	free_buf(&data.ss);

	if (MlKemEncapDataMsg_recv)
		ml_kem_encap_data_msg__free_unpacked(
			MlKemEncapDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_kem_encap =
{
	PB_ML_KEM_ENCAP,
	proto_ml_kem_encap_tester,	/* process_req */
	NULL
};

static int proto_ml_kem_decap_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	MlKemDecapDataMsg MlKemDecapDataMsg_send = ML_KEM_DECAP_DATA_MSG__INIT;
	struct ml_kem_decapsulation_data data = { 0 };
	MlKemDecapDataMsg *MlKemDecapDataMsg_recv = NULL;
	int ret;

	CKNULL(ml_kem_backend, -EINVAL);
	CKNULL(ml_kem_backend->ml_kem_decapsulation, -EINVAL);

	MlKemDecapDataMsg_recv =
		ml_kem_decap_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(MlKemDecapDataMsg_recv, -EBADMSG);

	data.c.buf = MlKemDecapDataMsg_recv->c.data;
	data.c.len = MlKemDecapDataMsg_recv->c.len;
	data.dk.buf = MlKemDecapDataMsg_recv->dk.data;
	data.dk.len = MlKemDecapDataMsg_recv->dk.len;
	data.cipher = MlKemDecapDataMsg_recv->cipher;

	CKINT(ml_kem_backend->ml_kem_decapsulation(&data, parsed_flags));

	MlKemDecapDataMsg_send.ss.data = data.ss.buf;
	MlKemDecapDataMsg_send.ss.len = data.ss.len;

	CKINT(proto_alloc_comm_buf(
		out,
		ml_kem_decap_data_msg__get_packed_size(
			&MlKemDecapDataMsg_send)));
	ml_kem_decap_data_msg__pack(&MlKemDecapDataMsg_send, out->buf);

out:
	free_buf(&data.ss);

	if (MlKemDecapDataMsg_recv)
		ml_kem_decap_data_msg__free_unpacked(
			MlKemDecapDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ml_kem_decap =
{
	PB_ML_KEM_DECAP,
	proto_ml_kem_decap_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_ml_kem)
static void register_proto_ml_kem(void)
{
	proto_register_tester(&proto_ml_kem_keygen, "ML_KEM Keygen");
	proto_register_tester(&proto_ml_kem_encap, "ML_KEM Encap");
	proto_register_tester(&proto_ml_kem_decap, "ML_KEM Decap");
}

void register_ml_kem_impl(struct ml_kem_backend *implementation)
{
	register_backend(ml_kem_backend, implementation, "ML_KEM");
}
