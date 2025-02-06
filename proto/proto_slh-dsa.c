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
#include "slh-dsa.pb-c.h"
#include "parser_slh_dsa.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct slh_dsa_backend *slh_dsa_backend = NULL;

static int proto_slh_dsa_keygen_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	SlhDsaKeygenDataMsg SlhDsaKeygenDataMsg_send =
		SLH_DSA_KEYGEN_DATA_MSG__INIT;
	struct slh_dsa_keygen_data data = { 0 };
	SlhDsaKeygenDataMsg *SlhDsaKeygenDataMsg_recv = NULL;
	int ret;

	CKNULL(slh_dsa_backend, -EINVAL);
	CKNULL(slh_dsa_backend->slh_dsa_keygen, -EINVAL);

	SlhDsaKeygenDataMsg_recv = slh_dsa_keygen_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(SlhDsaKeygenDataMsg_recv, -EBADMSG);

	data.cipher = SlhDsaKeygenDataMsg_recv->cipher;
	data.sk_seed.buf = SlhDsaKeygenDataMsg_recv->sk_seed.data;
	data.sk_seed.len = SlhDsaKeygenDataMsg_recv->sk_seed.len;
	data.sk_prf.buf = SlhDsaKeygenDataMsg_recv->sk_prf.data;
	data.sk_prf.len = SlhDsaKeygenDataMsg_recv->sk_prf.len;
	data.pk_seed.buf = SlhDsaKeygenDataMsg_recv->pk_seed.data;
	data.pk_seed.len = SlhDsaKeygenDataMsg_recv->pk_seed.len;

	CKINT(slh_dsa_backend->slh_dsa_keygen(&data, parsed_flags));

	SlhDsaKeygenDataMsg_send.pk.data = data.pk.buf;
	SlhDsaKeygenDataMsg_send.pk.len = data.pk.len;
	SlhDsaKeygenDataMsg_send.sk.data = data.sk.buf;
	SlhDsaKeygenDataMsg_send.sk.len = data.sk.len;

	CKINT(proto_alloc_comm_buf(
		out,
		slh_dsa_keygen_data_msg__get_packed_size(&SlhDsaKeygenDataMsg_send)));
	slh_dsa_keygen_data_msg__pack(&SlhDsaKeygenDataMsg_send, out->buf);

out:
	free_buf(&data.pk);
	free_buf(&data.sk);

	if (SlhDsaKeygenDataMsg_recv)
		slh_dsa_keygen_data_msg__free_unpacked(SlhDsaKeygenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_slh_dsa_keygen =
{
	PB_SLH_DSA_KEYGEN,
	proto_slh_dsa_keygen_tester,	/* process_req */
	NULL
};

static int proto_slh_dsa_siggen_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	SlhDsaSiggenDataMsg SlhDsaSiggenDataMsg_send =
		SLH_DSA_SIGGEN_DATA_MSG__INIT;
	struct slh_dsa_siggen_data data = { 0 };
	SlhDsaSiggenDataMsg *SlhDsaSiggenDataMsg_recv = NULL;
	int ret;

	CKNULL(slh_dsa_backend, -EINVAL);
	CKNULL(slh_dsa_backend->slh_dsa_siggen, -EINVAL);

	SlhDsaSiggenDataMsg_recv =
		slh_dsa_siggen_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(SlhDsaSiggenDataMsg_recv, -EBADMSG);

	data.msg.buf = SlhDsaSiggenDataMsg_recv->msg.data;
	data.msg.len = SlhDsaSiggenDataMsg_recv->msg.len;
	data.rnd.buf = SlhDsaSiggenDataMsg_recv->rnd.data;
	data.rnd.len = SlhDsaSiggenDataMsg_recv->rnd.len;
	data.sk.buf = SlhDsaSiggenDataMsg_recv->sk.data;
	data.sk.len = SlhDsaSiggenDataMsg_recv->sk.len;
	data.context.buf = SlhDsaSiggenDataMsg_recv->context.data;
	data.context.len = SlhDsaSiggenDataMsg_recv->context.len;
	data.interface.buf = SlhDsaSiggenDataMsg_recv->interface.data;
	data.interface.len = SlhDsaSiggenDataMsg_recv->interface.len;
	data.cipher = SlhDsaSiggenDataMsg_recv->cipher;
	data.hashalg = SlhDsaSiggenDataMsg_recv->hashalg;

	CKINT(slh_dsa_backend->slh_dsa_siggen(&data, parsed_flags));

	SlhDsaSiggenDataMsg_send.sig.data = data.sig.buf;
	SlhDsaSiggenDataMsg_send.sig.len = data.sig.len;

	CKINT(proto_alloc_comm_buf(
		out,
		slh_dsa_siggen_data_msg__get_packed_size(
			&SlhDsaSiggenDataMsg_send)));
	slh_dsa_siggen_data_msg__pack(&SlhDsaSiggenDataMsg_send, out->buf);

out:
	free_buf(&data.sig);

	if (SlhDsaSiggenDataMsg_recv)
		slh_dsa_siggen_data_msg__free_unpacked(
			SlhDsaSiggenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_slh_dsa_siggen =
{
	PB_SLH_DSA_SIGGEN,
	proto_slh_dsa_siggen_tester,	/* process_req */
	NULL
};

static int proto_slh_dsa_sigver_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	SlhDsaSigverDataMsg SlhDsaSigverDataMsg_send = SLH_DSA_SIGVER_DATA_MSG__INIT;
	struct slh_dsa_sigver_data data = { 0 };
	SlhDsaSigverDataMsg *SlhDsaSigverDataMsg_recv = NULL;
	int ret;

	CKNULL(slh_dsa_backend, -EINVAL);
	CKNULL(slh_dsa_backend->slh_dsa_sigver, -EINVAL);

	SlhDsaSigverDataMsg_recv =
		slh_dsa_sigver_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(SlhDsaSigverDataMsg_recv, -EBADMSG);

	data.msg.buf = SlhDsaSigverDataMsg_recv->msg.data;
	data.msg.len = SlhDsaSigverDataMsg_recv->msg.len;
	data.sig.buf = SlhDsaSigverDataMsg_recv->sig.data;
	data.sig.len = SlhDsaSigverDataMsg_recv->sig.len;
	data.pk.buf = SlhDsaSigverDataMsg_recv->pk.data;
	data.pk.len = SlhDsaSigverDataMsg_recv->pk.len;
	data.context.buf = SlhDsaSigverDataMsg_recv->context.data;
	data.context.len = SlhDsaSigverDataMsg_recv->context.len;
	data.interface.buf = SlhDsaSigverDataMsg_recv->interface.data;
	data.interface.len = SlhDsaSigverDataMsg_recv->interface.len;
	data.cipher = SlhDsaSigverDataMsg_recv->cipher;
	data.hashalg = SlhDsaSigverDataMsg_recv->hashalg;

	CKINT(slh_dsa_backend->slh_dsa_sigver(&data, parsed_flags));

	SlhDsaSigverDataMsg_send.sigver_success = data.sigver_success;

	CKINT(proto_alloc_comm_buf(
		out,
		slh_dsa_sigver_data_msg__get_packed_size(
			&SlhDsaSigverDataMsg_send)));
	slh_dsa_sigver_data_msg__pack(&SlhDsaSigverDataMsg_send, out->buf);

out:
	if (SlhDsaSigverDataMsg_recv)
		slh_dsa_sigver_data_msg__free_unpacked(
			SlhDsaSigverDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_slh_dsa_sigver =
{
	PB_SLH_DSA_SIGVER,
	proto_slh_dsa_sigver_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_slh_dsa)
static void register_proto_slh_dsa(void)
{
	proto_register_tester(&proto_slh_dsa_keygen, "SLH_DSA Keygen");
	proto_register_tester(&proto_slh_dsa_siggen, "SLH_DSA Siggen");
	proto_register_tester(&proto_slh_dsa_sigver, "SLH_DSA Sigver");
}

void register_slh_dsa_impl(struct slh_dsa_backend *implementation)
{
	register_backend(slh_dsa_backend, implementation, "SLH_DSA");
}
