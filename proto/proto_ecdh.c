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
#include "ecdh.pb-c.h"
#include "parser_ecdh.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct ecdh_backend *ecdh_backend = NULL;

static int proto_ecdh_ss_tester(struct buffer *in, struct buffer *out,
			       flags_t parsed_flags)
{
	EcdhSsDataMsg EcdhSsDataMsg_send = ECDH_SS_DATA_MSG__INIT;
	struct ecdh_ss_data data = { 0 };
	EcdhSsDataMsg *EcdhSsDataMsg_recv = NULL;
	int ret;

	CKNULL(ecdh_backend, -EINVAL);
	CKNULL(ecdh_backend->ecdh_ss, -EINVAL);

	EcdhSsDataMsg_recv = ecdh_ss_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EcdhSsDataMsg_recv, -EBADMSG);

	data.cipher = EcdhSsDataMsg_recv->cipher;
	data.Qxrem.buf = EcdhSsDataMsg_recv->qxrem.data;
	data.Qxrem.len = EcdhSsDataMsg_recv->qxrem.len;
	data.Qyrem.buf = EcdhSsDataMsg_recv->qyrem.data;
	data.Qyrem.len = EcdhSsDataMsg_recv->qyrem.len;

	CKINT(ecdh_backend->ecdh_ss(&data, parsed_flags));

	EcdhSsDataMsg_send.qxloc.data = data.Qxloc.buf;
	EcdhSsDataMsg_send.qxloc.len = data.Qxloc.len;
	EcdhSsDataMsg_send.qyloc.data = data.Qyloc.buf;
	EcdhSsDataMsg_send.qyloc.len = data.Qyloc.len;
	EcdhSsDataMsg_send.hashzz.data = data.hashzz.buf;
	EcdhSsDataMsg_send.hashzz.len = data.hashzz.len;

	CKINT(proto_alloc_comm_buf(
		out, ecdh_ss_data_msg__get_packed_size(&EcdhSsDataMsg_send)));
	ecdh_ss_data_msg__pack(&EcdhSsDataMsg_send, out->buf);

out:
	free_buf(&data.Qxloc);
	free_buf(&data.Qyloc);
	free_buf(&data.hashzz);

	if (EcdhSsDataMsg_recv)
		ecdh_ss_data_msg__free_unpacked(EcdhSsDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdh_ss =
{
	PB_ECDH_SS,
	proto_ecdh_ss_tester,	/* process_req */
	NULL
};

static int proto_ecdh_ss_ver_tester(struct buffer *in, struct buffer *out,
			       flags_t parsed_flags)
{
	EcdhSsVerDataMsg EcdhSsVerDataMsg_send = ECDH_SS_VER_DATA_MSG__INIT;
	struct ecdh_ss_ver_data data = { 0 };
	EcdhSsVerDataMsg *EcdhSsVerDataMsg_recv = NULL;
	int ret;

	CKNULL(ecdh_backend, -EINVAL);
	CKNULL(ecdh_backend->ecdh_ss_ver, -EINVAL);

	EcdhSsVerDataMsg_recv = ecdh_ss_ver_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(EcdhSsVerDataMsg_recv, -EBADMSG);

	data.cipher = EcdhSsVerDataMsg_recv->cipher;
	data.Qxrem.buf = EcdhSsVerDataMsg_recv->qxrem.data;
	data.Qxrem.len = EcdhSsVerDataMsg_recv->qxrem.len;
	data.Qyrem.buf = EcdhSsVerDataMsg_recv->qyrem.data;
	data.Qyrem.len = EcdhSsVerDataMsg_recv->qyrem.len;
	data.privloc.buf = EcdhSsVerDataMsg_recv->privloc.data;
	data.privloc.len = EcdhSsVerDataMsg_recv->privloc.len;
	data.Qxloc.buf = EcdhSsVerDataMsg_recv->qxloc.data;
	data.Qxloc.len = EcdhSsVerDataMsg_recv->qxloc.len;
	data.Qyloc.buf = EcdhSsVerDataMsg_recv->qyloc.data;
	data.Qyloc.len = EcdhSsVerDataMsg_recv->qyloc.len;
	data.hashzz.buf = EcdhSsVerDataMsg_recv->hashzz.data;
	data.hashzz.len = EcdhSsVerDataMsg_recv->hashzz.len;

	CKINT(ecdh_backend->ecdh_ss_ver(&data, parsed_flags));

	EcdhSsVerDataMsg_send.validity_success = data.validity_success;

	CKINT(proto_alloc_comm_buf(
		out, ecdh_ss_ver_data_msg__get_packed_size(&EcdhSsVerDataMsg_send)));
	ecdh_ss_ver_data_msg__pack(&EcdhSsVerDataMsg_send, out->buf);

out:
	if (EcdhSsVerDataMsg_recv)
		ecdh_ss_ver_data_msg__free_unpacked(EcdhSsVerDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_ecdh_ss_ver =
{
	PB_ECDH_SS_VER,
	proto_ecdh_ss_ver_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_ecdh)
static void register_proto_ecdh(void)
{
	proto_register_tester(&proto_ecdh_ss, "ECDH SS");
	proto_register_tester(&proto_ecdh_ss_ver, "ECDH SS Ver");
}

void register_ecdh_impl(struct ecdh_backend *implementation)
{
	register_backend(ecdh_backend, implementation, "DRBG");
}
