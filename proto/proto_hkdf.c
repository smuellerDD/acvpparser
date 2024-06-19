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
#include "kda_hkdf.pb-c.h"
#include "parser_kda_hkdf.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct hkdf_backend *hkdf_backend = NULL;

static int proto_hkdf_tester(struct buffer *in, struct buffer *out,
			       flags_t parsed_flags)
{
	HkdfDataMsg HkdfDataMsg_send = HKDF_DATA_MSG__INIT;
	struct hkdf_data data = { 0 };
	HkdfDataMsg *HkdfDataMsg_recv = NULL;
	int ret;

	CKNULL(hkdf_backend, -EINVAL);
	CKNULL(hkdf_backend->hkdf, -EINVAL);

	HkdfDataMsg_recv = hkdf_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(HkdfDataMsg_recv, -EBADMSG);

	data.hash = HkdfDataMsg_recv->hash;
	data.dkmlen = HkdfDataMsg_recv->dkmlen;
	data.salt.buf = HkdfDataMsg_recv->salt.data;
	data.salt.len = HkdfDataMsg_recv->salt.len;
	data.z.buf = HkdfDataMsg_recv->z.data;
	data.z.len = HkdfDataMsg_recv->z.len;
	data.t.buf = HkdfDataMsg_recv->t.data;
	data.t.len = HkdfDataMsg_recv->t.len;
	data.info.buf = HkdfDataMsg_recv->info.data;
	data.info.len = HkdfDataMsg_recv->info.len;
	data.dkm.buf = HkdfDataMsg_recv->dkm.data;
	data.dkm.len = HkdfDataMsg_recv->dkm.len;

	CKINT(hkdf_backend->hkdf(&data, parsed_flags));

	HkdfDataMsg_send.validity_success = data.validity_success;
	HkdfDataMsg_send.dkm.data = data.dkm.buf;
	HkdfDataMsg_send.dkm.len = data.dkm.len;

	CKINT(proto_alloc_comm_buf(
		out, hkdf_data_msg__get_packed_size(&HkdfDataMsg_send)));
	hkdf_data_msg__pack(&HkdfDataMsg_send, out->buf);

out:
	if (HkdfDataMsg_recv && data.dkm.buf != HkdfDataMsg_recv->dkm.data)
		free_buf(&data.dkm);

	if (HkdfDataMsg_recv)
		hkdf_data_msg__free_unpacked(HkdfDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_hkdf =
{
	PB_HKDF,
	proto_hkdf_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_hkdf)
static void register_proto_hkdf(void)
{
	proto_register_tester(&proto_hkdf, "HKDF");
}

void register_hkdf_impl(struct hkdf_backend *implementation)
{
	register_backend(hkdf_backend, implementation, "HKDF");
}
