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
#include "cshake.pb-c.h"
#include "parser_cshake.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct cshake_backend *cshake_backend = NULL;

static int proto_cshake_tester(struct buffer *in, struct buffer *out,
			       flags_t parsed_flags)
{
	CshakeDataMsg CshakeDataMsg_send = CSHAKE_DATA_MSG__INIT;
	struct cshake_data data = { 0 };
	CshakeDataMsg *CshakeDataMsg_recv = NULL;
	int ret;

	CKNULL(cshake_backend, -EINVAL);
	CKNULL(cshake_backend->cshake_generate, -EINVAL);

	CshakeDataMsg_recv = cshake_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(CshakeDataMsg_recv, -EBADMSG);

	data.cipher = CshakeDataMsg_recv->cipher;
	data.msg.buf = CshakeDataMsg_recv->msg.data;
	data.msg.len = CshakeDataMsg_recv->msg.len;
	data.bitlen = CshakeDataMsg_recv->bitlen;
	data.outlen = CshakeDataMsg_recv->outlen;
	data.minoutlen = CshakeDataMsg_recv->minoutlen;
	data.maxoutlen = CshakeDataMsg_recv->maxoutlen;
	data.function_name.buf = CshakeDataMsg_recv->function_name.data;
	data.function_name.len = CshakeDataMsg_recv->function_name.len;
	data.customization.buf = CshakeDataMsg_recv->customization.data;
	data.customization.len = CshakeDataMsg_recv->customization.len;

	CKINT(cshake_backend->cshake_generate(&data, parsed_flags));

	CshakeDataMsg_send.mac.data = data.mac.buf;
	CshakeDataMsg_send.mac.len = data.mac.len;

	CKINT(proto_alloc_comm_buf(
		out, cshake_data_msg__get_packed_size(&CshakeDataMsg_send)));
	cshake_data_msg__pack(&CshakeDataMsg_send, out->buf);

out:
	free_buf(&data.mac);

	if (CshakeDataMsg_recv)
		cshake_data_msg__free_unpacked(CshakeDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_cshake =
{
	PB_CSHAKE,
	proto_cshake_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_cshake)
static void register_proto_cshake(void)
{
	proto_register_tester(&proto_cshake, "cSHAKE");
}

void register_cshake_impl(struct cshake_backend *implementation)
{
	register_backend(cshake_backend, implementation, "cSHAKE");
}
