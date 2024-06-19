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
#include "hmac.pb-c.h"
#include "parser_hmac.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct hmac_backend *hmac_backend = NULL;

static int proto_hmac_tester(struct buffer *in, struct buffer *out,
			     flags_t parsed_flags)
{
	HmacDataMsg HmacDataMsg_send = HMAC_DATA_MSG__INIT;
	struct hmac_data data = { 0 };
	HmacDataMsg *HmacDataMsg_recv = NULL;
	int ret;

	CKNULL(hmac_backend, -EINVAL);

	HmacDataMsg_recv = hmac_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(HmacDataMsg_recv, -EBADMSG);

	data.msg.buf = HmacDataMsg_recv->msg.data;
	data.msg.len = HmacDataMsg_recv->msg.len;
	data.key.buf = HmacDataMsg_recv->key.data;
	data.key.len = HmacDataMsg_recv->key.len;
	data.maclen = HmacDataMsg_recv->maclen;
	data.cipher = HmacDataMsg_recv->cipher;

	CKINT(hmac_backend->hmac_generate(&data, parsed_flags));

	HmacDataMsg_send.mac.data = data.mac.buf;
	HmacDataMsg_send.mac.len = data.mac.len;

	CKINT(proto_alloc_comm_buf(
		out, hmac_data_msg__get_packed_size(&HmacDataMsg_send)));
	hmac_data_msg__pack(&HmacDataMsg_send, out->buf);

out:
	free_buf(&data.mac);

	if (HmacDataMsg_recv)
		hmac_data_msg__free_unpacked(HmacDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_hmac =
{
	PB_HMAC,
	proto_hmac_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_hmac)
static void register_proto_hmac(void)
{
	proto_register_tester(&proto_hmac, "HMAC");
}

void register_hmac_impl(struct hmac_backend *implementation)
{
	register_backend(hmac_backend, implementation, "HMAC");
}
