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
#include "kmac.pb-c.h"
#include "parser_kmac.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct kmac_backend *kmac_backend = NULL;

static int _proto_kmac_tester(struct buffer *in, struct buffer *out,
			      flags_t parsed_flags,
			      int (*op)(struct kmac_data *data,
					flags_t parsed_flags))
{
	KmacDataMsg KmacDataMsg_send = KMAC_DATA_MSG__INIT;
	struct kmac_data data = { 0 };
	KmacDataMsg *KmacDataMsg_recv = NULL;
	int ret;

	CKNULL(op, -EINVAL);

	KmacDataMsg_recv = kmac_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(KmacDataMsg_recv, -EBADMSG);

	data.key.buf = KmacDataMsg_recv->key.data;
	data.key.len = KmacDataMsg_recv->key.len;
	data.msg.buf = KmacDataMsg_recv->msg.data;
	data.msg.len = KmacDataMsg_recv->msg.len;
	data.mac.buf = KmacDataMsg_recv->mac.data;
	data.mac.len = KmacDataMsg_recv->mac.len;
	data.maclen = KmacDataMsg_recv->maclen;
	data.keylen = KmacDataMsg_recv->keylen;
	data.customization.buf = KmacDataMsg_recv->customization.data;
	data.customization.len = KmacDataMsg_recv->customization.len;
	data.xof_enabled = KmacDataMsg_recv->xof_enabled;
	data.cipher = KmacDataMsg_recv->cipher;

	CKINT(op(&data, parsed_flags));

	if (!KmacDataMsg_recv->mac.data) {
		/* Generate request */
		KmacDataMsg_send.mac.data = data.mac.buf;
		KmacDataMsg_send.mac.len = data.mac.len;
	} else {
		/* Verify request */
		KmacDataMsg_send.verify_result = data.verify_result;
	}

	CKINT(proto_alloc_comm_buf(
		out, kmac_data_msg__get_packed_size(&KmacDataMsg_send)));
	kmac_data_msg__pack(&KmacDataMsg_send, out->buf);

out:
	if (KmacDataMsg_recv && (KmacDataMsg_recv->mac.data != data.mac.buf))
		free_buf(&data.mac);

	if (KmacDataMsg_recv)
		kmac_data_msg__free_unpacked(KmacDataMsg_recv, NULL);

	return ret;
}

static int proto_kmac_gen_tester(struct buffer *in, struct buffer *out,
				 flags_t parsed_flags)
{
	if (!kmac_backend)
		return -EFAULT;
	return _proto_kmac_tester(in, out, parsed_flags,
				  kmac_backend->kmac_generate);
}

static struct proto_tester proto_kmac_gen =
{
	PB_KMAC_GENERATE,
	proto_kmac_gen_tester,	/* process_req */
	NULL
};

static int proto_kmac_ver_tester(struct buffer *in, struct buffer *out,
				 flags_t parsed_flags)
{
	if (!kmac_backend)
		return -EFAULT;
	return _proto_kmac_tester(in, out, parsed_flags,
				  kmac_backend->kmac_ver);
}

static struct proto_tester proto_kmac_ver =
{
	PB_KMAC_VERIFY,
	proto_kmac_ver_tester,	/* process_req */
	NULL
};
ACVP_DEFINE_CONSTRUCTOR(register_proto_kmac)
static void register_proto_kmac(void)
{
	proto_register_tester(&proto_kmac_gen, "KMAC Generate");
	proto_register_tester(&proto_kmac_ver, "KMAC Verify");
}

void register_kmac_impl(struct kmac_backend *implementation)
{
	register_backend(kmac_backend, implementation, "KMAC");
}
