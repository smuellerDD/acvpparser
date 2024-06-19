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
#include "kbkdf.pb-c.h"
#include "parser_kdf_108.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct kdf_108_backend *kdf_108_backend = NULL;

static int proto_kdf108_tester(struct buffer *in, struct buffer *out,
			       flags_t parsed_flags)
{
	Kdf108DataMsg Kdf108DataMsg_send = KDF108_DATA_MSG__INIT;
	struct kdf_108_data data = { 0 };
	Kdf108DataMsg *Kdf108DataMsg_recv = NULL;
	int ret;

	CKNULL(kdf_108_backend, -EINVAL);
	CKNULL(kdf_108_backend->kdf_108, -EINVAL);

	Kdf108DataMsg_recv = kdf108_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(Kdf108DataMsg_recv, -EBADMSG);

	data.mac = Kdf108DataMsg_recv->mac;
	data.kdfmode = Kdf108DataMsg_recv->kdfmode;
	data.counter_location = Kdf108DataMsg_recv->counter_location;
	data.counter_length = Kdf108DataMsg_recv->counter_length;
	data.derived_key_length = Kdf108DataMsg_recv->derived_key_length;
	data.key.buf = Kdf108DataMsg_recv->key.data;
	data.key.len = Kdf108DataMsg_recv->key.len;
	data.iv.buf = Kdf108DataMsg_recv->iv.data;
	data.iv.len = Kdf108DataMsg_recv->iv.len;
	data.context.buf = Kdf108DataMsg_recv->context.data;
	data.context.len = Kdf108DataMsg_recv->context.len;
	data.label.buf = Kdf108DataMsg_recv->label.data;
	data.label.len = Kdf108DataMsg_recv->label.len;

	CKINT(kdf_108_backend->kdf_108(&data, parsed_flags));

	Kdf108DataMsg_send.break_location = data.break_location;
	Kdf108DataMsg_send.fixed_data.data = data.fixed_data.buf;
	Kdf108DataMsg_send.fixed_data.len = data.fixed_data.len;
	Kdf108DataMsg_send.derived_key.data = data.derived_key.buf;
	Kdf108DataMsg_send.derived_key.len = data.derived_key.len;

	CKINT(proto_alloc_comm_buf(
		out, kdf108_data_msg__get_packed_size(&Kdf108DataMsg_send)));
	kdf108_data_msg__pack(&Kdf108DataMsg_send, out->buf);

out:
	free_buf(&data.fixed_data);
	free_buf(&data.derived_key);

	if (Kdf108DataMsg_recv)
		kdf108_data_msg__free_unpacked(Kdf108DataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_kdf108 =
{
	PB_KDF_108,
	proto_kdf108_tester,	/* process_req */
	NULL
};


static int proto_kdf108_kmac_tester(struct buffer *in, struct buffer *out,
				    flags_t parsed_flags)
{
	Kdf108KmacDataMsg Kdf108KmacDataMsg_send = KDF108_KMAC_DATA_MSG__INIT;
	struct kdf_108_kmac_data data = { 0 };
	Kdf108KmacDataMsg *Kdf108KmacDataMsg_recv = NULL;
	int ret;

	CKNULL(kdf_108_backend, -EINVAL);
	CKNULL(kdf_108_backend->kdf_108_kmac, -EINVAL);

	Kdf108KmacDataMsg_recv = kdf108_kmac_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(Kdf108KmacDataMsg_recv, -EBADMSG);

	data.mac = Kdf108KmacDataMsg_recv->mac;
	data.derived_key_length = Kdf108KmacDataMsg_recv->derived_key_length;
	data.key.buf = Kdf108KmacDataMsg_recv->key.data;
	data.key.len = Kdf108KmacDataMsg_recv->key.len;
	data.context.buf = Kdf108KmacDataMsg_recv->context.data;
	data.context.len = Kdf108KmacDataMsg_recv->context.len;
	data.label.buf = Kdf108KmacDataMsg_recv->label.data;
	data.label.len = Kdf108KmacDataMsg_recv->label.len;

	CKINT(kdf_108_backend->kdf_108_kmac(&data, parsed_flags));

	Kdf108KmacDataMsg_send.derived_key.data = data.derived_key.buf;
	Kdf108KmacDataMsg_send.derived_key.len = data.derived_key.len;

	CKINT(proto_alloc_comm_buf(
		out, kdf108_kmac_data_msg__get_packed_size(&Kdf108KmacDataMsg_send)));
	kdf108_kmac_data_msg__pack(&Kdf108KmacDataMsg_send, out->buf);

out:
	free_buf(&data.derived_key);

	if (Kdf108KmacDataMsg_recv)
		kdf108_kmac_data_msg__free_unpacked(Kdf108KmacDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_kdf108_kmac =
{
	PB_KDF_108_KMAC,
	proto_kdf108_kmac_tester,	/* process_req */
	NULL
};


ACVP_DEFINE_CONSTRUCTOR(register_proto_kdf108)
static void register_proto_kdf108(void)
{
	proto_register_tester(&proto_kdf108, "KBKDF");
	proto_register_tester(&proto_kdf108_kmac, "KBKDF KMAC ");
}

void register_kdf_108_impl(struct kdf_108_backend *implementation)
{
	register_backend(kdf_108_backend, implementation, "KBKDF");
}
