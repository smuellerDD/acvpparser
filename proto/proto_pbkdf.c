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
#include "pbkdf.pb-c.h"
#include "parser_pbkdf.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct pbkdf_backend *pbkdf_backend = NULL;

static int proto_pbkdf_tester(struct buffer *in, struct buffer *out,
			       flags_t parsed_flags)
{
	PbkdfDataMsg PbkdfDataMsg_send = PBKDF_DATA_MSG__INIT;
	struct pbkdf_data data = { 0 };
	PbkdfDataMsg *PbkdfDataMsg_recv = NULL;
	int ret;

	CKNULL(pbkdf_backend, -EINVAL);
	CKNULL(pbkdf_backend->pbkdf, -EINVAL);

	PbkdfDataMsg_recv = pbkdf_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(PbkdfDataMsg_recv, -EBADMSG);

	data.hash = PbkdfDataMsg_recv->hash;
	data.derived_key_length = PbkdfDataMsg_recv->derived_key_length;
	data.iteration_count = PbkdfDataMsg_recv->iteration_count;
	data.password.buf = PbkdfDataMsg_recv->password.data;
	data.password.len = PbkdfDataMsg_recv->password.len;
	data.salt.buf = PbkdfDataMsg_recv->salt.data;
	data.salt.len = PbkdfDataMsg_recv->salt.len;

	CKINT(pbkdf_backend->pbkdf(&data, parsed_flags));

	PbkdfDataMsg_send.derived_key.data = data.derived_key.buf;
	PbkdfDataMsg_send.derived_key.len = data.derived_key.len;

	CKINT(proto_alloc_comm_buf(
		out, pbkdf_data_msg__get_packed_size(&PbkdfDataMsg_send)));
	pbkdf_data_msg__pack(&PbkdfDataMsg_send, out->buf);

out:
	free_buf(&data.derived_key);

	if (PbkdfDataMsg_recv)
		pbkdf_data_msg__free_unpacked(PbkdfDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_pbkdf =
{
	PB_PBKDF,
	proto_pbkdf_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_pbkdf)
static void register_proto_pbkdf(void)
{
	proto_register_tester(&proto_pbkdf, "PBKDF");
}

void register_pbkdf_impl(struct pbkdf_backend *implementation)
{
	register_backend(pbkdf_backend, implementation, "PBKDF");
}
