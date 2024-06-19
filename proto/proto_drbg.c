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
#include "drbg.pb-c.h"
#include "parser_drbg.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct drbg_backend *drbg_backend = NULL;

static int proto_drbg_tester(struct buffer *in, struct buffer *out,
			       flags_t parsed_flags)
{
	DrbgDataMsg DrbgDataMsg_send = DRBG_DATA_MSG__INIT;
	struct drbg_data data = { 0 };
	DrbgDataMsg *DrbgDataMsg_recv = NULL;
	int ret;

	CKNULL(drbg_backend, -EINVAL);
	CKNULL(drbg_backend->drbg, -EINVAL);

	DrbgDataMsg_recv = drbg_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(DrbgDataMsg_recv, -EBADMSG);


	data.entropy.buf = DrbgDataMsg_recv->entropy.data;
	data.entropy.len = DrbgDataMsg_recv->entropy.len;
	data.nonce.buf = DrbgDataMsg_recv->nonce.data;
	data.nonce.len = DrbgDataMsg_recv->nonce.len;
	data.pers.buf = DrbgDataMsg_recv->pers.data;
	data.pers.len = DrbgDataMsg_recv->pers.len;

	data.addtl_reseed.buffers[0].buf = DrbgDataMsg_recv->addtl_reseed1.data;
	data.addtl_reseed.buffers[0].len = DrbgDataMsg_recv->addtl_reseed1.len;
	if (data.addtl_reseed.buffers[0].len)
		data.addtl_reseed.arraysize++;
	data.addtl_reseed.buffers[1].buf = DrbgDataMsg_recv->addtl_reseed2.data;
	data.addtl_reseed.buffers[1].len = DrbgDataMsg_recv->addtl_reseed2.len;
	if (data.addtl_reseed.buffers[1].len)
		data.addtl_reseed.arraysize++;

	data.entropy_reseed.buffers[0].buf = DrbgDataMsg_recv->entropy_reseed1.data;
	data.entropy_reseed.buffers[0].len = DrbgDataMsg_recv->entropy_reseed1.len;
	if (data.entropy_reseed.buffers[0].len)
		data.entropy_reseed.arraysize++;
	data.entropy_reseed.buffers[1].buf = DrbgDataMsg_recv->entropy_reseed2.data;
	data.entropy_reseed.buffers[1].len = DrbgDataMsg_recv->entropy_reseed2.len;
	if (data.entropy_reseed.buffers[1].len)
		data.entropy_reseed.arraysize++;

	data.addtl_generate.buffers[0].buf = DrbgDataMsg_recv->addtl_generate1.data;
	data.addtl_generate.buffers[0].len = DrbgDataMsg_recv->addtl_generate1.len;
	if (data.addtl_generate.buffers[0].len)
		data.addtl_generate.arraysize++;
	data.addtl_generate.buffers[1].buf = DrbgDataMsg_recv->addtl_generate2.data;
	data.addtl_generate.buffers[1].len = DrbgDataMsg_recv->addtl_generate2.len;
	if (data.addtl_generate.buffers[1].len)
		data.addtl_generate.arraysize++;

	data.entropy_generate.buffers[0].buf = DrbgDataMsg_recv->entropy_generate1.data;
	data.entropy_generate.buffers[0].len = DrbgDataMsg_recv->entropy_generate1.len;
	if (data.entropy_generate.buffers[0].len)
		data.entropy_generate.arraysize++;
	data.entropy_generate.buffers[1].buf = DrbgDataMsg_recv->entropy_generate2.data;
	data.entropy_generate.buffers[1].len = DrbgDataMsg_recv->entropy_generate2.len;
	if (data.entropy_generate.buffers[1].len)
		data.entropy_generate.arraysize++;

	data.type = DrbgDataMsg_recv->type;
	data.cipher = DrbgDataMsg_recv->cipher;
	data.rnd_data_bits_len = DrbgDataMsg_recv->rnd_data_bits_len;
	data.pr = DrbgDataMsg_recv->pr;
	data.df = DrbgDataMsg_recv->df;

	CKINT(drbg_backend->drbg(&data, parsed_flags));

	DrbgDataMsg_send.random.data = data.random.buf;
	DrbgDataMsg_send.random.len = data.random.len;

	CKINT(proto_alloc_comm_buf(
		out, drbg_data_msg__get_packed_size(&DrbgDataMsg_send)));
	drbg_data_msg__pack(&DrbgDataMsg_send, out->buf);

out:
	free_buf(&data.random);

	if (DrbgDataMsg_recv)
		drbg_data_msg__free_unpacked(DrbgDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_drbg =
{
	PB_DRBG,
	proto_drbg_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_drbg)
static void register_proto_drbg(void)
{
	proto_register_tester(&proto_drbg, "DRBG");
}

void register_drbg_impl(struct drbg_backend *implementation)
{
	register_backend(drbg_backend, implementation, "DRBG");
}
