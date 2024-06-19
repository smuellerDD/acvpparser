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
#include "sym.pb-c.h"
#include "parser_sym.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct sym_backend *sym_backend = NULL;

/* This pointer implies that this code must run single threaded */
static void *sym_priv = NULL;

static int _proto_sym_tester(struct buffer *in, struct buffer *out,
			     flags_t parsed_flags,
			     int (*op)(struct sym_data *data,
				       flags_t parsed_flags))
{
	SymDataMsg SymDataMsg_send = SYM_DATA_MSG__INIT;
	struct sym_data data = { 0 };
	SymDataMsg *SymDataMsg_recv = NULL;
	int ret;

	CKNULL(op, -EINVAL);

	SymDataMsg_recv = sym_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(SymDataMsg_recv, -EBADMSG);

	data.key.buf = SymDataMsg_recv->key.data;
	data.key.len = SymDataMsg_recv->key.len;
	data.iv.buf = SymDataMsg_recv->iv.data;
	data.iv.len = SymDataMsg_recv->iv.len;
	data.cipher = SymDataMsg_recv->cipher;
	data.data.buf = SymDataMsg_recv->data.data;
	data.data.len = SymDataMsg_recv->data.len;
	data.data_len_bits = SymDataMsg_recv->data_len_bits;
	data.xts_sequence_no = SymDataMsg_recv->xts_sequence_no;
	data.xts_data_unit_len = SymDataMsg_recv->xts_data_unit_len;
	data.kwcipher.buf = SymDataMsg_recv->kwcipher.data;
	data.kwcipher.len = SymDataMsg_recv->kwcipher.len;

	/* Restore any previously stored priv pointer */
	data.priv = sym_priv;

	CKINT(op(&data, parsed_flags));

	SymDataMsg_send.data.data = data.data.buf;
	SymDataMsg_send.data.len = data.data.len;
	SymDataMsg_send.inner_loop_final_cj1.data =
		data.inner_loop_final_cj1.buf;
	SymDataMsg_send.inner_loop_final_cj1.len =
		data.inner_loop_final_cj1.len;
	SymDataMsg_send.integrity_error = data.integrity_error;

	/* Safe-keep the priv pointer */
	sym_priv = data.priv;

	/* Restore protentially re-allocated memory */
	SymDataMsg_recv->data.data = data.data.buf;
	SymDataMsg_recv->data.len = data.data.len;

	CKINT(proto_alloc_comm_buf(
		out, sym_data_msg__get_packed_size(&SymDataMsg_send)));
	sym_data_msg__pack(&SymDataMsg_send, out->buf);

out:
	free_buf(&data.inner_loop_final_cj1);

	if (SymDataMsg_recv)
		sym_data_msg__free_unpacked(SymDataMsg_recv, NULL);

	return ret;
}

static int proto_sym_enc_tester(struct buffer *in, struct buffer *out,
				flags_t parsed_flags)
{
	if (!sym_backend)
		return -EFAULT;
	return _proto_sym_tester(in, out, parsed_flags, sym_backend->encrypt);
}

static struct proto_tester proto_sym_enc =
{
	PB_SYM_ENCRYPT,
	proto_sym_enc_tester,	/* process_req */
	NULL
};

static int proto_sym_dec_tester(struct buffer *in, struct buffer *out,
				flags_t parsed_flags)
{
	if (!sym_backend)
		return -EFAULT;
	return _proto_sym_tester(in, out, parsed_flags, sym_backend->decrypt);
}

static struct proto_tester proto_sym_dec =
{
	PB_SYM_DECRYPT,
	proto_sym_dec_tester,	/* process_req */
	NULL
};

static int proto_sym_mct_init_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	if (!sym_backend)
		return -EFAULT;
	return _proto_sym_tester(in, out, parsed_flags, sym_backend->mct_init);
}

static struct proto_tester proto_sym_mct_init =
{
	PB_SYM_MCT_INIT,
	proto_sym_mct_init_tester,	/* process_req */
	NULL
};

static int proto_sym_mct_update_tester(struct buffer *in, struct buffer *out,
				       flags_t parsed_flags)
{
	if (!sym_backend)
		return -EFAULT;
	return _proto_sym_tester(in, out, parsed_flags,
				 sym_backend->mct_update);
}

static struct proto_tester proto_sym_mct_update =
{
	PB_SYM_MCT_UPDATE,
	proto_sym_mct_update_tester,	/* process_req */
	NULL
};

static int proto_sym_mct_fini_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	if (!sym_backend)
		return -EFAULT;
	return _proto_sym_tester(in, out, parsed_flags, sym_backend->mct_fini);
}

static struct proto_tester proto_sym_mct_fini =
{
	PB_SYM_MCT_FINAL,
	proto_sym_mct_fini_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_sym)
static void register_proto_sym(void)
{
	proto_register_tester(&proto_sym_enc, "Sym Enc");
	proto_register_tester(&proto_sym_dec, "Sym Dec");
	proto_register_tester(&proto_sym_mct_init, "Sym MCT Init");
	proto_register_tester(&proto_sym_mct_update, "Sym MCT Update");
	proto_register_tester(&proto_sym_mct_fini, "Sym MCT Fini");
}

void register_sym_impl(struct sym_backend *implementation)
{
	register_backend(sym_backend, implementation, "SYM");
}
