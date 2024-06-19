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
#include "aead.pb-c.h"
#include "parser_aead.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct aead_backend *aead_backend = NULL;

static int _proto_aead_tester(struct buffer *in, struct buffer *out,
			      flags_t parsed_flags,
			      int (*op)(struct aead_data *data,
				        flags_t parsed_flags))
{
	AeadDataMsg AeadDataMsg_send = AEAD_DATA_MSG__INIT;
	struct aead_data data = { 0 };
	AeadDataMsg *AeadDataMsg_recv = NULL;
	int ret;

	CKNULL(op, -EINVAL);

	AeadDataMsg_recv = aead_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(AeadDataMsg_recv, -EBADMSG);

	data.key.buf = AeadDataMsg_recv->key.data;
	data.key.len = AeadDataMsg_recv->key.len;
	data.iv.buf = AeadDataMsg_recv->iv.data;
	data.iv.len = AeadDataMsg_recv->iv.len;
	data.ivlen = AeadDataMsg_recv->ivlen;
	data.assoc.buf = AeadDataMsg_recv->assoc.data;
	data.assoc.len = AeadDataMsg_recv->assoc.len;
	data.tag.buf = AeadDataMsg_recv->tag.data;
	data.tag.len = AeadDataMsg_recv->tag.len;
	data.cipher = AeadDataMsg_recv->cipher;
	data.ptlen = AeadDataMsg_recv->ptlen;
	data.data.buf = AeadDataMsg_recv->data.data;
	data.data.len = AeadDataMsg_recv->data.len;

	CKINT(op(&data, parsed_flags));

	AeadDataMsg_send.data.data = data.data.buf;
	AeadDataMsg_send.data.len = data.data.len;
	AeadDataMsg_send.iv.data = data.iv.buf;
	AeadDataMsg_send.iv.len = data.iv.len;
	AeadDataMsg_send.tag.data = data.tag.buf;
	AeadDataMsg_send.tag.len = data.tag.len;
	AeadDataMsg_send.integrity_error = data.integrity_error;

	CKINT(proto_alloc_comm_buf(
		out, aead_data_msg__get_packed_size(&AeadDataMsg_send)));
	aead_data_msg__pack(&AeadDataMsg_send, out->buf);

out:
	free_buf(&data.data);
	free_buf(&data.iv);
	free_buf(&data.tag);

	if (AeadDataMsg_recv)
		aead_data_msg__free_unpacked(AeadDataMsg_recv, NULL);

	return ret;
}

static int proto_aead_gcm_enc_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	if (!aead_backend)
		return -EFAULT;
	return _proto_aead_tester(in, out, parsed_flags,
				  aead_backend->gcm_encrypt);
}

static struct proto_tester proto_aead_gcm_enc =
{
	PB_AEAD_GCM_ENCRYPT,
	proto_aead_gcm_enc_tester,	/* process_req */
	NULL
};

static int proto_aead_gcm_dec_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	if (!aead_backend)
		return -EFAULT;
	return _proto_aead_tester(in, out, parsed_flags,
				  aead_backend->gcm_decrypt);
}

static struct proto_tester proto_aead_gcm_dec =
{
	PB_AEAD_GCM_DECRYPT,
	proto_aead_gcm_dec_tester,	/* process_req */
	NULL
};

static int proto_aead_ccm_enc_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	if (!aead_backend)
		return -EFAULT;
	return _proto_aead_tester(in, out, parsed_flags,
				  aead_backend->ccm_encrypt);
}

static struct proto_tester proto_aead_ccm_enc =
{
	PB_AEAD_CCM_ENCRYPT,
	proto_aead_ccm_enc_tester,	/* process_req */
	NULL
};

static int proto_aead_ccm_dec_tester(struct buffer *in, struct buffer *out,
				     flags_t parsed_flags)
{
	if (!aead_backend)
		return -EFAULT;
	return _proto_aead_tester(in, out, parsed_flags,
				  aead_backend->ccm_decrypt);
}

static struct proto_tester proto_aead_ccm_dec =
{
	PB_AEAD_CCM_DECRYPT,
	proto_aead_ccm_dec_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_aead)
static void register_proto_aead(void)
{
	proto_register_tester(&proto_aead_gcm_enc, "AEAD GCM Enc");
	proto_register_tester(&proto_aead_gcm_dec, "AEAD GCM Dec");
	proto_register_tester(&proto_aead_ccm_enc, "AEAD CCM Enc");
	proto_register_tester(&proto_aead_ccm_dec, "AEAD CCM Dec");
}

void register_aead_impl(struct aead_backend *implementation)
{
	register_backend(aead_backend, implementation, "AEAD");
}
