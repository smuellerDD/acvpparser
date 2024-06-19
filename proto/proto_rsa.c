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
#include "rsa.pb-c.h"
#include "parser_rsa.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

static struct rsa_backend *rsa_backend = NULL;

static int proto_rsa_keygen_tester(struct buffer *in, struct buffer *out,
				   flags_t parsed_flags)
{
	RsaKeygenDataMsg RsaKeygenDataMsg_send = RSA_KEYGEN_DATA_MSG__INIT;
	struct rsa_keygen_data data = { 0 };
	RsaKeygenDataMsg *RsaKeygenDataMsg_recv = NULL;
	int ret;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_keygen, -EINVAL);

	RsaKeygenDataMsg_recv = rsa_keygen_data_msg__unpack(NULL, in->len,
							    in->buf);
	CKNULL(RsaKeygenDataMsg_recv, -EBADMSG);

	data.e.buf = RsaKeygenDataMsg_recv->e.data;
	data.e.len = RsaKeygenDataMsg_recv->e.len;
	data.bitlen_in = RsaKeygenDataMsg_recv->bitlen_in;

	CKINT(rsa_backend->rsa_keygen(&data, parsed_flags));

	RsaKeygenDataMsg_send.n.data = data.n.buf;
	RsaKeygenDataMsg_send.n.len = data.n.len;
	RsaKeygenDataMsg_send.d.data = data.d.buf;
	RsaKeygenDataMsg_send.d.len = data.d.len;
	RsaKeygenDataMsg_send.p.data = data.p.buf;
	RsaKeygenDataMsg_send.p.len = data.p.len;
	RsaKeygenDataMsg_send.q.data = data.q.buf;
	RsaKeygenDataMsg_send.q.len = data.q.len;

	RsaKeygenDataMsg_send.xp.data = data.xp.buf;
	RsaKeygenDataMsg_send.xp.len = data.xp.len;
	RsaKeygenDataMsg_send.xp1.data = data.xp1.buf;
	RsaKeygenDataMsg_send.xp1.len = data.xp1.len;
	RsaKeygenDataMsg_send.xp2.data = data.xp2.buf;
	RsaKeygenDataMsg_send.xp2.len = data.xp2.len;

	RsaKeygenDataMsg_send.xq.data = data.xq.buf;
	RsaKeygenDataMsg_send.xq.len = data.xq.len;
	RsaKeygenDataMsg_send.xq1.data = data.xq1.buf;
	RsaKeygenDataMsg_send.xq1.len = data.xq1.len;
	RsaKeygenDataMsg_send.xq2.data = data.xq2.buf;
	RsaKeygenDataMsg_send.xq2.len = data.xq2.len;

	RsaKeygenDataMsg_send.bitlen1 = data.bitlen[0];
	RsaKeygenDataMsg_send.bitlen2 = data.bitlen[1];
	RsaKeygenDataMsg_send.bitlen3 = data.bitlen[2];
	RsaKeygenDataMsg_send.bitlen4 = data.bitlen[3];

	RsaKeygenDataMsg_send.dmp1.data = data.dmp1.buf;
	RsaKeygenDataMsg_send.dmp1.len = data.dmp1.len;
	RsaKeygenDataMsg_send.dmq1.data = data.dmq1.buf;
	RsaKeygenDataMsg_send.dmq1.len = data.dmq1.len;
	RsaKeygenDataMsg_send.iqmp.data = data.iqmp.buf;
	RsaKeygenDataMsg_send.iqmp.len = data.iqmp.len;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_keygen_data_msg__get_packed_size(&RsaKeygenDataMsg_send)));
	rsa_keygen_data_msg__pack(&RsaKeygenDataMsg_send, out->buf);

out:
	free_buf(&data.n);
	free_buf(&data.d);
	free_buf(&data.p);
	free_buf(&data.q);
	free_buf(&data.xp);
	free_buf(&data.xp1);
	free_buf(&data.xp2);
	free_buf(&data.xq);
	free_buf(&data.xq1);
	free_buf(&data.xq2);
	free_buf(&data.dmp1);
	free_buf(&data.dmq1);
	free_buf(&data.iqmp);

	if (RsaKeygenDataMsg_recv)
		rsa_keygen_data_msg__free_unpacked(RsaKeygenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_keygen =
{
	PB_RSA_KEYGEN,
	proto_rsa_keygen_tester,	/* process_req */
	NULL
};

static int proto_rsa_keygen_prime_tester(struct buffer *in, struct buffer *out,
					 flags_t parsed_flags)
{
	RsaKeygenPrimeDataMsg RsaKeygenPrimeDataMsg_send =
		RSA_KEYGEN_PRIME_DATA_MSG__INIT;
	struct rsa_keygen_prime_data data = { 0 };
	RsaKeygenPrimeDataMsg *RsaKeygenPrimeDataMsg_recv = NULL;
	int ret;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_keygen_prime, -EINVAL);

	RsaKeygenPrimeDataMsg_recv =
		rsa_keygen_prime_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaKeygenPrimeDataMsg_recv, -EBADMSG);

	data.modulus = RsaKeygenPrimeDataMsg_recv->modulus;
	data.p.buf = RsaKeygenPrimeDataMsg_recv->p.data;
	data.p.len = RsaKeygenPrimeDataMsg_recv->p.len;
	data.q.buf = RsaKeygenPrimeDataMsg_recv->q.data;
	data.q.len = RsaKeygenPrimeDataMsg_recv->q.len;
	data.e.buf = RsaKeygenPrimeDataMsg_recv->e.data;
	data.e.len = RsaKeygenPrimeDataMsg_recv->e.len;

	CKINT(rsa_backend->rsa_keygen_prime(&data, parsed_flags));

	RsaKeygenPrimeDataMsg_send.keygen_success = data.keygen_success;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_keygen_prime_data_msg__get_packed_size(
			&RsaKeygenPrimeDataMsg_send)));
	rsa_keygen_prime_data_msg__pack(&RsaKeygenPrimeDataMsg_send, out->buf);

out:
	if (RsaKeygenPrimeDataMsg_recv)
		rsa_keygen_prime_data_msg__free_unpacked(
			RsaKeygenPrimeDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_keygen_prime =
{
	PB_RSA_KEYGEN_PRIME,
	proto_rsa_keygen_prime_tester,	/* process_req */
	NULL
};

static int proto_rsa_keygen_prov_prime_tester(struct buffer *in,
					      struct buffer *out,
					      flags_t parsed_flags)
{
	RsaKeygenProvPrimeDataMsg RsaKeygenProvPrimeDataMsg_send =
		RSA_KEYGEN_PROV_PRIME_DATA_MSG__INIT;
	struct rsa_keygen_prov_prime_data data = { 0 };
	RsaKeygenProvPrimeDataMsg *RsaKeygenProvPrimeDataMsg_recv = NULL;
	int ret;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_keygen_prov_prime, -EINVAL);

	RsaKeygenProvPrimeDataMsg_recv =
		rsa_keygen_prov_prime_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaKeygenProvPrimeDataMsg_recv, -EBADMSG);

	data.modulus = RsaKeygenProvPrimeDataMsg_recv->modulus;
	data.seed.buf = RsaKeygenProvPrimeDataMsg_recv->seed.data;
	data.seed.len = RsaKeygenProvPrimeDataMsg_recv->seed.len;
	data.e.buf = RsaKeygenProvPrimeDataMsg_recv->e.data;
	data.e.len = RsaKeygenProvPrimeDataMsg_recv->e.len;
	data.cipher = RsaKeygenProvPrimeDataMsg_recv->cipher;

	CKINT(rsa_backend->rsa_keygen_prov_prime(&data, parsed_flags));

	RsaKeygenProvPrimeDataMsg_send.n.data = data.n.buf;
	RsaKeygenProvPrimeDataMsg_send.n.len = data.n.len;
	RsaKeygenProvPrimeDataMsg_send.d.data = data.d.buf;
	RsaKeygenProvPrimeDataMsg_send.d.len = data.d.len;
	RsaKeygenProvPrimeDataMsg_send.p.data = data.p.buf;
	RsaKeygenProvPrimeDataMsg_send.p.len = data.p.len;
	RsaKeygenProvPrimeDataMsg_send.q.data = data.q.buf;
	RsaKeygenProvPrimeDataMsg_send.q.len = data.q.len;
	RsaKeygenProvPrimeDataMsg_send.seed.data = data.seed.buf;
	RsaKeygenProvPrimeDataMsg_send.seed.len = data.seed.len;
	RsaKeygenProvPrimeDataMsg_send.e.data = data.e.buf;
	RsaKeygenProvPrimeDataMsg_send.e.len = data.e.len;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_keygen_prov_prime_data_msg__get_packed_size(
			&RsaKeygenProvPrimeDataMsg_send)));
	rsa_keygen_prov_prime_data_msg__pack(&RsaKeygenProvPrimeDataMsg_send, out->buf);

out:
	free_buf(&data.n);
	free_buf(&data.d);
	free_buf(&data.p);
	free_buf(&data.q);
	free_buf(&data.seed);
	if (RsaKeygenProvPrimeDataMsg_recv &&
	    RsaKeygenProvPrimeDataMsg_recv->e.data != data.e.buf)
		free_buf(&data.e);

	if (RsaKeygenProvPrimeDataMsg_recv)
		rsa_keygen_prov_prime_data_msg__free_unpacked(
			RsaKeygenProvPrimeDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_keygen_prov_prime =
{
	PB_RSA_KEYGEN_PROV_PRIME,
	proto_rsa_keygen_prov_prime_tester,	/* process_req */
	NULL
};

struct proto_rsa_privkey {
	uint32_t ref;
	void *privkey;
};

static struct proto_rsa_privkey proto_rsa_privkey = { 0, NULL };

static int proto_rsa_siggen_tester(struct buffer *in, struct buffer *out,
				   flags_t parsed_flags)
{
	RsaSiggenDataMsg RsaSiggenDataMsg_send = RSA_SIGGEN_DATA_MSG__INIT;
	struct rsa_siggen_data data = { 0 };
	RsaSiggenDataMsg *RsaSiggenDataMsg_recv = NULL;
	int ret;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_siggen, -EINVAL);

	RsaSiggenDataMsg_recv =
		rsa_siggen_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaSiggenDataMsg_recv, -EBADMSG);

	if (RsaSiggenDataMsg_recv->privkey != proto_rsa_privkey.ref) {
		ret = -ENOKEY;
		goto out;
	}

	data.modulus = RsaSiggenDataMsg_recv->modulus;
	data.cipher = RsaSiggenDataMsg_recv->cipher;
	data.saltlen = RsaSiggenDataMsg_recv->saltlen;
	data.e.buf = RsaSiggenDataMsg_recv->e.data;
	data.e.len = RsaSiggenDataMsg_recv->e.len;
	data.msg.buf = RsaSiggenDataMsg_recv->msg.data;
	data.msg.len = RsaSiggenDataMsg_recv->msg.len;
	data.n.buf = RsaSiggenDataMsg_recv->n.data;
	data.n.len = RsaSiggenDataMsg_recv->n.len;
	data.privkey = proto_rsa_privkey.privkey;

	CKINT(rsa_backend->rsa_siggen(&data, parsed_flags));

	RsaSiggenDataMsg_send.sig.data = data.sig.buf;
	RsaSiggenDataMsg_send.sig.len = data.sig.len;
	RsaSiggenDataMsg_send.n.data = data.n.buf;
	RsaSiggenDataMsg_send.n.len = data.n.len;
	RsaSiggenDataMsg_send.e.data = data.e.buf;
	RsaSiggenDataMsg_send.e.len = data.e.len;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_siggen_data_msg__get_packed_size(
			&RsaSiggenDataMsg_send)));
	rsa_siggen_data_msg__pack(&RsaSiggenDataMsg_send, out->buf);

out:
	if (RsaSiggenDataMsg_recv &&
	    RsaSiggenDataMsg_recv->n.data != data.n.buf)
		free_buf(&data.n);
	if (RsaSiggenDataMsg_recv &&
	    RsaSiggenDataMsg_recv->e.data != data.e.buf)
		free_buf(&data.e);
	free_buf(&data.sig);

	if (RsaSiggenDataMsg_recv)
		rsa_siggen_data_msg__free_unpacked(
			RsaSiggenDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_siggen =
{
	PB_RSA_SIGGEN,
	proto_rsa_siggen_tester,	/* process_req */
	NULL
};

static int proto_rsa_sigver_tester(struct buffer *in, struct buffer *out,
				   flags_t parsed_flags)
{
	RsaSigverDataMsg RsaSigverDataMsg_send = RSA_SIGVER_DATA_MSG__INIT;
	struct rsa_sigver_data data = { 0 };
	RsaSigverDataMsg *RsaSigverDataMsg_recv = NULL;
	int ret;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_sigver, -EINVAL);

	RsaSigverDataMsg_recv =
		rsa_sigver_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaSigverDataMsg_recv, -EBADMSG);

	data.modulus = RsaSigverDataMsg_recv->modulus;
	data.cipher = RsaSigverDataMsg_recv->cipher;
	data.saltlen = RsaSigverDataMsg_recv->saltlen;
	data.e.buf = RsaSigverDataMsg_recv->e.data;
	data.e.len = RsaSigverDataMsg_recv->e.len;
	data.msg.buf = RsaSigverDataMsg_recv->msg.data;
	data.msg.len = RsaSigverDataMsg_recv->msg.len;
	data.n.buf = RsaSigverDataMsg_recv->n.data;
	data.n.len = RsaSigverDataMsg_recv->n.len;
	data.sig.buf = RsaSigverDataMsg_recv->sig.data;
	data.sig.len = RsaSigverDataMsg_recv->sig.len;

	CKINT(rsa_backend->rsa_sigver(&data, parsed_flags));

	RsaSigverDataMsg_send.sig_result = data.sig_result;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_sigver_data_msg__get_packed_size(
			&RsaSigverDataMsg_send)));
	rsa_sigver_data_msg__pack(&RsaSigverDataMsg_send, out->buf);

out:
	if (RsaSigverDataMsg_recv)
		rsa_sigver_data_msg__free_unpacked(
			RsaSigverDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_sigver =
{
	PB_RSA_SIGVER,
	proto_rsa_sigver_tester,	/* process_req */
	NULL
};

static int proto_rsa_sigprim_tester(struct buffer *in, struct buffer *out,
				   flags_t parsed_flags)
{
	RsaSignaturePrimitiveDataMsg RsaSignaturePrimitiveDataMsg_send =
		RSA_SIGNATURE_PRIMITIVE_DATA_MSG__INIT;
	struct rsa_signature_primitive_data data = { 0 };
	RsaSignaturePrimitiveDataMsg *RsaSignaturePrimitiveDataMsg_recv = NULL;
	int ret;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_signature_primitive, -EINVAL);

	RsaSignaturePrimitiveDataMsg_recv =
		rsa_signature_primitive_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaSignaturePrimitiveDataMsg_recv, -EBADMSG);

	data.msg.buf = RsaSignaturePrimitiveDataMsg_recv->msg.data;
	data.msg.len = RsaSignaturePrimitiveDataMsg_recv->msg.len;
	data.n.buf = RsaSignaturePrimitiveDataMsg_recv->n.data;
	data.n.len = RsaSignaturePrimitiveDataMsg_recv->n.len;
	data.e.buf = RsaSignaturePrimitiveDataMsg_recv->e.data;
	data.e.len = RsaSignaturePrimitiveDataMsg_recv->e.len;
	data.d.buf = RsaSignaturePrimitiveDataMsg_recv->d.data;
	data.d.len = RsaSignaturePrimitiveDataMsg_recv->d.len;
	data.p.buf = RsaSignaturePrimitiveDataMsg_recv->p.data;
	data.p.len = RsaSignaturePrimitiveDataMsg_recv->p.len;
	data.q.buf = RsaSignaturePrimitiveDataMsg_recv->q.data;
	data.q.len = RsaSignaturePrimitiveDataMsg_recv->q.len;
	data.dmp1.buf = RsaSignaturePrimitiveDataMsg_recv->dmp1.data;
	data.dmp1.len = RsaSignaturePrimitiveDataMsg_recv->dmp1.len;
	data.dmq1.buf = RsaSignaturePrimitiveDataMsg_recv->dmq1.data;
	data.dmq1.len = RsaSignaturePrimitiveDataMsg_recv->dmq1.len;
	data.iqmp.buf = RsaSignaturePrimitiveDataMsg_recv->iqmp.data;
	data.iqmp.len = RsaSignaturePrimitiveDataMsg_recv->iqmp.len;

	CKINT(rsa_backend->rsa_signature_primitive(&data, parsed_flags));

	RsaSignaturePrimitiveDataMsg_send.signature.data = data.signature.buf;
	RsaSignaturePrimitiveDataMsg_send.signature.len = data.signature.len;
	RsaSignaturePrimitiveDataMsg_send.sig_result = data.sig_result;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_signature_primitive_data_msg__get_packed_size(
			&RsaSignaturePrimitiveDataMsg_send)));
	rsa_signature_primitive_data_msg__pack(
		&RsaSignaturePrimitiveDataMsg_send, out->buf);

out:
	free_buf(&data.signature);

	if (RsaSignaturePrimitiveDataMsg_recv)
		rsa_signature_primitive_data_msg__free_unpacked(
			RsaSignaturePrimitiveDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_sigprim =
{
	PB_RSA_SIG_PRIMITIVE,
	proto_rsa_sigprim_tester,	/* process_req */
	NULL
};

static int proto_rsa_decprim_tester(struct buffer *in, struct buffer *out,
				   flags_t parsed_flags)
{
	RsaDecryptionPrimitiveDataMsg RsaDecryptionPrimitiveDataMsg_send =
		RSA_DECRYPTION_PRIMITIVE_DATA_MSG__INIT;
	struct rsa_decryption_primitive_data data = { 0 };
	RsaDecryptionPrimitiveDataMsg *RsaDecryptionPrimitiveDataMsg_recv = NULL;
	int ret;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_keygen_en, -EINVAL);

	RsaDecryptionPrimitiveDataMsg_recv =
		rsa_decryption_primitive_data_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaDecryptionPrimitiveDataMsg_recv, -EBADMSG);

	data.modulus = RsaDecryptionPrimitiveDataMsg_recv->modulus;
	data.num = RsaDecryptionPrimitiveDataMsg_recv->num;
	data.num_failures = RsaDecryptionPrimitiveDataMsg_recv->num_failures;
	data.msg.buf = RsaDecryptionPrimitiveDataMsg_recv->msg.data;
	data.msg.len = RsaDecryptionPrimitiveDataMsg_recv->msg.len;
	data.n.buf = RsaDecryptionPrimitiveDataMsg_recv->n.data;
	data.n.len = RsaDecryptionPrimitiveDataMsg_recv->n.len;
	data.e.buf = RsaDecryptionPrimitiveDataMsg_recv->e.data;
	data.e.len = RsaDecryptionPrimitiveDataMsg_recv->e.len;
	data.d.buf = RsaDecryptionPrimitiveDataMsg_recv->d.data;
	data.d.len = RsaDecryptionPrimitiveDataMsg_recv->d.len;
	data.p.buf = RsaDecryptionPrimitiveDataMsg_recv->p.data;
	data.p.len = RsaDecryptionPrimitiveDataMsg_recv->p.len;
	data.q.buf = RsaDecryptionPrimitiveDataMsg_recv->q.data;
	data.q.len = RsaDecryptionPrimitiveDataMsg_recv->q.len;
	data.dmp1.buf = RsaDecryptionPrimitiveDataMsg_recv->dmp1.data;
	data.dmp1.len = RsaDecryptionPrimitiveDataMsg_recv->dmp1.len;
	data.dmq1.buf = RsaDecryptionPrimitiveDataMsg_recv->dmq1.data;
	data.dmq1.len = RsaDecryptionPrimitiveDataMsg_recv->dmq1.len;
	data.iqmp.buf = RsaDecryptionPrimitiveDataMsg_recv->iqmp.data;
	data.iqmp.len = RsaDecryptionPrimitiveDataMsg_recv->iqmp.len;

	CKINT(rsa_backend->rsa_decryption_primitive(&data, parsed_flags));

	RsaDecryptionPrimitiveDataMsg_send.n.data = data.n.buf;
	RsaDecryptionPrimitiveDataMsg_send.n.len = data.n.len;
	RsaDecryptionPrimitiveDataMsg_send.e.data = data.e.buf;
	RsaDecryptionPrimitiveDataMsg_send.e.len = data.e.len;
	RsaDecryptionPrimitiveDataMsg_send.s.data = data.s.buf;
	RsaDecryptionPrimitiveDataMsg_send.s.len = data.s.len;
	RsaDecryptionPrimitiveDataMsg_send.dec_result = data.dec_result;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_decryption_primitive_data_msg__get_packed_size(
			&RsaDecryptionPrimitiveDataMsg_send)));
	rsa_decryption_primitive_data_msg__pack(
		&RsaDecryptionPrimitiveDataMsg_send, out->buf);

out:
	if (RsaDecryptionPrimitiveDataMsg_recv &&
	    RsaDecryptionPrimitiveDataMsg_recv->e.data != data.e.buf)
		free_buf(&data.e);
	if (RsaDecryptionPrimitiveDataMsg_recv &&
	    RsaDecryptionPrimitiveDataMsg_recv->n.data != data.n.buf)
		free_buf(&data.n);
	free_buf(&data.s);

	if (RsaDecryptionPrimitiveDataMsg_recv)
		rsa_decryption_primitive_data_msg__free_unpacked(
			RsaDecryptionPrimitiveDataMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_decprim =
{
	PB_RSA_DEC_PRIMITIVE,
	proto_rsa_decprim_tester,	/* process_req */
	NULL
};

static int proto_rsa_keygen_en_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	RsaKeygenEnMsg RsaKeygenEnMsg_send = RSA_KEYGEN_EN_MSG__INIT;
	RsaKeygenEnMsg *RsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(ebuf)
	BUFFER_INIT(nbuf);
	static uint32_t ref = 1;
	int ret;

	(void)parsed_flags;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_keygen_en, -EINVAL);

	RsaKeygenEnMsg_recv = rsa_keygen_en_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaKeygenEnMsg_recv, -EBADMSG);

	if (proto_rsa_privkey.privkey) {
		ret = -EEXIST;
		goto out;
	}
	ebuf.buf = RsaKeygenEnMsg_recv->ebuf.data;
	ebuf.len = RsaKeygenEnMsg_recv->ebuf.len;
	CKINT(rsa_backend->rsa_keygen_en(&ebuf, RsaKeygenEnMsg_recv->modulus,
					 &proto_rsa_privkey.privkey, &nbuf));

	proto_rsa_privkey.ref = ref++;

	RsaKeygenEnMsg_send.nbuf.data = nbuf.buf;
	RsaKeygenEnMsg_send.nbuf.len = nbuf.len;
	RsaKeygenEnMsg_send.privkey = proto_rsa_privkey.ref;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_keygen_en_msg__get_packed_size(&RsaKeygenEnMsg_send)));
	rsa_keygen_en_msg__pack(&RsaKeygenEnMsg_send, out->buf);

out:
	free_buf(&nbuf);
	free_buf(&ebuf);

	if (RsaKeygenEnMsg_recv)
		rsa_keygen_en_msg__free_unpacked(RsaKeygenEnMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_keygen_en =
{
	PB_RSA_KEYGEN_EN,
	proto_rsa_keygen_en_tester,	/* process_req */
	NULL
};

static int proto_rsa_free_key_tester(struct buffer *in, struct buffer *out,
				      flags_t parsed_flags)
{
	RsaFreeKeyMsg RsaFreeKeyMsg_send = RSA_FREE_KEY_MSG__INIT;
	RsaFreeKeyMsg *RsaFreeKeyMsg_recv = NULL;
	int ret;

	(void)parsed_flags;

	CKNULL(rsa_backend, -EINVAL);
	CKNULL(rsa_backend->rsa_free_key, -EINVAL);

	RsaFreeKeyMsg_recv = rsa_free_key_msg__unpack(NULL, in->len, in->buf);
	CKNULL(RsaFreeKeyMsg_recv, -EBADMSG);

	if (!proto_rsa_privkey.privkey ||
	    proto_rsa_privkey.ref != RsaFreeKeyMsg_recv->privkey) {
		ret = -ENOKEY;
		goto out;
	}

	rsa_backend->rsa_free_key(proto_rsa_privkey.privkey);
	proto_rsa_privkey.privkey = NULL;
	proto_rsa_privkey.ref = 0;

	CKINT(proto_alloc_comm_buf(
		out,
		rsa_free_key_msg__get_packed_size(&RsaFreeKeyMsg_send)));
	rsa_free_key_msg__pack(&RsaFreeKeyMsg_send, out->buf);

out:
	if (RsaFreeKeyMsg_recv)
		rsa_free_key_msg__free_unpacked(RsaFreeKeyMsg_recv, NULL);

	return ret;
}

static struct proto_tester proto_rsa_free_key =
{
	PB_RSA_FREE_KEY,
	proto_rsa_free_key_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_proto_rsa)
static void register_proto_rsa(void)
{
	proto_register_tester(&proto_rsa_keygen, "RSA Keygen");
	proto_register_tester(&proto_rsa_keygen_prime, "RSA Keygen Prime");
	proto_register_tester(&proto_rsa_keygen_prov_prime,
			      "RSA Keygen Provable Prime");
	proto_register_tester(&proto_rsa_siggen, "RSA Siggen");
	proto_register_tester(&proto_rsa_sigver, "RSA Sigver");
	proto_register_tester(&proto_rsa_sigprim, "RSA Signature Primitive");
	proto_register_tester(&proto_rsa_decprim, "RSA Decryption Primitive");
	proto_register_tester(&proto_rsa_keygen_en, "RSA Keygen En");
	proto_register_tester(&proto_rsa_free_key, "RSA Free Key");
}

void register_rsa_impl(struct rsa_backend *implementation)
{
	register_backend(rsa_backend, implementation, "RSA");
}
