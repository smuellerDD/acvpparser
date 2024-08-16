/* Convert individual ACVP test cases into protobuf linear buffers
 *
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

#define _GNU_SOURCE /* secure_getenv */
#include <stdlib.h>

#include "backend_protobuf.h"
#include "protobuf-c/protobuf-c.h"

#include "backend_common.h"
#include "conversion_be_le.h"
#include "parser_sha_mct_helper.h"

#include "aead.pb-c.h"
#include "cshake.pb-c.h"
#include "drbg.pb-c.h"
#include "ecdh.pb-c.h"
#include "ecdsa.pb-c.h"
#include "eddsa.pb-c.h"
#include "hmac.pb-c.h"
#include "kbkdf.pb-c.h"
#include "kda_hkdf.pb-c.h"
#include "kmac.pb-c.h"
#include "ml-dsa.pb-c.h"
#include "ml-kem.pb-c.h"
#include "pbkdf.pb-c.h"
#include "rsa.pb-c.h"
#include "sha.pb-c.h"
#include "sym.pb-c.h"

/******************************************************************************
 * Protobuf interface configuration
 *
 * Select only one option out of the provided options
 ******************************************************************************/

/*
 * STDIN/STDOUT interface
 *
 * This interface writes the test vector data on STDOUT and reads the response
 * from STDIN
 */
#define PROTOBUF_BACKEND_EXIM_STDIN_STDOUT

/*
 * Linux Kernel interface corresponding to the implementation found in the
 * `linux_kernel` directory.
 */
#undef PROTOBUF_BACKEND_EXIM_DEBUGFS

static int pb_alloc_comm_buf(struct buffer *outbuf, size_t datalen,
			     enum pb_message_type type,
			     flags_t parsed_flags)
{
	pb_header_t header = {
		.message_type = le_bswap32(type),
		.parsed_flags = le_bswap64(parsed_flags),
		.datalen = le_bswap64(datalen),
	};
	char *envstr = NULL;
	int ret;

	envstr = secure_getenv("ACVPPARSER_PROTOBUF_IMPL");
	if (envstr) {
		unsigned long val = strtoul(envstr, NULL, 10);

		if (val > UINT32_MAX) {
			ret = -EINVAL;
			goto out;
		}
		header.implementation = le_bswap32((uint32_t)val);
	} else {
		header.implementation = 0;
	}

	CKINT(alloc_buf(datalen + PB_BUF_WRITE_HEADER_SZ, outbuf));

	memcpy(outbuf->buf, &header, PB_BUF_WRITE_HEADER_SZ);

	/*
	 * Move the pointer forward to avoid users to fiddle around with them -
	 * it will be undone in the send/receive function.
	 */
	outbuf->buf += PB_BUF_WRITE_HEADER_SZ;

out:
	return ret;
}

static int pb_received_data_check(pb_header_t *header,
				  enum pb_message_type type,
				  flags_t parsed_flags)
{
	if (header->parsed_flags != parsed_flags ||
	    header->message_type != type)
		return -EINVAL;

	return 0;
}

static int pb_header_sanity_check(pb_header_t *header)
{
	if (!header)
		return -EINVAL;

	header->message_type = le_bswap32(header->message_type);
	header->parsed_flags = le_bswap64(header->parsed_flags);
	header->datalen = le_bswap64(header->datalen);

	if (header->datalen > ACVP_MAXDATA) {
		logger(LOGGER_ERR, "Received data too large: %zu\n",
		       header->datalen);
		return -EOVERFLOW;
	}

	return 0;
}


#ifdef PROTOBUF_BACKEND_EXIM_STDIN_STDOUT
#include <unistd.h>
/*
 * This IPC wrapper uses STDIN/STDOUT for the input/output of data.
 *
 * The worker may easily be adopted when using different file descriptors.
 */
static int pb_send_receive_data_implementation(struct buffer *send,
					       struct buffer *received,
					       pb_header_t *header)
{
	ssize_t data_processed;
	int input_fd = 0; /* stdin */
	int output_fd = 1; /* stdout */
	int ret;

	data_processed = write(output_fd, send->buf, send->len);
	if (data_processed < 0) {
		ret = -errno;
		goto out;
	}
	if ((size_t)data_processed != send->len) {
		ret = -EOVERFLOW;
		goto out;
	}

	/* Read the header */
	CKINT(read_complete(input_fd, (uint8_t *)header,
			    PB_BUF_WRITE_HEADER_SZ));

	/* Initial check of header */
	CKINT(pb_header_sanity_check(header));

	/* Allocate requested amount of memory */
	CKINT(alloc_buf(header->datalen, received));

	/* Read the requested amount memory */
	CKINT(read_complete(input_fd, received->buf, header->datalen));

out:
	/* EOF is no error */
	if (ret == -ESPIPE)
		ret = 0;

	return ret;
}

#elif defined(PROTOBUF_BACKEND_EXIM_DEBUGFS)

#include <fcntl.h>
#include <unistd.h>

#define ACVPPROTO_DEBUGFS_FILE "/sys/kernel/debug/acvp_proto/data"
/*
 * This IPC wrapper uses the Linux kernel DebugFS for the input/output of data.
 */
static int debugfs_fd = -1;

static int pb_send_receive_data_implementation(struct buffer *send,
					       struct buffer *received,
					       pb_header_t *header)
{
	ssize_t data_processed;
	int ret;

	if (debugfs_fd < 0) {
		debugfs_fd = open(ACVPPROTO_DEBUGFS_FILE, O_RDWR | O_CLOEXEC);
		if (debugfs_fd < 0) {
			ret = -errno;
			logger(LOGGER_ERR,
			       "Cannot open the ACVP-Proto DebugFS %s file - error: %d\n", ACVPPROTO_DEBUGFS_FILE, ret);
			goto out;
		}
	}

	data_processed = write(debugfs_fd, send->buf, send->len);
	if (data_processed < 0) {
		ret = -errno;
		goto out;
	}
	if ((size_t)data_processed != send->len) {
		ret = -EOVERFLOW;
		goto out;
	}

	/* Read the header */
	CKINT(read_complete(debugfs_fd, (uint8_t *)header,
			    PB_BUF_WRITE_HEADER_SZ));

	/* Initial check of header */
	CKINT(pb_header_sanity_check(header));

	/* Allocate requested amount of memory */
	CKINT(alloc_buf(header->datalen, received));

	/* Read the requested amount memory */
	CKINT(read_complete(debugfs_fd, received->buf, header->datalen));

out:
	/* EOF is no error */
	if (ret == -ESPIPE)
		ret = 0;

	return ret;
}

#else
#error "Enable export/import interface"
#endif

static int pb_send_receive_data(struct buffer *send, struct buffer *received,
				pb_header_t *header)
{
	int ret;

	CKNULL(send, -EINVAL);
	CKNULL(received, -EINVAL);
	CKNULL(header, -EINVAL);

	/* Undo the pointer update from the allocation logic */
	send->buf -= PB_BUF_WRITE_HEADER_SZ;

	CKINT(pb_send_receive_data_implementation(send, received, header));

out:
	return ret;
}

static int pb_alloc_copy(struct buffer *dst, ProtobufCBinaryData *src)
{
	int ret = 0;

	CKNULL(src, -EINVAL);
	CKNULL(dst, -EINVAL);

	if (src->len) {
		CKINT(alloc_buf(src->len, dst));
		memcpy(dst->buf, src->data, src->len);
	}
out:
	return ret;
}

/************************************************
 * Symmetric cipher interface functions
 ************************************************/
static int pb_data_crypt(struct sym_data *data, flags_t parsed_flags,
			 enum pb_message_type type)
{
	pb_header_t header;
	SymDataMsg SymDataMsg_send = SYM_DATA_MSG__INIT;
	SymDataMsg *SymDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	SymDataMsg_send.key.data = data->key.buf;
	SymDataMsg_send.key.len = data->key.len;
	SymDataMsg_send.iv.data = data->iv.buf;
	SymDataMsg_send.iv.len = data->iv.len;
	SymDataMsg_send.cipher = data->cipher;
	SymDataMsg_send.data.data = data->data.buf;
	SymDataMsg_send.data.len = data->data.len;
	SymDataMsg_send.data_len_bits = data->data_len_bits;
	SymDataMsg_send.xts_sequence_no = data->xts_sequence_no;
	SymDataMsg_send.xts_data_unit_len = data->xts_data_unit_len;
	/* inner_loop_final_cj1 is output */
	/* integrity_error is output */
	SymDataMsg_send.kwcipher.data = data->kwcipher.buf;
	SymDataMsg_send.kwcipher.len = data->kwcipher.len;

	CKINT(pb_alloc_comm_buf(&send,
				sym_data_msg__get_packed_size(&SymDataMsg_send),
				type, parsed_flags));
	sym_data_msg__pack(&SymDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, type, parsed_flags));
	SymDataMsg_recv = sym_data_msg__unpack(NULL, received.len,
					       received.buf);
	CKNULL(SymDataMsg_recv, -EBADMSG);

	if (SymDataMsg_recv->data.len > data->data.len) {
		/* KW Enc increases the data buffer */
		free_buf(&data->data);
		CKINT(pb_alloc_copy(&data->data, &SymDataMsg_recv->data));
	} else {
		memcpy(data->data.buf, SymDataMsg_recv->data.data,
		       SymDataMsg_recv->data.len);
		data->data.len = SymDataMsg_recv->data.len;
	}

	CKINT(pb_alloc_copy(&data->inner_loop_final_cj1,
			    &SymDataMsg_recv->inner_loop_final_cj1));
	data->integrity_error = SymDataMsg_recv->integrity_error;

out:
	free_buf(&send);
	free_buf(&received);

	if (SymDataMsg_recv)
		sym_data_msg__free_unpacked(SymDataMsg_recv, NULL);

	return ret;
}

static int pb_sym_encrypt(struct sym_data *data, flags_t parsed_flags)
{
	return pb_data_crypt(data, parsed_flags, PB_SYM_ENCRYPT);
}

static int pb_sym_decrypt(struct sym_data *data, flags_t parsed_flags)
{
	return pb_data_crypt(data, parsed_flags, PB_SYM_DECRYPT);
}

static int pb_mct_init(struct sym_data *data, flags_t parsed_flags)
{
	return pb_data_crypt(data, parsed_flags, PB_SYM_MCT_INIT);
}

static int pb_mct_update(struct sym_data *data, flags_t parsed_flags)
{
	return pb_data_crypt(data, parsed_flags, PB_SYM_MCT_UPDATE);
}

static int pb_mct_final(struct sym_data *data, flags_t parsed_flags)
{
	return pb_data_crypt(data, parsed_flags, PB_SYM_MCT_FINAL);
}

static struct sym_backend pb_sym =
{
	pb_sym_encrypt,		/* encrypt */
	pb_sym_decrypt,		/* decrypt */
	pb_mct_init,		/* mct_init */
	pb_mct_update,		/* mct_update */
	pb_mct_final,		/* mct_fini */
};

ACVP_DEFINE_CONSTRUCTOR(pb_sym_backend)
static void pb_sym_backend(void)
{
	register_sym_impl(&pb_sym);
}

/************************************************
 * SHA cipher interface functions
 ************************************************/
static int _pb_sha_generate(struct sha_data *data, flags_t parsed_flags,
			    enum pb_message_type type)
{
	pb_header_t header;
	ShaDataMsg ShaDataMsg_send = SHA_DATA_MSG__INIT;
	ShaDataMsg *ShaDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	ShaDataMsg_send.msg.data = data->msg.buf;
	ShaDataMsg_send.msg.len = data->msg.len;
	ShaDataMsg_send.bitlen = data->bitlen;
	ShaDataMsg_send.ldt_expansion_size = data->ldt_expansion_size;
	ShaDataMsg_send.outlen = data->outlen;
	ShaDataMsg_send.minoutlen = data->minoutlen;
	ShaDataMsg_send.maxoutlen = data->maxoutlen;
	/* mac is output */
	ShaDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(&send,
				sha_data_msg__get_packed_size(&ShaDataMsg_send),
				type, parsed_flags));
	sha_data_msg__pack(&ShaDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, type, parsed_flags));
	ShaDataMsg_recv = sha_data_msg__unpack(NULL, received.len,
					       received.buf);
	CKNULL(ShaDataMsg_recv, -EBADMSG);

	CKINT(alloc_buf(ShaDataMsg_recv->mac.len, &data->mac));
	memcpy(data->mac.buf, ShaDataMsg_recv->mac.data, data->mac.len);
	data->outlen = ShaDataMsg_recv->outlen;

out:
	free_buf(&send);
	free_buf(&received);

	if (ShaDataMsg_recv)
		sha_data_msg__free_unpacked(ShaDataMsg_recv, NULL);

	return ret;
}

static int pb_sha_generate(struct sha_data *data, flags_t parsed_flags)
{
	return _pb_sha_generate(data, parsed_flags, PB_SHA);
}

static int pb_sha_inner_loop_generate(struct sha_data *data, flags_t parsed_flags)
{
	return _pb_sha_generate(data, parsed_flags, PB_SHA_MCP_INNER_LOOP);
}

static struct sha_backend pb_sha =
{
	pb_sha_generate,   /* hash_generate */
	pb_sha_inner_loop_generate,
};

ACVP_DEFINE_CONSTRUCTOR(pb_sha_backend)
static void pb_sha_backend(void)
{
	register_sha_impl(&pb_sha);
}

/************************************************
 * AEAD cipher interface functions
 ************************************************/
static int pb_aead_data_crypt(struct aead_data *data, flags_t parsed_flags,
			      enum pb_message_type type)
{
	pb_header_t header;
	AeadDataMsg AeadDataMsg_send = AEAD_DATA_MSG__INIT;
	AeadDataMsg *AeadDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	AeadDataMsg_send.key.data = data->key.buf;
	AeadDataMsg_send.key.len = data->key.len;
	AeadDataMsg_send.iv.data = data->iv.buf;
	AeadDataMsg_send.iv.len = data->iv.len;
	AeadDataMsg_send.ivlen = data->ivlen;
	AeadDataMsg_send.assoc.data = data->assoc.buf;
	AeadDataMsg_send.assoc.len = data->assoc.len;
	AeadDataMsg_send.tag.data = data->tag.buf;
	AeadDataMsg_send.tag.len = data->tag.len;
	AeadDataMsg_send.taglen = data->taglen;
	AeadDataMsg_send.cipher = data->cipher;
	AeadDataMsg_send.ptlen = data->ptlen;
	AeadDataMsg_send.data.data = data->data.buf;
	AeadDataMsg_send.data.len = data->data.len;
	/* integrity_error is output */

	CKINT(pb_alloc_comm_buf(&send,
				aead_data_msg__get_packed_size(&AeadDataMsg_send),
				type, parsed_flags));
	aead_data_msg__pack(&AeadDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, type, parsed_flags));
	AeadDataMsg_recv = aead_data_msg__unpack(NULL, received.len,
						 received.buf);
	CKNULL(AeadDataMsg_recv, -EBADMSG);

	memcpy(data->data.buf, AeadDataMsg_recv->data.data,
	       (data->data.len > AeadDataMsg_recv->data.len) ?
	        AeadDataMsg_recv->data.len : data->data.len);
	if (!data->iv.len)
		CKINT(pb_alloc_copy(&data->iv, &AeadDataMsg_recv->iv));
	if (!data->tag.len)
		CKINT(pb_alloc_copy(&data->tag, &AeadDataMsg_recv->tag));

	data->integrity_error = AeadDataMsg_recv->integrity_error;

out:
	free_buf(&send);
	free_buf(&received);

	if (AeadDataMsg_recv)
		aead_data_msg__free_unpacked(AeadDataMsg_recv, NULL);

	return ret;
}

static int pb_gcm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	return pb_aead_data_crypt(data, parsed_flags, PB_AEAD_GCM_ENCRYPT);
}

static int pb_aead_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	return pb_aead_data_crypt(data, parsed_flags, PB_AEAD_GCM_DECRYPT);
}

static int pb_ccm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	return pb_aead_data_crypt(data, parsed_flags, PB_AEAD_CCM_ENCRYPT);
}

static int pb_ccm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	return pb_aead_data_crypt(data, parsed_flags, PB_AEAD_CCM_DECRYPT);
}

static struct aead_backend kcapi_aead =
{
	pb_gcm_encrypt,	/* gcm_encrypt */
	pb_aead_decrypt,/* gcm_decrypt */
	pb_ccm_encrypt,	/* ccm_encrypt */
	pb_ccm_decrypt,	/* ccm_decrypt */
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_aead_backend)
static void kcapi_aead_backend(void)
{
	register_aead_impl(&kcapi_aead);
}

/************************************************
 * cSHAKE cipher interface functions
 ************************************************/

static int pb_cshake_generate(struct cshake_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	CshakeDataMsg CshakeDataMsg_send = CSHAKE_DATA_MSG__INIT;
	CshakeDataMsg *CshakeDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	CshakeDataMsg_send.cipher = data->cipher;
	CshakeDataMsg_send.msg.data = data->msg.buf;
	CshakeDataMsg_send.msg.len = data->msg.len;
	CshakeDataMsg_send.bitlen = data->bitlen;
	CshakeDataMsg_send.outlen = data->outlen;
	CshakeDataMsg_send.minoutlen = data->minoutlen;
	CshakeDataMsg_send.maxoutlen = data->maxoutlen;
	CshakeDataMsg_send.function_name.data = data->function_name.buf;
	CshakeDataMsg_send.function_name.len = data->function_name.len;
	CshakeDataMsg_send.customization.data = data->customization.buf;
	CshakeDataMsg_send.customization.len = data->customization.len;
	/* mac is output */

	CKINT(pb_alloc_comm_buf(
		&send, cshake_data_msg__get_packed_size(&CshakeDataMsg_send),
		PB_CSHAKE, parsed_flags));
	cshake_data_msg__pack(&CshakeDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_CSHAKE, parsed_flags));
	CshakeDataMsg_recv = cshake_data_msg__unpack(NULL, received.len,
						     received.buf);
	CKNULL(CshakeDataMsg_recv, -EBADMSG);

	CKINT(alloc_buf(CshakeDataMsg_recv->mac.len, &data->mac));
	memcpy(data->mac.buf, CshakeDataMsg_recv->mac.data, data->mac.len);

out:
	free_buf(&send);
	free_buf(&received);

	if (CshakeDataMsg_recv)
		cshake_data_msg__free_unpacked(CshakeDataMsg_recv, NULL);

	return ret;
}

static struct cshake_backend pb_cshake_backend =
{
	pb_cshake_generate,	/* cshake_generate */
};

ACVP_DEFINE_CONSTRUCTOR(pb_cshake_backend_c)
static void pb_cshake_backend_c(void)
{
	register_cshake_impl(&pb_cshake_backend);
}

/************************************************
 * HMAC cipher interface functions
 ************************************************/

static int pb_hmac_generate(struct hmac_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	HmacDataMsg HmacDataMsg_send = HMAC_DATA_MSG__INIT;
	HmacDataMsg *HmacDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	HmacDataMsg_send.key.data = data->key.buf;
	HmacDataMsg_send.key.len = data->key.len;
	HmacDataMsg_send.msg.data = data->msg.buf;
	HmacDataMsg_send.msg.len = data->msg.len;
	HmacDataMsg_send.maclen = data->maclen;
	HmacDataMsg_send.cipher = data->cipher;
	/* mac is output */

	CKINT(pb_alloc_comm_buf(
		&send, hmac_data_msg__get_packed_size(&HmacDataMsg_send),
		PB_HMAC, parsed_flags));
	hmac_data_msg__pack(&HmacDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_HMAC, parsed_flags));
	HmacDataMsg_recv = hmac_data_msg__unpack(NULL, received.len,
						 received.buf);
	CKNULL(HmacDataMsg_recv, -EBADMSG);

	CKINT(alloc_buf(HmacDataMsg_recv->mac.len, &data->mac));
	memcpy(data->mac.buf, HmacDataMsg_recv->mac.data, data->mac.len);

out:
	free_buf(&send);
	free_buf(&received);

	if (HmacDataMsg_recv)
		hmac_data_msg__free_unpacked(HmacDataMsg_recv, NULL);

	return ret;
}

static struct hmac_backend pb_hmac_backend =
{
	pb_hmac_generate,	/* hmac_generate */
};

ACVP_DEFINE_CONSTRUCTOR(pb_hmac_backend_c)
static void pb_hmac_backend_c(void)
{
	register_hmac_impl(&pb_hmac_backend);
}

/************************************************
 * KMAC cipher interface functions
 ************************************************/

static int pb_kmac_internal(struct kmac_data *data, flags_t parsed_flags,
			    enum pb_message_type type)
{
	pb_header_t header;
	KmacDataMsg KmacDataMsg_send = KMAC_DATA_MSG__INIT;
	KmacDataMsg *KmacDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	KmacDataMsg_send.key.data = data->key.buf;
	KmacDataMsg_send.key.len = data->key.len;
	KmacDataMsg_send.msg.data = data->msg.buf;
	KmacDataMsg_send.msg.len = data->msg.len;
	KmacDataMsg_send.maclen = data->maclen;
	KmacDataMsg_send.keylen = data->keylen;
	/* mac is output for generate */
	if (type == PB_KMAC_VERIFY) {
		KmacDataMsg_send.mac.data = data->mac.buf;
		KmacDataMsg_send.mac.len = data->mac.len;
	}
	KmacDataMsg_send.customization.data = data->customization.buf;
	KmacDataMsg_send.customization.len = data->customization.len;
	/* verify_result is output */
	KmacDataMsg_send.xof_enabled = data->xof_enabled;
	KmacDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, kmac_data_msg__get_packed_size(&KmacDataMsg_send),
		type, parsed_flags));
	kmac_data_msg__pack(&KmacDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, type, parsed_flags));
	KmacDataMsg_recv = kmac_data_msg__unpack(NULL, received.len,
						 received.buf);
	CKNULL(KmacDataMsg_recv, -EBADMSG);

	if (type == PB_KMAC_GENERATE) {
		CKINT(pb_alloc_copy(&data->mac, &KmacDataMsg_recv->mac));
	} else {
		data->verify_result = KmacDataMsg_recv->verify_result;
	}

out:
	free_buf(&send);
	free_buf(&received);

	if (KmacDataMsg_recv)
		kmac_data_msg__free_unpacked(KmacDataMsg_recv, NULL);

	return ret;
}

static int pb_kmac_generate(struct kmac_data *data, flags_t parsed_flags)
{
	return pb_kmac_internal(data, parsed_flags, PB_KMAC_GENERATE);
}

static int pb_kmac_verify(struct kmac_data *data, flags_t parsed_flags)
{
	return pb_kmac_internal(data, parsed_flags, PB_KMAC_VERIFY);
}

static struct kmac_backend pb_kmac_backend =
{
	pb_kmac_generate,	/* kmac_generate */
	pb_kmac_verify
};

ACVP_DEFINE_CONSTRUCTOR(pb_kmac_backend_c)
static void pb_kmac_backend_c(void)
{
	register_kmac_impl(&pb_kmac_backend);
}

/************************************************
 * RSA cipher interface functions
 ************************************************/

struct pb_privkey_buf {
	uint32_t ref;
};

static int pb_rsa_keygen(struct rsa_keygen_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	RsaKeygenDataMsg RsaKeygenDataMsg_send = RSA_KEYGEN_DATA_MSG__INIT;
	RsaKeygenDataMsg *RsaKeygenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	RsaKeygenDataMsg_send.modulus = data->modulus;
	RsaKeygenDataMsg_send.e.data = data->e.buf;
	RsaKeygenDataMsg_send.e.len = data->e.len;
	RsaKeygenDataMsg_send.bitlen_in = data->bitlen_in;

	CKINT(pb_alloc_comm_buf(
		&send, rsa_keygen_data_msg__get_packed_size(&RsaKeygenDataMsg_send),
		PB_RSA_KEYGEN, parsed_flags));
	rsa_keygen_data_msg__pack(&RsaKeygenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_KEYGEN, parsed_flags));
	RsaKeygenDataMsg_recv = rsa_keygen_data_msg__unpack(NULL, received.len,
							    received.buf);
	CKNULL(RsaKeygenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->n, &RsaKeygenDataMsg_recv->n));
	CKINT(pb_alloc_copy(&data->d, &RsaKeygenDataMsg_recv->d));
	CKINT(pb_alloc_copy(&data->p, &RsaKeygenDataMsg_recv->p));
	CKINT(pb_alloc_copy(&data->q, &RsaKeygenDataMsg_recv->q));
	if (!data->e.len)
		CKINT(pb_alloc_copy(&data->e, &RsaKeygenDataMsg_recv->e));

	CKINT(pb_alloc_copy(&data->xp, &RsaKeygenDataMsg_recv->xp));
	CKINT(pb_alloc_copy(&data->xp1, &RsaKeygenDataMsg_recv->xp1));
	CKINT(pb_alloc_copy(&data->xp2, &RsaKeygenDataMsg_recv->xp2));
	CKINT(pb_alloc_copy(&data->xq, &RsaKeygenDataMsg_recv->xq));
	CKINT(pb_alloc_copy(&data->xq1, &RsaKeygenDataMsg_recv->xq1));
	CKINT(pb_alloc_copy(&data->xq2, &RsaKeygenDataMsg_recv->xq2));
	data->bitlen[0] = RsaKeygenDataMsg_recv->bitlen1;
	data->bitlen[1] = RsaKeygenDataMsg_recv->bitlen2;
	data->bitlen[2] = RsaKeygenDataMsg_recv->bitlen3;
	data->bitlen[3] = RsaKeygenDataMsg_recv->bitlen4;

	CKINT(pb_alloc_copy(&data->dmp1, &RsaKeygenDataMsg_recv->dmp1));
	CKINT(pb_alloc_copy(&data->dmq1, &RsaKeygenDataMsg_recv->dmq1));
	CKINT(pb_alloc_copy(&data->iqmp, &RsaKeygenDataMsg_recv->iqmp));

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaKeygenDataMsg_recv)
		rsa_keygen_data_msg__free_unpacked(RsaKeygenDataMsg_recv, NULL);

	return ret;
}

static int pb_rsa_keygen_prime(struct rsa_keygen_prime_data *data,
			       flags_t parsed_flags)
{
	pb_header_t header;
	RsaKeygenPrimeDataMsg RsaKeygenPrimeDataMsg_send =
		RSA_KEYGEN_PRIME_DATA_MSG__INIT;
	RsaKeygenPrimeDataMsg *RsaKeygenPrimeDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	RsaKeygenPrimeDataMsg_send.modulus = data->modulus;
	RsaKeygenPrimeDataMsg_send.p.data = data->p.buf;
	RsaKeygenPrimeDataMsg_send.p.len = data->p.len;
	RsaKeygenPrimeDataMsg_send.q.data = data->q.buf;
	RsaKeygenPrimeDataMsg_send.q.len = data->q.len;
	RsaKeygenPrimeDataMsg_send.e.data = data->e.buf;
	RsaKeygenPrimeDataMsg_send.e.len = data->e.len;

	CKINT(pb_alloc_comm_buf(
		&send, rsa_keygen_prime_data_msg__get_packed_size(
			&RsaKeygenPrimeDataMsg_send),
		PB_RSA_KEYGEN_PRIME, parsed_flags));
	rsa_keygen_prime_data_msg__pack(&RsaKeygenPrimeDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_KEYGEN_PRIME,
				     parsed_flags));
	RsaKeygenPrimeDataMsg_recv = rsa_keygen_prime_data_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(RsaKeygenPrimeDataMsg_recv, -EBADMSG);

	data->keygen_success = RsaKeygenPrimeDataMsg_recv->keygen_success;

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaKeygenPrimeDataMsg_recv)
		rsa_keygen_prime_data_msg__free_unpacked(
			RsaKeygenPrimeDataMsg_recv, NULL);

	return ret;
}

static int pb_rsa_keygen_prov_prime(struct rsa_keygen_prov_prime_data *data,
				    flags_t parsed_flags)
{
	pb_header_t header;
	RsaKeygenProvPrimeDataMsg RsaKeygenProvPrimeDataMsg_send =
		RSA_KEYGEN_PROV_PRIME_DATA_MSG__INIT;
	RsaKeygenProvPrimeDataMsg *RsaKeygenProvPrimeDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	RsaKeygenProvPrimeDataMsg_send.modulus = data->modulus;
	RsaKeygenProvPrimeDataMsg_send.seed.data = data->seed.buf;
	RsaKeygenProvPrimeDataMsg_send.seed.len = data->seed.len;
	RsaKeygenProvPrimeDataMsg_send.e.data = data->e.buf;
	RsaKeygenProvPrimeDataMsg_send.e.len = data->e.len;
	RsaKeygenProvPrimeDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, rsa_keygen_prov_prime_data_msg__get_packed_size(
			&RsaKeygenProvPrimeDataMsg_send),
		PB_RSA_KEYGEN_PROV_PRIME, parsed_flags));
	rsa_keygen_prov_prime_data_msg__pack(&RsaKeygenProvPrimeDataMsg_send,
					     send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_KEYGEN_PROV_PRIME,
				     parsed_flags));
	RsaKeygenProvPrimeDataMsg_recv = rsa_keygen_prov_prime_data_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(RsaKeygenProvPrimeDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->n, &RsaKeygenProvPrimeDataMsg_recv->n));
	CKINT(pb_alloc_copy(&data->d, &RsaKeygenProvPrimeDataMsg_recv->d));
	CKINT(pb_alloc_copy(&data->p, &RsaKeygenProvPrimeDataMsg_recv->p));
	CKINT(pb_alloc_copy(&data->q, &RsaKeygenProvPrimeDataMsg_recv->q));
	CKINT(pb_alloc_copy(&data->seed, &RsaKeygenProvPrimeDataMsg_recv->seed));
	CKINT(pb_alloc_copy(&data->e, &RsaKeygenProvPrimeDataMsg_recv->e));

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaKeygenProvPrimeDataMsg_recv)
		rsa_keygen_prov_prime_data_msg__free_unpacked(
			RsaKeygenProvPrimeDataMsg_recv, NULL);

	return ret;
}

static int pb_rsa_siggen(struct rsa_siggen_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	RsaSiggenDataMsg RsaSiggenDataMsg_send = RSA_SIGGEN_DATA_MSG__INIT;
	RsaSiggenDataMsg *RsaSiggenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	RsaSiggenDataMsg_send.modulus = data->modulus;
	RsaSiggenDataMsg_send.cipher = data->cipher;
	RsaSiggenDataMsg_send.saltlen = data->saltlen;
	RsaSiggenDataMsg_send.e.data = data->e.buf;
	RsaSiggenDataMsg_send.e.len = data->e.len;
	RsaSiggenDataMsg_send.msg.data = data->msg.buf;
	RsaSiggenDataMsg_send.msg.len = data->msg.len;
	/* sig is output */
	RsaSiggenDataMsg_send.n.data = data->n.buf;
	RsaSiggenDataMsg_send.n.len = data->n.len;
	if (data->privkey) {
		struct pb_privkey_buf *priv = data->privkey;

		RsaSiggenDataMsg_send.privkey = priv->ref;
	}

	CKINT(pb_alloc_comm_buf(
		&send, rsa_siggen_data_msg__get_packed_size(&RsaSiggenDataMsg_send),
		PB_RSA_SIGGEN, parsed_flags));
	rsa_siggen_data_msg__pack(&RsaSiggenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_SIGGEN, parsed_flags));
	RsaSiggenDataMsg_recv = rsa_siggen_data_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(RsaSiggenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->sig, &RsaSiggenDataMsg_recv->sig));
	CKINT(pb_alloc_copy(&data->n, &RsaSiggenDataMsg_recv->n));
	CKINT(pb_alloc_copy(&data->e, &RsaSiggenDataMsg_recv->e));

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaSiggenDataMsg_recv)
		rsa_siggen_data_msg__free_unpacked(RsaSiggenDataMsg_recv, NULL);

	return ret;
}

static int pb_rsa_sigver(struct rsa_sigver_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	RsaSigverDataMsg RsaSigverDataMsg_send = RSA_SIGVER_DATA_MSG__INIT;
	RsaSigverDataMsg *RsaSigverDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	RsaSigverDataMsg_send.modulus = data->modulus;
	RsaSigverDataMsg_send.cipher = data->cipher;
	RsaSigverDataMsg_send.saltlen = data->saltlen;
	RsaSigverDataMsg_send.n.data = data->n.buf;
	RsaSigverDataMsg_send.n.len = data->n.len;
	RsaSigverDataMsg_send.e.data = data->e.buf;
	RsaSigverDataMsg_send.e.len = data->e.len;
	RsaSigverDataMsg_send.msg.data = data->msg.buf;
	RsaSigverDataMsg_send.msg.len = data->msg.len;
	RsaSigverDataMsg_send.sig.data = data->sig.buf;
	RsaSigverDataMsg_send.sig.len = data->sig.len;
	/* sig_result is output */

	CKINT(pb_alloc_comm_buf(
		&send, rsa_sigver_data_msg__get_packed_size(&RsaSigverDataMsg_send),
		PB_RSA_SIGVER, parsed_flags));
	rsa_sigver_data_msg__pack(&RsaSigverDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_SIGVER, parsed_flags));
	RsaSigverDataMsg_recv = rsa_sigver_data_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(RsaSigverDataMsg_recv, -EBADMSG);

	data->sig_result = RsaSigverDataMsg_recv->sig_result;

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaSigverDataMsg_recv)
		rsa_sigver_data_msg__free_unpacked(RsaSigverDataMsg_recv, NULL);

	return ret;
}

static int pb_rsa_sigprim(struct rsa_signature_primitive_data *data,
			  flags_t parsed_flags)
{
	pb_header_t header;
	RsaSignaturePrimitiveDataMsg RsaSignaturePrimitiveDataMsg_send =
		RSA_SIGNATURE_PRIMITIVE_DATA_MSG__INIT;
	RsaSignaturePrimitiveDataMsg *RsaSignaturePrimitiveDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	RsaSignaturePrimitiveDataMsg_send.msg.data = data->msg.buf;
	RsaSignaturePrimitiveDataMsg_send.msg.len = data->msg.len;
	RsaSignaturePrimitiveDataMsg_send.n.data = data->n.buf;
	RsaSignaturePrimitiveDataMsg_send.n.len = data->n.len;
	RsaSignaturePrimitiveDataMsg_send.e.data = data->e.buf;
	RsaSignaturePrimitiveDataMsg_send.e.len = data->e.len;
	RsaSignaturePrimitiveDataMsg_send.d.data = data->d.buf;
	RsaSignaturePrimitiveDataMsg_send.d.len = data->d.len;
	RsaSignaturePrimitiveDataMsg_send.p.data = data->p.buf;
	RsaSignaturePrimitiveDataMsg_send.p.len = data->p.len;
	RsaSignaturePrimitiveDataMsg_send.q.data = data->q.buf;
	RsaSignaturePrimitiveDataMsg_send.q.len = data->q.len;
	RsaSignaturePrimitiveDataMsg_send.dmp1.data = data->dmp1.buf;
	RsaSignaturePrimitiveDataMsg_send.dmp1.len = data->dmp1.len;
	RsaSignaturePrimitiveDataMsg_send.dmq1.data = data->dmq1.buf;
	RsaSignaturePrimitiveDataMsg_send.dmq1.len = data->dmq1.len;
	RsaSignaturePrimitiveDataMsg_send.iqmp.data = data->iqmp.buf;
	RsaSignaturePrimitiveDataMsg_send.iqmp.len = data->iqmp.len;

	CKINT(pb_alloc_comm_buf(
		&send, rsa_signature_primitive_data_msg__get_packed_size(
			&RsaSignaturePrimitiveDataMsg_send),
		PB_RSA_SIG_PRIMITIVE, parsed_flags));
	rsa_signature_primitive_data_msg__pack(
		&RsaSignaturePrimitiveDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_SIG_PRIMITIVE,
				     parsed_flags));
	RsaSignaturePrimitiveDataMsg_recv =
		rsa_signature_primitive_data_msg__unpack(
			NULL, received.len, received.buf);
	CKNULL(RsaSignaturePrimitiveDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->signature,
			    &RsaSignaturePrimitiveDataMsg_recv->signature));
	data->sig_result = RsaSignaturePrimitiveDataMsg_recv->sig_result;

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaSignaturePrimitiveDataMsg_recv)
		rsa_signature_primitive_data_msg__free_unpacked(
			RsaSignaturePrimitiveDataMsg_recv, NULL);

	return ret;
}

static int pb_rsa_decprim(struct rsa_decryption_primitive_data *data,
			  flags_t parsed_flags)
{
	pb_header_t header;
	RsaDecryptionPrimitiveDataMsg RsaDecryptionPrimitiveDataMsg_send =
		RSA_DECRYPTION_PRIMITIVE_DATA_MSG__INIT;
	RsaDecryptionPrimitiveDataMsg *RsaDecryptionPrimitiveDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	RsaDecryptionPrimitiveDataMsg_send.modulus = data->modulus;
	RsaDecryptionPrimitiveDataMsg_send.num = data->num;
	RsaDecryptionPrimitiveDataMsg_send.num_failures = data->num_failures;
	RsaDecryptionPrimitiveDataMsg_send.msg.data = data->msg.buf;
	RsaDecryptionPrimitiveDataMsg_send.msg.len = data->msg.len;
	RsaDecryptionPrimitiveDataMsg_send.n.data = data->n.buf;
	RsaDecryptionPrimitiveDataMsg_send.n.len = data->n.len;
	RsaDecryptionPrimitiveDataMsg_send.e.data = data->e.buf;
	RsaDecryptionPrimitiveDataMsg_send.e.len = data->e.len;
	RsaDecryptionPrimitiveDataMsg_send.d.data = data->d.buf;
	RsaDecryptionPrimitiveDataMsg_send.d.len = data->d.len;
	RsaDecryptionPrimitiveDataMsg_send.p.data = data->p.buf;
	RsaDecryptionPrimitiveDataMsg_send.p.len = data->p.len;
	RsaDecryptionPrimitiveDataMsg_send.q.data = data->q.buf;
	RsaDecryptionPrimitiveDataMsg_send.q.len = data->q.len;
	RsaDecryptionPrimitiveDataMsg_send.dmp1.data = data->dmp1.buf;
	RsaDecryptionPrimitiveDataMsg_send.dmp1.len = data->dmp1.len;
	RsaDecryptionPrimitiveDataMsg_send.dmq1.data = data->dmq1.buf;
	RsaDecryptionPrimitiveDataMsg_send.dmq1.len = data->dmq1.len;
	RsaDecryptionPrimitiveDataMsg_send.iqmp.data = data->iqmp.buf;
	RsaDecryptionPrimitiveDataMsg_send.iqmp.len = data->iqmp.len;

	CKINT(pb_alloc_comm_buf(
		&send, rsa_decryption_primitive_data_msg__get_packed_size(
			&RsaDecryptionPrimitiveDataMsg_send),
		PB_RSA_DEC_PRIMITIVE, parsed_flags));
	rsa_decryption_primitive_data_msg__pack(
		&RsaDecryptionPrimitiveDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_DEC_PRIMITIVE,
				     parsed_flags));
	RsaDecryptionPrimitiveDataMsg_recv =
		rsa_decryption_primitive_data_msg__unpack(
			NULL, received.len, received.buf);
	CKNULL(RsaDecryptionPrimitiveDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->n, &RsaDecryptionPrimitiveDataMsg_recv->n));
	CKINT(pb_alloc_copy(&data->e, &RsaDecryptionPrimitiveDataMsg_recv->e));
	CKINT(pb_alloc_copy(&data->s, &RsaDecryptionPrimitiveDataMsg_recv->s));
	data->dec_result = RsaDecryptionPrimitiveDataMsg_recv->dec_result;

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaDecryptionPrimitiveDataMsg_recv)
		rsa_decryption_primitive_data_msg__free_unpacked(
			RsaDecryptionPrimitiveDataMsg_recv, NULL);

	return ret;
}

static int pb_rsa_keygen_en(struct buffer *ebuf, uint32_t modulus,
			    void **privkey, struct buffer *nbuf)
{
	pb_header_t header;
	RsaKeygenEnMsg RsaKeygenEnMsg_send = RSA_KEYGEN_EN_MSG__INIT;
	RsaKeygenEnMsg *RsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *tmp;
	int ret;

	RsaKeygenEnMsg_send.ebuf.data = ebuf->buf;
	RsaKeygenEnMsg_send.ebuf.len = ebuf->len;
	RsaKeygenEnMsg_send.modulus = modulus;

	CKINT(pb_alloc_comm_buf(
		&send, rsa_keygen_en_msg__get_packed_size(&RsaKeygenEnMsg_send),
		PB_RSA_KEYGEN_EN, 0));
	rsa_keygen_en_msg__pack(&RsaKeygenEnMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_KEYGEN_EN, 0));
	RsaKeygenEnMsg_recv = rsa_keygen_en_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(RsaKeygenEnMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(nbuf, &RsaKeygenEnMsg_recv->nbuf));
	tmp = calloc(1, sizeof(struct pb_privkey_buf));
	CKNULL(tmp, -ENOMEM);
	tmp->ref = RsaKeygenEnMsg_recv->privkey;
	*privkey = tmp;

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaKeygenEnMsg_recv)
		rsa_keygen_en_msg__free_unpacked(RsaKeygenEnMsg_recv, NULL);

	return ret;
}

static void pb_rsa_free_key(void *privkey)
{
	pb_header_t header;
	RsaFreeKeyMsg RsaFreeKeyMsg_send = RSA_FREE_KEY_MSG__INIT;
	RsaFreeKeyMsg *RsaFreeKeyMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *priv;
	int ret;

	CKNULL(privkey, 0);

	priv = privkey;

	RsaFreeKeyMsg_send.privkey = priv->ref;

	CKINT(pb_alloc_comm_buf(
		&send, rsa_free_key_msg__get_packed_size(&RsaFreeKeyMsg_send),
		PB_RSA_FREE_KEY, 0));
	rsa_free_key_msg__pack(&RsaFreeKeyMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_FREE_KEY, 0));
	RsaFreeKeyMsg_recv = rsa_free_key_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(RsaFreeKeyMsg_recv, -EBADMSG);

out:
	free_buf(&send);
	free_buf(&received);

	if (RsaFreeKeyMsg_recv)
		rsa_free_key_msg__free_unpacked(RsaFreeKeyMsg_recv, NULL);
}

static struct rsa_backend pb_rsa =
{
	pb_rsa_keygen,
	pb_rsa_siggen,
	pb_rsa_sigver,
	pb_rsa_keygen_prime,
	pb_rsa_keygen_prov_prime,
	pb_rsa_keygen_en,
	pb_rsa_free_key,
	pb_rsa_sigprim,
	pb_rsa_decprim,
};

ACVP_DEFINE_CONSTRUCTOR(pb_rsa_backend)
static void pb_rsa_backend(void)
{
	register_rsa_impl(&pb_rsa);
}

/************************************************
 * DRBG cipher interface functions
 ************************************************/

static int pb_drbg_generate(struct drbg_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	DrbgDataMsg DrbgDataMsg_send = DRBG_DATA_MSG__INIT;
	DrbgDataMsg *DrbgDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	DrbgDataMsg_send.entropy.data = data->entropy.buf;
	DrbgDataMsg_send.entropy.len = data->entropy.len;
	DrbgDataMsg_send.nonce.data = data->nonce.buf;
	DrbgDataMsg_send.nonce.len = data->nonce.len;
	DrbgDataMsg_send.pers.data = data->pers.buf;
	DrbgDataMsg_send.pers.len = data->pers.len;

	if (data->addtl_reseed.arraysize >= 1) {
		DrbgDataMsg_send.addtl_reseed1.data = data->addtl_reseed.buffers[0].buf;
		DrbgDataMsg_send.addtl_reseed1.len = data->addtl_reseed.buffers[0].len;
	}
	if (data->addtl_reseed.arraysize >= 2) {
		DrbgDataMsg_send.addtl_reseed2.data = data->addtl_reseed.buffers[1].buf;
		DrbgDataMsg_send.addtl_reseed2.len = data->addtl_reseed.buffers[1].len;
	}

	if (data->entropy_reseed.arraysize >= 1) {
		DrbgDataMsg_send.entropy_reseed1.data = data->entropy_reseed.buffers[0].buf;
		DrbgDataMsg_send.entropy_reseed1.len = data->entropy_reseed.buffers[0].len;
	}
	if (data->entropy_reseed.arraysize >= 2) {
		DrbgDataMsg_send.entropy_reseed2.data = data->entropy_reseed.buffers[1].buf;
		DrbgDataMsg_send.entropy_reseed2.len = data->entropy_reseed.buffers[1].len;
	}

	if (data->addtl_generate.arraysize >= 1) {
		DrbgDataMsg_send.addtl_generate1.data = data->addtl_generate.buffers[0].buf;
		DrbgDataMsg_send.addtl_generate1.len = data->addtl_generate.buffers[0].len;
	}
	if (data->addtl_generate.arraysize >= 2) {
		DrbgDataMsg_send.addtl_generate2.data = data->addtl_generate.buffers[1].buf;
		DrbgDataMsg_send.addtl_generate2.len = data->addtl_generate.buffers[1].len;
	}

	if (data->entropy_generate.arraysize >= 1) {
		DrbgDataMsg_send.entropy_generate1.data = data->entropy_generate.buffers[0].buf;
		DrbgDataMsg_send.entropy_generate1.len = data->entropy_generate.buffers[0].len;
	}
	if (data->entropy_generate.arraysize >= 2) {
		DrbgDataMsg_send.entropy_generate2.data = data->entropy_generate.buffers[1].buf;
		DrbgDataMsg_send.entropy_generate2.len = data->entropy_generate.buffers[1].len;
	}

	DrbgDataMsg_send.type = data->type;
	DrbgDataMsg_send.cipher = data->cipher;
	DrbgDataMsg_send.rnd_data_bits_len = data->rnd_data_bits_len;
	DrbgDataMsg_send.pr = data->pr;
	DrbgDataMsg_send.df = data->df;
	/* random is output */

	CKINT(pb_alloc_comm_buf(
		&send, drbg_data_msg__get_packed_size(&DrbgDataMsg_send),
		PB_DRBG, parsed_flags));
	drbg_data_msg__pack(&DrbgDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_DRBG, parsed_flags));
	DrbgDataMsg_recv = drbg_data_msg__unpack(NULL, received.len,
						 received.buf);
	CKNULL(DrbgDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->random, &DrbgDataMsg_recv->random));

out:
	free_buf(&send);
	free_buf(&received);

	if (DrbgDataMsg_recv)
		drbg_data_msg__free_unpacked(DrbgDataMsg_recv, NULL);

	return ret;
}

static struct drbg_backend pb_drbg_backend =
{
	pb_drbg_generate,	/* drbg_generate */
};

ACVP_DEFINE_CONSTRUCTOR(pb_drbg_backend_c)
static void pb_drbg_backend_c(void)
{
	register_drbg_impl(&pb_drbg_backend);
}

/************************************************
 * ECDH cipher interface functions
 ************************************************/

static int pb_ecdh_ss(struct ecdh_ss_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EcdhSsDataMsg EcdhSsDataMsg_send = ECDH_SS_DATA_MSG__INIT;
	EcdhSsDataMsg *EcdhSsDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EcdhSsDataMsg_send.cipher = data->cipher;
	EcdhSsDataMsg_send.qxrem.data = data->Qxrem.buf;
	EcdhSsDataMsg_send.qxrem.len = data->Qxrem.len;
	EcdhSsDataMsg_send.qyrem.data = data->Qyrem.buf;
	EcdhSsDataMsg_send.qyrem.len = data->Qyrem.len;
	/* Qxloc is output */
	/* Qyloc is output */
	/* hashzz is output */

	CKINT(pb_alloc_comm_buf(
		&send, ecdh_ss_data_msg__get_packed_size(&EcdhSsDataMsg_send),
		PB_ECDH_SS, parsed_flags));
	ecdh_ss_data_msg__pack(&EcdhSsDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDH_SS, parsed_flags));
	EcdhSsDataMsg_recv = ecdh_ss_data_msg__unpack(NULL, received.len,
						 received.buf);
	CKNULL(EcdhSsDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->Qxloc, &EcdhSsDataMsg_recv->qxloc));
	CKINT(pb_alloc_copy(&data->Qyloc, &EcdhSsDataMsg_recv->qyloc));
	CKINT(pb_alloc_copy(&data->hashzz, &EcdhSsDataMsg_recv->hashzz));

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdhSsDataMsg_recv)
		ecdh_ss_data_msg__free_unpacked(EcdhSsDataMsg_recv, NULL);

	return ret;
}

static int pb_ecdh_ss_ver(struct ecdh_ss_ver_data *data,
		flags_t parsed_flags)
{
	pb_header_t header;
	EcdhSsVerDataMsg EcdhSsVerDataMsg_send = ECDH_SS_VER_DATA_MSG__INIT;
	EcdhSsVerDataMsg *EcdhSsVerDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EcdhSsVerDataMsg_send.cipher = data->cipher;
	EcdhSsVerDataMsg_send.qxrem.data = data->Qxrem.buf;
	EcdhSsVerDataMsg_send.qxrem.len = data->Qxrem.len;
	EcdhSsVerDataMsg_send.qyrem.data = data->Qyrem.buf;
	EcdhSsVerDataMsg_send.qyrem.len = data->Qyrem.len;
	EcdhSsVerDataMsg_send.privloc.data = data->privloc.buf;
	EcdhSsVerDataMsg_send.privloc.len = data->privloc.len;
	EcdhSsVerDataMsg_send.qxloc.data = data->Qxloc.buf;
	EcdhSsVerDataMsg_send.qxloc.len = data->Qxloc.len;
	EcdhSsVerDataMsg_send.qyloc.data = data->Qyloc.buf;
	EcdhSsVerDataMsg_send.qyloc.len = data->Qyloc.len;
	EcdhSsVerDataMsg_send.hashzz.data = data->hashzz.buf;
	EcdhSsVerDataMsg_send.hashzz.len = data->hashzz.len;
	/* validity_success is output */

	CKINT(pb_alloc_comm_buf(
		&send, ecdh_ss_ver_data_msg__get_packed_size(&EcdhSsVerDataMsg_send),
		PB_ECDH_SS_VER, parsed_flags));
	ecdh_ss_ver_data_msg__pack(&EcdhSsVerDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDH_SS_VER, parsed_flags));
	EcdhSsVerDataMsg_recv = ecdh_ss_ver_data_msg__unpack(NULL, received.len,
						 received.buf);
	CKNULL(EcdhSsVerDataMsg_recv, -EBADMSG);

	data->validity_success = EcdhSsVerDataMsg_recv->validity_success;

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdhSsVerDataMsg_recv)
		ecdh_ss_ver_data_msg__free_unpacked(EcdhSsVerDataMsg_recv, NULL);

	return ret;
}

static struct ecdh_backend pb_ecdh =
{
	pb_ecdh_ss,
	pb_ecdh_ss_ver,
};

ACVP_DEFINE_CONSTRUCTOR(pb_ecdh_backend)
static void pb_ecdh_backend(void)
{
	register_ecdh_impl(&pb_ecdh);
}

/************************************************
 * ECDSA cipher interface functions
 ************************************************/

static int pb_ecdsa_keygen(struct ecdsa_keygen_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EcdsaKeygenDataMsg EcdsaKeygenDataMsg_send =
		ECDSA_KEYGEN_DATA_MSG__INIT;
	EcdsaKeygenDataMsg *EcdsaKeygenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EcdsaKeygenDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ecdsa_keygen_data_msg__get_packed_size(&EcdsaKeygenDataMsg_send),
		PB_ECDSA_KEYGEN, parsed_flags));
	ecdsa_keygen_data_msg__pack(&EcdsaKeygenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDSA_KEYGEN, parsed_flags));
	EcdsaKeygenDataMsg_recv =
		ecdsa_keygen_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EcdsaKeygenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->d, &EcdsaKeygenDataMsg_recv->d));
	CKINT(pb_alloc_copy(&data->Qx, &EcdsaKeygenDataMsg_recv->qx));
	CKINT(pb_alloc_copy(&data->Qy, &EcdsaKeygenDataMsg_recv->qy));

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdsaKeygenDataMsg_recv)
		ecdsa_keygen_data_msg__free_unpacked(EcdsaKeygenDataMsg_recv, NULL);

	return ret;
}

static int pb_ecdsa_keygen_extra(struct ecdsa_keygen_extra_data *data,
				 flags_t parsed_flags)
{
	pb_header_t header;
	EcdsaKeygenExtraDataMsg EcdsaKeygenExtraDataMsg_send =
		ECDSA_KEYGEN_EXTRA_DATA_MSG__INIT;
	EcdsaKeygenExtraDataMsg *EcdsaKeygenExtraDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EcdsaKeygenExtraDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ecdsa_keygen_extra_data_msg__get_packed_size(&EcdsaKeygenExtraDataMsg_send),
		PB_ECDSA_KEYGEN_EXTRA, parsed_flags));
	ecdsa_keygen_extra_data_msg__pack(&EcdsaKeygenExtraDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDSA_KEYGEN_EXTRA,
				     parsed_flags));
	EcdsaKeygenExtraDataMsg_recv =
		ecdsa_keygen_extra_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EcdsaKeygenExtraDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->d, &EcdsaKeygenExtraDataMsg_recv->d));
	CKINT(pb_alloc_copy(&data->Qx, &EcdsaKeygenExtraDataMsg_recv->qx));
	CKINT(pb_alloc_copy(&data->Qy, &EcdsaKeygenExtraDataMsg_recv->qy));

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdsaKeygenExtraDataMsg_recv)
		ecdsa_keygen_extra_data_msg__free_unpacked(EcdsaKeygenExtraDataMsg_recv, NULL);

	return ret;
}

static int pb_ecdsa_pkvver(struct ecdsa_pkvver_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EcdsaPkvverDataMsg EcdsaPkvverDataMsg_send =
		ECDSA_PKVVER_DATA_MSG__INIT;
	EcdsaPkvverDataMsg *EcdsaPkvverDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EcdsaPkvverDataMsg_send.cipher = data->cipher;
	EcdsaPkvverDataMsg_send.qx.data = data->Qx.buf;
	EcdsaPkvverDataMsg_send.qx.len = data->Qx.len;
	EcdsaPkvverDataMsg_send.qy.data = data->Qy.buf;
	EcdsaPkvverDataMsg_send.qy.len = data->Qy.len;

	CKINT(pb_alloc_comm_buf(
		&send, ecdsa_pkvver_data_msg__get_packed_size(&EcdsaPkvverDataMsg_send),
		PB_ECDSA_PKVVER, parsed_flags));
	ecdsa_pkvver_data_msg__pack(&EcdsaPkvverDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDSA_PKVVER, parsed_flags));
	EcdsaPkvverDataMsg_recv =
		ecdsa_pkvver_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EcdsaPkvverDataMsg_recv, -EBADMSG);

	data->keyver_success = EcdsaPkvverDataMsg_recv->keyver_success;

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdsaPkvverDataMsg_recv)
		ecdsa_pkvver_data_msg__free_unpacked(EcdsaPkvverDataMsg_recv, NULL);

	return ret;
}

static int pb_ecdsa_siggen(struct ecdsa_siggen_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EcdsaSiggenDataMsg EcdsaSiggenDataMsg_send =
		ECDSA_SIGGEN_DATA_MSG__INIT;
	EcdsaSiggenDataMsg *EcdsaSiggenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EcdsaSiggenDataMsg_send.msg.data = data->msg.buf;
	EcdsaSiggenDataMsg_send.msg.len = data->msg.len;
	EcdsaSiggenDataMsg_send.qx.data = data->Qx.buf;
	EcdsaSiggenDataMsg_send.qx.len = data->Qx.len;
	EcdsaSiggenDataMsg_send.qy.data = data->Qy.buf;
	EcdsaSiggenDataMsg_send.qy.len = data->Qy.len;
	EcdsaSiggenDataMsg_send.component = data->component;
	EcdsaSiggenDataMsg_send.cipher = data->cipher;
	if (data->privkey) {
		struct pb_privkey_buf *priv = data->privkey;

		EcdsaSiggenDataMsg_send.privkey = priv->ref;
	}

	CKINT(pb_alloc_comm_buf(
		&send, ecdsa_siggen_data_msg__get_packed_size(&EcdsaSiggenDataMsg_send),
		PB_ECDSA_SIGGEN, parsed_flags));
	ecdsa_siggen_data_msg__pack(&EcdsaSiggenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDSA_SIGGEN, parsed_flags));
	EcdsaSiggenDataMsg_recv =
		ecdsa_siggen_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EcdsaSiggenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->Qx, &EcdsaSiggenDataMsg_recv->qx));
	CKINT(pb_alloc_copy(&data->Qy, &EcdsaSiggenDataMsg_recv->qy));
	CKINT(pb_alloc_copy(&data->R, &EcdsaSiggenDataMsg_recv->r));
	CKINT(pb_alloc_copy(&data->S, &EcdsaSiggenDataMsg_recv->s));

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdsaSiggenDataMsg_recv)
		ecdsa_siggen_data_msg__free_unpacked(EcdsaSiggenDataMsg_recv, NULL);

	return ret;
}

static int pb_ecdsa_sigver(struct ecdsa_sigver_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EcdsaSigverDataMsg EcdsaSigverDataMsg_send =
		ECDSA_SIGVER_DATA_MSG__INIT;
	EcdsaSigverDataMsg *EcdsaSigverDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EcdsaSigverDataMsg_send.msg.data = data->msg.buf;
	EcdsaSigverDataMsg_send.msg.len = data->msg.len;
	EcdsaSigverDataMsg_send.qx.data = data->Qx.buf;
	EcdsaSigverDataMsg_send.qx.len = data->Qx.len;
	EcdsaSigverDataMsg_send.qy.data = data->Qy.buf;
	EcdsaSigverDataMsg_send.qy.len = data->Qy.len;
	EcdsaSigverDataMsg_send.r.data = data->R.buf;
	EcdsaSigverDataMsg_send.r.len = data->R.len;
	EcdsaSigverDataMsg_send.s.data = data->S.buf;
	EcdsaSigverDataMsg_send.s.len = data->S.len;
	EcdsaSigverDataMsg_send.component = data->component;
	EcdsaSigverDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ecdsa_sigver_data_msg__get_packed_size(&EcdsaSigverDataMsg_send),
		PB_ECDSA_SIGVER, parsed_flags));
	ecdsa_sigver_data_msg__pack(&EcdsaSigverDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDSA_SIGVER, parsed_flags));
	EcdsaSigverDataMsg_recv =
		ecdsa_sigver_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EcdsaSigverDataMsg_recv, -EBADMSG);

	data->sigver_success = EcdsaSigverDataMsg_recv->sigver_success;

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdsaSigverDataMsg_recv)
		ecdsa_sigver_data_msg__free_unpacked(EcdsaSigverDataMsg_recv, NULL);

	return ret;
}

static int pb_ecdsa_keygen_en(uint64_t curve, struct buffer *Qx_buf,
			      struct buffer *Qy_buf, void **privkey)
{
	pb_header_t header;
	EcdsaKeygenEnMsg EcdsaKeygenEnMsg_send = ECDSA_KEYGEN_EN_MSG__INIT;
	EcdsaKeygenEnMsg *EcdsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *tmp;
	int ret;

	EcdsaKeygenEnMsg_send.curve = curve;

	CKINT(pb_alloc_comm_buf(
		&send,
		ecdsa_keygen_en_msg__get_packed_size(&EcdsaKeygenEnMsg_send),
		PB_ECDSA_KEYGEN_EN, 0));
	ecdsa_keygen_en_msg__pack(&EcdsaKeygenEnMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDSA_KEYGEN_EN, 0));
	EcdsaKeygenEnMsg_recv = ecdsa_keygen_en_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(EcdsaKeygenEnMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(Qx_buf, &EcdsaKeygenEnMsg_recv->qx));
	CKINT(pb_alloc_copy(Qy_buf, &EcdsaKeygenEnMsg_recv->qy));
	tmp = calloc(1, sizeof(struct pb_privkey_buf));
	CKNULL(tmp, -ENOMEM);
	tmp->ref = EcdsaKeygenEnMsg_recv->privkey;
	*privkey = tmp;

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdsaKeygenEnMsg_recv)
		ecdsa_keygen_en_msg__free_unpacked(EcdsaKeygenEnMsg_recv, NULL);

	return ret;
}

static void pb_ecdsa_free_key(void *privkey)
{
	pb_header_t header;
	EcdsaFreeKeyMsg EcdsaFreeKeyMsg_send = ECDSA_FREE_KEY_MSG__INIT;
	EcdsaFreeKeyMsg *EcdsaFreeKeyMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *priv;
	int ret;

	CKNULL(privkey, 0);

	priv = privkey;

	EcdsaFreeKeyMsg_send.privkey = priv->ref;

	CKINT(pb_alloc_comm_buf(
		&send, ecdsa_free_key_msg__get_packed_size(&EcdsaFreeKeyMsg_send),
		PB_ECDSA_FREE_KEY, 0));
	ecdsa_free_key_msg__pack(&EcdsaFreeKeyMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ECDSA_FREE_KEY, 0));
	EcdsaFreeKeyMsg_recv = ecdsa_free_key_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(EcdsaFreeKeyMsg_recv, -EBADMSG);

out:
	free_buf(&send);
	free_buf(&received);

	if (EcdsaFreeKeyMsg_recv)
		ecdsa_free_key_msg__free_unpacked(EcdsaFreeKeyMsg_recv, NULL);
}

static struct ecdsa_backend pb_ecdsa =
{
	pb_ecdsa_keygen,   /* ecdsa_keygen_testing */
	pb_ecdsa_keygen_extra,
	pb_ecdsa_pkvver,   /* ecdsa_pkvver */
	pb_ecdsa_siggen,   /* ecdsa_siggen */
	pb_ecdsa_sigver,   /* ecdsa_sigver */
	pb_ecdsa_keygen_en,
	pb_ecdsa_free_key,
};

ACVP_DEFINE_CONSTRUCTOR(pb_ecdsa_backend)
static void pb_ecdsa_backend(void)
{
	register_ecdsa_impl(&pb_ecdsa);
}

/************************************************
 * SP800-108 KDF cipher interface functions
 ************************************************/
static int pb_kdf_108_generate(struct kdf_108_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	Kdf108DataMsg Kdf108DataMsg_send = KDF108_DATA_MSG__INIT;
	Kdf108DataMsg *Kdf108DataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	Kdf108DataMsg_send.mac = data->mac;
	Kdf108DataMsg_send.kdfmode = data->kdfmode;
	Kdf108DataMsg_send.counter_location = data->counter_location;
	Kdf108DataMsg_send.counter_length = data->counter_length;
	Kdf108DataMsg_send.derived_key_length = data->derived_key_length;
	Kdf108DataMsg_send.key.data = data->key.buf;
	Kdf108DataMsg_send.key.len = data->key.len;
	Kdf108DataMsg_send.iv.data = data->iv.buf;
	Kdf108DataMsg_send.iv.len = data->iv.len;
	Kdf108DataMsg_send.context.data = data->context.buf;
	Kdf108DataMsg_send.context.len = data->context.len;
	Kdf108DataMsg_send.label.data = data->label.buf;
	Kdf108DataMsg_send.label.len = data->label.len;

	CKINT(pb_alloc_comm_buf(
		&send, kdf108_data_msg__get_packed_size(&Kdf108DataMsg_send),
		PB_KDF_108, parsed_flags));
	kdf108_data_msg__pack(&Kdf108DataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_KDF_108, parsed_flags));
	Kdf108DataMsg_recv =
		kdf108_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(Kdf108DataMsg_recv, -EBADMSG);

	data->break_location = Kdf108DataMsg_recv->break_location;
	CKINT(pb_alloc_copy(&data->fixed_data, &Kdf108DataMsg_recv->fixed_data));
	CKINT(pb_alloc_copy(&data->derived_key,
			    &Kdf108DataMsg_recv->derived_key));

out:
	free_buf(&send);
	free_buf(&received);

	if (Kdf108DataMsg_recv)
		kdf108_data_msg__free_unpacked(Kdf108DataMsg_recv, NULL);

	return ret;
}

static int pb_kdf_108_kmac_generate(struct kdf_108_kmac_data *data,
				    flags_t parsed_flags)
{
	pb_header_t header;
	Kdf108KmacDataMsg Kdf108KmacDataMsg_send = KDF108_KMAC_DATA_MSG__INIT;
	Kdf108KmacDataMsg *Kdf108KmacDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	Kdf108KmacDataMsg_send.mac = data->mac;
	Kdf108KmacDataMsg_send.derived_key_length = data->derived_key_length;
	Kdf108KmacDataMsg_send.key.data = data->key.buf;
	Kdf108KmacDataMsg_send.key.len = data->key.len;
	Kdf108KmacDataMsg_send.context.data = data->context.buf;
	Kdf108KmacDataMsg_send.context.len = data->context.len;
	Kdf108KmacDataMsg_send.label.data = data->label.buf;
	Kdf108KmacDataMsg_send.label.len = data->label.len;

	CKINT(pb_alloc_comm_buf(
		&send, kdf108_kmac_data_msg__get_packed_size(&Kdf108KmacDataMsg_send),
		PB_KDF_108_KMAC, parsed_flags));
	kdf108_kmac_data_msg__pack(&Kdf108KmacDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_KDF_108_KMAC, parsed_flags));
	Kdf108KmacDataMsg_recv =
		kdf108_kmac_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(Kdf108KmacDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->derived_key,
			    &Kdf108KmacDataMsg_recv->derived_key));

out:
	free_buf(&send);
	free_buf(&received);

	if (Kdf108KmacDataMsg_recv)
		kdf108_kmac_data_msg__free_unpacked(Kdf108KmacDataMsg_recv, NULL);

	return ret;
}

static struct kdf_108_backend pb_108 =
{
	pb_kdf_108_generate,
	pb_kdf_108_kmac_generate,
};

ACVP_DEFINE_CONSTRUCTOR(pb_108_backend)
static void pb_108_backend(void)
{
	register_kdf_108_impl(&pb_108);
}

/************************************************
 * SP800-132 PBKDF cipher interface functions
 ************************************************/
static int pb_pbkdf_generate(struct pbkdf_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	PbkdfDataMsg PbkdfDataMsg_send = PBKDF_DATA_MSG__INIT;
	PbkdfDataMsg *PbkdfDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	PbkdfDataMsg_send.hash = data->hash;
	PbkdfDataMsg_send.derived_key_length = data->derived_key_length;
	PbkdfDataMsg_send.iteration_count = data->iteration_count;
	PbkdfDataMsg_send.password.data = data->password.buf;
	PbkdfDataMsg_send.password.len = data->password.len;
	PbkdfDataMsg_send.salt.data = data->salt.buf;
	PbkdfDataMsg_send.salt.len = data->salt.len;

	CKINT(pb_alloc_comm_buf(
		&send, pbkdf_data_msg__get_packed_size(&PbkdfDataMsg_send),
		PB_PBKDF, parsed_flags));
	pbkdf_data_msg__pack(&PbkdfDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_PBKDF, parsed_flags));
	PbkdfDataMsg_recv =
		pbkdf_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(PbkdfDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->derived_key,
			    &PbkdfDataMsg_recv->derived_key));

out:
	free_buf(&send);
	free_buf(&received);

	if (PbkdfDataMsg_recv)
		pbkdf_data_msg__free_unpacked(PbkdfDataMsg_recv, NULL);

	return ret;
}

static struct pbkdf_backend pb_pbkdf =
{
	pb_pbkdf_generate,
};

ACVP_DEFINE_CONSTRUCTOR(pb_pbkdf_backend)
static void pb_pbkdf_backend(void)
{
	register_pbkdf_impl(&pb_pbkdf);
}

/************************************************
 * RFC5869 HKDF cipher interface functions
 ************************************************/
static int pb_hkdf_generate(struct hkdf_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	HkdfDataMsg HkdfDataMsg_send = HKDF_DATA_MSG__INIT;
	HkdfDataMsg *HkdfDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	HkdfDataMsg_send.hash = data->hash;
	HkdfDataMsg_send.dkmlen = data->dkmlen;
	HkdfDataMsg_send.salt.data = data->salt.buf;
	HkdfDataMsg_send.salt.len = data->salt.len;
	HkdfDataMsg_send.z.data = data->z.buf;
	HkdfDataMsg_send.z.len = data->z.len;
	HkdfDataMsg_send.t.data = data->t.buf;
	HkdfDataMsg_send.t.len = data->t.len;
	HkdfDataMsg_send.info.data = data->info.buf;
	HkdfDataMsg_send.info.len = data->info.len;
	HkdfDataMsg_send.dkm.data = data->dkm.buf;
	HkdfDataMsg_send.dkm.len = data->dkm.len;

	CKINT(pb_alloc_comm_buf(
		&send, hkdf_data_msg__get_packed_size(&HkdfDataMsg_send),
		PB_HKDF, parsed_flags));
	hkdf_data_msg__pack(&HkdfDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_HKDF, parsed_flags));
	HkdfDataMsg_recv =
		hkdf_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(HkdfDataMsg_recv, -EBADMSG);

	if (!data->dkm.buf) {
		CKINT(pb_alloc_copy(&data->dkm, &HkdfDataMsg_recv->dkm));
	} else {
		data->validity_success = HkdfDataMsg_recv->validity_success;
	}

out:
	free_buf(&send);
	free_buf(&received);

	if (HkdfDataMsg_recv)
		hkdf_data_msg__free_unpacked(HkdfDataMsg_recv, NULL);

	return ret;
}

static struct hkdf_backend pb_hkdf_back =
{
	pb_hkdf_generate,
};

ACVP_DEFINE_CONSTRUCTOR(pb_hkdf_backend)
static void pb_hkdf_backend(void)
{
	register_hkdf_impl(&pb_hkdf_back);
}

/************************************************
 * ML-DSA interface functions
 ************************************************/

static int pb_ml_dsa_keygen(struct ml_dsa_keygen_data *data,
			       flags_t parsed_flags)
{
	pb_header_t header;
	MlDsaKeygenDataMsg MlDsaKeygenDataMsg_send =
		ML_DSA_KEYGEN_DATA_MSG__INIT;
	MlDsaKeygenDataMsg *MlDsaKeygenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	MlDsaKeygenDataMsg_send.seed.data = data->seed.buf;
	MlDsaKeygenDataMsg_send.seed.len = data->seed.len;
	MlDsaKeygenDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ml_dsa_keygen_data_msg__get_packed_size(&MlDsaKeygenDataMsg_send),
		PB_ML_DSA_KEYGEN, parsed_flags));
	ml_dsa_keygen_data_msg__pack(&MlDsaKeygenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ML_DSA_KEYGEN, parsed_flags));
	MlDsaKeygenDataMsg_recv =
		ml_dsa_keygen_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(MlDsaKeygenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->pk, &MlDsaKeygenDataMsg_recv->pk));
	CKINT(pb_alloc_copy(&data->sk, &MlDsaKeygenDataMsg_recv->sk));

out:
	free_buf(&send);
	free_buf(&received);

	if (MlDsaKeygenDataMsg_recv)
		ml_dsa_keygen_data_msg__free_unpacked(MlDsaKeygenDataMsg_recv, NULL);

	return ret;
}

static int pb_ml_dsa_siggen(struct ml_dsa_siggen_data *data,
			       flags_t parsed_flags)
{
	pb_header_t header;
	MlDsaSiggenDataMsg MlDsaSiggenDataMsg_send =
		ML_DSA_SIGGEN_DATA_MSG__INIT;
	MlDsaSiggenDataMsg *MlDsaSiggenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	MlDsaSiggenDataMsg_send.msg.data = data->msg.buf;
	MlDsaSiggenDataMsg_send.msg.len = data->msg.len;
	MlDsaSiggenDataMsg_send.rnd.data = data->rnd.buf;
	MlDsaSiggenDataMsg_send.rnd.len = data->rnd.len;
	MlDsaSiggenDataMsg_send.sk.data = data->sk.buf;
	MlDsaSiggenDataMsg_send.sk.len = data->sk.len;
	MlDsaSiggenDataMsg_send.cipher = data->cipher;
	if (data->privkey) {
		struct pb_privkey_buf *priv = data->privkey;

		MlDsaSiggenDataMsg_send.privkey = priv->ref;
	}

	CKINT(pb_alloc_comm_buf(
		&send, ml_dsa_siggen_data_msg__get_packed_size(&MlDsaSiggenDataMsg_send),
		PB_ML_DSA_SIGGEN, parsed_flags));
	ml_dsa_siggen_data_msg__pack(&MlDsaSiggenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ML_DSA_SIGGEN, parsed_flags));
	MlDsaSiggenDataMsg_recv =
		ml_dsa_siggen_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(MlDsaSiggenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->sig, &MlDsaSiggenDataMsg_recv->sig));

out:
	free_buf(&send);
	free_buf(&received);

	if (MlDsaSiggenDataMsg_recv)
		ml_dsa_siggen_data_msg__free_unpacked(MlDsaSiggenDataMsg_recv, NULL);

	return ret;
}

static int pb_ml_dsa_sigver(struct ml_dsa_sigver_data *data,
			    flags_t parsed_flags)
{
	pb_header_t header;
	MlDsaSigverDataMsg MlDsaSigverDataMsg_send =
		ML_DSA_SIGVER_DATA_MSG__INIT;
	MlDsaSigverDataMsg *MlDsaSigverDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	MlDsaSigverDataMsg_send.msg.data = data->msg.buf;
	MlDsaSigverDataMsg_send.msg.len = data->msg.len;
	MlDsaSigverDataMsg_send.sig.data = data->sig.buf;
	MlDsaSigverDataMsg_send.sig.len = data->sig.len;
	MlDsaSigverDataMsg_send.pk.data = data->pk.buf;
	MlDsaSigverDataMsg_send.pk.len = data->pk.len;
	MlDsaSigverDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ml_dsa_sigver_data_msg__get_packed_size(&MlDsaSigverDataMsg_send),
		PB_ML_DSA_SIGVER, parsed_flags));
	ml_dsa_sigver_data_msg__pack(&MlDsaSigverDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ML_DSA_SIGVER, parsed_flags));
	MlDsaSigverDataMsg_recv =
		ml_dsa_sigver_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(MlDsaSigverDataMsg_recv, -EBADMSG);

	data->sigver_success = MlDsaSigverDataMsg_recv->sigver_success;

out:
	free_buf(&send);
	free_buf(&received);

	if (MlDsaSigverDataMsg_recv)
		ml_dsa_sigver_data_msg__free_unpacked(MlDsaSigverDataMsg_recv, NULL);

	return ret;
}

static int pb_ml_dsa_keygen_en(uint64_t cipher, struct buffer *pk,
			       void **sk)
{
	pb_header_t header;
	MlDsaKeygenEnMsg MlDsaKeygenEnMsg_send = ML_DSA_KEYGEN_EN_MSG__INIT;
	MlDsaKeygenEnMsg *MlDsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *tmp;
	int ret;

	MlDsaKeygenEnMsg_send.cipher = cipher;

	CKINT(pb_alloc_comm_buf(
		&send,
		ml_dsa_keygen_en_msg__get_packed_size(&MlDsaKeygenEnMsg_send),
		PB_ML_DSA_KEYGEN_EN, 0));
	ml_dsa_keygen_en_msg__pack(&MlDsaKeygenEnMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ML_DSA_KEYGEN_EN, 0));
	MlDsaKeygenEnMsg_recv = ml_dsa_keygen_en_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(MlDsaKeygenEnMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(pk, &MlDsaKeygenEnMsg_recv->pk));
	tmp = calloc(1, sizeof(struct pb_privkey_buf));
	CKNULL(tmp, -ENOMEM);
	tmp->ref = MlDsaKeygenEnMsg_recv->privkey;
	*sk = tmp;

out:
	free_buf(&send);
	free_buf(&received);

	if (MlDsaKeygenEnMsg_recv)
		ml_dsa_keygen_en_msg__free_unpacked(MlDsaKeygenEnMsg_recv,
						    NULL);

	return ret;
}

static void pb_ml_dsa_free_key(void *privkey)
{
	pb_header_t header;
	MlDsaFreeKeyMsg MlDsaFreeKeyMsg_send = ML_DSA_FREE_KEY_MSG__INIT;
	MlDsaFreeKeyMsg *MlDsaFreeKeyMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *priv;
	int ret;

	CKNULL(privkey, 0);

	priv = privkey;

	MlDsaFreeKeyMsg_send.privkey = priv->ref;

	CKINT(pb_alloc_comm_buf(
		&send, ml_dsa_free_key_msg__get_packed_size(&MlDsaFreeKeyMsg_send),
		PB_RSA_FREE_KEY, 0));
	ml_dsa_free_key_msg__pack(&MlDsaFreeKeyMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_RSA_FREE_KEY, 0));
	MlDsaFreeKeyMsg_recv = ml_dsa_free_key_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(MlDsaFreeKeyMsg_recv, -EBADMSG);

out:
	free_buf(&send);
	free_buf(&received);

	if (MlDsaFreeKeyMsg_recv)
		ml_dsa_free_key_msg__free_unpacked(MlDsaFreeKeyMsg_recv, NULL);
}

static struct ml_dsa_backend pb_ml_dsa =
{
	pb_ml_dsa_keygen,
	pb_ml_dsa_siggen,
	pb_ml_dsa_sigver,
	pb_ml_dsa_keygen_en,
	pb_ml_dsa_free_key
};

ACVP_DEFINE_CONSTRUCTOR(pb_ml_dsa_backend)
static void pb_ml_dsa_backend(void)
{
	register_ml_dsa_impl(&pb_ml_dsa);
}

/************************************************
 * ML-KEM interface functions
 ************************************************/

static int pb_ml_kem_keygen(struct ml_kem_keygen_data *data,
			    flags_t parsed_flags)
{
	pb_header_t header;
	MlKemKeygenDataMsg MlKemKeygenDataMsg_send =
		ML_KEM_KEYGEN_DATA_MSG__INIT;
	MlKemKeygenDataMsg *MlKemKeygenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	MlKemKeygenDataMsg_send.d.data = data->d.buf;
	MlKemKeygenDataMsg_send.d.len = data->d.len;
	MlKemKeygenDataMsg_send.z.data = data->z.buf;
	MlKemKeygenDataMsg_send.z.len = data->z.len;
	MlKemKeygenDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ml_kem_keygen_data_msg__get_packed_size(&MlKemKeygenDataMsg_send),
		PB_ML_KEM_KEYGEN, parsed_flags));
	ml_kem_keygen_data_msg__pack(&MlKemKeygenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ML_KEM_KEYGEN, parsed_flags));
	MlKemKeygenDataMsg_recv =
		ml_kem_keygen_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(MlKemKeygenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->ek, &MlKemKeygenDataMsg_recv->ek));
	CKINT(pb_alloc_copy(&data->dk, &MlKemKeygenDataMsg_recv->dk));

out:
	free_buf(&send);
	free_buf(&received);

	if (MlKemKeygenDataMsg_recv)
		ml_kem_keygen_data_msg__free_unpacked(MlKemKeygenDataMsg_recv, NULL);

	return ret;
}

static int pb_ml_kem_encapsulation(struct ml_kem_encapsulation_data *data,
				   flags_t parsed_flags)
{
	pb_header_t header;
	MlKemEncapDataMsg MlKemEncapDataMsg_send = ML_KEM_ENCAP_DATA_MSG__INIT;
	MlKemEncapDataMsg *MlKemEncapDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	MlKemEncapDataMsg_send.msg.data = data->msg.buf;
	MlKemEncapDataMsg_send.msg.len = data->msg.len;
	MlKemEncapDataMsg_send.ek.data = data->ek.buf;
	MlKemEncapDataMsg_send.ek.len = data->ek.len;
	MlKemEncapDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ml_kem_encap_data_msg__get_packed_size(&MlKemEncapDataMsg_send),
		PB_ML_KEM_ENCAP, parsed_flags));
	ml_kem_encap_data_msg__pack(&MlKemEncapDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ML_KEM_ENCAP, parsed_flags));
	MlKemEncapDataMsg_recv =
		ml_kem_encap_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(MlKemEncapDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->c, &MlKemEncapDataMsg_recv->c));
	CKINT(pb_alloc_copy(&data->ss, &MlKemEncapDataMsg_recv->ss));

out:
	free_buf(&send);
	free_buf(&received);

	if (MlKemEncapDataMsg_recv)
		ml_kem_encap_data_msg__free_unpacked(MlKemEncapDataMsg_recv, NULL);

	return ret;
}

static int pb_ml_kem_decapsulation(struct ml_kem_decapsulation_data *data,
				   flags_t parsed_flags)
{
	pb_header_t header;
	MlKemDecapDataMsg MlKemDecapDataMsg_send = ML_KEM_DECAP_DATA_MSG__INIT;
	MlKemDecapDataMsg *MlKemDecapDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	MlKemDecapDataMsg_send.c.data = data->c.buf;
	MlKemDecapDataMsg_send.c.len = data->c.len;
	MlKemDecapDataMsg_send.dk.data = data->dk.buf;
	MlKemDecapDataMsg_send.dk.len = data->dk.len;
	MlKemDecapDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, ml_kem_decap_data_msg__get_packed_size(&MlKemDecapDataMsg_send),
		PB_ML_KEM_DECAP, parsed_flags));
	ml_kem_decap_data_msg__pack(&MlKemDecapDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_ML_KEM_DECAP, parsed_flags));
	MlKemDecapDataMsg_recv =
		ml_kem_decap_data_msg__unpack(NULL, received.len, received.buf);
	CKNULL(MlKemDecapDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->ss, &MlKemDecapDataMsg_recv->ss));

out:
	free_buf(&send);
	free_buf(&received);

	if (MlKemDecapDataMsg_recv)
		ml_kem_decap_data_msg__free_unpacked(MlKemDecapDataMsg_recv, NULL);

	return ret;
}

static struct ml_kem_backend pb_ml_kem =
{
	pb_ml_kem_keygen,
	pb_ml_kem_encapsulation,
	pb_ml_kem_decapsulation,
};

ACVP_DEFINE_CONSTRUCTOR(pb_ml_kem_backend)
static void pb_ml_kem_backend(void)
{
	register_ml_kem_impl(&pb_ml_kem);
}

/************************************************
 * EDDSA cipher interface functions
 ************************************************/

static int pb_eddsa_keygen(struct eddsa_keygen_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EddsaKeygenDataMsg EddsaKeygenDataMsg_send =
		EDDSA_KEYGEN_DATA_MSG__INIT;
	EddsaKeygenDataMsg *EddsaKeygenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EddsaKeygenDataMsg_send.cipher = data->cipher;

	CKINT(pb_alloc_comm_buf(
		&send, eddsa_keygen_data_msg__get_packed_size(&EddsaKeygenDataMsg_send),
		PB_EDDSA_KEYGEN, parsed_flags));
	eddsa_keygen_data_msg__pack(&EddsaKeygenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_EDDSA_KEYGEN, parsed_flags));
	EddsaKeygenDataMsg_recv =
		eddsa_keygen_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EddsaKeygenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->d, &EddsaKeygenDataMsg_recv->d));
	CKINT(pb_alloc_copy(&data->q, &EddsaKeygenDataMsg_recv->q));

out:
	free_buf(&send);
	free_buf(&received);

	if (EddsaKeygenDataMsg_recv)
		eddsa_keygen_data_msg__free_unpacked(EddsaKeygenDataMsg_recv, NULL);

	return ret;
}

static int pb_eddsa_keyver(struct eddsa_keyver_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EddsaKeyverDataMsg EddsaKeyverDataMsg_send =
		EDDSA_KEYVER_DATA_MSG__INIT;
	EddsaKeyverDataMsg *EddsaKeyverDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EddsaKeyverDataMsg_send.cipher = data->cipher;
	EddsaKeyverDataMsg_send.q.data = data->q.buf;
	EddsaKeyverDataMsg_send.q.len = data->q.len;

	CKINT(pb_alloc_comm_buf(
		&send, eddsa_keyver_data_msg__get_packed_size(&EddsaKeyverDataMsg_send),
		PB_EDDSA_KEYVER, parsed_flags));
	eddsa_keyver_data_msg__pack(&EddsaKeyverDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_EDDSA_KEYVER, parsed_flags));
	EddsaKeyverDataMsg_recv =
		eddsa_keyver_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EddsaKeyverDataMsg_recv, -EBADMSG);

	data->keyver_success = EddsaKeyverDataMsg_recv->keyver_success;

out:
	free_buf(&send);
	free_buf(&received);

	if (EddsaKeyverDataMsg_recv)
		eddsa_keyver_data_msg__free_unpacked(EddsaKeyverDataMsg_recv, NULL);

	return ret;
}

static int pb_eddsa_siggen(struct eddsa_siggen_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EddsaSiggenDataMsg EddsaSiggenDataMsg_send =
		EDDSA_SIGGEN_DATA_MSG__INIT;
	EddsaSiggenDataMsg *EddsaSiggenDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EddsaSiggenDataMsg_send.msg.data = data->msg.buf;
	EddsaSiggenDataMsg_send.msg.len = data->msg.len;
	EddsaSiggenDataMsg_send.context.data = data->context.buf;
	EddsaSiggenDataMsg_send.context.len = data->context.len;
	EddsaSiggenDataMsg_send.cipher = data->cipher;
	EddsaSiggenDataMsg_send.prehash = data->prehash;
	if (data->privkey) {
		struct pb_privkey_buf *priv = data->privkey;

		EddsaSiggenDataMsg_send.privkey = priv->ref;
	} else {
		/*
		 * We insist on the privkey (and thus the presence of
		 * keygen_en) to generate and manage ->q
		 */
		return -EOPNOTSUPP;
	}

	CKINT(pb_alloc_comm_buf(
		&send, eddsa_siggen_data_msg__get_packed_size(&EddsaSiggenDataMsg_send),
		PB_EDDSA_SIGGEN, parsed_flags));
	eddsa_siggen_data_msg__pack(&EddsaSiggenDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_EDDSA_SIGGEN, parsed_flags));
	EddsaSiggenDataMsg_recv =
		eddsa_siggen_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EddsaSiggenDataMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(&data->signature,
			    &EddsaSiggenDataMsg_recv->signature));

out:
	free_buf(&send);
	free_buf(&received);

	if (EddsaSiggenDataMsg_recv)
		eddsa_siggen_data_msg__free_unpacked(EddsaSiggenDataMsg_recv, NULL);

	return ret;
}

static int pb_eddsa_sigver(struct eddsa_sigver_data *data, flags_t parsed_flags)
{
	pb_header_t header;
	EddsaSigverDataMsg EddsaSigverDataMsg_send =
		EDDSA_SIGVER_DATA_MSG__INIT;
	EddsaSigverDataMsg *EddsaSigverDataMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	int ret;

	EddsaSigverDataMsg_send.msg.data = data->msg.buf;
	EddsaSigverDataMsg_send.msg.len = data->msg.len;
	EddsaSigverDataMsg_send.q.data = data->q.buf;
	EddsaSigverDataMsg_send.q.len = data->q.len;
	EddsaSigverDataMsg_send.signature.data = data->signature.buf;
	EddsaSigverDataMsg_send.signature.len = data->signature.len;
	EddsaSigverDataMsg_send.cipher = data->cipher;
	EddsaSigverDataMsg_send.prehash = data->prehash;

	CKINT(pb_alloc_comm_buf(
		&send, eddsa_sigver_data_msg__get_packed_size(&EddsaSigverDataMsg_send),
		PB_EDDSA_SIGVER, parsed_flags));
	eddsa_sigver_data_msg__pack(&EddsaSigverDataMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_EDDSA_SIGVER, parsed_flags));
	EddsaSigverDataMsg_recv =
		eddsa_sigver_data_msg__unpack(NULL, received.len,
					      received.buf);
	CKNULL(EddsaSigverDataMsg_recv, -EBADMSG);

	data->sigver_success = EddsaSigverDataMsg_recv->sigver_success;

out:
	free_buf(&send);
	free_buf(&received);

	if (EddsaSigverDataMsg_recv)
		eddsa_sigver_data_msg__free_unpacked(EddsaSigverDataMsg_recv, NULL);

	return ret;
}

static int pb_eddsa_keygen_en(struct buffer *qbuf, uint64_t curve,
			      void **privkey)
{
	pb_header_t header;
	EddsaKeygenEnMsg EddsaKeygenEnMsg_send = EDDSA_KEYGEN_EN_MSG__INIT;
	EddsaKeygenEnMsg *EddsaKeygenEnMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *tmp;
	int ret;

	EddsaKeygenEnMsg_send.curve = curve;

	CKINT(pb_alloc_comm_buf(
		&send,
		eddsa_keygen_en_msg__get_packed_size(&EddsaKeygenEnMsg_send),
		PB_EDDSA_KEYGEN_EN, 0));
	eddsa_keygen_en_msg__pack(&EddsaKeygenEnMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_EDDSA_KEYGEN_EN, 0));
	EddsaKeygenEnMsg_recv = eddsa_keygen_en_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(EddsaKeygenEnMsg_recv, -EBADMSG);

	CKINT(pb_alloc_copy(qbuf, &EddsaKeygenEnMsg_recv->qbuf));
	tmp = calloc(1, sizeof(struct pb_privkey_buf));
	CKNULL(tmp, -ENOMEM);
	tmp->ref = EddsaKeygenEnMsg_recv->privkey;
	*privkey = tmp;

out:
	free_buf(&send);
	free_buf(&received);

	if (EddsaKeygenEnMsg_recv)
		eddsa_keygen_en_msg__free_unpacked(EddsaKeygenEnMsg_recv, NULL);

	return ret;
}

static void pb_eddsa_free_key(void *privkey)
{
	pb_header_t header;
	EddsaFreeKeyMsg EddsaFreeKeyMsg_send = EDDSA_FREE_KEY_MSG__INIT;
	EddsaFreeKeyMsg *EddsaFreeKeyMsg_recv = NULL;
	BUFFER_INIT(send);
	BUFFER_INIT(received);
	struct pb_privkey_buf *priv;
	int ret;

	CKNULL(privkey, 0);

	priv = privkey;

	EddsaFreeKeyMsg_send.privkey = priv->ref;

	CKINT(pb_alloc_comm_buf(
		&send, eddsa_free_key_msg__get_packed_size(&EddsaFreeKeyMsg_send),
		PB_EDDSA_FREE_KEY, 0));
	eddsa_free_key_msg__pack(&EddsaFreeKeyMsg_send, send.buf);

	/*************************** SEND / RECEIVE ***************************/
	CKINT(pb_send_receive_data(&send, &received, &header));

	/*********************** Process received data ************************/

	CKINT(pb_received_data_check(&header, PB_EDDSA_FREE_KEY, 0));
	EddsaFreeKeyMsg_recv = eddsa_free_key_msg__unpack(
		NULL, received.len, received.buf);
	CKNULL(EddsaFreeKeyMsg_recv, -EBADMSG);

out:
	free_buf(&send);
	free_buf(&received);

	if (EddsaFreeKeyMsg_recv)
		eddsa_free_key_msg__free_unpacked(EddsaFreeKeyMsg_recv, NULL);
}

static struct eddsa_backend pb_eddsa =
{
	pb_eddsa_keygen,   /* eddsa_keygen_testing */
	pb_eddsa_keyver,   /* eddsa_pkvver */
	pb_eddsa_siggen,   /* eddsa_siggen */
	pb_eddsa_sigver,   /* eddsa_sigver */
	pb_eddsa_keygen_en,
	pb_eddsa_free_key,
};

ACVP_DEFINE_CONSTRUCTOR(pb_eddsa_backend)
static void pb_eddsa_backend(void)
{
	register_eddsa_impl(&pb_eddsa);
}
