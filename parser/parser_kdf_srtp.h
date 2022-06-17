/*
 * Copyright (C) 2022 - 2022, Joachim Vandersmissen <joachim@atsec.com>
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

#ifndef _PARSER_KDF_SRTP_H
#define _PARSER_KDF_SRTP_H

#include "parser.h"
#include "parser_flags.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief SRTP PRF testing context
 *
 * @var aes_key_length [in] The AES Key Length used for the KDF
 * @var kdr [in] The Key Derivation Rate used for the KDF
 * @var master_key [in] Master key value
 * @var master_salt [in] Master salt value
 * @var index [in] Index value for SRTP
 * @var srtcp_index [in] Index value for SRTCP
 * @var srtp_ke [out] SRTP encryption key
 * @var srtp_ka [out] SRTP authentication key
 * @var srtp_ks [out] SRTP salting key
 * @var srtcp_ke [out] SRTCP encryption key
 * @var srtcp_ka [out] SRTCP authentication key
 * @var srtcp_ks [out] SRTCP salting key
 */
struct kdf_srtp_data {
	uint32_t aes_key_length;
	struct buffer kdr;
	struct buffer master_key;
	struct buffer master_salt;
	struct buffer index;
	struct buffer srtcp_index;
	struct buffer srtp_ke;
	struct buffer srtp_ka;
	struct buffer srtp_ks;
	struct buffer srtcp_ke;
	struct buffer srtcp_ka;
	struct buffer srtcp_ks;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @var kdf_srtp Invoke the SRTP PRF testing.
 */

struct kdf_srtp_backend {
	int (*kdf_srtp)(struct kdf_srtp_data *data, flags_t parsed_flags);
};

void register_kdf_srtp_impl(struct kdf_srtp_backend *implementation);

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_KDF_SRTP_H */
