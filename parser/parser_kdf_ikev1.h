/*
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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

#ifndef _PARSER_KDF_IKEV1_H
#define _PARSER_KDF_IKEV1_H

#include "parser.h"
#include "parser_flags.h"

/**
 * @brief IKEV1 PRF testing context
 *
 * @param hashalg [in] Hash algorithm to be used for PRF.
 * @param n_init [in] Value of initiator nonce
 * @param n_resp [in] Value of responder nonce
 * @param cookie_init [in] Initiator's cookie
 * @param cookie_resp [in] Responder's cookie
 * @param gxy [in] New Diffie-Hellman shared secret
 * @param pre_shared_key [in] Pre-shared key (only provided for PSK auth)
 * @param s_key_id [out] Results of the extraction step
 * @param s_key_id_d [out] Results of the expansion step
 * @param s_key_id_a [out] Results of the expansion step
 * @param s_key_id_e [out] Results of the expansion step
 */
struct kdf_ikev1_data {
	uint64_t hashalg;
	struct buffer n_init;
	struct buffer n_resp;
	struct buffer cookie_init;
	struct buffer cookie_resp;
	struct buffer gxy;
	struct buffer pre_shared_key;
	struct buffer s_key_id;
	struct buffer s_key_id_d;
	struct buffer s_key_id_a;
	struct buffer s_key_id_e;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @param kdf_ikev1 Invoke the IKEV1 PRF testing.
 */

struct kdf_ikev1_backend {
	int (*kdf_ikev1)(struct kdf_ikev1_data *data, flags_t parsed_flags);
};

void register_kdf_ikev1_impl(struct kdf_ikev1_backend *implementation);

#endif /* _PARSER_KDF_IKEV1_H */
