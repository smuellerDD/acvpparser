/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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

#ifndef _PARSER_KDF_IKEV2_H
#define _PARSER_KDF_IKEV2_H

#include "parser.h"
#include "parser_flags.h"

/**
 * @brief IKEV2 PRF testing context
 *
 * @var hashalg [in] Hash algorithm to be used for PRF.
 * @var dkmlen [in] Length of derived key material to be produced
 * @var n_init [in] Value of initiator nonce
 * @var n_resp [in] Value of responder nonce
 * @var spi_init [in] Security parameter indice of the initiator
 * @var spi_resp [in] Security parameter indice of the responder
 * @var gir [in] Diffie-Hellman shared secret
 * @var gir_new [in] New Diffie-Hellman shared secret
 * @var s_key_seed [out] Results of the extraction step
 * @var s_key_seed_rekey [out] Results of the newly created skeyid
 * @var dkm [out] Derived key material from expansion step
 * @var dkm_child [out] Expansion step results for child SA
 * @var dkm_child_dh [out] Expansion step results for child SA DH
 */
struct kdf_ikev2_data {
	uint64_t hashalg;
	uint32_t dkmlen;
	struct buffer n_init;
	struct buffer n_resp;
	struct buffer spi_init;
	struct buffer spi_resp;
	struct buffer gir;
	struct buffer gir_new;
	struct buffer s_key_seed;
	struct buffer s_key_seed_rekey;
	struct buffer dkm;
	struct buffer dkm_child;
	struct buffer dkm_child_dh;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @var kdf_ikev2 Invoke the IKEV2 PRF testing.
 */

struct kdf_ikev2_backend {
	int (*kdf_ikev2)(struct kdf_ikev2_data *data, flags_t parsed_flags);
};

void register_kdf_ikev2_impl(struct kdf_ikev2_backend *implementation);

#endif /* _PARSER_KDF_IKEV2_H */
