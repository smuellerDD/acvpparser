/*
 * Copyright (C) 2022 - 2022, Joachim Vandersmissen <joachim@atsec.com>
 *
 * License: see LICENSE file
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT KDF_108LL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _PARSER_ANSI_X942_H
#define _PARSER_ANSI_X942_H

#define OID_TDES	"\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x06"
#define OID_AES_128_KW	"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x05"
#define OID_AES_192_KW	"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x19"
#define OID_AES_256_KW	"\x06\x09\x60\x86\x48\x01\x65\x03\x04\x01\x2D"

#include "parser_flags.h"
#include "stringhelper.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief ANSI X9.42 KDF testing
 *
 * @var kdf_type [in] The type of ANS x9.42 KDF.
 * @var hashalg [in] Hash algorithm to be used for KDF.
 * @var wrapalg [in] Wrapping algorithm to be used for the "DER" KDF. Can be one
 * 		     of: ACVP_TDESKW, ACVP_AES128, ACVP_AES192, or ACVP_AES256.
 * @var oid [in] The OID used within the other info in the "DER" KDF.
 * @var key_len [in] The expected length in bits of the resulting derived key.
 * @var zz [in] Zz value buffer.
 * @var party_u_info [in] Buffer with supplemental party U information for
 * 			  kdf_type == "DER".
 * @var party_v_info [in] Buffer with supplemental party V information for
 * 			  kdf_type == "DER".
 * @var supp_pub_info [in] Buffer with supplemental public information for
 * 			   kdf_type == "DER".
 * @var supp_priv_info [in] Buffer with supplemental private information for
 * 			    kdf_type == "DER".
 * @var other_info [in] Buffer with other information for
 * 			kdf_type == "concatenation".
 * @var derived_key [out] Buffer with the generated key - backend must allocate
 *			  buffer, the parser takes care of disposing of it.
 */
struct ansi_x942_data {
	struct buffer kdf_type;
	uint64_t hashalg;
	uint64_t wrapalg;
	struct buffer oid;
	uint32_t key_len;
	struct buffer zz;
	struct buffer party_u_info;
	struct buffer party_v_info;
	struct buffer supp_pub_info;
	struct buffer supp_priv_info;
	struct buffer other_info;
	struct buffer derived_key;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @var ansi_x942 Perform a ANSI X9.42 key derivation
 */
struct ansi_x942_backend {
	int (*ansi_x942)(struct ansi_x942_data *data, flags_t parsed_flags);
};

void register_ansi_x942_impl(struct ansi_x942_backend *implementation);

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_ANSI_X942_H */
