/*
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef _PARSER_ECDH_H
#define _PARSER_ECDH_H

#include "parser_flags.h"
#include "stringhelper.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief One-Step KDF parameters
 *
 * @var aux_functinn [in] auxiliary function (i.e. a hash)'
 * @var label [in] Label to be used for KDF- note, the buffer
 *		    contains the ID string (i.e. ASCII-printable characters).
 *		    The label->len value contains the size of the ID including
 *		    the terminating zero. If you need the size of the string,
 *		    use strlen(label->buf) or label->len - 1.
 * @var label [in] ASCII string describing the fixed info structure (e.g.
 *		   "label||uPartyInfo||vPartyInfo")
 */
struct ecdh_onestep_kdf {
	uint64_t aux_function;
	struct buffer label;
	struct buffer fixed_info_pattern;
};

/**
 * @brief ECC CDH primitive and hashed Shared Secret generation
 *
 * @var cipher [in] ECC curve containing an OR of: one curve out of
 * 		      CURVEMASK, one hash out of HASHMASK, one MAC out
 * 		      of HMACMASK when using KDF
 * @var Qxrem [in] affine X coordinate of remote pubkey
 * @var Qyrem [in] affine Y coordinate of remote pubkey
 * @var Qxrem2 [in] optional affine X coordinate of second remote pubkey (e.g.
 *		    ephemeral for full unitified)
 * @var Qyrem2 [in] optional affine Y coordinate of second remote pubkey (e.g.
 *		    ephemeral for full unitified)
 * @var privloc [disregard]
 * @var Qxloc [out] affine X coordinate of local pubkey
 * @var Qyloc [out] affine Y coordinate of local pubkey
 * @var privloc2 [disregard]
 * @var Qxloc2 [out] affine X coordinate of second local pubkey (e.g.
 *		     ephemeral for full unitified)
 * @var Qyloc2 [out] affine Y coordinate of second local pubkey (e.g.
 *		     ephemeral for full unitified)
 * @var iut_id [in] IUT ID to be used for full unified ECDH- note, the buffer
 *		    contains the ID string (i.e. ASCII-printable characters).
 *		    The iut_id->len value contains the size of the ID including
 *		    the terminating zero. If you need the size of the string,
 *		    use strlen(iut_id->buf) or iut_id->len - 1.
 * @var server_id [in] Server ID to be used for full unified ECDH- note, the buffer
 *		    contains the ID string (i.e. ASCII-printable characters).
 *		    The server_id->len value contains the size of the ID including
 *		    the terminating zero. If you need the size of the string,
 *		    use strlen(server_id->buf) or server_id->len - 1.
 * @var hashzz [out] hashed shared secret / raw shared secret for ECC CDH
 */
struct ecdh_ss_data {
	uint64_t cipher;
	struct buffer Qxrem;
	struct buffer Qyrem;
	struct buffer Qxrem2;
	struct buffer Qyrem2;
	struct buffer privloc;
	struct buffer Qxloc;
	struct buffer Qyloc;
	struct buffer privloc2;
	struct buffer Qxloc2;
	struct buffer Qyloc2;
	struct buffer iut_id;
	struct buffer server_id;
	struct buffer hashzz;

	struct ecdh_onestep_kdf onestep_kdf;
};

/**
 * @brief ECC hashed Shared Secret verification
 *
 * @var cipher [in] ECC curve containing an OR of: one curve out of
 * 		      CURVEMASK, one hash out of HASHMASK, one MAC out
 * 		      of HMACMASK
 * @var Qxrem [in] affine X coordinate of remote pubkey
 * @var Qyrem [in] affine Y coordinate of remote pubkey
 * @var Qxrem2 [in] optional affine X coordinate of second remote pubkey (e.g.
 *		    ephemeral for full unitified)
 * @var Qyrem2 [in] optional affine Y coordinate of second remote pubkey (e.g.
 *		    ephemeral for full unitified)
 * @var privloc [in] private local key
 * @var Qxloc [in] affine X coordinate of local pubkey
 * @var Qyloc [in] affine Y coordinate of local pubkey
 * @var privloc2 [in] optional second private local key (e.g.
 *		      ephemeral for full unitified)
 * @var Qxloc2 [in] affine X coordinate of optional second local pubkey (e.g.
 *		    ephemeral for full unitified)
 * @var Qyloc2 [in] affine Y coordinate of optional second local pubkey (e.g.
 *		    ephemeral for full unitified)
 * @var hashzz [in] hashed shared secret / raw shared secret for ECC CDH
 * @var iut_id [in] IUT ID to be used for full unified ECDH- note, the buffer
 *		    contains the ID string (i.e. ASCII-printable characters).
 *		    The iut_id->len value contains the size of the ID including
 *		    the terminating zero. If you need the size of the string,
 *		    use strlen(iut_id->buf) or iut_id->len - 1.
 * @var server_id [in] Server ID to be used for full unified ECDH- note, the buffer
 *		    contains the ID string (i.e. ASCII-printable characters).
 *		    The server_id->len value contains the size of the ID including
 *		    the terminating zero. If you need the size of the string,
 *		    use strlen(server_id->buf) or server_id->len - 1.
 * @var validity_success [out] Does the generated shared secret match with
 *				 @var hashzz (true - 1) or not (false - 0).
 */
struct ecdh_ss_ver_data {
	uint64_t cipher;
	struct buffer Qxrem;
	struct buffer Qyrem;
	struct buffer Qxrem2;
	struct buffer Qyrem2;

	struct buffer privloc;
	struct buffer Qxloc;
	struct buffer Qyloc;
	struct buffer privloc2;
	struct buffer Qxloc2;
	struct buffer Qyloc2;

	struct buffer hashzz;
	struct buffer iut_id;
	struct buffer server_id;
	uint32_t validity_success;

	struct ecdh_onestep_kdf onestep_kdf;
};

/**
 * @brief Callback data structure that must be implemented by the backend. Some
 *	  callbacks only need to be implemented if the respective cipher support
 *	  shall be tested.
 *
 * All functions return 0 on success or != 0 on error. Note, a failure in the
 * validity check @var ecdh_ss_ver due to a mismatch between the expected
 * and the actual shared secret is expected. In such cases, the validity test
 * error is still considered to be a successful operation and the return code
 * should be 0. Only if some general error is
 * detected a return code != must be returned.
 *
 * @var ecdh_ss ECC shared secret generation
 * @var ecdh_ss_ver ECC shared secret verification
 */
struct ecdh_backend {
	int (*ecdh_ss)(struct ecdh_ss_data *data, flags_t parsed_flags);
	int (*ecdh_ss_ver)(struct ecdh_ss_ver_data *data, flags_t parsed_flags);
};

void register_ecdh_impl(struct ecdh_backend *implementation);

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_ECDH_H */
