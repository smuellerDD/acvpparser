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

#ifndef _PARSER_SLH_DSA_H
#define _PARSER_SLH_DSA_H

#include "parser_flags.h"
#include "stringhelper.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief FIPS 205 SLH-DSA key generation cipher data structure holding
 *	  the data for the cipher operations specified in slh_dsa_keygen
 *	  backend
 *
 * @var sk_seed [in] SK_seed for key generation in binary form
 * @var sk_prf [in] SK_prf for key generation in binary form
 * @var pk_seed [in] PK_seed for key generation in binary form
 * @var pk [out] Generated public key in binary form.
 *		 Note, the backend must allocate the buffer of the right
 *		 size before storing data in it. The parser frees the memory.
 * @var sk [out] Generated secret key in binary form.
 *		 Note, the backend must allocate the buffer of the right
 *		 size before storing data in it. The parser frees the memory.
 * @var cipher [in] Cipher specification as defined in cipher_definitions.h
 */
struct slh_dsa_keygen_data {
	struct buffer sk_seed;
	struct buffer sk_prf;
	struct buffer pk_seed;
	struct buffer pk;
	struct buffer sk;
	uint64_t cipher;
};

/**
 * @brief FIPS 205 SLH-DSA signature generation cipher data structure holding
 *	  the data for the cipher operations specified in slh_dsa_siggen
 *	  backend
 *
 * Note: The backend is expected to generate a key pair for the signature
 * operation and report the public key back.
 *
 * @var msg [in] Message to be signed
 * @var sig [out] Signature to be created
 *		  Note, the backend must allocate the buffer of the right
 *		  size before storing data in it. The parser frees the memory.
 * @var rnd [in] Random number for signature generation
 *		     When (parsed_flags & FLAG_OP_SLH_DSA_TYPE_MASK) ==
 *			   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC
 *			   then: When rnd->len == 0 then generate the rnd buffer
 *				 filled with the used random value, else use
 *				 the value in rnd as the random value
 *		     When (parsed_flags & FLAG_OP_SLH_DSA_TYPE_MASK) ==
 *			   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC
 *			   then: perform deterministic signature generation
 * @var sk [in] SLH-DSA secret key to be used for signature generation as
 *		provided by the ACVP server. NOTE: if this buffer is present,
 *		privkey is not used.
 * @var context [in] SLH-DSA context to be used. Note, this may also be a NULL
 *		     buffer as the context is optional.
 * @var interface [in] Interface type: string of:
 *		       "external" - external interface
 *		       "internal" - internal interface
 * @var cipher [in] Cipher specification as defined in cipher_definitions.h
 *		    This value refers to the SLH-DSA algorithm type /
 *		    parameter set.
 * @var hashalg [in] Hash algorith following the cipher specification as defined
 *		     in cipher_definitions.h - this content is optional and
 *		     if there is a hash algorithm specified, it implies
 *		     pre-hashed SLH-DSA
 */
struct slh_dsa_siggen_data {
	struct buffer msg;
	struct buffer sig;
	struct buffer rnd;
	struct buffer sk;
	struct buffer context;
	struct buffer interface;
	uint64_t cipher;
	uint64_t hashalg;
};

/**
 * @brief FIPS 205 SLH-DSA signature verification cipher data structure holding
 *	  the data for the cipher operations specified in slh_dsa_sigver
 *	  backend
 *
 * @var msg [in] Message to be signed
 * @var sig [in] Signature to be verified
 * @var pk [in] Public key in binary form to be used for the verification op.
 * @var context [in] SLH-DSA context to be used. Note, this may also be a NULL
 *		     buffer as the context is optional.
 * @var interface [in] Interface type: string of:
 *		       "external" - external interface
 *		       "internal" - internal interface
 * @var cipher [in] Cipher specification as defined in cipher_definitions.h
 *		    This value refers to the SLH-DSA algorithm type /
 *		    parameter set.
 * @var hashalg [in] Hash algorith following the cipher specification as defined
 *		     in cipher_definitions.h - this content is optional and
 *		     if there is a hash algorithm specified, it implies
 *		     pre-hashed SLH-DSA
 * @var sigver_success [out] Is SLH-DSA signature verification with given
 *			     parameters successful (1) or whether it
 *			     failed (0).
 */
struct slh_dsa_sigver_data {
	struct buffer msg;
	struct buffer sig;
	struct buffer pk;
	struct buffer context;
	struct buffer interface;
	uint64_t cipher;
	uint64_t hashalg;
	uint32_t sigver_success;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @var slh_dsa_keygen Perform a SLH-DSA key generation operation with the given
 *		      data.
 * @var slh_dsa_siggen Perform a SLH-DSA signature generation operation with the
 *		      given data.
 * @var slh_dsa_sigver Perform a SLH-DSA signature verification operation with the
 *		      given data.
 */

struct slh_dsa_backend {
	int (*slh_dsa_keygen)(struct slh_dsa_keygen_data *data,
			     flags_t parsed_flags);
	int (*slh_dsa_siggen)(struct slh_dsa_siggen_data *data,
			     flags_t parsed_flags);
	int (*slh_dsa_sigver)(struct slh_dsa_sigver_data *data,
			     flags_t parsed_flags);
};

void register_slh_dsa_impl(struct slh_dsa_backend *implementation);

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_SLH_DSA_H */
