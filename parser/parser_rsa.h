/*
 * Copyright (C) 2017 - 2018, Stephan Mueller <smueller@chronox.de>
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

#ifndef _PARSER_RSA_H
#define _PARSER_RSA_H

#include "parser.h"
#include "parser_flags.h"

/**
 * @brief RSA key generation data structure holding the data for the cipher
 *	  operations specified in rsa_keygen_prime_data. This test is used
 *	  for FIPS 186-4 B.3.3 tests as specified in the RSA CAVS specification
 *	  section 6.2.2.2.
 *
 * @param modulus [in] RSA modulus in bits
 * @param p [in] RSA P parameter
 * @param q [in] RSA Q parameter
 * @param e [in] RSA exponent
 * @param keygen_success [out] Is RSA key generation with given parameters
 *			       successful (1) or whether it failed (0).
 */
struct rsa_keygen_prime_data {
	uint32_t modulus; /* input: modulus size in bits */
	struct buffer p; /* input */
	struct buffer q; /* input */
	struct buffer e; /* input */
	uint32_t keygen_success;
};

/**
 * @brief RSA key generation data structure holding the data for the cipher
 *	  operations specified in rsa_keygen_data. This test is used
 *	  for FIPS 186-4 B.3.3 tests as specified in the RSA CAVS specification
 *	  section 6.2.2.1.
 *
 * @param modulus [in] RSA modulus in bits
 * @param n [out] RSA N parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param d [out] RSA D parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param p [out] RSA P parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param q [out] RSA Q parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param e [in/out] RSA exponent as input. If this buffer is empty (only when
 *		     random e is supported by the module), the module
 *		     generates the random e value, allocates memory for this
 *		     buffer and places it into this buffer.
 */
struct rsa_keygen_data {
	uint32_t modulus;
	struct buffer n;
	struct buffer d;
	struct buffer p;
	struct buffer q;
	struct buffer e;
};

/**
 * @brief RSA key generation data structure holding the data for the cipher
 *	  operations specified in rsa_keygen_prov_prime_data. This test is used
 *	  for FIPS 186-4 B.3.2 tests as specified in the RSA CAVS specification
 *	  section 6.2.1.
 *
 * @param modulus [in] RSA modulus in bits.
 * @param n [out] RSA N parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param d [out] RSA D parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param p [out] RSA P parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param q [out] RSA Q parameter. Buffer must be allocated by module and is
 *		  released by parser.
 * @param seed [out] RSA random seed parameter used to generate the RSA key.
 *		     Buffer must be allocated by module and is released by
 *		     parser.
 * @param e [in/out] RSA exponent as input. If this buffer is empty (only when
 *		     random e is supported by the module), the module
 *		     generates the random e value, allocates memory for this
 *		     buffer and places it into this buffer.
 * @param cipher [in] Hash algorithm to be used for RSA key generation.
 */
struct rsa_keygen_prov_prime_data {
	unsigned int modulus;
	struct buffer n;
	struct buffer d;
	struct buffer p;
	struct buffer q;
	struct buffer seed;
	struct buffer e;
	uint64_t cipher;
};

/**
 * @brief RSA signature generation data structure holding the data for the
 *	  signature generation operation. This test is specified in the RSA CAVS
 *	  specification section 6.3.
 *
 * NOTE: You MUST use the very same private key for the same modulo. That means
 *	 you generate a new RSA key when a new @param modulo value is provided.
 *	 If the n and e values of the data structure below are not filled,
 *	 you must copy the RSA.e and RSA.n from you used key. To simplify the
 *	 entire key handling, you may implement the helper functions
 *	 registered with @param rsa_keygen_en and @param rsa_free_key below.
 *	 When using these functions, you must ensure that the RSA signature
 *	 generation is invoked single-threaded because the generated
 *	 RSA key and the n and e parameter are stored in a global variable.
 *
 * @param cipher [in] Hash algorithm to be used for RSA signature generation.
 * @param modulus [in] RSA modulus in bits.
 * @param saltlen [in] Length of salt for RSA PSS.
 * @param e [in/out] RSA exponent as input. If this buffer is empty (only when
 *		     random e is supported by the module), the module
 *		     generates the random e value, allocates memory for this
 *		     buffer and places it into this buffer.
 * @param msg [in] Plaintext message to be signed.
 * @param sig [out] Signature generated by the module. Buffer must be allocated
 *		    by module and is released by parser.
 * @param n [in/out] RSA N parameter. Buffer must be allocated by module and is
 *		     released by parser.
 * @param privkey [in] RSA private key to be used for signature generation.
 *		  This variable is only set if rsa_keygen_en callback provided.
 */
struct rsa_siggen_data {
	uint64_t cipher;
	uint32_t modulus;
	uint32_t saltlen;
	struct buffer e;
	struct buffer msg;
	struct buffer sig;
	struct buffer n;
	void *privkey;
};

/**
 * @brief RSA signature verification data structure holding the data for the
 *	  signature verification operation. This test is specified in the RSA
 *	  CAVS specification section 6.4.
 *
 * @param n [in] RSA N parameter
 * @param e [in] RSA exponent
 * @param msg [in] Plaintext message to be signed.
 * @param sig [in] Signature of message to be verified.
 * @param modulus [in] RSA modulus in bits
 * @param saltlen [in] Length of salt for RSA PSS.
 * @param cipher [in] Hash algorithm to be used for RSA signature generation.
 * @param sig_result [out] Is RSA signature successfully verified (1) or
 *			   whether the verification failed (0).
 */
struct rsa_sigver_data {
	struct buffer n;
	struct buffer e;
	struct buffer msg;
	struct buffer sig;
	uint32_t modulus;
	uint32_t saltlen;
	uint64_t cipher;
	uint32_t sig_result;
};

/**
 * @brief Callback data structure that must be implemented by the backend. Some
 *	  callbacks only need to be implemented if the respective cipher support
 *	  shall be tested.
 *
 * All functions return 0 on success or != 0 on error. Note, a failure in the
 * RSA key generation @param rsa_keygen_prime due to problematic input
 * parameters is expected. In such cases, an RSA key generation error is still
 * considered to be a successful operation and the return code should be 0.
 * Similarly, the signature verification callback @param rsa_sigver shall
 * return 0 if the signature verification fails. Only if some general error is
 * detected a return code != must be returned.
 *
 * @param rsa_keygen RSA key generation for B.3.3 (CAVS test specification
 * 		     section 6.2.2.1)
 * @param rsa_siggen RSA signature generation
 * @param rsa_sigver RSA signature verification
 * @param rsa_keygen_prime RSA key generation for B.3.3 (CAVS test
 *			   specification 6.2.2.2)
 * @param rsa_keygen_prov_prime RSA key generation for B.3.2 (CAVS test
 *				specification section 6.2.1).
 *
 * @param rsa_keygen_en This is an optional helper call to reduce the amount
 *			of code in the backend for signature generation. The
 *			ACVP protocol requires that the same RSA key is used
 *			for multiple signature generation operation. Yet,
 *			the module must generate the RSA key. To allow the
 *			ACVP Parser to manage the RSA key and invoke the
 *			RSA key generation, you may provide this function with
 *			the following parameters:
 *			@param ebuf [in/out] Buffer holding RSA.e. If the
 *				    buffer is empty (e.len == 0), the module
 *				    is requested to generate e and store it
 *				    in this buffer.
 *			@param modulus [in] Modulus of the RSA key to generate.
 *			@param privkey [out] Provide the pointer to the RSA
 *				        private key.
 *			@param nbuf [out] Buffer filled with the public RSA key
 *				    parameter RSA.n.
 * @param rsa_free_key This function is required if rsa_keygen_en is registered.
 *		       This function is intended to free the private RSA key
 *		       handle created with rsa_keygen_en.
 */
struct rsa_backend {
	int (*rsa_keygen)(struct rsa_keygen_data *data, flags_t parsed_flags);
	int (*rsa_siggen)(struct rsa_siggen_data *data, flags_t parsed_flags);
	int (*rsa_sigver)(struct rsa_sigver_data *data, flags_t parsed_flags);
	int (*rsa_keygen_prime)(struct rsa_keygen_prime_data *data,
				flags_t parsed_flags);
	int (*rsa_keygen_prov_prime)(struct rsa_keygen_prov_prime_data *data,
				     flags_t parsed_flags);

	int (*rsa_keygen_en)(struct buffer *ebuf, uint32_t modulus,
			     void **privkey, struct buffer *nbuf);
	void (*rsa_free_key)(void *privkey);
};

void register_rsa_impl(struct rsa_backend *implementation);

#endif /* _PARSER_RSA_H */
