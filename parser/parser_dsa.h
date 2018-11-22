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

#ifndef _PARSER_DSA_H
#define _PARSER_DSA_H

#include "parser.h"
#include "parser_flags.h"

/**
 * @brief: Data structure exchanged with backend for PQG operation
 *
 * This data structure is used for PQ generation and verification with
 * provable and probable primes, In addition it is used for the canonical
 * and unverifiable G generation. This implies that some values are
 * used depending on the PQG operation type.
 *
 * The backend can analyze the requested PQG operation as follows (note,
 * a backend is not required to implement all operation types as they are
 * selected during test vector generation time):
 *
 *	parsed_flags &= ~FLAG_OP_GDT;
 *
 *	if (parsed_flags ==
 *	    (FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_PROBABLE_PQ_GEN))
 *		return pq_generation_probable_p_q;
 *	else if (parsed_flags ==
 *		 (FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_PROVABLE_PQ_GEN))
 *		return pq_generation_provable_p_q;
 *
 *	else if (parsed_flags ==
 *		 (FLAG_OP_DSA_TYPE_PQGVER | FLAG_OP_DSA_PROBABLE_PQ_GEN))
 *		return pq_verification_probable_p_q;
 *	else if (parsed_flags ==
 *		 (FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_PROVABLE_PQ_GEN))
 *		return pq_verification_provable_p_q;
 *
 *	else if (parsed_flags ==
 *		 (FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_UNVERIFIABLE_G_GEN))
 *		return unverifiable_g_generation;
 *	else if (parsed_flags ==
 *		 (FLAG_OP_DSA_TYPE_PQGGEN | FLAG_OP_DSA_CANONICAL_G_GEN))
 *		return canonical_g_generation;
 *
 *	else if (parsed_flags ==
 *		 (FLAG_OP_DSA_TYPE_PQGVER | FLAG_OP_DSA_UNVERIFIABLE_G_GEN))
 *		return unverifiable_g_verification;
 *	else if (parsed_flags ==
 *		 (FLAG_OP_DSA_TYPE_PQGVER | FLAG_OP_DSA_CANONICAL_G_GEN))
 *		return canonical_g_verification;
 *
 *	else
 *		BUG();
 *
 * General note: all data buffers that are returned by the backend must be
 * allocated by the backend. The parser takes care of deallocating them.
 *
 * @param L [in] L size in bits
 * @param N [in] N size in bits
 * @param cipher [in] Hash type to use for PQG operation
 * @param P [out: PQ generation, in: G generation, in: PQG verification] domain
 *	    parameter P
 * @param Q [out: PQ generation, in: G generation, in: PQG verification] domain
 *	    parameter Q
 * @param G [out: G generation, in: PQG verification] domain parameter G
 *
 * @param g_canon_index [out: G generation, in: G verification] The index
 *			value provided to the generator in canonical method.
 *			Only to be used for canonical G generation /
 *			verification.
 * @param g_canon_domain_param_seed [out: G generation, in: G verification] The
 *				    seed used for the P and Q generation in
 *				    the probable method. Only to be used for
 *				    unverifiable G generation / verification.
 *
 * @param g_unver_domain_param_seed [out: G generation, in: G verification] The
 *				    seed used for the P and Q generation in
 *				    the probable method. Only to be used for
 *				    unverifiable G generation / verification.
 * @param g_unver_h [out: G generation, in: G verification] The index
 *		    value provided to the generator in unverifiable method.
 *		    Only to be used for unverifiable G generation /
 *		    verification.
 *
 * @param pg_prob_counter [out: PQ generation, in: PQ verification] The counter
 *			  to be used for the probable P and Q generation. Only
 *			  to be used for PQ generation / verification with
 *			  probable primes.
 * @param pq_prob_domain_param_seed [out: PQ generation, in: PQ verification]
 *				    The seed used for the P and Q generation in
 *				    the probable method. Only to be used for
 *				    probable P/Q generation / verification.
 *
 * @param pq_prov_firstseed [out: PQ generation, in: PQ: verification]
 *			    Firstseed for PQ generation. Only to be used for PQ
 *			    generation / verification with provable primes.
 * @param pq_prov_pcounter [out: PQ generation, in: PQ verification] The counter
 *			   to be used for the provable P generation. Only to be
 *			   used for PQ generation / verification with provable
 *			   primes.
 * @param pq_prov_qcounter [out: PQ generation, in: PQ verification] The counter
 *			   to be used for the provable Q generation. Only to be
 *			   used for PQ generation / verification with provable
 *			   primes.
 * @param pq_prov_pseed [out] PQ generation, in: PQ verification] The seed
 *			to be used for the provable P generation. Only to be
 *			used for PQ generation / verification with provable
 *			primes.
 * @param pq_prov_qseed [out] PQ generation, in: PQ verification] The seed
 *			to be used for the provable Q generation. Only to be
 *			used for PQ generation / verification with provable
 *			primes.
 *
 * @param pqgver_success [out] for PQG verification only] Is PQ or G
 *			 verification with given parameters successful (1) or
 *			 whether it failed (0).
 */
struct dsa_pqg_data {
	uint32_t L;
	uint32_t N;
	uint64_t cipher;
	struct buffer P;
	struct buffer Q;
	struct buffer G;

	struct buffer g_canon_index;
	struct buffer g_canon_domain_param_seed;

	struct buffer g_unver_domain_param_seed;
	struct buffer g_unver_h;

	uint32_t pq_prob_counter;
	struct buffer pq_prob_domain_param_seed;

	struct buffer pq_prov_firstseed;
	uint32_t pq_prov_pcounter;
	uint32_t pq_prov_qcounter;
	struct buffer pq_prov_pseed;
	struct buffer pq_prov_qseed;

	uint32_t pqgver_success;
};

/**
 * @brief DSA PQG data structure holding the data for the cipher
 *	  operations specified with dsa_pqggen. It is also used to provide the
 *	  input data for key generation, signature generation and verification.
 *
 * General note: all data buffers that are returned by the backend must be
 * allocated by the backend. The parser takes care of deallocating them.
 *
 * @param cipher [in] Hash type to use for signature operation
 * @param L [in] L size in bits
 * @param N [in] N size in bits
 * @param P [out] domain parameter P
 * @param Q [out] domain parameter Q
 * @param G [out] domain parameter G
 */
struct dsa_pqggen_data {
	uint64_t cipher;
	uint32_t L;
	uint32_t N;
	struct buffer P;
	struct buffer Q;
	struct buffer G;
};

/**
 * @brief DSA key generation data structure holding the data for the cipher
 *	  operations specified with dsa_keygen.
 *
 * General note: all data buffers that are returned by the backend must be
 * allocated by the backend. The parser takes care of deallocating them.
 *
 * @param pqg.L [in] L size in bits
 * @param pqg.N [in] N size in bits
 * @param pqg.P [in] domain parameter P
 * @param pqg.Q [in] domain parameter Q
 * @param pqg.G [in] domain parameter G
 * @param X [out] private DSA key parameter X
 * @param Y [out] public DSA key parameter Y
 */
struct dsa_keygen_data {
	struct dsa_pqggen_data pqg;
	struct buffer X;
	struct buffer Y;
};

/**
 * @brief DSA signature generation data structure holding the data for the
 *	  cipher operations specified with dsa_siggen.
 *
 * NOTE: You MUST use the very same private key for the same modulo. That means
 *	 you generate a new DSA key when a new @param pqg value set is provided.
 *	 If the Y value of the data structure below is not filled,
 *	 you must copy the DSA.Y from your used key. To simplify the
 *	 entire key handling, you may implement the helper functions
 *	 registered with @param dsa_keygen_en and @param dsa_free_key below.
 *	 When using these functions, you must ensure that the DSA signature
 *	 generation is invoked single-threaded because the generated
 *	 DSA key and the Y parameter is stored in a global variable.
 *
 * General note: all data buffers that are returned by the backend must be
 * allocated by the backend. The parser takes care of deallocating them.
 *
 * @param cipher [in] Hash type to use for signature operation
 * @param msg [in] Message that shall be signed
 * @param pqg.L [in] L size in bits
 * @param pqg.N [in] N size in bits
 * @param pqg.P [out] domain parameter P
 * @param pqg.Q [out] domain parameter Q
 * @param pqg.G [out] domain parameter G
 * @param Y [out] public DSA key parameter Y
 * @param R [out] DSA signature parameter R
 * @param S [out] DSA signature parameter S
 * @param privkey [in] DSA private key to be used for signature generation.
 *		  This variable is only set if dsa_keygen_en callback provided.
 */
struct dsa_siggen_data {
	uint64_t cipher;
	struct buffer msg;
	struct dsa_pqggen_data pqg;
	struct buffer Y;
	struct buffer R;
	struct buffer S;
	void *privkey;
};

/**
 * @brief DSA signature verification data structure holding the data for the
 *	  cipher operations specified with dsa_sigver.
 *
 * General note: all data buffers that are returned by the backend must be
 * allocated by the backend. The parser takes care of deallocating them.
 *
 * @param pqg.L [in] L size in bits
 * @param pqg.N [in] N size in bits
 * @param cipher [in] Hash type to use for signature operation
 * @param msg [in] Message whose signature shall be verified
 * @param pqg.P [in] domain parameter P
 * @param pqg.Q [in] domain parameter Q
 * @param pqg.G [in] domain parameter G
 * @param Y [in] public DSA key parameter Y
 * @param R [in] DSA signature parameter R
 * @param S [in] DSA signature parameter S
 * @param sigver_success [out] Is DSA signature successfully verified (1) or
 *			 whether the verification failed (0).
 */
struct dsa_sigver_data {
	uint64_t cipher;
	struct buffer msg;
	struct dsa_pqggen_data pqg;
	struct buffer Y;
	struct buffer R;
	struct buffer S;
	uint32_t sigver_success;
};

/**
 * @brief Callback data structure that must be implemented by the backend. Some
 *	  callbacks only need to be implemented if the respective cipher support
 *	  shall be tested.
 *
 * All functions return 0 on success or != 0 on error. Note, a failure in the
 * DSA PQG verification @param dsa_pqg due to problematic input parameters is
 * expected. In such cases, a DSA PQG verification error is still considered to
 * be a successful operation and the return code should be 0. Similarly, the
 * signature verification callback @param dsa_sigver shall return 0 if the
 * signature verification fails. Only if some general error is detected a
 * return code != must be returned.
 *
 * @param dsa_keygen DSA key generation
 * @param dsa_siggen DSA signature generation
 * @param dsa_sigver DSA signature verification
 * @param dsa_pqg PQG generation and verification callback handler -- see
 *		  the documentation for dsa_pqg_data how the backend can
 *		  identify the PQG operation type.
 * @param dsa_pqggen Generic PQG generation functionality without specific
 *		     limitations or requirements.
 *
 * @param dsa_keygen_en This is an optional helper call to reduce the amount
 *			of code in the backend for signature generation. The
 *			ACVP protocol requires that the same DSA key is used
 *			for multiple signature generation operation. Yet,
 *			the module must generate the DSA key. To allow the
 *			ACVP Parser to manage the DSA key and invoke the
 *			DSA key generation, you may provide this function with
 *			the following parameters:
 *			@param pqg [in] Buffer holding the PQG information to
 *					generate the DSA key.
 *			@param Y [out] Buffer with the DSA public key.
 *			@param privkey [out] Provide the pointer to the RSA
 *				        private key.
 * @param dsa_free_key This function is required if dsa_keygen_en is registered.
 *		       This function is intended to free the private RSA key
 *		       handle created with dsa_keygen_en.
 */
struct dsa_backend {
	int (*dsa_keygen)(struct dsa_keygen_data *data, flags_t parsed_flags);
	int (*dsa_siggen)(struct dsa_siggen_data *data, flags_t parsed_flags);
	int (*dsa_sigver)(struct dsa_sigver_data *data, flags_t parsed_flags);
	int (*dsa_pqg)(struct dsa_pqg_data *data, flags_t parsed_flags);
	int (*dsa_pqggen)(struct dsa_pqggen_data *data, flags_t parsed_flags);

	int (*dsa_keygen_en)(struct dsa_pqggen_data *pqg, struct buffer *Y,
			     void **privkey);
	void (*dsa_free_key)(void *privkey);
};

void register_dsa_impl(struct dsa_backend *implementation);

#endif /* _PARSER_DSA_H */
