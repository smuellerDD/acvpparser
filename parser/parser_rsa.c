/*
 * Copyright (C) 2017, Stephan Mueller <smueller@chronox.de>
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

#include <limits.h>
#include <string.h>

#include "parser.h"
#include "logger.h"

#include "parser_common.h"
#include "parser_rsa.h"
#include "stringhelper.h"

#define RSA_DEF_CALLBACK(name, flags)		DEF_CALLBACK(rsa, name, flags)
#define RSA_DEF_CALLBACK_HELPER(name, flags, helper)			       \
				DEF_CALLBACK_HELPER(rsa, name, flags, helper)

struct rsa_backend *rsa_backend = NULL;

struct rsa_static_key {
	void *key;
	uint32_t modulus;
	struct buffer e;
	struct buffer n;
};
static struct rsa_static_key rsa_key = { 0 };

static void rsa_key_free(struct rsa_static_key *key)
{
	if (key->key)
		rsa_backend->rsa_free_key(key->key);
	key->key = NULL;
	key->modulus = 0;

	free_buf(&key->e);
	free_buf(&key->n);
}

static void rsa_key_free_static(void)
{
	rsa_key_free(&rsa_key);
}

static int rsa_duplicate_buf(const struct buffer *src, struct buffer *dst)
{
	int ret;

	CKINT(alloc_buf(src->len, dst));
	memcpy(dst->buf, src->buf, dst->len);

out:
	return ret;
}

static int rsa_siggen_keygen(struct rsa_siggen_data *data, void **rsa_privkey)
{
	int ret = 0;

	if ((rsa_key.modulus != data->modulus) || !rsa_key.key) {
		rsa_key_free_static();
		CKINT(rsa_backend->rsa_keygen_en(&data->e, data->modulus,
						 &rsa_key.key, &data->n));

		logger_binary(LOGGER_DEBUG, data->n.buf, data->n.len,
			      "RSA generated n");
		logger_binary(LOGGER_DEBUG, data->e.buf, data->e.len,
			      "RSA generated e");

		/* Free the global variable at exit */
		atexit(rsa_key_free_static);

		CKINT(rsa_duplicate_buf(&data->e, &rsa_key.e));
		CKINT(rsa_duplicate_buf(&data->n, &rsa_key.n));
		rsa_key.modulus = data->modulus;
	}

	if (!data->e.len)
		CKINT(rsa_duplicate_buf(&rsa_key.e, &data->e));
	if (!data->n.len)
		CKINT(rsa_duplicate_buf(&rsa_key.n, &data->n));

	*rsa_privkey = rsa_key.key;

out:
	return ret;
}

static int rsa_siggen_helper(const struct json_array *processdata,
			     flags_t parsed_flags,
			     struct json_object *testvector,
			     struct json_object *testresults,
	int (*callback)(struct rsa_siggen_data *vector, flags_t parsed_flags),
			struct rsa_siggen_data *vector)
{
	int ret;
	void *rsa_privkey = NULL;

	(void)processdata;
	(void)testvector;
	(void)testresults;

	if (rsa_backend->rsa_keygen_en && rsa_backend->rsa_free_key) {
		CKINT(rsa_siggen_keygen(vector, &rsa_privkey));
	}

	vector->privkey = rsa_privkey;

	CKINT(callback(vector, parsed_flags));

out:
	return ret;
}

static int rsa_tester(struct json_object *in, struct json_object *out,
		      uint64_t cipher)
{
	(void)cipher;

	if (!rsa_backend) {
		logger(LOGGER_WARN, "No RSA backend set\n");
		return -EOPNOTSUPP;
	}

	/**********************************************************************
	 * RSA B.3.4, B.3.5, B.3.6 KeyGen KAT and KeyGen GDT
	 **********************************************************************/
	RSA_DEF_CALLBACK(rsa_keygen, FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES);

	const struct json_entry rsa_keygen_testresult_entries[] = {
		{"e",	{.data.buf = &rsa_keygen_vector.e, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES},
		{"p",	{.data.buf = &rsa_keygen_vector.p, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES},
		{"q",	{.data.buf = &rsa_keygen_vector.q, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES},
		{"n",	{.data.buf = &rsa_keygen_vector.n, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES},
		{"d",	{.data.buf = &rsa_keygen_vector.d, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES},
	};
	const struct json_testresult rsa_keygen_testresult = SET_ARRAY(rsa_keygen_testresult_entries, &rsa_keygen_callbacks);

	/* search for empty arrays */
	const struct json_array rsa_keygen_test = {NULL, 0 , &rsa_keygen_testresult};

	/**********************************************************************
	 * RSA B.3.2 KeyGen KAT and KeyGen GDT
	 **********************************************************************/
	RSA_DEF_CALLBACK(rsa_keygen_prov_prime, FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES);

	const struct json_entry rsa_keygen_prov_prime_testresult_entries[] = {
		{"e",	{.data.buf = &rsa_keygen_prov_prime_vector.e, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
		{"seed",	{.data.buf = &rsa_keygen_prov_prime_vector.seed, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
		{"p",	{.data.buf = &rsa_keygen_prov_prime_vector.p, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
		{"q",	{.data.buf = &rsa_keygen_prov_prime_vector.q, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
		{"n",	{.data.buf = &rsa_keygen_prov_prime_vector.n, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
		{"d",	{.data.buf = &rsa_keygen_prov_prime_vector.d, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
	};
	const struct json_testresult rsa_keygen_prov_prime_testresult =
		SET_ARRAY(rsa_keygen_prov_prime_testresult_entries,
			  &rsa_keygen_prov_prime_callbacks);

	/* search for empty arrays */
	const struct json_array rsa_keygen_prov_prime_test = {NULL, 0 , &rsa_keygen_prov_prime_testresult};

	/**********************************************************************
	 * RSA B.3.3 KeyGen KAT
	 **********************************************************************/
	RSA_DEF_CALLBACK(rsa_keygen_prime, FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES);

	const struct json_entry rsa_keygen_prime_testresult_entries[] = {
		{"testPassed",	{.data.integer = &rsa_keygen_prime_vector.keygen_success, WRITER_BOOL},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES},
	};

	const struct json_entry rsa_keygen_prime_test_entries[] = {
		{"e",		{.data.buf = &rsa_keygen_prime_vector.e, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES},
		{"p",	{.data.buf = &rsa_keygen_prime_vector.p, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES},
		{"q",		{.data.buf = &rsa_keygen_prime_vector.q, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES},
	};

	const struct json_testresult rsa_keygen_prime_testresult =
		SET_ARRAY(rsa_keygen_prime_testresult_entries,
			  &rsa_keygen_prime_callbacks);

	/* search for empty arrays */
	const struct json_array rsa_keygen_prime_test = SET_ARRAY(rsa_keygen_prime_test_entries, &rsa_keygen_prime_testresult);

	/**********************************************************************
	 * RSA SigGen
	 **********************************************************************/
	RSA_DEF_CALLBACK_HELPER(rsa_siggen, FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK, rsa_siggen_helper);

	/*
	 * Define which test result data should be written to the test result
	 * JSON file.
	 */
	const struct json_entry rsa_siggen_testresult_entries[] = {
		{"signature",	{.data.buf = &rsa_siggen_vector.sig, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_testresult rsa_siggen_testresult = SET_ARRAY(rsa_siggen_testresult_entries, &rsa_siggen_callbacks);

	const struct json_entry rsa_siggen_test_entries[] = {
		{"message",		{.data.buf = &rsa_siggen_vector.msg, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_array rsa_siggen_test = SET_ARRAY(rsa_siggen_test_entries, &rsa_siggen_testresult);

	/**********************************************************************
	 * RSA PKCS1 SigVer
	 **********************************************************************/
	RSA_DEF_CALLBACK(rsa_sigver, FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK);

	/*
	 * Define which test result data should be written to the test result
	 * JSON file.
	 */
	const struct json_entry rsa_sigver_testresult_entries[] = {
		{"testPassed",	{.data.integer = &rsa_sigver_vector.sig_result, WRITER_BOOL},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_testresult rsa_sigver_testresult = SET_ARRAY(rsa_sigver_testresult_entries, &rsa_sigver_callbacks);


	const struct json_entry rsa_sigver_test_entries[] = {
		{"message",		{.data.buf = &rsa_sigver_vector.msg, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"signature",		{.data.buf = &rsa_sigver_vector.sig, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_array rsa_sigver_test = SET_ARRAY(rsa_sigver_test_entries, &rsa_sigver_testresult);

	/**********************************************************************
	 * RSA common test group
	 **********************************************************************/
	const struct json_entry rsa_keygen_testgroup_entries[] = {
		{"modulo",	{.data.integer = &rsa_keygen_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES},
		{"modulo",	{.data.integer = &rsa_keygen_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B33_PRIMES},
		{"modulo",	{.data.integer = &rsa_keygen_prime_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES},

		{"modulo",	{.data.integer = &rsa_keygen_prov_prime_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
		{"hashAlg",	{.data.largeint = &rsa_keygen_prov_prime_vector.cipher, PARSER_CIPHER},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},

		{"tests",	{.data.array = &rsa_keygen_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES},
		{"tests",	{.data.array = &rsa_keygen_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B33_PRIMES},

		{"tests",	{.data.array = &rsa_keygen_prime_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES},

		{"tests",	{.data.array = &rsa_keygen_prov_prime_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES},
	};
	const struct json_array rsa_keygen_testgroup = SET_ARRAY(rsa_keygen_testgroup_entries, NULL);

	const struct json_entry rsa_siggen_testgroup_result_entries[] = {
		{"e",	{.data.buf = &rsa_siggen_vector.e, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"n",	{.data.buf = &rsa_siggen_vector.n, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
	};
	/*
	 * The NULL for the function callbacks implies that the n and e
	 * are printed at the same hierarchy level as tgID
	 */
	const struct json_testresult rsa_siggen_testgroup_result = SET_ARRAY(rsa_siggen_testgroup_result_entries, NULL);

	const struct json_entry rsa_siggen_testgroup_entries[] = {
		{"hashAlg",	{.data.largeint = &rsa_siggen_vector.cipher, PARSER_CIPHER},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"saltLen",	{.data.integer = &rsa_siggen_vector.saltlen, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK | FLAG_OPTIONAL},
		{"modulo",	{.data.integer = &rsa_siggen_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"tests",	{.data.array = &rsa_siggen_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_SIGGEN | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_array rsa_siggen_testgroup = SET_ARRAY(rsa_siggen_testgroup_entries, &rsa_siggen_testgroup_result);

	const struct json_entry rsa_sigver_testgroup_entries[] = {
		{"hashAlg",	{.data.largeint = &rsa_sigver_vector.cipher, PARSER_CIPHER},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"saltLen",	{.data.integer = &rsa_sigver_vector.saltlen, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK | FLAG_OPTIONAL},
		{"modulo",	{.data.integer = &rsa_sigver_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"n",		{.data.buf = &rsa_sigver_vector.n, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"e",		{.data.buf = &rsa_sigver_vector.e, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK},
		{"tests",	{.data.array = &rsa_sigver_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_SIGVER | FLAG_OP_GDT | FLAG_OP_RSA_SIG_MASK}
	};
	const struct json_array rsa_sigver_testgroup = SET_ARRAY(rsa_sigver_testgroup_entries, NULL);

	const struct json_entry rsa_testanchor_entries[] = {
		{"testGroups",	{.data.array = &rsa_keygen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_KEYGEN},
		{"testGroups",	{.data.array = &rsa_siggen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGGEN},
		{"testGroups",	{.data.array = &rsa_sigver_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGVER},
	};
	const struct json_array rsa_testanchor = SET_ARRAY(rsa_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&rsa_testanchor, "0.5", in, out);
}

static struct cavs_tester rsa =
{
	ACVP_RSA,
	rsa_tester,
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_rsa)
static void register_rsa(void)
{
	register_tester(&rsa, "RSA");
}

void register_rsa_impl(struct rsa_backend *implementation)
{
	register_backend(rsa_backend, implementation, "RSA");
}
