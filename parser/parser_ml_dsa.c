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

#include <string.h>

#include "cipher_definitions.h"
#include "constructor.h"
#include "stringhelper.h"
#include "read_json.h"
#include "logger.h"

#include "parser_common.h"
#include "parser_ml_dsa.h"

#define ML_DSA_DEF_CALLBACK(name, flags) DEF_CALLBACK(ml_dsa, name, flags)
#define ML_DSA_DEF_CALLBACK_HELPER(name, flags, helper)			       \
				DEF_CALLBACK_HELPER(ml_dsa, name, flags, helper)


static struct ml_dsa_backend *ml_dsa_backend = NULL;

struct ml_dsa_static_key {
	void *sk;
	uint64_t cipher;
	struct buffer pk;
};
static struct ml_dsa_static_key ml_dsa_key = { NULL, 0, {NULL, 0} };

static void ml_dsa_key_free(struct ml_dsa_static_key *key)
{
	if (!key)
		return;

	free_buf(&key->pk);
	if (ml_dsa_backend->ml_dsa_free_key)
		ml_dsa_backend->ml_dsa_free_key(&key->sk);
	key->sk = NULL;
	key->cipher  = 0;
}

static void ml_dsa_key_free_static(void)
{
	ml_dsa_key_free(&ml_dsa_key);
}

static int ml_dsa_duplicate_buf(const struct buffer *src, struct buffer *dst)
{
	int ret;

	CKINT(alloc_buf(src->len, dst));
	memcpy(dst->buf, src->buf, dst->len);

out:
	return ret;
}

static int ml_dsa_siggen_keygen(struct ml_dsa_siggen_data *data)
{
	int ret = 0;

	/* Do not generate anything if SK is provided */
	if (data->sk.len)
		return 0;

	if ((ml_dsa_key.cipher != data->cipher) || !ml_dsa_key.sk) {
		ml_dsa_key_free_static();
		CKINT(ml_dsa_backend->ml_dsa_keygen_en(data->cipher,
						       &data->pk,
						       &ml_dsa_key.sk));

		logger_binary(LOGGER_DEBUG, data->pk.buf, data->pk.len,
			      "ML-DSA generated public key");

		/* Free the global variable at exit */
		atexit(ml_dsa_key_free_static);

		CKINT(ml_dsa_duplicate_buf(&data->pk, &ml_dsa_key.pk));
		ml_dsa_key.cipher = data->cipher;
	}

	if (!data->pk.len)
		CKINT(ml_dsa_duplicate_buf(&ml_dsa_key.pk, &data->pk));

	data->privkey = ml_dsa_key.sk;

out:
	return ret;
}

static int ml_dsa_siggen_helper(const struct json_array *processdata,
				flags_t parsed_flags,
				struct json_object *testvector,
				struct json_object *testresults,
	int (*callback)(struct ml_dsa_siggen_data *vector, flags_t parsed_flags),
			struct ml_dsa_siggen_data *vector)
{
	int ret;

	(void)processdata;
	(void)testvector;
	(void)testresults;

	if (ml_dsa_backend->ml_dsa_keygen_en) {
		CKINT(ml_dsa_siggen_keygen(vector));
	}

	CKINT(callback(vector, parsed_flags));

out:
	return ret;
}

static int ml_dsa_tester(struct json_object *in, struct json_object *out,
			 uint64_t cipher)
{
	if (!ml_dsa_backend) {
		logger(LOGGER_WARN, "No ML-DSA backend set\n");
		return -EOPNOTSUPP;
	}

	/**********************************************************************
	 * ML-DSA signature verification
	 **********************************************************************/
	ML_DSA_DEF_CALLBACK(ml_dsa_sigver,
			    FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC);

	const struct json_entry ml_dsa_sigver_testresult_entries[] = {
		{"testPassed",	{.data.integer = &ml_dsa_sigver_vector.sigver_success, WRITER_BOOL},
			         FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},
	};
	const struct json_testresult ml_dsa_sigver_testresult = SET_ARRAY(ml_dsa_sigver_testresult_entries, &ml_dsa_sigver_callbacks);

	const struct json_entry ml_dsa_sigver_test_entries[] = {
		{"message",	{.data.buf = &ml_dsa_sigver_vector.msg, PARSER_BIN},
			        FLAG_OP_AFT |  FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},
		{"signature",	{.data.buf = &ml_dsa_sigver_vector.sig, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},
	};

	/* search for empty arrays */
	const struct json_array ml_dsa_sigver_test = SET_ARRAY(ml_dsa_sigver_test_entries, &ml_dsa_sigver_testresult);

	const struct json_entry ml_dsa_sigver_testgroup_entries[] = {
		{"parameterSet",	{.data.largeint = &ml_dsa_sigver_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER},
		{"pk",		{.data.buf = &ml_dsa_sigver_vector.pk, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER},

		{"tests",	{.data.array = &ml_dsa_sigver_test, PARSER_ARRAY},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER  |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},
	};
	const struct json_array ml_dsa_sigver_testgroup = SET_ARRAY(ml_dsa_sigver_testgroup_entries, NULL);

	/**********************************************************************
	 * ML-DSA signature generation GDT and AFT
	 **********************************************************************/
	ML_DSA_DEF_CALLBACK_HELPER(ml_dsa_siggen,
				   FLAG_OP_GDT | FLAG_OP_AFT |
				   FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC,
				   ml_dsa_siggen_helper);

	const struct json_entry ml_dsa_siggen_testresult_entries[] = {
		{"signature",		{.data.buf = &ml_dsa_siggen_vector.sig, WRITER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC}
	};
	const struct json_testresult ml_dsa_siggen_testresult =
	SET_ARRAY(ml_dsa_siggen_testresult_entries, &ml_dsa_siggen_callbacks);


	const struct json_entry ml_dsa_siggen_test_entries[] = {
		/* canonical and unverifiable G generation */
		{"message",	{.data.buf = &ml_dsa_siggen_vector.msg, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},
		{"rnd",		{.data.buf = &ml_dsa_siggen_vector.rnd, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC | FLAG_OPTIONAL},
		{"sk",		{.data.buf = &ml_dsa_siggen_vector.sk, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC | FLAG_OPTIONAL},
	};

	const struct json_array ml_dsa_siggen_test = SET_ARRAY(ml_dsa_siggen_test_entries, &ml_dsa_siggen_testresult);

	const struct json_entry ml_dsa_siggen_testgroup_result_entries[] = {
		{"pk",		{.data.buf = &ml_dsa_siggen_vector.pk, WRITER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},
	};
	/*
	 * The NULL for the function callbacks implies that the n and e
	 * are printed at the same hierarchy level as tgID
	 */
	const struct json_testresult ml_dsa_siggen_testgroup_result = SET_ARRAY(ml_dsa_siggen_testgroup_result_entries, NULL);

	const struct json_entry ml_dsa_siggen_testgroup_entries[] = {
		/* L, N are provided for SP800-56A rev 1 / FIPS 186-4 siggen */
		{"parameterSet",	{.data.largeint = &ml_dsa_siggen_vector.cipher, PARSER_CIPHER},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},

		{"tests",	{.data.array = &ml_dsa_siggen_test, PARSER_ARRAY},		FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_ML_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_ML_DSA_TYPE_NONDETERMINISTIC},
	};

	const struct json_array ml_dsa_siggen_testgroup =
		SET_ARRAY(ml_dsa_siggen_testgroup_entries,
			  &ml_dsa_siggen_testgroup_result);

	/**********************************************************************
	 * ML-DSA key generation
	 **********************************************************************/
	ML_DSA_DEF_CALLBACK(ml_dsa_keygen,
			    FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN);

	const struct json_entry ml_dsa_keygen_testresult_entries[] = {
		{"pk",		{.data.buf = &ml_dsa_keygen_vector.pk, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
		{"sk",		{.data.buf = &ml_dsa_keygen_vector.sk, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};
	const struct json_testresult ml_dsa_keygen_testresult =
	SET_ARRAY(ml_dsa_keygen_testresult_entries, &ml_dsa_keygen_callbacks);


	const struct json_entry ml_dsa_keygen_test_entries[] = {
		{"seed",	{.data.buf = &ml_dsa_keygen_vector.seed, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};

	const struct json_array ml_dsa_keygen_test = SET_ARRAY(ml_dsa_keygen_test_entries, &ml_dsa_keygen_testresult);

	const struct json_entry ml_dsa_keygen_testgroup_entries[] = {
		{"parameterSet",	{.data.largeint = &ml_dsa_keygen_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},

		{"tests",	{.data.array = &ml_dsa_keygen_test, PARSER_ARRAY},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};

	const struct json_array ml_dsa_keygen_testgroup =
		SET_ARRAY(ml_dsa_keygen_testgroup_entries, NULL);

	/**********************************************************************
	 * ML-DSA common test group
	 **********************************************************************/
	const struct json_entry ml_dsa_testanchor_entries[] = {
		{"testGroups",	{.data.array = &ml_dsa_keygen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_KEYGEN},
		{"testGroups",	{.data.array = &ml_dsa_siggen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGGEN},
		{"testGroups",	{.data.array = &ml_dsa_sigver_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGVER},
	};
	const struct json_array ml_dsa_testanchor = SET_ARRAY(ml_dsa_testanchor_entries, NULL);

	(void)cipher;

	/* Process all. */
	return process_json(&ml_dsa_testanchor, "1.0", in, out);
}

static struct cavs_tester ml_dsa =
{
	0,
	ACVP_ML_DSA,
	ml_dsa_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_ml_dsa)
static void register_ml_dsa(void)
{
	register_tester(&ml_dsa, "ML-DSA");
}

void register_ml_dsa_impl(struct ml_dsa_backend *implementation)
{
	register_backend(ml_dsa_backend, implementation, "ML-DSA");
}
