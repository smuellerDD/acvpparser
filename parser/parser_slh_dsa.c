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
#include "parser_slh_dsa.h"

#define SLH_DSA_DEF_CALLBACK(name, flags) DEF_CALLBACK(slh_dsa, name, flags)
#define SLH_DSA_DEF_CALLBACK_HELPER(name, flags, helper)		       \
				DEF_CALLBACK_HELPER(slh_dsa, name, flags, helper)


static struct slh_dsa_backend *slh_dsa_backend = NULL;

static int slh_dsa_tester(struct json_object *in, struct json_object *out,
			 uint64_t cipher)
{
	if (!slh_dsa_backend) {
		logger(LOGGER_WARN, "No SLH-DSA backend set\n");
		return -EOPNOTSUPP;
	}

	/**********************************************************************
	 * SLH-DSA signature verification
	 **********************************************************************/
	SLH_DSA_DEF_CALLBACK(slh_dsa_sigver,
			    FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL);

	const struct json_entry slh_dsa_sigver_testresult_entries[] = {
		{"testPassed",	{.data.integer = &slh_dsa_sigver_vector.sigver_success, WRITER_BOOL},
			         FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
	};
	const struct json_testresult slh_dsa_sigver_testresult = SET_ARRAY(slh_dsa_sigver_testresult_entries, &slh_dsa_sigver_callbacks);

	const struct json_entry slh_dsa_sigver_test_entries[] = {
		{"pk",		{.data.buf = &slh_dsa_sigver_vector.pk, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
		{"message",	{.data.buf = &slh_dsa_sigver_vector.msg, PARSER_BIN},
			        FLAG_OP_AFT |  FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
		{"signature",	{.data.buf = &slh_dsa_sigver_vector.sig, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
		{"context",	{.data.buf = &slh_dsa_sigver_vector.context, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL | FLAG_OPTIONAL},
		{"hashAlg",	{.data.largeint = &slh_dsa_sigver_vector.hashalg, PARSER_CIPHER},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL | FLAG_OPTIONAL},
	};

	/* search for empty arrays */
	const struct json_array slh_dsa_sigver_test = SET_ARRAY(slh_dsa_sigver_test_entries, &slh_dsa_sigver_testresult);

	const struct json_entry slh_dsa_sigver_testgroup_entries[] = {
		{"parameterSet",	{.data.largeint = &slh_dsa_sigver_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
		{"signatureInterface",	{.data.buf = &slh_dsa_sigver_vector.interface, PARSER_STRING},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},

		{"tests",	{.data.array = &slh_dsa_sigver_test, PARSER_ARRAY},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER  |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
	};
	const struct json_array slh_dsa_sigver_testgroup = SET_ARRAY(slh_dsa_sigver_testgroup_entries, NULL);

	/**********************************************************************
	 * SLH-DSA signature generation GDT and AFT
	 **********************************************************************/
	SLH_DSA_DEF_CALLBACK(slh_dsa_siggen,
				   FLAG_OP_GDT | FLAG_OP_AFT |
				   FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL);

	const struct json_entry slh_dsa_siggen_testresult_entries[] = {
		{"signature",		{.data.buf = &slh_dsa_siggen_vector.sig, WRITER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL}
	};
	const struct json_testresult slh_dsa_siggen_testresult =
	SET_ARRAY(slh_dsa_siggen_testresult_entries, &slh_dsa_siggen_callbacks);


	const struct json_entry slh_dsa_siggen_test_entries[] = {
		/* canonical and unverifiable G generation */
		{"message",	{.data.buf = &slh_dsa_siggen_vector.msg, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
		{"additionalRandomness",		{.data.buf = &slh_dsa_siggen_vector.rnd, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL | FLAG_OPTIONAL},
		{"sk",		{.data.buf = &slh_dsa_siggen_vector.sk, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL | FLAG_OPTIONAL},
		{"context",		{.data.buf = &slh_dsa_siggen_vector.context, PARSER_BIN},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL | FLAG_OPTIONAL},
		{"hashAlg",		{.data.largeint = &slh_dsa_siggen_vector.hashalg, PARSER_CIPHER},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL | FLAG_OPTIONAL},
	};

	const struct json_array slh_dsa_siggen_test = SET_ARRAY(slh_dsa_siggen_test_entries, &slh_dsa_siggen_testresult);

	const struct json_entry slh_dsa_siggen_testgroup_entries[] = {
		/* L, N are provided for SP800-56A rev 1 / FIPS 186-4 siggen */
		{"parameterSet",	{.data.largeint = &slh_dsa_siggen_vector.cipher, PARSER_CIPHER},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
		{"signatureInterface",	{.data.buf = &slh_dsa_siggen_vector.interface, PARSER_STRING},	FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},

		{"tests",	{.data.array = &slh_dsa_siggen_test, PARSER_ARRAY},		FLAG_OP_GDT | FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGGEN |
				   FLAG_OP_SLH_DSA_TYPE_DETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_NONDETERMINISTIC |
				   FLAG_OP_SLH_DSA_TYPE_EXTERNAL |
				   FLAG_OP_SLH_DSA_TYPE_INTERNAL},
	};

	const struct json_array slh_dsa_siggen_testgroup =
		SET_ARRAY(slh_dsa_siggen_testgroup_entries, NULL);

	/**********************************************************************
	 * SLH-DSA key generation
	 **********************************************************************/
	SLH_DSA_DEF_CALLBACK(slh_dsa_keygen,
			    FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN);

	const struct json_entry slh_dsa_keygen_testresult_entries[] = {
		{"pk",		{.data.buf = &slh_dsa_keygen_vector.pk, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
		{"sk",		{.data.buf = &slh_dsa_keygen_vector.sk, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};
	const struct json_testresult slh_dsa_keygen_testresult =
	SET_ARRAY(slh_dsa_keygen_testresult_entries, &slh_dsa_keygen_callbacks);


	const struct json_entry slh_dsa_keygen_test_entries[] = {
		{"skSeed",	{.data.buf = &slh_dsa_keygen_vector.sk_seed, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
		{"skPrf",	{.data.buf = &slh_dsa_keygen_vector.sk_prf, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
		{"pkSeed",	{.data.buf = &slh_dsa_keygen_vector.pk_seed, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};

	const struct json_array slh_dsa_keygen_test = SET_ARRAY(slh_dsa_keygen_test_entries, &slh_dsa_keygen_testresult);

	const struct json_entry slh_dsa_keygen_testgroup_entries[] = {
		{"parameterSet",	{.data.largeint = &slh_dsa_keygen_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},

		{"tests",	{.data.array = &slh_dsa_keygen_test, PARSER_ARRAY},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};

	const struct json_array slh_dsa_keygen_testgroup =
		SET_ARRAY(slh_dsa_keygen_testgroup_entries, NULL);

	/**********************************************************************
	 * SLH-DSA common test group
	 **********************************************************************/
	const struct json_entry slh_dsa_testanchor_entries[] = {
		{"testGroups",	{.data.array = &slh_dsa_keygen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_KEYGEN},
		{"testGroups",	{.data.array = &slh_dsa_siggen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGGEN},
		{"testGroups",	{.data.array = &slh_dsa_sigver_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGVER},
	};
	const struct json_array slh_dsa_testanchor = SET_ARRAY(slh_dsa_testanchor_entries, NULL);

	(void)cipher;

	/* Process all. */
	return process_json(&slh_dsa_testanchor, "1.0", in, out);
}

static struct cavs_tester slh_dsa =
{
	0,
	ACVP_SLH_DSA,
	slh_dsa_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_slh_dsa)
static void register_slh_dsa(void)
{
	register_tester(&slh_dsa, "SLH-DSA");
}

void register_slh_dsa_impl(struct slh_dsa_backend *implementation)
{
	register_backend(slh_dsa_backend, implementation, "SLH-DSA");
}
