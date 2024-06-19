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
#include "parser_ml_kem.h"

#define ML_KEM_DEF_CALLBACK(name, flags) DEF_CALLBACK(ml_kem, name, flags)
#define ML_KEM_DEF_CALLBACK_HELPER(name, flags, helper)			       \
				DEF_CALLBACK_HELPER(ml_kem, name, flags, helper)


static struct ml_kem_backend *ml_kem_backend = NULL;

static int ml_kem_tester(struct json_object *in, struct json_object *out,
			 uint64_t cipher)
{
	if (!ml_kem_backend) {
		logger(LOGGER_WARN, "No ML-KEM backend set\n");
		return -EOPNOTSUPP;
	}

	/**********************************************************************
	 * ML-KEM decapsulation
	 **********************************************************************/
	ML_KEM_DEF_CALLBACK(ml_kem_decapsulation,
			    FLAG_OP_VAL | FLAG_OP_ML_KEM_TYPE_DECAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP);

	const struct json_entry ml_kem_decapsulation_testresult_entries[] = {
		{"k",	{.data.buf = &ml_kem_decapsulation_vector.ss, WRITER_BIN},
			         FLAG_OP_VAL | FLAG_OP_ML_KEM_TYPE_DECAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
	};
	const struct json_testresult ml_kem_decapsulation_testresult = SET_ARRAY(ml_kem_decapsulation_testresult_entries,
		  &ml_kem_decapsulation_callbacks);

	const struct json_entry ml_kem_decapsulation_test_entries[] = {
		{"c",	{.data.buf = &ml_kem_decapsulation_vector.c, PARSER_BIN},
			        FLAG_OP_VAL |  FLAG_OP_ML_KEM_TYPE_DECAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
	};

	/* search for empty arrays */
	const struct json_array ml_kem_decapsulation_test =
		SET_ARRAY(ml_kem_decapsulation_test_entries,
			  &ml_kem_decapsulation_testresult);

	/**********************************************************************
	 * ML-KEM encapsulation
	 **********************************************************************/
	ML_KEM_DEF_CALLBACK(ml_kem_encapsulation,
			    FLAG_OP_AFT | FLAG_OP_ML_KEM_TYPE_ENCAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP);

	const struct json_entry ml_kem_encapsulation_testresult_entries[] = {
		{"c",		{.data.buf = &ml_kem_encapsulation_vector.c, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ML_KEM_TYPE_ENCAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
		{"k",		{.data.buf = &ml_kem_encapsulation_vector.ss, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ML_KEM_TYPE_ENCAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
	};
	const struct json_testresult ml_kem_encapsulation_testresult =
	SET_ARRAY(ml_kem_encapsulation_testresult_entries,
		  &ml_kem_encapsulation_callbacks);


	const struct json_entry ml_kem_encapsulation_test_entries[] = {
		/* canonical and unverifiable G generation */
		{"m",	{.data.buf = &ml_kem_encapsulation_vector.msg, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ML_KEM_TYPE_ENCAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
		{"ek",		{.data.buf = &ml_kem_encapsulation_vector.ek, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ML_KEM_TYPE_ENCAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
	};

	const struct json_array ml_kem_encapsulation_test = SET_ARRAY(ml_kem_encapsulation_test_entries, &ml_kem_encapsulation_testresult);

	const struct json_entry ml_kem_encapsulation_testgroup_entries[] = {
		/* Encapsulation */
		{"parameterSet",	{.data.largeint = &ml_kem_encapsulation_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_ML_KEM_TYPE_ENCAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
		{"tests",	{.data.array = &ml_kem_encapsulation_test, PARSER_ARRAY},		FLAG_OP_AFT | FLAG_OP_ML_KEM_TYPE_ENCAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},

		/* Decapsulation */
		{"parameterSet",	{.data.largeint = &ml_kem_decapsulation_vector.cipher, PARSER_CIPHER},	FLAG_OP_VAL | FLAG_OP_ML_KEM_TYPE_DECAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
		{"dk",		{.data.buf = &ml_kem_decapsulation_vector.dk, PARSER_BIN},	FLAG_OP_VAL | FLAG_OP_ML_KEM_TYPE_DECAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP},
		{"tests",	{.data.array = &ml_kem_decapsulation_test, PARSER_ARRAY},		FLAG_OP_VAL | FLAG_OP_ML_KEM_TYPE_DECAPSULATION | FLAG_OP_ASYM_TYPE_ENCAPDECAP },
	};

	const struct json_array ml_kem_encapsulation_testgroup =
		SET_ARRAY(ml_kem_encapsulation_testgroup_entries, NULL);

	/**********************************************************************
	 * ML-KEM key generation
	 **********************************************************************/
	ML_KEM_DEF_CALLBACK(ml_kem_keygen,
			    FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN);

	const struct json_entry ml_kem_keygen_testresult_entries[] = {
		{"ek",		{.data.buf = &ml_kem_keygen_vector.ek, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
		{"dk",		{.data.buf = &ml_kem_keygen_vector.dk, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};
	const struct json_testresult ml_kem_keygen_testresult =
	SET_ARRAY(ml_kem_keygen_testresult_entries, &ml_kem_keygen_callbacks);


	const struct json_entry ml_kem_keygen_test_entries[] = {
		/* canonical and unverifiable G generation */
		{"z",	{.data.buf = &ml_kem_keygen_vector.z, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
		{"d",	{.data.buf = &ml_kem_keygen_vector.d, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};

	const struct json_array ml_kem_keygen_test = SET_ARRAY(ml_kem_keygen_test_entries, &ml_kem_keygen_testresult);

	const struct json_entry ml_kem_keygen_testgroup_entries[] = {
		/* L, N are provided for SP800-56A rev 1 / FIPS 186-4 keygen */
		{"parameterSet",	{.data.largeint = &ml_kem_keygen_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},

		{"tests",	{.data.array = &ml_kem_keygen_test, PARSER_ARRAY},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN},
	};

	const struct json_array ml_kem_keygen_testgroup =
		SET_ARRAY(ml_kem_keygen_testgroup_entries, NULL);

	/**********************************************************************
	 * ML-KEM common test group
	 **********************************************************************/
	const struct json_entry ml_kem_testanchor_entries[] = {
		{"testGroups",	{.data.array = &ml_kem_keygen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_KEYGEN},
		{"testGroups",	{.data.array = &ml_kem_encapsulation_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_ENCAPDECAP},
	};
	const struct json_array ml_kem_testanchor = SET_ARRAY(ml_kem_testanchor_entries, NULL);

	(void)cipher;

	/* Process all. */
	return process_json(&ml_kem_testanchor, "1.0", in, out);
}

static struct cavs_tester ml_kem =
{
	0,
	ACVP_ML_KEM,
	ml_kem_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_ml_kem)
static void register_ml_kem(void)
{
	register_tester(&ml_kem, "ML-KEM");
}

void register_ml_kem_impl(struct ml_kem_backend *implementation)
{
	register_backend(ml_kem_backend, implementation, "ML-KEM");
}
