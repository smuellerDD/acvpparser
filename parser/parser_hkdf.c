/*
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#include "logger.h"
#include "parser_common.h"

static struct hkdf_backend *hkdf_backend = NULL;

static int hkdf_tester(struct json_object *in, struct json_object *out,
			  uint64_t cipher)
{
	(void)cipher;

	if (!hkdf_backend) {
		logger(LOGGER_WARN, "No SP800-108 KDF backend set\n");
		return -EOPNOTSUPP;
	}

	DEF_CALLBACK(hkdf, hkdf, FLAG_OP_AFT);

	/*
	 * Define which test result data should be written to the test result
	 * JSON file.
	 */
	const struct json_entry hkdf_testresult_entries[] = {
		{"okm",	{.data.buf = &hkdf_vector.okm, WRITER_BIN}, FLAG_OP_AFT},
		{"salt",{.data.buf = &hkdf_vector.salt, WRITER_BIN}, FLAG_OP_AFT},
		{"info",{.data.buf = &hkdf_vector.info, WRITER_BIN}, FLAG_OP_AFT},
	};
	const struct json_testresult hkdf_testresult = SET_ARRAY(hkdf_testresult_entries, &hkdf_callbacks);

	/*
	 * Define one particular test vector that is expected in the JSON
	 * file.
	 */
	const struct json_entry hkdf_test_entries[] = {
		{"ikm",	{.data.buf = &hkdf_vector.ikm, PARSER_BIN}, FLAG_OP_AFT},
	};
	const struct json_array hkdf_test =
		SET_ARRAY(hkdf_test_entries, &hkdf_testresult);

	/*
	 * Define the test group which contains ancillary data and eventually
	 * the array of individual test vectors.
	 *
	 * As this definition does not mark specific individual test vectors,
	 * the testresult entry is set to NULL.
	 */
	const struct json_entry hkdf_testgroup_entries[] = {
		{"macMode",	{.data.largeint = &hkdf_vector.mac, PARSER_CIPHER}, FLAG_OP_AFT},

		{"okmLength",	{.data.integer = &hkdf_vector.okmlen, PARSER_UINT}, FLAG_OP_AFT},

		{"tests",	{.data.array = &hkdf_test, PARSER_ARRAY}, FLAG_OP_AFT},
	};
	const struct json_array hkdf_testgroup = SET_ARRAY(hkdf_testgroup_entries, NULL);

	/*
	 * Define the anchor of the tests in the highest level of the JSON
	 * input data.
	 */
	const struct json_entry hkdf_testanchor_entries[] = {
		{"testGroups",	{.data.array = &hkdf_testgroup, PARSER_ARRAY},	0},
	};
	const struct json_array hkdf_testanchor = SET_ARRAY(hkdf_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&hkdf_testanchor, "1.0", in, out);
}

static struct cavs_tester hkdf =
{
	ACVP_HKDF,
	hkdf_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_hkdf)
static void register_hkdf(void)
{
	register_tester(&hkdf, "HKDF");
}

void register_hkdf_impl(struct hkdf_backend *implementation)
{
	register_backend(hkdf_backend, implementation, "HKDF");
}
