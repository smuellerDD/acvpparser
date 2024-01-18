/*
 * Copyright (C) 2017 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "conversion_be_le.h"
#include "parser.h"
#include "stringhelper.h"
#include "read_json.h"
#include "logger.h"

#include "parser_common.h"
#include "parser_cshake.h"
#include "parser_sha_mct_helper.h"

static struct cshake_backend *cshake_backend = NULL;

#define min(x, y)	(((size_t)x < (size_t)y) ? x : y)

static int cshake_mct_helper(const struct json_array *processdata,
			     flags_t parsed_flags,
			     struct json_object *testvector,
			     struct json_object *testresults,
			     int (*callback)(struct cshake_data *vector,
					     flags_t parsed_flags),
			     struct cshake_data *vector)
{
	unsigned int i;
	int ret;
	struct json_object *testresult, *resultsarray = NULL;
	uint8_t tmp[16];

	(void)callback;
	(void)processdata;

	CKNULL(cshake_backend->cshake_generate, -EOPNOTSUPP);

	/* Create output stream. */
	resultsarray = json_object_new_array();
	CKNULL(resultsarray, -ENOMEM);
	testresult = json_object_new_object();
	CKNULL(testresult, -ENOMEM);
	CKINT(json_add_test_data(testvector, testresult));

	vector->outlen = vector->maxoutlen;

	/*
	 * Ensure that we only look at the leftmost 16 bytes. This should be
	 * a noop these days, but keep the check to be sure.
	 */
	vector->msg.len = min(vector->msg.len, sizeof(tmp));
	memcpy(tmp, vector->msg.buf, vector->msg.len);

	for (i = 0; i < 100; i++) {
		struct json_object *single_mct_result;

		/*
		 * Create the output JSON stream holding the test
		 * results.
		 */
		single_mct_result = json_object_new_object();
		CKNULL(single_mct_result, -ENOMEM);
		/* Append the output JSON stream with test results. */
		CKINT(json_object_array_add(resultsarray, single_mct_result));

		CKINT(parser_cshake_inner_loop(vector, parsed_flags,
			cshake_backend->cshake_generate));

		CKINT(json_add_bin2hex(single_mct_result, "md",
				       &vector->mac));
		CKINT(json_object_object_add(single_mct_result, "outLen",
				json_object_new_int((int)vector->mac.len * 8)));
	}

	CKINT(json_object_object_add(testresult, "resultsArray", resultsarray));
	/* Append the output JSON stream with test results. */
	CKINT(json_object_array_add(testresults, testresult));

	/* We have written data, generic parser should not write it. */
	ret = FLAG_RES_DATA_WRITTEN;

out:
	if (ret && ret != FLAG_RES_DATA_WRITTEN) {
		if (resultsarray)
			json_object_put(resultsarray);
	}

	return ret;
}

static int cshake_tester(struct json_object *in, struct json_object *out,
			 uint64_t cipher)
{
	struct cshake_data vector;

	if (!cshake_backend) {
		logger(LOGGER_WARN, "No cSHAKE backend set\n");
		return -EOPNOTSUPP;
	}

	/* Referencing the backend functions */
	const struct cshake_callback cshake_aft = { cshake_backend->cshake_generate, &vector, NULL};
	const struct json_callback cshake_callback_aft[] = {
		{ .callback.cshake = cshake_aft, CB_TYPE_cshake, FLAG_OP_AFT},
	};
	const struct json_callbacks cshake_callbacks_aft = SET_CALLBACKS(cshake_callback_aft);

	const struct cshake_callback cshake_mct = { cshake_backend->cshake_generate, &vector, cshake_mct_helper};
	const struct json_callback cshake_callback_mct[] = {
		{ .callback.cshake = cshake_mct, CB_TYPE_cshake, FLAG_OP_MCT},
	};
	const struct json_callbacks cshake_callbacks_mct = SET_CALLBACKS(cshake_callback_mct);

	/*
	 * Define which test result data should be written to the test result
	 * JSON file.
	 */
	const struct json_entry cshake_testresult_aft_entries[] = {
		{"md",		{.data.buf = &vector.mac, WRITER_BIN}, FLAG_OP_AFT},
		{"outLen",	{.data.integer = &vector.outlen, WRITER_UINT}, FLAG_OP_AFT},
	};
	const struct json_testresult cshake_testresult_aft = SET_ARRAY(cshake_testresult_aft_entries, &cshake_callbacks_aft);

	const struct json_entry cshake_testresult_mct_entries[] = {
		{"md",		{.data.buf = &vector.mac, WRITER_BIN}, FLAG_OP_MCT},
	};
	const struct json_testresult cshake_testresult_mct = SET_ARRAY(cshake_testresult_mct_entries, &cshake_callbacks_mct);

	/*
	 * Define one particular test vector that is expected in the JSON
	 * file.
	 */
	const struct json_entry cshake_test_aft_entries[] = {
		{"msg",			{.data.buf = &vector.msg, PARSER_BIN},			FLAG_OP_AFT},
		{"len",			{.data.integer = &vector.bitlen, PARSER_UINT},		FLAG_OP_AFT},
		{"outLen",		{.data.integer = &vector.outlen, PARSER_UINT},		FLAG_OP_AFT},
		{"functionName",	{.data.buf = &vector.function_name, PARSER_STRING},	FLAG_OP_AFT},
		{"customization",	{.data.buf = &vector.customization, PARSER_STRING},	FLAG_OP_AFT | FLAG_OPTIONAL},
		{"customizationHex",	{.data.buf = &vector.customization, PARSER_BIN},	FLAG_OP_AFT | FLAG_OPTIONAL},
	};
	const struct json_array cshake_test_aft = SET_ARRAY(cshake_test_aft_entries, &cshake_testresult_aft);

	const struct json_entry cshake_test_mct_entries[] = {
		{"msg",			{.data.buf = &vector.msg, PARSER_BIN},			FLAG_OP_MCT},
		{"len",			{.data.integer = &vector.bitlen, PARSER_UINT},		FLAG_OP_MCT},
		{"functionName",	{.data.buf = &vector.function_name, PARSER_BIN},	FLAG_OP_MCT},
		{"customization",	{.data.buf = &vector.customization, PARSER_STRING},	FLAG_OP_MCT | FLAG_OPTIONAL},
		{"customizationHex",	{.data.buf = &vector.customization, PARSER_BIN},	FLAG_OP_MCT | FLAG_OPTIONAL},
	};
	const struct json_array cshake_test_mct = SET_ARRAY(cshake_test_mct_entries, &cshake_testresult_mct);

	/*
	 * Define the test group which contains ancillary data and eventually
	 * the array of individual test vectors.
	 *
	 * As this definition does not mark specific individual test vectors,
	 * the testresult entry is set to NULL.
	 */
	const struct json_entry cshake_testgroup_entries[] = {
		{"tests",	{.data.array = &cshake_test_aft, PARSER_ARRAY},	FLAG_OP_AFT},

		{"maxOutLen",	{.data.integer = &vector.maxoutlen, PARSER_UINT}, FLAG_OP_MCT},
		{"minOutLen",	{.data.integer = &vector.minoutlen, PARSER_UINT}, FLAG_OP_MCT},
		{"tests",	{.data.array = &cshake_test_mct, PARSER_ARRAY},	FLAG_OP_MCT},
	};
	const struct json_array cshake_testgroup = SET_ARRAY(cshake_testgroup_entries, NULL);

	/*
	 * Define the anchor of the tests in the highest level of the JSON
	 * input data.
	 */
	const struct json_entry cshake_testanchor_entries[] = {
		{"testGroups",	{.data.array = &cshake_testgroup, PARSER_ARRAY},	0},
	};
	const struct json_array cshake_testanchor = SET_ARRAY(cshake_testanchor_entries, NULL);

	memset(&vector, 0, sizeof(struct cshake_data));
	vector.cipher = cipher;

	/* Process all. */
	return process_json(&cshake_testanchor, "1.0", in, out);
}

static struct cavs_tester cshake =
{
	0,
	ACVP_CSHAKEMASK,
	cshake_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_cshake)
static void register_cshake(void)
{
	register_tester(&cshake, "cSHAKE");
}

void register_cshake_impl(struct cshake_backend *implementation)
{
	register_backend(cshake_backend, implementation, "cSHAKE");
}
