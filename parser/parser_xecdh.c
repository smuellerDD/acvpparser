/*
 * Copyright (C) 2026, Joachim Vandersmissen <joachim.vandersmissen@atsec.com>
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

#include "constructor.h"
#include "stringhelper.h"
#include "logger.h"
#include "read_json.h"

#include "parser_common.h"

#define XECDH_DEF_CALLBACK(name, flags)	DEF_CALLBACK(xecdh, name, flags)

static struct xecdh_backend *xecdh_backend = NULL;

static int xecdh_tester(struct json_object *in, struct json_object *out,
			uint64_t cipher)
{
	(void)cipher;

	if (!xecdh_backend) {
		logger(LOGGER_WARN, "No XECDH backend set\n");
		return -EOPNOTSUPP;
	}

	/**********************************************************************
	 * XECDH key generation
	 **********************************************************************/
	XECDH_DEF_CALLBACK(xecdh_keygen, FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN);

	const struct json_entry xecdh_keygen_testresult_entries[] = {
		{"privateKey",	{.data.buf = &xecdh_keygen_vector.private_key, WRITER_BIN},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN },
		{"publicKey",	{.data.buf = &xecdh_keygen_vector.public_key, WRITER_BIN},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN },
	};
	const struct json_testresult xecdh_keygen_testresult = SET_ARRAY(xecdh_keygen_testresult_entries, &xecdh_keygen_callbacks);

	/* search for empty arrays */
	const struct json_array xecdh_keygen_test = {NULL, 0, &xecdh_keygen_testresult};

	const struct json_entry xecdh_keygen_testgroup_entries[] = {
		{"curve",	{.data.largeint = &xecdh_keygen_vector.cipher, PARSER_CIPHER},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN },
		{"tests",	{.data.array = &xecdh_keygen_test, PARSER_ARRAY},			FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYGEN },
	};
	const struct json_array xecdh_keygen_testgroup = SET_ARRAY(xecdh_keygen_testgroup_entries, NULL);

	/**********************************************************************
	 * XECDH key verification
	 **********************************************************************/
	XECDH_DEF_CALLBACK(xecdh_keyver, FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYVER);

	const struct json_entry xecdh_keyver_testresult_entries[] = {
		{"testPassed",	{.data.integer = &xecdh_keyver_vector.keyver_success, WRITER_BOOL},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYVER },
	};
	const struct json_testresult xecdh_keyver_testresult = SET_ARRAY(xecdh_keyver_testresult_entries, &xecdh_keyver_callbacks);

	const struct json_entry xecdh_keyver_test_entries[] = {
		{"publicKey",	{.data.buf = &xecdh_keyver_vector.public_key, PARSER_BIN},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYVER },
	};

	const struct json_array xecdh_keyver_test = SET_ARRAY(xecdh_keyver_test_entries, &xecdh_keyver_testresult);

	const struct json_entry xecdh_keyver_testgroup_entries[] = {
		{"curve",	{.data.largeint = &xecdh_keyver_vector.cipher, PARSER_CIPHER},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYVER },
		{"tests",	{.data.array = &xecdh_keyver_test, PARSER_ARRAY},			FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_KEYVER },
	};
	const struct json_array xecdh_keyver_testgroup = SET_ARRAY(xecdh_keyver_testgroup_entries, NULL);

	/**********************************************************************
	 * XECDH shared secret computation
	 **********************************************************************/
	XECDH_DEF_CALLBACK(xecdh_ssc, FLAG_OP_AFT | FLAG_OP_XECDH_TYPE_SSC);

	/*
	 * Shared secret generation testing.
	 */
	const struct json_entry xecdh_ssc_testresult_entries[] = {
		{"publicIut",	{.data.buf = &xecdh_ssc_vector.public_iut, WRITER_BIN},			FLAG_OP_AFT | FLAG_OP_XECDH_TYPE_SSC },
		{"z",		{.data.buf = &xecdh_ssc_vector.z, WRITER_BIN},				FLAG_OP_AFT | FLAG_OP_XECDH_TYPE_SSC },
	};
	const struct json_testresult xecdh_ssc_testresult = SET_ARRAY(xecdh_ssc_testresult_entries, &xecdh_ssc_callbacks);

	const struct json_entry xecdh_ssc_test_entries[] = {
		{"publicServer",{.data.buf = &xecdh_ssc_vector.public_server, PARSER_BIN},		FLAG_OP_AFT | FLAG_OP_XECDH_TYPE_SSC },
	};

	const struct json_array xecdh_ssc_test = SET_ARRAY(xecdh_ssc_test_entries, &xecdh_ssc_testresult);

	const struct json_entry xecdh_ssc_testgroup_entries[] = {
		{"curve",	{.data.largeint = &xecdh_ssc_vector.cipher, PARSER_CIPHER}, 		FLAG_OP_AFT | FLAG_OP_XECDH_TYPE_SSC },
		{"tests",	{.data.array = &xecdh_ssc_test, PARSER_ARRAY},				FLAG_OP_AFT | FLAG_OP_XECDH_TYPE_SSC },
	};
	const struct json_array xecdh_ssc_testgroup = SET_ARRAY(xecdh_ssc_testgroup_entries, NULL);

	/*
	 * Define the anchor of the tests in the highest level of the JSON
	 * input data.
	 */
	const struct json_entry xecdh_testanchor_entries[] = {
		{"testGroups",	{.data.array = &xecdh_keygen_testgroup, PARSER_ARRAY},			FLAG_OP_ASYM_TYPE_KEYGEN },
		{"testGroups",	{.data.array = &xecdh_keyver_testgroup, PARSER_ARRAY},			FLAG_OP_ASYM_TYPE_KEYVER },
		{"testGroups",	{.data.array = &xecdh_ssc_testgroup, PARSER_ARRAY},			FLAG_OP_XECDH_TYPE_SSC }
	};
	const struct json_array xecdh_testanchor = SET_ARRAY(xecdh_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&xecdh_testanchor, "1.0", in, out);
}

static struct cavs_tester xecdh =
{
	ACVP_XECDH,
	0,
	xecdh_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_xecdh)
static void register_xecdh(void)
{
	register_tester(&xecdh, "XECDH");
}

void register_xecdh_impl(struct xecdh_backend *implementation)
{
	register_backend(xecdh_backend, implementation, "XECDH");
}
