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

#include "cipher_definitions.h"
#include "constructor.h"
#include "stringhelper.h"
#include "parser.h"
#include "binhexbin.h"
#include "logger.h"

#include "parser_common.h"

#define LMS_DEF_CALLBACK(name, flags)		DEF_CALLBACK(lms, name, flags)
#define LMS_DEF_CALLBACK_HELPER(name, flags, helper)			       \
				DEF_CALLBACK_HELPER(lms, name, flags, helper)

static struct lms_backend *lms_backend = NULL;

static int lms_tester(struct json_object *in, struct json_object *out,
		      uint64_t cipher)
{
	(void)cipher;

	if (!lms_backend) {
		logger(LOGGER_WARN, "No LMS backend set\n");
		return -EOPNOTSUPP;
	}

	/**********************************************************************
	 * LMS signature verification
	 **********************************************************************/
	LMS_DEF_CALLBACK(lms_sigver, FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER);

	const struct json_entry lms_sigver_testresult_entries[] = {
		{"testPassed",	{.data.integer = &lms_sigver_vector.sigver_success, WRITER_BOOL},
			         FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER},
	};
	const struct json_testresult lms_sigver_testresult = SET_ARRAY(lms_sigver_testresult_entries, &lms_sigver_callbacks);

	const struct json_entry lms_sigver_test_entries[] = {
		{"message",	{.data.buf = &lms_sigver_vector.msg, PARSER_BIN},
			         FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER},
		{"signature",	{.data.buf = &lms_sigver_vector.sig, PARSER_BIN},
			         FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER},
	};

	/* search for empty arrays */
	const struct json_array lms_sigver_test = SET_ARRAY(lms_sigver_test_entries, &lms_sigver_testresult);

	const struct json_entry lms_sigver_testgroup_entries[] = {
		{"lmsMode",	{.data.buf = &lms_sigver_vector.lmsMode, PARSER_STRING},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER },
		{"lmOtsMode",	{.data.buf = &lms_sigver_vector.lmOtsMode, PARSER_STRING},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER },
		{"publicKey",	{.data.buf = &lms_sigver_vector.pub, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER},
		{"tests",	{.data.array = &lms_sigver_test, PARSER_ARRAY},		FLAG_OP_AFT | FLAG_OP_ASYM_TYPE_SIGVER },
	};
	const struct json_array lms_sigver_testgroup = SET_ARRAY(lms_sigver_testgroup_entries, NULL);

	/**********************************************************************
	 * LMS common test group
	 **********************************************************************/
	const struct json_entry lms_testanchor_entries[] = {
		{"testGroups",	{.data.array = &lms_sigver_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGVER},
	};
	const struct json_array lms_testanchor = SET_ARRAY(lms_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&lms_testanchor, "1.0", in, out);
}

static struct cavs_tester lms =
{
	ACVP_LMS,
	0,
	lms_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_lms)
static void register_lms(void)
{
	register_tester(&lms, "LMS");
}

void register_lms_impl(struct lms_backend *implementation)
{
	register_backend(lms_backend, implementation, "LMS");
}
