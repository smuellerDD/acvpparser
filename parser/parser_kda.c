/*
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include <assert.h>
#include <string.h>

#include "bool.h"
#include "stringhelper.h"
#include "logger.h"
#include "read_json.h"

#include "parser_common.h"

#define HKDF_DEF_CALLBACK_HELPER(flags, helper)				       \
		DEF_CALLBACK_HELPER(hkdf, hkdf, flags, helper)
#define KDA_ONESTEP_DEF_CALLBACK_HELPER(flags, helper)			       \
		DEF_CALLBACK_HELPER(kda_onestep, kda_onestep, flags, helper)
#define KDA_TWOSTEP_DEF_CALLBACK_HELPER(flags, helper)			       \
		DEF_CALLBACK_HELPER(kda_twostep, kda_twostep, flags, helper)

static int parse_fixed_info_pattern(uint64_t encoding,
				    struct buffer *fixed_info_pattern,
				    struct buffer *algorithm_id,
				    struct buffer *context,
				    struct buffer *label,
				    struct buffer *fi_partyU,
				    struct buffer *fi_partyU_ephem,
				    struct buffer *fi_partyV,
				    struct buffer *fi_partyV_ephem,
				    uint32_t dkmlen,
				    struct buffer *t,
				    struct buffer *info)
{
	int ret = 0;

	// TODO: actually parse the pattern.
	(void)fixed_info_pattern;
	(void)algorithm_id;
	(void)context;
	(void)label;
	(void)dkmlen;
	(void)t;

	if (convert_cipher_match(encoding, ACVP_KAS_ENCODING_CONCATENATION,
				 ACVP_CIPHERTYPE_KAS)) {
		// This assumes uPartyInfo||vPartyInfo.
		CKINT(alloc_buf(fi_partyU->len + fi_partyU_ephem->len +
				fi_partyV->len + fi_partyV_ephem->len, info));

		size_t i = 0;
		memcpy(info->buf + i, fi_partyU->buf, fi_partyU->len);
		i += fi_partyU->len;
		memcpy(info->buf + i, fi_partyU_ephem->buf,
		       fi_partyU_ephem->len);
		i += fi_partyU_ephem->len;
		memcpy(info->buf + i, fi_partyV->buf, fi_partyV->len);
		i += fi_partyV->len;
		memcpy(info->buf + i, fi_partyV_ephem->buf,
		       fi_partyV_ephem->len);
		//Call not needed
		//i += fi_partyV_ephem->len;

		logger_binary(LOGGER_DEBUG, info->buf, info->len, "info");

		ret = 0;
	} else {
		logger(LOGGER_ERR, "Unsupported fixed info encoding\n");
		ret = -EINVAL;
	}

out:
	return ret;
}

/******************************************************************************
 * KDA HKDF callback definitions
 ******************************************************************************/
static struct hkdf_backend *hkdf_backend = NULL;

static int hkdf_helper(const struct json_array *processdata,
		       flags_t parsed_flags,
		       struct json_object *testvector,
		       struct json_object *testresults,
	int (*callback)(struct hkdf_data *vector, flags_t parsed_flags),
		       struct hkdf_data *vector)
{
	int ret = 0;

	(void)testvector;
	(void)processdata;
	(void)testresults;

	CKINT(parse_fixed_info_pattern(vector->fixed_info_encoding,
				       &vector->fixed_info_pattern,
				       &vector->algorithm_id,
				       &vector->context,
				       &vector->label,
				       &vector->fi_partyU,
				       &vector->fi_partyU_ephem,
				       &vector->fi_partyV,
				       &vector->fi_partyV_ephem,
				       vector->dkmlen,
				       &vector->t,
				       &vector->info));

	CKINT(callback(vector, parsed_flags));

out:
	free_buf(&vector->info);
	return ret;
}

static int kda_tester_hkdf(struct json_object *in, struct json_object *out,
			   uint64_t cipher)
{
	(void)cipher;

	/**********************************************************************
	 * KDA HKDF operation
	 **********************************************************************/
	HKDF_DEF_CALLBACK_HELPER(FLAG_OP_AFT | FLAG_OP_VAL, hkdf_helper);

	const struct json_entry hkdf_testresult_entries[] = {
		{"dkm",		{.data.buf = &hkdf_vector.dkm,			WRITER_BIN}, FLAG_OP_AFT},
		{"testPassed",	{.data.integer = &hkdf_vector.validity_success,	WRITER_BOOL}, FLAG_OP_VAL},
	};
	const struct json_testresult hkdf_testresult =
		SET_ARRAY(hkdf_testresult_entries, &hkdf_callbacks);

	/* kdfConfiguration */
	const struct json_entry hkdf_kdf_config_entries[] = {
		// TODO: what to do with kdfType? Already covered by mode?
		// TODO: what to do with saltMethod?
		// TODO: what to do with saltLen? Already covered by kdfParameter.salt?
		{"fixedInfoPattern",	{.data.buf = &hkdf_vector.fixed_info_pattern,		PARSER_STRING}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoEncoding",	{.data.largeint = &hkdf_vector.fixed_info_encoding,	PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"hmacAlg",		{.data.largeint = &hkdf_vector.hash,			PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"l",			{.data.integer = &hkdf_vector.dkmlen,			PARSER_UINT}, FLAG_OP_AFT | FLAG_OP_VAL},
	};
	const struct json_array hkdf_kdf_config_test =
		SET_ARRAY(hkdf_kdf_config_entries, NULL);

	/* kdfParameter */
	const struct json_entry hkdf_kdf_entries[] = {
		// TODO: what to do with kdfType? Already covered by mode?
		{"salt",		{.data.buf = &hkdf_vector.salt,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"algorithmId",		{.data.buf = &hkdf_vector.algorithm_id,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"context",		{.data.buf = &hkdf_vector.context,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"label",		{.data.buf = &hkdf_vector.label,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		// TODO: what to do with l? Already covered by kdfConfiguration.l?
		{"z",			{.data.buf = &hkdf_vector.z,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"t",			{.data.buf = &hkdf_vector.t,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array hkdf_kdf_test =
		SET_ARRAY(hkdf_kdf_entries, NULL);

	/* fixed info party V */
	const struct json_entry hkdf_fi_partyV_entries[] = {
		{"partyId",		{.data.buf = &hkdf_vector.fi_partyV,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL },
		{"ephemeralData",	{.data.buf = &hkdf_vector.fi_partyV_ephem,	PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array hkdf_fi_partyV_test =
		SET_ARRAY(hkdf_fi_partyV_entries, NULL);

	/* fixed info party U */
	const struct json_entry hkdf_fi_partyU_entries[] = {
		{"partyId",		{.data.buf = &hkdf_vector.fi_partyU,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"ephemeralData",	{.data.buf = &hkdf_vector.fi_partyU_ephem,	PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array hkdf_fi_partyU_test =
		SET_ARRAY(hkdf_fi_partyU_entries, NULL);

	const struct json_entry hkdf_test_entries[] = {
		{"kdfParameter",	{.data.array = &hkdf_kdf_test, 			PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoPartyU",	{.data.array = &hkdf_fi_partyU_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoPartyV",	{.data.array = &hkdf_fi_partyV_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"dkm",			{.data.buf = &hkdf_vector.dkm,			PARSER_BIN}, FLAG_OP_VAL},
	};
	const struct json_array hkdf_test =
		SET_ARRAY(hkdf_test_entries, &hkdf_testresult);

	const struct json_entry hkdf_testgroup_entries[] = {
		{"kdfConfiguration",	{.data.array = &hkdf_kdf_config_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"tests",		{.data.array = &hkdf_test, 			PARSER_ARRAY}, FLAG_OP_AFT | FLAG_OP_VAL},
	};
	const struct json_array hkdf_testgroup =
		SET_ARRAY(hkdf_testgroup_entries, NULL);

	const struct json_entry hkdf_testanchor_entries[] = {
		{"testGroups",	{.data.array = &hkdf_testgroup, PARSER_ARRAY},	0},
	};
	const struct json_array hkdf_testanchor =
		SET_ARRAY(hkdf_testanchor_entries, NULL);

	return process_json(&hkdf_testanchor, "1.0", in, out);
}


/******************************************************************************
 * KDA OneStep callback definitions
 ******************************************************************************/
static struct kda_onestep_backend *kda_onestep_backend = NULL;

static int kda_onestep_helper(const struct json_array *processdata,
			      flags_t parsed_flags,
			      struct json_object *testvector,
			      struct json_object *testresults,
	int (*callback)(struct kda_onestep_data *vector, flags_t parsed_flags),
			      struct kda_onestep_data *vector)
{
	int ret = 0;

	(void)testvector;
	(void)processdata;
	(void)testresults;

	CKINT(parse_fixed_info_pattern(vector->fixed_info_encoding,
				       &vector->fixed_info_pattern,
				       &vector->algorithm_id,
				       &vector->context,
				       &vector->label,
				       &vector->fi_partyU,
				       &vector->fi_partyU_ephem,
				       &vector->fi_partyV,
				       &vector->fi_partyV_ephem,
				       vector->dkmlen,
				       &vector->t,
				       &vector->info));

	CKINT(callback(vector, parsed_flags));

out:
	free_buf(&vector->info);
	return ret;
}

static int kda_tester_onestep(struct json_object *in, struct json_object *out,
			      uint64_t cipher)
{
	(void)cipher;

	/**********************************************************************
	 * KDA OneStep operation
	 **********************************************************************/
	KDA_ONESTEP_DEF_CALLBACK_HELPER(FLAG_OP_AFT | FLAG_OP_VAL,
					kda_onestep_helper);

	const struct json_entry kda_onestep_testresult_entries[] = {
		{"dkm",		{.data.buf = &kda_onestep_vector.dkm,			WRITER_BIN}, FLAG_OP_AFT},
		{"testPassed",	{.data.integer = &kda_onestep_vector.validity_success,	WRITER_BOOL}, FLAG_OP_VAL},
	};
	const struct json_testresult kda_onestep_testresult =
		SET_ARRAY(kda_onestep_testresult_entries, &kda_onestep_callbacks);

	/* kdfConfiguration */
	const struct json_entry kda_onestep_kdf_config_entries[] = {
		// TODO: what to do with kdfType? Already covered by mode?
		// TODO: what to do with saltMethod?
		// TODO: what to do with saltLen? Already covered by kdfParameter.salt?
		{"fixedInfoPattern",	{.data.buf = &kda_onestep_vector.fixed_info_pattern,		PARSER_STRING}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoEncoding",	{.data.largeint = &kda_onestep_vector.fixed_info_encoding,	PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"auxFunction",		{.data.largeint = &kda_onestep_vector.aux_function,		PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"l",			{.data.integer = &kda_onestep_vector.dkmlen,			PARSER_UINT}, FLAG_OP_AFT | FLAG_OP_VAL},
	};
	const struct json_array kda_onestep_kdf_config_test =
		SET_ARRAY(kda_onestep_kdf_config_entries, NULL);

	/* kdfParameter */
	const struct json_entry kda_onestep_kdf_entries[] = {
		// TODO: what to do with kdfType? Already covered by mode?
		{"salt",		{.data.buf = &kda_onestep_vector.salt,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"algorithmId",		{.data.buf = &kda_onestep_vector.algorithm_id,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"context",		{.data.buf = &kda_onestep_vector.context,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"label",		{.data.buf = &kda_onestep_vector.label,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		// TODO: what to do with l? Already covered by kdfConfiguration.l?
		{"z",			{.data.buf = &kda_onestep_vector.z,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"t",			{.data.buf = &kda_onestep_vector.t,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array kda_onestep_kdf_test =
		SET_ARRAY(kda_onestep_kdf_entries, NULL);

	/* fixed info party V */
	const struct json_entry kda_onestep_fi_partyV_entries[] = {
		{"partyId",		{.data.buf = &kda_onestep_vector.fi_partyV,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL },
		{"ephemeralData",	{.data.buf = &kda_onestep_vector.fi_partyV_ephem,	PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array kda_onestep_fi_partyV_test =
		SET_ARRAY(kda_onestep_fi_partyV_entries, NULL);

	/* fixed info party U */
	const struct json_entry kda_onestep_fi_partyU_entries[] = {
		{"partyId",		{.data.buf = &kda_onestep_vector.fi_partyU,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"ephemeralData",	{.data.buf = &kda_onestep_vector.fi_partyU_ephem,	PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array kda_onestep_fi_partyU_test =
		SET_ARRAY(kda_onestep_fi_partyU_entries, NULL);

	const struct json_entry kda_onestep_test_entries[] = {
		{"kdfParameter",	{.data.array = &kda_onestep_kdf_test, 			PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoPartyU",	{.data.array = &kda_onestep_fi_partyU_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoPartyV",	{.data.array = &kda_onestep_fi_partyV_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"dkm",			{.data.buf = &kda_onestep_vector.dkm,			PARSER_BIN}, FLAG_OP_VAL},
	};
	const struct json_array kda_onestep_test =
		SET_ARRAY(kda_onestep_test_entries, &kda_onestep_testresult);

	const struct json_entry kda_onestep_testgroup_entries[] = {
		{"kdfConfiguration",	{.data.array = &kda_onestep_kdf_config_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"tests",		{.data.array = &kda_onestep_test, 			PARSER_ARRAY}, FLAG_OP_AFT | FLAG_OP_VAL},
	};
	const struct json_array kda_onestep_testgroup =
		SET_ARRAY(kda_onestep_testgroup_entries, NULL);

	const struct json_entry kda_onestep_testanchor_entries[] = {
		{"testGroups",	{.data.array = &kda_onestep_testgroup, PARSER_ARRAY},	0},
	};
	const struct json_array kda_onestep_testanchor =
		SET_ARRAY(kda_onestep_testanchor_entries, NULL);

	return process_json(&kda_onestep_testanchor, "1.0", in, out);
}

/******************************************************************************
 * KDA TwoStep callback definitions
 ******************************************************************************/
static struct kda_twostep_backend *kda_twostep_backend = NULL;

static int kda_twostep_helper(const struct json_array *processdata,
			      flags_t parsed_flags,
			      struct json_object *testvector,
			      struct json_object *testresults,
	int (*callback)(struct kda_twostep_data *vector, flags_t parsed_flags),
			      struct kda_twostep_data *vector)
{
	int ret = 0;

	(void)testvector;
	(void)processdata;
	(void)testresults;

	CKINT(parse_fixed_info_pattern(vector->fixed_info_encoding,
				       &vector->fixed_info_pattern,
				       &vector->algorithm_id,
				       &vector->context,
				       &vector->label,
				       &vector->fi_partyU,
				       &vector->fi_partyU_ephem,
				       &vector->fi_partyV,
				       &vector->fi_partyV_ephem,
				       vector->dkmlen,
				       &vector->t,
				       &vector->info));

	CKINT(callback(vector, parsed_flags));

out:
	free_buf(&vector->info);
	return ret;
}

static int kda_tester_twostep(struct json_object *in, struct json_object *out,
			      uint64_t cipher)
{
	(void)cipher;

	/**********************************************************************
	 * KDA TwoStep operation
	 **********************************************************************/
	KDA_TWOSTEP_DEF_CALLBACK_HELPER(FLAG_OP_AFT | FLAG_OP_VAL,
					kda_twostep_helper);

	const struct json_entry kda_twostep_testresult_entries[] = {
		{"dkm",		{.data.buf = &kda_twostep_vector.dkm,			WRITER_BIN}, FLAG_OP_AFT},
		{"testPassed",	{.data.integer = &kda_twostep_vector.validity_success,	WRITER_BOOL}, FLAG_OP_VAL},
	};
	const struct json_testresult kda_twostep_testresult =
		SET_ARRAY(kda_twostep_testresult_entries, &kda_twostep_callbacks);

	/* kdfConfiguration */
	const struct json_entry kda_twostep_kdf_config_entries[] = {
		// TODO: what to do with kdfType? Already covered by mode?
		// TODO: what to do with saltMethod?
		// TODO: what to do with saltLen? Already covered by kdfParameter.salt?
		// TODO: what to do with ivLen? Already covered by kdfParameter.iv?
		{"fixedInfoPattern",	{.data.buf = &kda_twostep_vector.fixed_info_pattern,		PARSER_STRING}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoEncoding",	{.data.largeint = &kda_twostep_vector.fixed_info_encoding,	PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"macMode",		{.data.largeint = &kda_twostep_vector.mac,			PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"kdfMode",		{.data.largeint = &kda_twostep_vector.kdfmode,			PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"counterLocation",	{.data.largeint = &kda_twostep_vector.counter_location,		PARSER_CIPHER}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"counterLen",		{.data.integer = &kda_twostep_vector.counter_length,		PARSER_UINT}, FLAG_OP_AFT},
		{"l",			{.data.integer = &kda_twostep_vector.dkmlen,			PARSER_UINT}, FLAG_OP_AFT | FLAG_OP_VAL},
	};
	const struct json_array kda_twostep_kdf_config_test =
		SET_ARRAY(kda_twostep_kdf_config_entries, NULL);

	/* kdfParameter */
	const struct json_entry kda_twostep_kdf_entries[] = {
		// TODO: what to do with kdfType? Already covered by mode?
		{"salt",		{.data.buf = &kda_twostep_vector.salt,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"iv",			{.data.buf = &kda_twostep_vector.iv,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"algorithmId",		{.data.buf = &kda_twostep_vector.algorithm_id,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"context",		{.data.buf = &kda_twostep_vector.context,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		{"label",		{.data.buf = &kda_twostep_vector.label,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
		// TODO: what to do with l? Already covered by kdfConfiguration.l?
		{"z",			{.data.buf = &kda_twostep_vector.z,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"t",			{.data.buf = &kda_twostep_vector.t,			PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array kda_twostep_kdf_test =
		SET_ARRAY(kda_twostep_kdf_entries, NULL);

	/* fixed info party V */
	const struct json_entry kda_twostep_fi_partyV_entries[] = {
		{"partyId",		{.data.buf = &kda_twostep_vector.fi_partyV,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL },
		{"ephemeralData",	{.data.buf = &kda_twostep_vector.fi_partyV_ephem,	PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array kda_twostep_fi_partyV_test =
		SET_ARRAY(kda_twostep_fi_partyV_entries, NULL);

	/* fixed info party U */
	const struct json_entry kda_twostep_fi_partyU_entries[] = {
		{"partyId",		{.data.buf = &kda_twostep_vector.fi_partyU,		PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"ephemeralData",	{.data.buf = &kda_twostep_vector.fi_partyU_ephem,	PARSER_BIN}, FLAG_OP_AFT | FLAG_OP_VAL | FLAG_OPTIONAL},
	};
	const struct json_array kda_twostep_fi_partyU_test =
		SET_ARRAY(kda_twostep_fi_partyU_entries, NULL);

	const struct json_entry kda_twostep_test_entries[] = {
		{"kdfParameter",	{.data.array = &kda_twostep_kdf_test, 			PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoPartyU",	{.data.array = &kda_twostep_fi_partyU_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"fixedInfoPartyV",	{.data.array = &kda_twostep_fi_partyV_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"dkm",			{.data.buf = &kda_twostep_vector.dkm,			PARSER_BIN}, FLAG_OP_VAL},
	};
	const struct json_array kda_twostep_test =
		SET_ARRAY(kda_twostep_test_entries, &kda_twostep_testresult);

	const struct json_entry kda_twostep_testgroup_entries[] = {
		{"kdfConfiguration",	{.data.array = &kda_twostep_kdf_config_test, 		PARSER_OBJECT}, FLAG_OP_AFT | FLAG_OP_VAL},
		{"tests",		{.data.array = &kda_twostep_test, 			PARSER_ARRAY}, FLAG_OP_AFT | FLAG_OP_VAL},
	};
	const struct json_array kda_twostep_testgroup =
		SET_ARRAY(kda_twostep_testgroup_entries, NULL);

	const struct json_entry kda_twostep_testanchor_entries[] = {
		{"testGroups",	{.data.array = &kda_twostep_testgroup, PARSER_ARRAY},	0},
	};
	const struct json_array kda_twostep_testanchor =
		SET_ARRAY(kda_twostep_testanchor_entries, NULL);

	return process_json(&kda_twostep_testanchor, "1.0", in, out);
}

/******************************************************************************
 * KDA generic parser definitions
 ******************************************************************************/
static int kda_tester(struct json_object *in, struct json_object *out,
		      uint64_t cipher)
{
	int ret = 0;
	struct json_object *acvpdata, *versiondata;
	const char *mode;
	bool executed = false;

	/* Get version and ACVP test vector data */
	CKINT(json_split_version(in, &acvpdata, &versiondata));
	CKINT(json_get_string(acvpdata, "mode", &mode));

	if (hkdf_backend && !strncmp(mode, "HKDF", 4)) {
		CKINT(kda_tester_hkdf(in, out, cipher));
		executed = true;
	}
	if (kda_onestep_backend && !strncmp(mode, "OneStep", 7)) {
		CKINT(kda_tester_onestep(in, out, cipher));
		executed = true;
	}
	// TODO: OneStepNoCounter?
	if (kda_twostep_backend && !strncmp(mode, "TwoStep", 5)) {
		CKINT(kda_tester_twostep(in, out, cipher));
		executed = true;
	}

	/*
	 * If !executed -> None of the backends were registered -> -EOPNOTSUPP.
	 *
	 * If executed, then we have at least one successful run and data
	 * -> clear out any -EOPNOTSUPP.
	 */
	if (!executed)
		ret = -EOPNOTSUPP;
	else
		ret = 0;

out:
	return ret;
}


static struct cavs_tester kda =
{
	ACVP_KDA,
	0,
	kda_tester,	/* process_req */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_kda)
static void register_kda(void)
{
	register_tester(&kda, "KDA");
}

void register_hkdf_impl(struct hkdf_backend *implementation)
{
	register_backend(hkdf_backend, implementation, "KDA_HKDF");
}

void register_kda_onestep_impl(struct kda_onestep_backend *implementation)
{
	register_backend(kda_onestep_backend, implementation, "KDA_ONESTEP");
}

// TODO: OneStepNoCounter?

void register_kda_twostep_impl(struct kda_twostep_backend *implementation)
{
	register_backend(kda_twostep_backend, implementation, "KDA_TWOSTEP");
}
