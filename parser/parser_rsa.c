/*
 * Copyright (C) 2017 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "read_json.h"
#include "stringhelper.h"

#define RSA_DEF_CALLBACK(name, flags)		DEF_CALLBACK(rsa, name, flags)
#define RSA_DEF_CALLBACK_HELPER(name, flags, helper)			       \
				DEF_CALLBACK_HELPER(rsa, name, flags, helper)

static struct rsa_backend *rsa_backend = NULL;

struct rsa_static_key {
	void *key;
	uint32_t modulus;
	struct buffer e;
	struct buffer n;
};
static struct rsa_static_key rsa_key = { NULL, 0, {NULL, 0}, {NULL, 0} };

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

static int rsa_decprim_keygen(struct rsa_decryption_primitive_data *data,
			      void **rsa_privkey)
{
	int ret = 0;

	free_buf(&data->e);
	free_buf(&data->n);
	CKINT(rsa_backend->rsa_keygen_en(&data->e, data->modulus,
					 &rsa_key.key, &data->n));

	logger_binary(LOGGER_DEBUG, data->n.buf, data->n.len,
		      "RSA generated n");
	logger_binary(LOGGER_DEBUG, data->e.buf, data->e.len,
		      "RSA generated e");

	/* Free the global variable at exit */
	atexit(rsa_key_free_static);

	rsa_key.modulus = data->modulus;

	*rsa_privkey = rsa_key.key;

out:
	return ret;
}

static int rsa_decprim_helper(const struct json_array *processdata,
			      flags_t parsed_flags,
			      struct json_object *testvector,
			      struct json_object *testresults,
	int (*callback)(struct rsa_decryption_primitive_data *vector,
			flags_t parsed_flags),
			      struct rsa_decryption_primitive_data *vector)
{
	struct json_object *testresult = NULL, *resultsarray = NULL,
			   *resultsobject = NULL;
	static uint32_t failures = 0, total_cases = 0;
	int ret;
	void *rsa_privkey = NULL;
	unsigned int it;
	const unsigned int iteration_limit = 30;
	const unsigned int probing_limit = 15;
	unsigned int fails = 0, successes = 0;
	static struct rsa_decryption_primitive_data *fails_mem;

	(void)processdata;
	(void)testvector;
	(void)testresults;

	if (total_cases == 0) {
		fails_mem = calloc(vector->num, sizeof(struct rsa_decryption_primitive_data));
		CKNULL(fails_mem, -ENOMEM);
	}
	logger(LOGGER_DEBUG, "CASE %u/%u\n", total_cases + 1, vector->num);
	/* We try at most these many times times */
	for (it = 1; it <= iteration_limit; it++) {
		logger(LOGGER_DEBUG,
			"%u/%u failures found, [0] = 0x%x, iteration %u/%u\n",
			failures, vector->num_failures, vector->msg.buf[0], it, iteration_limit);
		vector->dec_result = false;
		free_buf(&vector->s);

		if (rsa_backend->rsa_keygen_en && rsa_backend->rsa_free_key) {
			CKINT(rsa_decprim_keygen(vector, &rsa_privkey));
		}

		vector->privkey = rsa_privkey;

		CKINT(callback(vector, parsed_flags));
		if (vector->dec_result)
			successes++;
		else {
			fails++;
			if (!fails_mem[total_cases].e.buf) {
				logger(LOGGER_DEBUG, "Storing failure e and n for future use\n");
				copy_ptr_buf(&fails_mem[total_cases].e, &vector->e);
				copy_ptr_buf(&fails_mem[total_cases].n, &vector->n);
				vector->e.buf = NULL;
				vector->n.buf = NULL;
				alloc_buf(vector->e.len, &vector->e);
				alloc_buf(vector->n.len, &vector->n);
			}
		}
		if (it >= probing_limit)
		{
			int have_to_fail = ( (vector->num - total_cases) <=
								 (vector->num_failures - failures) );
			if (vector->dec_result) {
				/* Don't accept success if the test have to fail */
				if (!have_to_fail)
					break;
			} else {
				if (failures < vector->num_failures &&
				    (have_to_fail || successes == 0))
					break;
			}
		}
		continue;
		/*
		 * There should be totalFailingCases number of messages with
		 * two leading one bits. Let us try to fail those. See
		 * https://github.com/usnistgov/ACVP/issues/1219#issuecomment-900382457
		 */
		if (failures < vector->num_failures
				&& (vector->msg.buf[0] & 0xc0) == 0xc0) {
			/* This is a message which should fail relatively quickly with
			 * randomly generated keys, and we still need more failures, so
			 * keep trying until we have a failure here. */
			if (vector->dec_result) {
				logger(LOGGER_DEBUG,
					"%d/%d failures found, vector[0] & 0xc0 == 0xc0 but"
					" succeeded, retrying...\n", failures,
					vector->num_failures);
				continue;
			}
			break;
		}

		/* Messages without two leading ones should pass, try until we found
		 * a passing key. */
		if ((vector->msg.buf[0] & 0xc0) != 0xc0 && !vector->dec_result) {
			logger(LOGGER_DEBUG,
				"%d/%d failures found, vector[0] & 0xc0 != 0xc0 but failed,"
				" retrying...\n", failures, vector->num_failures);
			continue;
		}

		/* If we arrive here, we either need more failures and the vector
		 * doesn't start with 0b11, or we already have enough failures but the
		 * vector does start with 0b11, so it's just down to trying repeatedly
		 * until we find a solution. */
		if (failures < vector->num_failures && !vector->dec_result)
			break;
		if (vector->dec_result)
			break;
	}
	total_cases++;

	if (!vector->dec_result) {
		failures++;
		if (failures > vector->num_failures) {
			logger(LOGGER_ERR, "Failures limit exceeded\n");
			return -EFAULT;
		}
	}

	/*
	 * Create object with following structure:
	 *
	 * {
		"vsId": 0,
		"algorithm": "RSA",
		"mode": "decryptionPrimitive",
		"revision": "1.0",
		"testGroups": [
		{
			"tgId": 1,
			"tests": [
			{
				"tcId": 1,
				"resultsArray": [
				{
					"e": "60BDBEF656869D",
					"n": "8FA73CF9CAD37456B64B3B3DF75C3D3BF254A62C82F445682D0BC34FC998F893039C964E3F3B2F0BD70AA39FB693AD5E1C29398BCE7D43A6F57C34FADF4C6159EBF2D1A4BB5A652BDF74A9C69A3AE46105A29B2AF2E385D54152A8A4660F8081D03DDA9AF5B301B8542B6E535285F89D219A095FCD3296C58DC758BC12B9564EC8FC4B92D805FC0F01695D89A9129C9A0EBB5EBC5D487D1CD0B3A0F2C30321B1B41766EF1F0659805667A84B4F66792DB91BBF346B0A652FEB6B9932855377AAB4ACF0224056B6CEF0CAC7C378698869E526453AADD65EA43AA746D5D5494A1E2A20B4D7D05F53FF566C0BC9AFA0D731416E7BD071A2CA6984C08294560D3BFB",
					"testPassed": false
				},
	 */

	if (json_object_array_length(testresults) > 1) {
		logger(LOGGER_ERR, "Unexpected\n");
		ret = -EFAULT;
		goto out;
	} else if (json_object_array_length(testresults) < 1) {
		testresult = json_object_new_object();
		CKNULL(testresult, -ENOMEM);
		/* Append the output JSON stream with test results. */
		json_object_array_add(testresults, testresult);
	} else {
		testresult = json_object_array_get_idx(testresults, 0);
	}

	if (json_find_key(testresult, "tcId", &resultsarray,
			  json_type_int) < 0) {
		CKINT(json_object_object_add(testresult, "tcId",
				json_object_new_int((int)vector->tcid)));
	}

	if (json_find_key(testresult, "resultsArray", &resultsarray,
			  json_type_array) < 0) {
		/* Results-array */
		resultsarray = json_object_new_array();
		CKNULL(resultsarray, -ENOMEM);
		json_object_object_add(testresult, "resultsArray", resultsarray);
	}

	/* One object holding the test results */
	resultsobject = json_object_new_object();
	CKNULL(resultsobject, -ENOMEM);

	CKINT(json_add_bin2hex(resultsobject, "e", &vector->e));
	CKINT(json_add_bin2hex(resultsobject, "n", &vector->n));

	if (vector->dec_result) {
		CKINT(json_add_bin2hex(resultsobject, "plainText",
				       &vector->s));
	}

	CKINT(json_object_object_add(resultsobject, "testPassed",
			json_object_new_boolean((int)vector->dec_result)));
	free_buf(&vector->s);
	json_object_array_add(resultsarray, resultsobject);

	/*
	 * Sanity check that we have the exact number of expected failures.
	 *
	 * If we have a different number of failures (e.g. the number of
	 * attempts in the loop above is insufficient), the test vector must
	 * be rerun.
	 */
	if (json_object_array_length(resultsarray) == vector->num) {
		uint32_t i, boolean, count = 0;

		for (i = 0; i < vector->num; i++) {
			testresult = json_object_array_get_idx(resultsarray, i);

			if (!json_get_bool(testresult, "testPassed", &boolean) && !boolean)
				count++;

			if (failures < vector->num_failures && boolean &&
				fails_mem[i].e.buf) {
				logger(LOGGER_DEBUG, "Found needed failure for case: %u\n", i);
				failures++;
				count++;
				json_object_object_del(testresult, "plainText");
				json_object_object_del(testresult, "e");
				json_object_object_del(testresult, "n");
				CKINT(json_add_bin2hex(testresult, "e", &fails_mem[i].e));
				CKINT(json_add_bin2hex(testresult, "n", &fails_mem[i].n));
				json_object_object_del(testresult, "testPassed");
				CKINT(json_object_object_add(testresult, "testPassed",
						json_object_new_boolean(0)));
			}
			/* Release memory if any */
			free_buf(&fails_mem[i].e);
			free_buf(&fails_mem[i].n);
		}

		if (count != vector->num_failures) {
			logger(LOGGER_ERR,
			       "Rerun RSA decryption primitive test as the number of test failures (%u) does not match with the expected number of failures (%u)!\n",
			       count, vector->num_failures);
			ret = -EFAULT;
			goto out;
		}
		/* Release failures memory */
		free(fails_mem);
	}

	ret = FLAG_RES_DATA_WRITTEN;

out:
	return ret;
}

static int rsa_keygen_helper(const struct json_array *processdata,
			     flags_t parsed_flags,
			     struct json_object *testvector,
			     struct json_object *testresults,
	int (*callback)(struct rsa_keygen_data *vector, flags_t parsed_flags),
			struct rsa_keygen_data *vector)
{
	int ret = 0;
	const char *bitlens_name = "bitlens";
	struct json_object *json_nobj;
	unsigned int i;

	if (!json_find_key(testvector, bitlens_name, &json_nobj, json_type_array)) {
		if (!json_nobj) {
			logger(LOGGER_ERR,
				"Parsing of entry %s with expected array failed\n", bitlens_name);
			return -EINVAL;
		}
		vector->bitlen_in = (unsigned int)json_object_array_length(json_nobj);
		for (i = 0; i < vector->bitlen_in; i++) {
			struct json_object *testvector =
				json_object_array_get_idx(json_nobj, i);

			CKNULL_LOG(testvector, -EINVAL, "No vector\n");
			vector->bitlen[i] = json_object_get_int(testvector);
		}
	} else {
		vector->bitlen_in = 0;
	}
	CKINT(callback(vector, parsed_flags));

	if (parsed_flags & FLAG_OP_RSA_PQ_B36_PRIMES) {
		struct json_object *bitlenarray = NULL;
		struct json_object *testresult = NULL;
		const struct json_entry *entry;
		unsigned int i;

		testresult = json_object_new_object();
		CKNULL(testresult, -ENOMEM);
		/* Append the output JSON stream with test results. */
		json_object_array_add(testresults, testresult);

		CKINT(json_add_test_data(testvector, testresult));

		/* Iterate over each write definition and invoke it. */
		for_each_testresult(processdata->testresult, entry, i)
			CKINT(write_one_entry(entry, testresult, parsed_flags));

		bitlenarray = json_object_new_array();
		CKNULL(bitlenarray, -ENOMEM);
		/* Append the output JSON stream with test results. */
		json_object_object_add(testresult, bitlens_name, bitlenarray);
		json_object_array_add(bitlenarray,
				json_object_new_int((int)vector->bitlen[0]));
		json_object_array_add(bitlenarray,
				json_object_new_int((int)vector->bitlen[1]));
		json_object_array_add(bitlenarray,
				json_object_new_int((int)vector->bitlen[2]));
		json_object_array_add(bitlenarray,
				json_object_new_int((int)vector->bitlen[3]));

		ret = FLAG_RES_DATA_WRITTEN;
	}

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
	RSA_DEF_CALLBACK_HELPER(rsa_keygen, FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT, rsa_keygen_helper);

	const struct json_entry rsa_keygen_testresult_entries[] = {
		{"e",	{.data.buf = &rsa_keygen_vector.e, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"p",	{.data.buf = &rsa_keygen_vector.p, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"q",	{.data.buf = &rsa_keygen_vector.q, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"n",	{.data.buf = &rsa_keygen_vector.n, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"d",	{.data.buf = &rsa_keygen_vector.d, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT |  FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},

		/* B.3.6 specific data */
		{"xP",	{.data.buf = &rsa_keygen_vector.xp, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"xP1",	{.data.buf = &rsa_keygen_vector.xp1, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"xP2",	{.data.buf = &rsa_keygen_vector.xp2, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"xQ",	{.data.buf = &rsa_keygen_vector.xq, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"xQ1",	{.data.buf = &rsa_keygen_vector.xq1, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"xQ2",	{.data.buf = &rsa_keygen_vector.xq2, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},

		/* CRT key format specific data */
		{"dmp1",	{.data.buf = &rsa_keygen_vector.dmp1, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"dmq1",	{.data.buf = &rsa_keygen_vector.dmq1, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"iqmp",	{.data.buf = &rsa_keygen_vector.iqmp, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
	};
	const struct json_testresult rsa_keygen_testresult = SET_ARRAY(rsa_keygen_testresult_entries, &rsa_keygen_callbacks);

	const struct json_entry rsa_keygen_test_entries[] = {
		{"xP",	{.data.buf = &rsa_keygen_vector.xp, PARSER_BIN},
					FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OPTIONAL },
		{"xP1",	{.data.buf = &rsa_keygen_vector.xp1, PARSER_BIN},
					FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OPTIONAL },
		{"xP2",	{.data.buf = &rsa_keygen_vector.xp2, PARSER_BIN},
					FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OPTIONAL },
		{"xQ",	{.data.buf = &rsa_keygen_vector.xq, PARSER_BIN},
					FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OPTIONAL },
		{"xQ1",	{.data.buf = &rsa_keygen_vector.xq1, PARSER_BIN},
					FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OPTIONAL },
		{"xQ2",	{.data.buf = &rsa_keygen_vector.xq2, PARSER_BIN},
					FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OPTIONAL },
		{"e",	{.data.buf = &rsa_keygen_vector.e, PARSER_BIN},
					FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OPTIONAL },
	};
	const struct json_array rsa_keygen_test = SET_ARRAY(rsa_keygen_test_entries, &rsa_keygen_testresult);

	/**********************************************************************
	 * RSA B.3.2 KeyGen KAT and KeyGen GDT
	 **********************************************************************/
	RSA_DEF_CALLBACK(rsa_keygen_prov_prime, FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT);

	const struct json_entry rsa_keygen_prov_prime_testresult_entries[] = {
		{"e",	{.data.buf = &rsa_keygen_prov_prime_vector.e, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
		{"seed",	{.data.buf = &rsa_keygen_prov_prime_vector.seed, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
		{"p",	{.data.buf = &rsa_keygen_prov_prime_vector.p, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
		{"q",	{.data.buf = &rsa_keygen_prov_prime_vector.q, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
		{"n",	{.data.buf = &rsa_keygen_prov_prime_vector.n, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
		{"d",	{.data.buf = &rsa_keygen_prov_prime_vector.d, WRITER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
	};
	const struct json_testresult rsa_keygen_prov_prime_testresult =
		SET_ARRAY(rsa_keygen_prov_prime_testresult_entries,
			  &rsa_keygen_prov_prime_callbacks);

	/* search for empty arrays */
	const struct json_array rsa_keygen_prov_prime_test = {NULL, 0 , &rsa_keygen_prov_prime_testresult};

	/**********************************************************************
	 * RSA B.3.3 KeyGen KAT
	 **********************************************************************/
	RSA_DEF_CALLBACK(rsa_keygen_prime, FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT);

	const struct json_entry rsa_keygen_prime_testresult_entries[] = {
		{"testPassed",	{.data.integer = &rsa_keygen_prime_vector.keygen_success, WRITER_BOOL},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},
	};

	const struct json_entry rsa_keygen_prime_test_entries[] = {
		{"e",		{.data.buf = &rsa_keygen_prime_vector.e, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},
		{"p",	{.data.buf = &rsa_keygen_prime_vector.p, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},
		{"q",		{.data.buf = &rsa_keygen_prime_vector.q, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},
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
	 * RSA signature primitive regular key type
	 **********************************************************************/
	RSA_DEF_CALLBACK(rsa_signature_primitive, FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK);

	/*
	 * Define which test result data should be written to the test result
	 * JSON file.
	 */
	const struct json_entry rsa_signature_primitive_testresult_entries[] = {
		{"signature",	{.data.buf = &rsa_signature_primitive_vector.signature, WRITER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"testPassed",	{.data.integer = &rsa_signature_primitive_vector.sig_result, WRITER_BOOL},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_testresult rsa_signature_primitive_testresult = SET_ARRAY(rsa_signature_primitive_testresult_entries, &rsa_signature_primitive_callbacks);


	const struct json_entry rsa_signature_primitive_test_entries[] = {
		{"message",	{.data.buf = &rsa_signature_primitive_vector.msg, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"n",		{.data.buf = &rsa_signature_primitive_vector.n, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"d",		{.data.buf = &rsa_signature_primitive_vector.d, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"e",		{.data.buf = &rsa_signature_primitive_vector.e, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
#if 0
		/* d is marked optional in case of CRT */
		{"d",		{.data.buf = &rsa_signature_primitive_vector.u.rsa_regular.d, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK | FLAG_OPTIONAL},
		{"dmp1",	{.data.buf = &rsa_signature_primitive_vector.u.rsa_crt.dmp1, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK | FLAG_OP_RSA_CRT},
		{"dmq1",	{.data.buf = &rsa_signature_primitive_vector.u.rsa_crt.dmq1, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK | FLAG_OP_RSA_CRT},
		{"iqmp",	{.data.buf = &rsa_signature_primitive_vector.u.rsa_crt.iqmp, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK | FLAG_OP_RSA_CRT},
#endif
	};
	const struct json_array rsa_signature_primitive_test = SET_ARRAY(rsa_signature_primitive_test_entries, &rsa_signature_primitive_testresult);

	/**********************************************************************
	 * RSA decryption primitive
	 **********************************************************************/
	RSA_DEF_CALLBACK_HELPER(rsa_decryption_primitive, FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT, rsa_decprim_helper);

	/*
	 * Define which test result data should be written to the test result
	 * JSON file.
	 */
	const struct json_entry rsa_decryption_primitive_testresult_entries[] = {
		{"e",		{.data.buf = &rsa_decryption_primitive_vector.e, WRITER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"n",		{.data.buf = &rsa_decryption_primitive_vector.n, WRITER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"plainText",	{.data.buf = &rsa_decryption_primitive_vector.s, WRITER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"testPassed",	{.data.integer = &rsa_decryption_primitive_vector.dec_result, WRITER_BOOL},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_testresult rsa_decryption_primitive_testresult = SET_ARRAY(rsa_decryption_primitive_testresult_entries, &rsa_decryption_primitive_callbacks);

	const struct json_entry rsa_decryption_primitive_test_entries[] = {
		{"cipherText",	{.data.buf = &rsa_decryption_primitive_vector.msg, PARSER_BIN},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
	};
	const struct json_array rsa_decryption_primitive_test = SET_ARRAY(rsa_decryption_primitive_test_entries, &rsa_decryption_primitive_testresult);

	const struct json_entry rsa_decryption_primitive_testresults_entries[] = {
		{"tcId",	{.data.integer = &rsa_decryption_primitive_vector.tcid, PARSER_UINT},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK},
		{"resultsArray",	{.data.array = &rsa_decryption_primitive_test, PARSER_ARRAY},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT | FLAG_OP_RSA_SIG_MASK}
	};
	const struct json_array rsa_decryption_primitive_testresults = SET_ARRAY(rsa_decryption_primitive_testresults_entries, NULL);

	/**********************************************************************
	 * RSA common test group
	 **********************************************************************/
	const struct json_entry rsa_keygen_testgroup_entries[] = {
		{"modulo",	{.data.integer = &rsa_keygen_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"modulo",	{.data.integer = &rsa_keygen_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},
		{"fixedPubExp",	{.data.buf = &rsa_keygen_vector.e, PARSER_BIN},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT | FLAG_OPTIONAL},
		{"modulo",	{.data.integer = &rsa_keygen_prime_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},

		{"modulo",	{.data.integer = &rsa_keygen_prov_prime_vector.modulus, PARSER_UINT},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
		{"hashAlg",	{.data.largeint = &rsa_keygen_prov_prime_vector.cipher, PARSER_CIPHER},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},

		{"tests",	{.data.array = &rsa_keygen_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B34_PRIMES | FLAG_OP_RSA_PQ_B35_PRIMES | FLAG_OP_RSA_PQ_B36_PRIMES | FLAG_OP_RSA_CRT},
		{"tests",	{.data.array = &rsa_keygen_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_GDT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},

		{"tests",	{.data.array = &rsa_keygen_prime_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_KAT | FLAG_OP_RSA_PQ_B33_PRIMES | FLAG_OP_RSA_CRT},

		{"tests",	{.data.array = &rsa_keygen_prov_prime_test, PARSER_ARRAY},
			         FLAG_OP_ASYM_TYPE_KEYGEN | FLAG_OP_AFT | FLAG_OP_RSA_PQ_B32_PRIMES | FLAG_OP_RSA_CRT},
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

	const struct json_entry rsa_signature_primitive_testgroup_entries[] = {
		{"tests",	{.data.array = &rsa_signature_primitive_test, PARSER_ARRAY},
			         FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE | FLAG_OP_AFT}
	};
	const struct json_array rsa_signature_primitive_testgroup = SET_ARRAY(rsa_signature_primitive_testgroup_entries, NULL);

	const struct json_entry rsa_decryption_primitive_testgroup_entries[] = {
		{"modulo",	{.data.integer = &rsa_decryption_primitive_vector.modulus, PARSER_UINT}, FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT},
		{"totalFailingCases",	{.data.integer = &rsa_decryption_primitive_vector.num_failures, PARSER_UINT}, FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT},
		{"totalTestCases",	{.data.integer = &rsa_decryption_primitive_vector.num, PARSER_UINT}, FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT},
		{"tests",	{.data.array = &rsa_decryption_primitive_testresults, PARSER_ARRAY},
			         FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE | FLAG_OP_AFT}
	};
	const struct json_array rsa_decryption_primitive_testgroup = SET_ARRAY(rsa_decryption_primitive_testgroup_entries, NULL);

	const struct json_entry rsa_testanchor_entries[] = {
		{"testGroups",	{.data.array = &rsa_keygen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_KEYGEN},
		{"testGroups",	{.data.array = &rsa_siggen_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGGEN},
		{"testGroups",	{.data.array = &rsa_sigver_testgroup, PARSER_ARRAY},	FLAG_OP_ASYM_TYPE_SIGVER},
		{"testGroups",	{.data.array = &rsa_signature_primitive_testgroup, PARSER_ARRAY},	FLAG_OP_RSA_TYPE_COMPONENT_SIG_PRIMITIVE},
		{"testGroups",	{.data.array = &rsa_decryption_primitive_testgroup, PARSER_ARRAY},	FLAG_OP_RSA_TYPE_COMPONENT_DEC_PRIMITIVE},
	};
	const struct json_array rsa_testanchor = SET_ARRAY(rsa_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&rsa_testanchor, "1.0", in, out);
}

static struct cavs_tester rsa =
{
	ACVP_RSA,
	0,
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
