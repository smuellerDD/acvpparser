/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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

#include "bool.h"
#include "stringhelper.h"
#include "binhexbin.h"
#include "logger.h"

#include "parser_common.h"

/******************************************************************************
 * KDF TLS callback definitions
 ******************************************************************************/
struct kdf_tls_backend *kdf_tls_backend = NULL;

static int kdf_tester_tls(struct json_object *in, struct json_object *out,
			  uint64_t cipher)
{
	(void)cipher;

	/**********************************************************************
	 * KDF TLS operation
	 **********************************************************************/
	DEF_CALLBACK(kdf_tls, kdf_tls, FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS);

	const struct json_entry kdf_tls_testresult_entries[] = {
		{"masterSecret",		{.data.buf = &kdf_tls_vector.master_secret, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS},
		{"keyBlock",			{.data.buf = &kdf_tls_vector.key_block, WRITER_BIN},		FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS},
	};
	const struct json_testresult kdf_tls_testresult =
		SET_ARRAY(kdf_tls_testresult_entries, &kdf_tls_callbacks);

	const struct json_entry kdf_tls_test_entries[] = {
		{"clientHelloRandom",		{.data.buf = &kdf_tls_vector.client_hello_random, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS},
		{"serverHelloRandom",		{.data.buf = &kdf_tls_vector.server_hello_random, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS},
		{"clientRandom",		{.data.buf = &kdf_tls_vector.client_random, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS},
		{"serverRandom",		{.data.buf = &kdf_tls_vector.server_random, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS},
		{"preMasterSecret",		{.data.buf = &kdf_tls_vector.pre_master_secret, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS},
	};

	/* search for empty arrays */
	const struct json_array kdf_tls_test = SET_ARRAY(kdf_tls_test_entries, &kdf_tls_testresult);

	const struct json_entry kdf_tls_testgroup_entries[] = {
		{"hashAlg",			{.data.largeint = &kdf_tls_vector.hashalg, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS },
		{"preMasterSecretLength",	{.data.integer = &kdf_tls_vector.pre_master_secret_length, PARSER_UINT},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS },
		{"keyBlockLength",		{.data.integer = &kdf_tls_vector.key_block_length, PARSER_UINT}, FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS },
		{"tests",			{.data.array = &kdf_tls_test, PARSER_ARRAY},			FLAG_OP_AFT | FLAG_OP_KDF_TYPE_TLS },
	};
	const struct json_array kdf_tls_testgroup = SET_ARRAY(kdf_tls_testgroup_entries, NULL);

	/**********************************************************************
	 * KDF common test group
	 **********************************************************************/
	const struct json_entry kdf_tls_testanchor_entries[] = {
		{"testGroups",			{.data.array = &kdf_tls_testgroup, PARSER_ARRAY},	FLAG_OP_KDF_TYPE_TLS},
	};
	const struct json_array kdf_tls_testanchor = SET_ARRAY(kdf_tls_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&kdf_tls_testanchor, "1.0", in, out);
}

/******************************************************************************
 * KDF SSH callback definitions
 ******************************************************************************/
struct kdf_ssh_backend *kdf_ssh_backend = NULL;

static int kdf_tester_ssh(struct json_object *in, struct json_object *out,
			  uint64_t cipher)
{
	(void)cipher;

	/**********************************************************************
	 * KDF SSH operation
	 **********************************************************************/
	DEF_CALLBACK(kdf_ssh, kdf_ssh, FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH);

	const struct json_entry kdf_ssh_testresult_entries[] = {
		{"initialIvClient",		{.data.buf = &kdf_ssh_vector.initial_iv_client, WRITER_BIN},		FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
		{"encryptionKeyClient",		{.data.buf = &kdf_ssh_vector.encryption_key_client, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
		{"integrityKeyClient",		{.data.buf = &kdf_ssh_vector.integrity_key_client, WRITER_BIN},		FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
		{"initialIvServer",		{.data.buf = &kdf_ssh_vector.initial_iv_server, WRITER_BIN},		FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
		{"encryptionKeyServer",		{.data.buf = &kdf_ssh_vector.encryption_key_server, WRITER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
		{"integrityKeyServer",		{.data.buf = &kdf_ssh_vector.integrity_key_server, WRITER_BIN},		FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
	};
	const struct json_testresult kdf_ssh_testresult =
		SET_ARRAY(kdf_ssh_testresult_entries, &kdf_ssh_callbacks);

	const struct json_entry kdf_ssh_test_entries[] = {
		{"k",		{.data.buf = &kdf_ssh_vector.k, PARSER_MPINT},		FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
		{"h",		{.data.buf = &kdf_ssh_vector.h, PARSER_BIN},		FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
		{"sessionId",	{.data.buf = &kdf_ssh_vector.session_id, PARSER_BIN},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH},
	};

	/* search for empty arrays */
	const struct json_array kdf_ssh_test = SET_ARRAY(kdf_ssh_test_entries, &kdf_ssh_testresult);

	const struct json_entry kdf_ssh_testgroup_entries[] = {
		{"hashAlg",	{.data.largeint = &kdf_ssh_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH },
		{"cipher",	{.data.largeint = &kdf_ssh_vector.cipher, PARSER_CIPHER},	FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH },
		{"tests",	{.data.array = &kdf_ssh_test, PARSER_ARRAY},			FLAG_OP_AFT | FLAG_OP_KDF_TYPE_SSH },
	};
	const struct json_array kdf_ssh_testgroup = SET_ARRAY(kdf_ssh_testgroup_entries, NULL);

	/**********************************************************************
	 * KDF common test group
	 **********************************************************************/
	const struct json_entry kdf_ssh_testanchor_entries[] = {
		{"testGroups",			{.data.array = &kdf_ssh_testgroup, PARSER_ARRAY},	FLAG_OP_KDF_TYPE_SSH},
	};
	const struct json_array kdf_ssh_testanchor = SET_ARRAY(kdf_ssh_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&kdf_ssh_testanchor, "1.0", in, out);
}

/******************************************************************************
 * KDF IKEV1 callback definitions
 ******************************************************************************/
struct kdf_ikev1_backend *kdf_ikev1_backend = NULL;

static int kdf_tester_ikev1(struct json_object *in, struct json_object *out,
			  uint64_t cipher)
{
	(void)cipher;

	/**********************************************************************
	 * KDF IKEV1 operation
	 **********************************************************************/
	DEF_CALLBACK(kdf_ikev1, kdf_ikev1, FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT);

	const struct json_entry kdf_ikev1_testresult_entries[] = {
		{"sKeyId",	{.data.buf = &kdf_ikev1_vector.s_key_id,   WRITER_BIN},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"sKeyIdD",	{.data.buf = &kdf_ikev1_vector.s_key_id_d, WRITER_BIN},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"sKeyIdA",	{.data.buf = &kdf_ikev1_vector.s_key_id_a, WRITER_BIN},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"sKeyIdE",	{.data.buf = &kdf_ikev1_vector.s_key_id_e, WRITER_BIN},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
	};
	const struct json_testresult kdf_ikev1_testresult =
		SET_ARRAY(kdf_ikev1_testresult_entries, &kdf_ikev1_callbacks);

	const struct json_entry kdf_ikev1_test_entries[] = {
		{"nInit",	{.data.buf = &kdf_ikev1_vector.n_init, PARSER_BIN},		FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"nResp",	{.data.buf = &kdf_ikev1_vector.n_resp, PARSER_BIN},		FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"ckyInit",	{.data.buf = &kdf_ikev1_vector.cookie_init, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"ckyResp",	{.data.buf = &kdf_ikev1_vector.cookie_resp, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"gxy",		{.data.buf = &kdf_ikev1_vector.gxy, PARSER_BIN},		FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"preSharedKey",{.data.buf = &kdf_ikev1_vector.pre_shared_key, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
	};

	/* search for empty arrays */
	const struct json_array kdf_ikev1_test = SET_ARRAY(kdf_ikev1_test_entries, &kdf_ikev1_testresult);

	const struct json_entry kdf_ikev1_testgroup_entries[] = {
		{"hashAlg",			{.data.largeint = &kdf_ikev1_vector.hashalg, PARSER_CIPHER},	FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK | FLAG_OP_AFT},
		{"tests",			{.data.array = &kdf_ikev1_test, PARSER_ARRAY},			FLAG_OP_KDF_TYPE_IKEV1 | FLAG_OP_KDF_TYPE_IKEV1_DSA | FLAG_OP_KDF_TYPE_IKEV1_PKE | FLAG_OP_KDF_TYPE_IKEV1_PSK  | FLAG_OP_AFT},
	};
	const struct json_array kdf_ikev1_testgroup = SET_ARRAY(kdf_ikev1_testgroup_entries, NULL);

	/**********************************************************************
	 * KDF common test group
	 **********************************************************************/
	const struct json_entry kdf_ikev1_testanchor_entries[] = {
		{"testGroups",			{.data.array = &kdf_ikev1_testgroup, PARSER_ARRAY},	FLAG_OP_KDF_TYPE_IKEV1},
	};
	const struct json_array kdf_ikev1_testanchor = SET_ARRAY(kdf_ikev1_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&kdf_ikev1_testanchor, "1.0", in, out);
}

/******************************************************************************
 * KDF IKEV2 callback definitions
 ******************************************************************************/
struct kdf_ikev2_backend *kdf_ikev2_backend = NULL;

static int kdf_tester_ikev2(struct json_object *in, struct json_object *out,
			  uint64_t cipher)
{
	(void)cipher;

	/**********************************************************************
	 * KDF IKEV2 operation
	 **********************************************************************/
	DEF_CALLBACK(kdf_ikev2, kdf_ikev2, FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT);

	const struct json_entry kdf_ikev2_testresult_entries[] = {
		{"sKeySeed",			{.data.buf = &kdf_ikev2_vector.s_key_seed, WRITER_BIN},		FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"sKeySeedReKey",		{.data.buf = &kdf_ikev2_vector.s_key_seed_rekey, WRITER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"derivedKeyingMaterial",	{.data.buf = &kdf_ikev2_vector.dkm, WRITER_BIN},		FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"derivedKeyingMaterialChild",	{.data.buf = &kdf_ikev2_vector.dkm_child, WRITER_BIN},		FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"derivedKeyingMaterialDh",{.data.buf = &kdf_ikev2_vector.dkm_child_dh, WRITER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
	};
	const struct json_testresult kdf_ikev2_testresult =
		SET_ARRAY(kdf_ikev2_testresult_entries, &kdf_ikev2_callbacks);

	const struct json_entry kdf_ikev2_test_entries[] = {
		{"nInit",	{.data.buf = &kdf_ikev2_vector.n_init, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"nResp",	{.data.buf = &kdf_ikev2_vector.n_resp, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"spiInit",	{.data.buf = &kdf_ikev2_vector.spi_init, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"spiResp",	{.data.buf = &kdf_ikev2_vector.spi_resp, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"gir",		{.data.buf = &kdf_ikev2_vector.gir, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"girNew",	{.data.buf = &kdf_ikev2_vector.gir_new, PARSER_BIN},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
	};

	/* search for empty arrays */
	const struct json_array kdf_ikev2_test = SET_ARRAY(kdf_ikev2_test_entries, &kdf_ikev2_testresult);

	const struct json_entry kdf_ikev2_testgroup_entries[] = {
		{"hashAlg",			{.data.largeint = &kdf_ikev2_vector.hashalg, PARSER_CIPHER},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT},
		{"derivedKeyingMaterialLength",	{.data.integer = &kdf_ikev2_vector.dkmlen, PARSER_UINT},	FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT },
		{"tests",			{.data.array = &kdf_ikev2_test, PARSER_ARRAY},			FLAG_OP_KDF_TYPE_IKEV2 | FLAG_OP_AFT },
	};
	const struct json_array kdf_ikev2_testgroup = SET_ARRAY(kdf_ikev2_testgroup_entries, NULL);

	/**********************************************************************
	 * KDF common test group
	 **********************************************************************/
	const struct json_entry kdf_ikev2_testanchor_entries[] = {
		{"testGroups",			{.data.array = &kdf_ikev2_testgroup, PARSER_ARRAY},	FLAG_OP_KDF_TYPE_IKEV2},
	};
	const struct json_array kdf_ikev2_testanchor = SET_ARRAY(kdf_ikev2_testanchor_entries, NULL);

	/* Process all. */
	return process_json(&kdf_ikev2_testanchor, "1.0", in, out);
}

/******************************************************************************
 * KDF generic parser definitions
 ******************************************************************************/
static void kdf_tester_copy_array(struct json_object *src,
				  struct json_object *dst, bool version_copied)
{
	unsigned int i;

	for (i = 0; i < (uint32_t)json_object_array_length(src); i++) {
		struct json_object *entry =
			json_object_array_get_idx(src, i);

		if (!entry)
			continue;

		/* Do not copy version information again */
		if (version_copied &&
		    json_object_object_get_ex(entry, "version", NULL))
			continue;

		json_object_array_add(dst, entry);
		json_object_get(entry);
	}
}

#include "read_json.h"
static int kdf_tester(struct json_object *in, struct json_object *out,
		      uint64_t cipher)
{
	int ret = 0;
	unsigned int executed = 0;
	struct json_object *tmp, *acvpdata, *versiondata, *testgroups;
	bool version_copied = false;

	if (kdf_ssh_backend) {
		tmp = json_object_new_array();
		CKNULL(tmp, -ENOMEM);

		CKINT(kdf_tester_ssh(in, tmp, cipher));

		/* Did we receive any data? */
		CKINT(json_split_version(tmp, &acvpdata, &versiondata));
		CKINT(json_find_key(acvpdata, "testGroups", &testgroups,
				    json_type_array));
		if (json_object_array_length(tmp) <= 1)
			goto exec;

		if ((json_object_array_length(testgroups) > 0) && !ret) {
			kdf_tester_copy_array(tmp, out, version_copied);
			version_copied = true;
		}
		json_object_put(tmp);
		if (ret < 0)
			goto out;

		executed = 1;
	}
	if (kdf_tls_backend) {
		tmp = json_object_new_array();
		CKNULL(tmp, -ENOMEM);

		CKINT(kdf_tester_tls(in, tmp, cipher));

		/* Did we receive any data? */
		CKINT(json_split_version(tmp, &acvpdata, &versiondata));
		CKINT(json_find_key(acvpdata, "testGroups", &testgroups,
				    json_type_array));
		if (json_object_array_length(testgroups) <= 1)
			goto exec;

		if ((json_object_array_length(testgroups) > 0) && !ret) {
			kdf_tester_copy_array(tmp, out, version_copied);
			version_copied = true;
		}
		json_object_put(tmp);
		if (ret < 0)
			goto out;

		executed = 1;
	}
	if (kdf_ikev1_backend) {
		tmp = json_object_new_array();
		CKNULL(tmp, -ENOMEM);

		CKINT(kdf_tester_ikev1(in, tmp, cipher));

		/* Did we receive any data? */
		CKINT(json_split_version(tmp, &acvpdata, &versiondata));
		CKINT(json_find_key(acvpdata, "testGroups", &testgroups,
				    json_type_array));
		if (json_object_array_length(tmp) <= 1)
			goto exec;

		if ((json_object_array_length(testgroups) > 0) && !ret) {
			kdf_tester_copy_array(tmp, out, version_copied);
			version_copied = true;
		}
		json_object_put(tmp);
		if (ret < 0)
			goto out;

		executed = 1;
	}
	if (kdf_ikev2_backend) {
		tmp = json_object_new_array();
		CKNULL(tmp, -ENOMEM);

		CKINT(kdf_tester_ikev2(in, tmp, cipher));

		/* Did we receive any data? */
		CKINT(json_split_version(tmp, &acvpdata, &versiondata));
		CKINT(json_find_key(acvpdata, "testGroups", &testgroups,
				    json_type_array));
		if (json_object_array_length(tmp) <= 1)
			goto exec;

		if ((json_object_array_length(testgroups) > 0) && !ret) {
			kdf_tester_copy_array(tmp, out, version_copied);
		}
		json_object_put(tmp);
		if (ret < 0)
			goto out;

		executed = 1;
	}

	/*
	 * If !executed -> None of the backends were registered -> -EOPNOTSUPP.
	 *
	 * If executed, then we have at least one successful run and data
	 * -> clear out any -EOPNOTSUPP.
	 */
exec:
	if (!executed)
		ret = -EOPNOTSUPP;
	else
		ret = 0;

out:
	return ret;
}

static struct cavs_tester kdf =
{
	ACVP_KDF_COMPONENT,
	kdf_tester,
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(register_kdf)
static void register_kdf(void)
{
	register_tester(&kdf, "KDF");
}

void register_kdf_tls_impl(struct kdf_tls_backend *implementation)
{
	register_backend(kdf_tls_backend, implementation, "KDF_TLS");
}

void register_kdf_ssh_impl(struct kdf_ssh_backend *implementation)
{
	register_backend(kdf_ssh_backend, implementation, "KDF_SSH");
}

void register_kdf_ikev1_impl(struct kdf_ikev1_backend *implementation)
{
	register_backend(kdf_ikev1_backend, implementation, "KDF_IKEv1");
}

void register_kdf_ikev2_impl(struct kdf_ikev2_backend *implementation)
{
	register_backend(kdf_ikev2_backend, implementation, "KDF_IKEv2");
}
