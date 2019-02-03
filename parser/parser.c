/*
 * Copyright (C) 2017 - 2019, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
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

#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "parser.h"
#include "logger.h"
#include "read_json.h"
#include "stringhelper.h"
#include "term_colors.h"

/* no locking -> single threaded */
struct cavs_tester *tester = NULL;

void register_tester(struct cavs_tester *curr_tester, const char *log)
{
	struct cavs_tester *tmp_tester;

	if (!tester) {
		logger(LOGGER_DEBUG, "Register first executor (%s)\n", log);
		tester = curr_tester;
		return;
	}
	for (tmp_tester = tester;
	     tmp_tester != NULL;
	     tmp_tester = tmp_tester->next) {
		if (!tmp_tester->next) {
			logger(LOGGER_DEBUG, "Register next executor (%s)\n",
			       log);
			tmp_tester->next = curr_tester;
			return;
		}
	}
}

static const struct { char *algo; uint64_t cipher; } conv[] = {
	{"AES-ECB", ACVP_ECB},
	{"AES-CBC", ACVP_CBC},
	{"AES-OFB", ACVP_OFB},
	{"AES-CFB8", ACVP_CFB8},
	{"AES-CFB128", ACVP_CFB128},
	{"AES-CFB1", ACVP_CFB1},
	{"AES-CTR", ACVP_CTR},
	{"AES-GCM", ACVP_GCM},
	{"AES-CCM", ACVP_CCM},
	{"AES-XTS", ACVP_XTS},
	{"AES-KWP", ACVP_KWP},
	{"AES-KW", ACVP_KW},
	{"AES-128", ACVP_AES128},
	{"AES-192", ACVP_AES192},
	{"AES-256", ACVP_AES256},

	{"TDES-ECB", ACVP_TDESECB},
	{"TDES-CBC", ACVP_TDESCBC},
	{"TDES-OFB", ACVP_TDESOFB},
	{"TDES-CFB1", ACVP_TDESCFB1},
	{"TDES-CFB8", ACVP_TDESCFB8},
	{"TDES-CFB64", ACVP_TDESCFB64},
	{"TDES-CTR", ACVP_TDESCTR},
	{"TDES-KW", ACVP_TDESKW},
	/* CTR DRBG */
	{"3keyTDEA", ACVP_TDESCTR},

	{"CMAC-AES", ACVP_AESCMAC},
	{"CMAC-TDES", ACVP_TDESCMAC},
	{"HMAC-SHA-1", ACVP_HMACSHA1},
	{"HMAC-SHA2-224", ACVP_HMACSHA2_224},
	{"HMAC-SHA2-256", ACVP_HMACSHA2_256},
	{"HMAC-SHA2-384", ACVP_HMACSHA2_384},
	{"HMAC-SHA2-512", ACVP_HMACSHA2_512},
	{"HMAC-SHA2-512/224", ACVP_HMACSHA2_512224},
	{"HMAC-SHA2-512/256", ACVP_HMACSHA2_512256},
	{"HMAC-SHA3-224", ACVP_HMACSHA3_224},
	{"HMAC-SHA3-256", ACVP_HMACSHA3_256},
	{"HMAC-SHA3-384", ACVP_HMACSHA3_384},
	{"HMAC-SHA3-512", ACVP_HMACSHA3_512},

	{"RSA", ACVP_RSA},
	{"ECDSA", ACVP_ECDSA},
	{"EDDSA", ACVP_EDDSA},
	{"DSA", ACVP_DSA},

	{"SHA-1", ACVP_SHA1},

	{"SHA3-224", ACVP_SHA3_224},
	{"SHA3-256", ACVP_SHA3_256},
	{"SHA3-384", ACVP_SHA3_384},
	{"SHA3-512", ACVP_SHA3_512},
	{"SHA2-224", ACVP_SHA224},
	{"SHA2-256", ACVP_SHA256},
	{"SHA2-384", ACVP_SHA384},
	{"SHA2-512", ACVP_SHA512},
	{"SHA2-512/224", ACVP_SHA512224},
	{"SHA2-512/256", ACVP_SHA512256},
	{"ctrDRBG", ACVP_DRBGCTR},
	{"hashDRBG", ACVP_DRBGHASH},
	{"hmacDRBG", ACVP_DRBGHMAC},

	{"KAS-ECC", ACVP_ECDH},
	{"KAS-FFC", ACVP_DH},

	{"kdf-components", ACVP_KDF_COMPONENT},
	{"KDF", ACVP_KDF_800_108},
	{"double pipeline iteration", ACVP_KDF_108_DOUBLE_PIPELINE},
	{"feedback", ACVP_KDF_108_FEEDBACK},
	{"counter", ACVP_KDF_108_COUNTER},
	{"after fixed data", ACVP_KDF_108_AFTER_FIXED},
	{"before fixed data", ACVP_KDF_108_BEFORE_FIXED},
	{"middle fixed data", ACVP_KDF_108_MIDDLE_FIXED},
	{"before iterator", ACVP_KDF_108_BEFORE_ITERATOR},

	{"P-224", ACVP_NISTP224},
	{"P-256", ACVP_NISTP256},
	{"P-384", ACVP_NISTP384},
	{"P-521", ACVP_NISTP521},
	{"K-233", ACVP_NISTK233},
	{"K-283", ACVP_NISTK283},
	{"K-409", ACVP_NISTK409},
	{"K-571", ACVP_NISTK571},
	{"B-233", ACVP_NISTB233},
	{"B-283", ACVP_NISTB283},
	{"B-409", ACVP_NISTB409},
	{"B-571", ACVP_NISTB571},

	{"ED-25519", ACVP_ED25519},
	{"ED-448", ACVP_ED448},

	/* SSH */
	{"TDES", ACVP_TDESECB},

	/* Conversion from uint64_t back to a name */
	{"ctrDRBG_AES128", (ACVP_DRBGCTR | ACVP_AES128)},
	{"ctrDRBG_AES192", ACVP_DRBGCTR | ACVP_AES192},
	{"ctrDRBG_AES256", ACVP_DRBGCTR | ACVP_AES256},
	{"hashDRBG_SHA-1", ACVP_DRBGHASH | ACVP_SHA1},
	{"hashDRBG_SHA-224", ACVP_DRBGHASH | ACVP_SHA224},
	{"hashDRBG_SHA-256", ACVP_DRBGHASH | ACVP_SHA256},
	{"hashDRBG_SHA-384", ACVP_DRBGHASH | ACVP_SHA384},
	{"hashDRBG_SHA-512", ACVP_DRBGHASH | ACVP_SHA512},
	{"hashDRBG_SHA-512224", ACVP_DRBGHASH | ACVP_SHA512224},
	{"hashDRBG_SHA-512256", ACVP_DRBGHASH | ACVP_SHA512256},
	{"hmacDRBG_SHA-1", ACVP_DRBGHMAC | ACVP_SHA1},
	{"hmacDRBG_SHA-224", ACVP_DRBGHMAC | ACVP_SHA224},
	{"hmacDRBG_SHA-256", ACVP_DRBGHMAC | ACVP_SHA256},
	{"hmacDRBG_SHA-384", ACVP_DRBGHMAC | ACVP_SHA384},
	{"hmacDRBG_SHA-512", ACVP_DRBGHMAC | ACVP_SHA512},
	{"hmacDRBG_SHA-512224", ACVP_DRBGHMAC | ACVP_SHA512224},
	{"hmacDRBG_SHA-512256", ACVP_DRBGHMAC | ACVP_SHA512256},
};

uint64_t convert_algo_cipher(const char *algo, uint64_t cipher)
{
	uint64_t p_res = 0;
	unsigned int i;

	logger(LOGGER_DEBUG, "Convert cipher %s into internal representation\n",
	       algo);

	if (!algo) return ACVP_UNKNOWN;

	for (i = 0; i < ARRAY_SIZE(conv); i++) {
		if (strstr(algo, conv[i].algo)) {
			p_res = conv[i].cipher;
			break;
		}
	}
	if (p_res == 0)
		return ACVP_UNKNOWN;

	return (cipher | p_res);
}

int convert_cipher_algo(uint64_t cipher, const char **algo)
{
	unsigned int i;
	unsigned int found = 0;

	if (!algo)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(conv); i++) {
		if (cipher == conv[i].cipher) {
			*algo = conv[i].algo;
			found = 1;
			break;
		}
	}

	if (!found)
		return -EINVAL;

	return 0;
}

static int test_algo(struct json_object *in, struct json_object *out,
		     const char *algo)
{
	struct cavs_tester *curr_tester;
	uint64_t cipher;
	int ret;

	CKNULL_LOG(tester, -EINVAL, "No text executor registered\n");

	cipher = convert_algo_cipher(algo, 0);
	if (cipher == ACVP_UNKNOWN) {
		logger(LOGGER_ERR, "Unknown cipher %s\n", algo);
		return -EINVAL;
	}

	/* loop through the testers to find a test handler */
	for (curr_tester = tester;
		curr_tester != NULL;
		curr_tester = curr_tester->next) {
		if (cipher & curr_tester->mask) {
			logger(LOGGER_DEBUG, "Found test executor for %s\n",
			       algo);
			return curr_tester->process_req(in, out, cipher);
		}
	}

	ret = -ENOMSG;

out:
	return ret;
}

static int get_algorithm(struct json_object *obj, const char **algo)
{
	struct json_object *o, *acvpdata, *versiondata;
	int ret;

	*algo = NULL;

	CKINT(json_split_version(obj, &acvpdata, &versiondata));

	CKINT(json_find_key(acvpdata, "algorithm", &o, json_type_string));

	*algo = json_object_to_json_string(o);

out:
	return ret;
}

static int write_data(struct json_object *jobj, const char *filename)
{
	FILE *outfile;

	if (!jobj)
		return 0;

	outfile = fopen(filename, "w");

	if (!outfile) {
		int errsv = -errno;

		logger(LOGGER_ERR,
		       "Cannot open output file %s for writing: %d\n",
		       filename, errsv);
		return errsv;
	}
	json_print_data(jobj, outfile);

	fclose(outfile);

	return 0;
}

static int versionstring(char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "ACVPParser/%d.%d.%d",
			MAJVERSION, MINVERSION, PATCHLEVEL);
}

static int match_expected(const char *actualfile, const char *expectedfile)
{
	struct json_object *actual = NULL, *expobj = NULL;
	struct json_object *expecteddata, *expectedversion,
			   *actualdata, *actualversion;;
	int ret;

	/* Open and parse expected test result */
	CKINT(json_read_data(expectedfile, &expobj));
	CKINT(json_split_version(expobj, &expecteddata, &expectedversion));

	/* Open and parse actual test result */
	CKINT(json_read_data(actualfile, &actual));
	CKINT(json_split_version(actual, &actualdata, &actualversion));

	ret = json_object_equal(expecteddata, actualdata);
	if (ret) {
		if (logger_get_verbosity() >= LOGGER_WARN) {
			fprintf_green(stdout, "[PASSED] ");
			fprintf(stdout,"compare %s with %s\n", actualfile,
			        expectedfile);
		}
		ret = 0;
	} else {
		if (logger_get_verbosity() >= LOGGER_WARN) {
			fprintf_red(stdout, "[FAILED] ");
			fprintf(stdout, "compare %s with %s\n", actualfile,
			        expectedfile);
		}
		ret = -EIO;
	}

out:
	if (actual)
		json_object_put(actual);
	if (expobj)
		json_object_put(expobj);

	return ret;
}

static int perform_testing(const char *infile, const char *outfile)
{
	struct json_object *inobj = NULL, *outobj = NULL;
	int ret;
	const char *algo;

	CKINT(json_read_data(infile, &inobj));
	logger(LOGGER_DEBUG, "Request file %s read successfully\n", infile);

	CKINT(get_algorithm(inobj, &algo))
	logger(LOGGER_DEBUG, "Algorithm %s found in request file %s\n",
	       algo, infile);

	outobj = json_object_new_array();
	CKNULL_LOG(outobj, -ENOMEM,
		   "Cannot create toplevel output JSON object\n");

	ret = test_algo(inobj, outobj, algo);
	if (ret) {
		char filename[FILENAME_MAX];

		snprintf(filename, sizeof(filename), "%s.partial", outfile);
		write_data(outobj, filename);
	} else {
		ret = write_data(outobj, outfile);
	}

out:
	if (outobj)
		json_object_put(outobj);
	if (inobj)
		json_object_put(inobj);

	return ret;
}

#ifdef ACVP_PARSER_IUT
#define _ACVP_PARSER_IUT ACVP_PARSER_IUT
#else
#define _ACVP_PARSER_IUT NULL
#endif

static void usage(void)
{
	char version[50];

	versionstring(version, sizeof(version));

	fprintf(stderr, "\nACVP Parser executing the crypto implementation %s\n",
		(_ACVP_PARSER_IUT) ? _ACVP_PARSER_IUT : "(undefined)");
	fprintf(stderr, "\nACVP Parser version: %s\n\n", version);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, " acvp-parser [OPTIONS] <testvector-request.json> <testvector-response.json>\n");
	fprintf(stderr, " acvp-parser [OPTIONS] -e <expected-response.json> <testvector-response.json>\n\n");

	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-e --expected\tPerform a JSON matching between the two files\n");
	fprintf(stderr, "\t\t\t\t(return code 0 - both files match)\n");
	fprintf(stderr, "\t\t\t\t(return code 1 - both files mismatch)\n");

	fprintf(stderr, "\n\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr, "\t-h --help\tPrint this help information\n");
}

int main(int argc, char *argv[])
{
	const char *infile, *outfile = NULL;
	int ret, expected = 0;;
	int curr_argc = 1, options_argc = argc - 2;

	logger_set_verbosity(LOGGER_ERR);

	if (argc == 2 && (!strncmp(argv[1], "-h", 2) ||
		!strncmp(argv[curr_argc], "--help", 6))) {
		usage();
		return 0;
	}

	if (argc < 3 ) {
		usage();
		return EINVAL;
	}

	/* The last two arguments are our file names */
	while (curr_argc < options_argc) {
		if (!strncmp(argv[curr_argc], "-v", 2) ||
		    !strncmp(argv[curr_argc], "--verbose", 9)) {
			logger_inc_verbosity();
		}

		if (!strncmp(argv[curr_argc], "-e", 2) ||
		    !strncmp(argv[curr_argc], "--expected", 10)) {
			expected = 1;
		}

		curr_argc++;
	}

	infile = argv[curr_argc];
	curr_argc++;
	outfile = argv[curr_argc];

	if (expected) {
		ret = match_expected(infile, outfile);
	} else {
		ret = perform_testing(infile, outfile);
	}

	return -ret;
}
