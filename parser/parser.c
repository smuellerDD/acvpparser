/*
 * Copyright (C) 2017 - 2021, Stephan Mueller <smueller@chronox.de>
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
#include <getopt.h>
#include <string.h>
#include <stdarg.h>

#include "parser.h"
#include "parser_common.h"
#include "logger.h"
#include "read_json.h"
#include "stringhelper.h"
#include "term_colors.h"

/* no locking -> single threaded */
struct cavs_tester *tester = NULL;

int generate_testvector = 0;

static struct main_extension *main_extension = NULL;

#if !defined(NO_MAIN)
void register_main_extension(struct main_extension* extension)
{
	register_backend(main_extension, extension, "main backend");
}
#endif

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
		if ((curr_tester->testid && (cipher == curr_tester->testid)) ||
		    (curr_tester->mask && (convert_cipher_contain(cipher,
						curr_tester->mask, 0)))) {
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
	struct json_object *acvpdata, *versiondata;
	int ret;

	*algo = NULL;

	CKINT(json_split_version(obj, &acvpdata, &versiondata));

	CKINT(json_get_string(acvpdata, "algorithm", algo));

out:
	return ret;
}

#if !defined(NO_MAIN)
static int versionstring(char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "ACVPParser/%d.%d.%d",
			MAJVERSION, MINVERSION, PATCHLEVEL);
}
#else
static int versionstring(char *buf, size_t buflen)
{
	(void)buf;
	(void)buflen;
	return 0;
}
#endif

int match_expected_vector(const char *actualfile, const char *expectedfile)
{
	int ret = 0;

	if (json_validate_result(actualfile, expectedfile) ==
	    JSON_VAL_RES_PASS_EXPECTED) {
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

	return ret;
}

int perform_testing(const char *infile, const char *outfile)
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
		json_write_data(outobj, filename);
	} else {
		ret = json_write_data(outobj, outfile);
	}

out:
	if (outobj)
		json_object_put(outobj);
	if (inobj)
		json_object_put(inobj);

	return ret;
}

int perform_testing_regression(const char *infile,
				      const char *expectedfile)
{
	struct json_object *inobj = NULL, *outobj = NULL, *expected = NULL;
	int ret;
	const char *algo;

	CKINT(json_read_data(infile, &inobj));
	logger(LOGGER_DEBUG, "Request file %s read successfully\n", infile);

	CKINT(json_read_data(expectedfile, &expected));
	logger(LOGGER_DEBUG, "Expected data file %s read successfully\n",
	       expectedfile);

	CKINT(get_algorithm(inobj, &algo))
	logger(LOGGER_DEBUG, "Algorithm %s found in request file %s\n",
	       algo, infile);

	outobj = json_object_new_array();
	CKNULL_LOG(outobj, -ENOMEM,
		   "Cannot create toplevel output JSON object\n");

	ret = test_algo(inobj, outobj, algo);
	if (ret) {
		if (logger_get_verbosity() >= LOGGER_WARN) {
			fprintf_red(stdout, "[FAILED] ");
			fprintf(stdout, "Generation of test results failed\n");
		}
		ret = -EIO;
		goto out;
	}

	if (json_validate_result_json(outobj, expected) ==
	    JSON_VAL_RES_PASS_EXPECTED) {
		if (logger_get_verbosity() >= LOGGER_WARN) {
			fprintf_green(stdout, "[PASSED] ");
			fprintf(stdout, "regression test match\n");
		}
		ret = 0;
	} else {
		if (logger_get_verbosity() >= LOGGER_WARN) {
			fprintf_red(stdout, "[FAILED] ");
			fprintf(stdout, "regression test failure\n");
		}
		ret = -EIO;
	}

out:
	if (outobj)
		json_object_put(outobj);
	if (inobj)
		json_object_put(inobj);
	if (expected)
		json_object_put(expected);

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
	fprintf(stderr, " acvp-parser [OPTIONS] -r <testvector-request.json> <expected-response.json>\n\n");

	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-e --expected\tPerform a JSON matching between the two files\n");
	fprintf(stderr, "\t\t\t\t(return code 0 - both files match)\n");
	fprintf(stderr, "\t\t\t\t(return code 1 - both files mismatch)\n");
	fprintf(stderr, "\t-r --regression\tPerform a JSON regression testing\n");
	fprintf(stderr, "\t-t --testvector\tGenerate testvector\n");

	fprintf(stderr, "\n\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr, "\t-h --help\tPrint this help information\n");

	if (main_extension && main_extension->usage) {
		fprintf(stderr, "\n");
		main_extension->usage();
	}
}

int main(int argc, char *argv[])
{
	const char *infile, *outfile = NULL;
	int ret, expected = 0, regression = 0, c = 0;

#define ACVP_PARSER_WITH_GETOPTLONG

	opterr = 0;

	logger_set_verbosity(LOGGER_ERR);

	while (1) {
		int opt_index = 0;

#ifdef ACVP_PARSER_WITH_GETOPTLONG
		static struct option options[] = {
			{"verbose",		no_argument,		0, 'v'},
			{"expected",		no_argument,		0, 'e'},
			{"regression",		no_argument,		0, 'r'},
			{"testvector",		no_argument,		0, 't'},
			{"help",		no_argument,		0, 'h'},

			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "verth", options, &opt_index);
#else
		c = getopt(argc, argv, "verth");
#endif
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				logger_inc_verbosity();
				break;
			case 1:
				expected = 1;
				break;
			case 2:
				regression = 1;
				break;
			case 3:
				generate_testvector = 1;
				break;
			case 4:
				usage();
				return 0;

			default:
				if (main_extension) {
					ret = main_extension->main(argc, argv);
				} else {
					usage();
					ret = -EINVAL;
				}
				goto out;
			}
			break;

		case 'v':
			logger_inc_verbosity();
			break;
		case 'e':
			expected = 1;
			break;
		case 'r':
			regression = 1;
			break;
		case 't':
			generate_testvector = 1;
			break;
		case 'h':
			usage();
			return 0;
		default:
			if (main_extension) {
				ret = main_extension->main(argc, argv);
			} else {
				usage();
				ret = -EINVAL;
			}
			goto out;
		}
	}

	if (expected && regression) {
		logger(LOGGER_ERR, "The options of -r and -e are mutually exclusive\n");
		ret = -EINVAL;
		goto out;
	}

	if (argc != optind + 2) {
		usage();
		ret = -EINVAL;
		goto out;
	}

	infile = argv[optind];
	outfile = argv[optind + 1];

	if (expected) {
		ret = match_expected_vector(infile, outfile);
	} else if (regression) {
		ret = perform_testing_regression(infile, outfile);
	} else {
		ret = perform_testing(infile, outfile);
	}

out:
	return -ret;
}
