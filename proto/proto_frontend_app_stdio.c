/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#define _DEFAULT_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proto.h"
#include "stringhelper.h"

static int proto_ipc_workerloop(int input_fd, int output_fd)
{
	pb_header_t header;
	BUFFER_INIT(input_buf);
	BUFFER_INIT(output_buf);
	ssize_t data_processed;
	int ret;

	CKINT(alloc_buf(ACVP_MAXDATA, &input_buf));

	while (1) {
		char str[11];

		CKINT(read_complete(input_fd, (uint8_t *)&header,
				    PB_BUF_WRITE_HEADER_SZ));

		if (header.datalen > ACVP_MAXDATA) {
			logger(LOGGER_ERR, "Received data too large: %zu\n",
			       header.datalen);
			ret = -EOVERFLOW;
			goto out;
		}

		CKINT(read_complete(input_fd, input_buf.buf, header.datalen));
		input_buf.len = header.datalen;


		/* Set environment variable for implementation */
		snprintf(str, sizeof(str), "%u", header.implementation);
		if (setenv("ACVP_PROTO_IMPLEMENTATION", str, 1) == -1) {
			ret = -errno;
			goto out;
		}

		CKINT(proto_test_algo(&input_buf, &output_buf, &header));

		if (output_buf.buf) {
			data_processed = write(output_fd, output_buf.buf,
					       output_buf.len);
			if (data_processed < 0)
				ret = -errno;

			if ((size_t)data_processed != output_buf.len)
				ret = -EOVERFLOW;

			free_buf(&output_buf);
		} else {
			header.datalen = 0;

			data_processed = write(output_fd, &header,
					       PB_BUF_WRITE_HEADER_SZ);
			if (data_processed < 0)
				ret = -errno;

			if ((size_t)data_processed != PB_BUF_WRITE_HEADER_SZ)
				ret = -EOVERFLOW;
		}

		CKINT(ret);
	}

out:
	free_buf(&input_buf);
	free_buf(&output_buf);

	/* EOF is no error */
	if (ret == -ESPIPE)
		ret = 0;

	return ret;
}

/*
 * This IPC wrapper uses STDIN/STDOUT for the input/output of data.
 *
 * The worker may easily be adopted when using different file descriptors.
 */
static int proto_ipc_invocation_stdin_stdout(void)
{
	return proto_ipc_workerloop(0, 1);
}

static int versionstring(char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "ACVPProto/%d.%d.%d",
			MAJVERSION, MINVERSION, PATCHLEVEL);
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

	fprintf(stderr, "\nACVP Proto executing the crypto implementation %s\n",
		(_ACVP_PARSER_IUT) ? _ACVP_PARSER_IUT : "(undefined)");
	fprintf(stderr, "\nACVP Proto version: %s\n\n", version);

	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\n\t-v --verbose\tVerbose logging, multiple options increase verbosity\n");
	fprintf(stderr, "\t-h --help\tPrint this help information\n");
}

int main(int argc, char *argv[])
{
	int ret, c = 0;

#define ACVP_PARSER_WITH_GETOPTLONG

	opterr = 0;

	logger_set_verbosity(LOGGER_ERR);

	while (1) {
		int opt_index = 0;

#ifdef ACVP_PARSER_WITH_GETOPTLONG
		static struct option options[] = {
			{"verbose",		no_argument,		0, 'v'},
			{"help",		no_argument,		0, 'h'},

			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "vh", options, &opt_index);
#else
		c = getopt(argc, argv, "vh");
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
				usage();
				return 0;

			default:
				usage();
				ret = -EINVAL;
				goto out;
			}
			break;

		case 'v':
			logger_inc_verbosity();
			break;
		case 'h':
			usage();
			return 0;
		default:
			usage();
			ret = -EINVAL;
			goto out;
		}
	}

	ret = proto_ipc_invocation_stdin_stdout();

out:
	return -ret;
}
