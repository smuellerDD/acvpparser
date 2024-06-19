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

#include "frontend_headers.h"

#include "conversion_be_le.h"
#include "logger.h"
#include "proto.h"
#include "ret_checkers.h"
#include "stringhelper.h"

/* no locking -> single threaded */
static struct proto_tester *tester = NULL;
static struct proto_forwarder *forwarder = NULL;

void proto_register_tester(struct proto_tester *curr_tester, const char *log)
{
	struct proto_tester *tmp_tester;

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

int proto_register_forwarder(struct proto_forwarder *fwd)
{
	if (forwarder)
		return -EEXIST;
	forwarder = fwd;

	return 0;
}

int proto_alloc_comm_buf(struct buffer *outbuf, size_t datalen)
{
	int ret;

	CKINT(alloc_buf(datalen + PB_BUF_WRITE_HEADER_SZ, outbuf));

	/* Adjust pointer for header */
	outbuf->buf += PB_BUF_WRITE_HEADER_SZ;

out:
	return ret;
}

int proto_test_algo(struct buffer *in, struct buffer *out, pb_header_t *header)
{
	struct proto_tester *curr_tester;
	int ret;

	header->message_type = le_bswap32(header->message_type);
	header->parsed_flags = le_bswap64(header->parsed_flags);
	header->datalen = le_bswap64(header->datalen);
	header->implementation = le_bswap32(header->implementation);

	/*
	 * If we have a forwarder installed, invoke it if the mask covers the
	 * implementation.
	 */
	if (forwarder &&
	    (header->implementation & forwarder->implementation_mask))
		return forwarder->forward(in, out, header);

	CKNULL_LOG(tester, -EINVAL, "No text executor registered\n");

	if (header->message_type == PB_UNKNOWN) {
		logger(LOGGER_ERR, "Unknown cipher\n");
		return -EINVAL;
	}

	logger(LOGGER_DEBUG, "Received test type %u\n", header->message_type);
	/* loop through the testers to find a test handler */
	for (curr_tester = tester;
	     curr_tester != NULL;
	     curr_tester = curr_tester->next) {
		if (curr_tester->type == header->message_type) {
			logger(LOGGER_DEBUG,
			       "Found test executor for %u, implementation %u\n",
			       curr_tester->type, header->implementation);

			/* Invoke test execution */
			ret = curr_tester->process_req(in, out,
						       header->parsed_flags);

			if (out->buf) {
				/*
				 * Undo adjustment in proto_alloc_comm_buf. This
				 * assumes that all tester use the function
				 * proto_alloc_comm_buf for allocating the
				 * output buffer!
				 */
				out->buf -= PB_BUF_WRITE_HEADER_SZ;
				header->datalen = out->len -
						  PB_BUF_WRITE_HEADER_SZ;

				/* Copy header into output buffer */
				memcpy(out->buf, header,
				       PB_BUF_WRITE_HEADER_SZ);
			}

			return ret;
		}
	}

	ret = -ENOMSG;

out:
	return ret;
}
