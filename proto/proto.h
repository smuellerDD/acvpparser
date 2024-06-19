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

#ifndef _PROTO_H
#define _PROTO_H

#include "backend_protobuf.h"
#include "common.h"
#include "parser_flags.h"

#ifdef __cplusplus
extern "C"
{
#endif

#undef MAJVERSION
#undef MINVERSION
#undef PATCHLEVEL

#define MAJVERSION 0   /* API / ABI incompatible changes,
			* functional changes that require consumer
			* to be updated (as long as this number is
			* zero, the API is not considered stable
			* and can change without a bump of the
			* major version). */
#define MINVERSION 0   /* API compatible, ABI may change,
			* functional enhancements only, consumer
			* can be left unchanged if enhancements are
			* not considered. */
#define PATCHLEVEL 1   /* API / ABI compatible, no functional
			* changes, no enhancements, bug fixes
			* only. */

/**
 * Data structure used to register a new parser
 *
 * @param [in] type Parser type
 * @param [in] process_req function pointer that is the starting point of the
 *			   parser which is invoked if the ACVP Proto framework
 *			   identifies a test vector that is matched by either
 *			   @param type.
 * @param [in] next initialize this field to NULL - it is used by the ACVP
 *		    Parser framework.
 */
struct proto_tester {
	enum pb_message_type type;
	int (*process_req)(struct buffer *in, struct buffer *out,
			   flags_t parsed_flags);
	struct proto_tester *next;
};

void proto_register_tester(struct proto_tester *curr_tester, const char *log);

/**
 * Data structure used to register a new forwarder
 *
 * The goal of this function is to hand in the header along with the
 * input/output data pointers. This allows using the ACVP Proto to act as a
 * relay to forward the request to yet another ACVP Proto instance executing
 * somewhere else. The selection criteria whether the forwarder is used is
 * the implementation_mask parameter. This mask is applied to the received
 * implementation variable which is set by the ACVP-Parser backend_protobuf.c
 * (see pb_alloc_comm_buf).
 *
 * @param [in] implementation_mask Mask for which implementation the forwarder
 *				   shall be used
 * @param [in] forward function pointer that receives the forwarding request
 */
struct proto_forwarder {
	uint32_t implementation_mask;
	int (*forward)(struct buffer *in, struct buffer *out,
		       pb_header_t *header);
};

int proto_register_forwarder(struct proto_forwarder *fwd);

/**
 * @brief Allocate the memory for the output buffer
 */
int proto_alloc_comm_buf(struct buffer *outbuf, size_t datalen);

/**
 * @brief Invocation of test code.
 */
int proto_test_algo(struct buffer *in, struct buffer *out, pb_header_t *header);

#ifdef __cplusplus
}
#endif

#endif /* _PROTO_H */
