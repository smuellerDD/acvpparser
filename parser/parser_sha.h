/*
 * Copyright (C) 2015 - 2019, Stephan Mueller <smueller@chronox.de>
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

#ifndef _PARSER_SHA_H
#define _PARSER_SHA_H

#include "parser.h"
#include "parser_flags.h"

/**
 * @brief Hash cipher data structure holding the data for the cipher
 *	  operations specified in sha_backend
 *
 * @param msg [in] Data buffer holding the message to be hashed in binary form.
 * @param bitllen [in] Size of the message in bits - NOTE the @param msg is a
 *		       buffer containing the message in full bytes. If the
 *		       request for message sizes are made that are not full
 *		       buffers, the @param bitlen field can be consulted to
 *		       identify the number of rightmost bits to be pulled from
 *		       @param msg. @param bitlen is per definition at most 7
 *		       bits smaller than the message buffer in @param msg and
 *		       never larger.
 * @param outlen [in] Size of the output message digest to be created in bits.
 *		      This field is required for variable-sized output message
 *		      digests, such as SHAKE.
 * @param minoutlen [in] MinimumOutputLength as defined for the SHAKE MCT. Note,
 *			 this value is only used for the MCT operation and does
 *			 not need to be considered by a backend.
 * @param maxoutlen [in] MaximumOutputLength as defined for the SHAKE MCT. Note,
 *			 this value is only used for the MCT operation and does
 *			 not need to be considered by a backend.
 * @param mac [out] Message digest of the message in binary form.
 *		    Note, the backend must allocate the buffer of the right
 *		    size before storing data in it. The parser frees the memory.
 * @param cipher [in] Cipher specification as defined in cipher_definitions.h
 */
struct sha_data {
	struct buffer msg;
	uint32_t bitlen;
	uint32_t outlen;
	uint32_t minoutlen;
	uint32_t maxoutlen;
	struct buffer mac;
	uint64_t cipher;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @param hash_generate Perform a message digest operation with the given data.
 */
struct sha_backend {
	int (*hash_generate)(struct sha_data *data, flags_t parsed_flags);
};

void register_sha_impl(struct sha_backend *implementation);

#endif /* _PARSER_SHA_H */
