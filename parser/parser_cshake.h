/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef _PARSER_CSHAKE_H
#define _PARSER_CSHAKE_H

#include "parser.h"
#include "parser_flags.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief cSHAKE cipher data structure holding the data for the cipher
 *	  operations specified in cshake_backend
 *
 * @var cipher [in] Cipher specification as defined in cipher_definitions.h
 * @var msg [in] Data buffer holding the message to be hashed in binary form.
 * @var bitllen [in] Size of the message in bits - NOTE the @var msg is a
 *		       buffer containing the message in full bytes. If the
 *		       request for message sizes are made that are not full
 *		       buffers, the @var bitlen field can be consulted to
 *		       identify the number of rightmost bits to be pulled from
 *		       @var msg. @var bitlen is per definition at most 7
 *		       bits smaller than the message buffer in @var msg and
 *		       never larger.
 * @var outlen [in] Size of the output message digest to be created in bits.
 * @var minoutlen [in] MinimumOutputLength as defined for the cSHAKE MCT. Note,
 *			 this value is only used for the MCT operation and does
 *			 not need to be considered by a backend.
 * @var maxoutlen [in] MaximumOutputLength as defined for the cSHAKE MCT. Note,
 *			 this value is only used for the MCT operation and does
 *			 not need to be considered by a backend.
 * @var function_name [in] The function name for cSHAKE as defined in
 *			   SP800-185
 * @var customization [in] The customization string as define SP800-185.
 *			   Note, the parser already converts the test data
 *			   into the right format. I.e. if the test vector
 *			   defines a hexadecimal buffer, the parser converts
 *			   it automatically into binary. If it is a string
 *			   the customization string is found in the buffer.
 *			   The IUT simply has to consume the provided buffer
 *			   without performing any conversion operation.
 * @var digest [out] Message digest of the message in binary form.
 *		     Note, the backend must allocate the buffer of the right
 *		     size before storing data in it. The parser frees the
 *		     memory.
 */
struct cshake_data {
	uint64_t cipher;
	struct buffer msg;
	uint32_t bitlen;
	uint32_t outlen;
	uint32_t minoutlen;
	uint32_t maxoutlen;
	struct buffer function_name;
	struct buffer customization;

	struct buffer mac;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @var hash_generate Perform a message digest operation with the given data.
 */
struct cshake_backend {
	int (*cshake_generate)(struct cshake_data *data, flags_t parsed_flags);
};

void register_cshake_impl(struct cshake_backend *implementation);

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_CSHAKE_H */
