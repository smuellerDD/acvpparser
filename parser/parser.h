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

#ifndef _PARSER_H
#define _PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#include <json-c/json.h>

#include "binhexbin.h"
#include "cipher_definitions.h"
#include "constructor.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MAJVERSION 0   /* API / ABI incompatible changes,
			* functional changes that require consumer
			* to be updated (as long as this number is
			* zero, the API is not considered stable
			* and can change without a bump of the
			* major version). */
#define MINVERSION 5   /* API compatible, ABI may change,
			* functional enhancements only, consumer
			* can be left unchanged if enhancements are
			* not considered. */
#define PATCHLEVEL 0   /* API / ABI compatible, no functional
			* changes, no enhancements, bug fixes
			* only. */

#define CIPHER_DECRYPTION_FAILED	"\xde\xad\xbe\xef"
#define CIPHER_DECRYPTION_FAILED_LEN	(sizeof(CIPHER_DECRYPTION_FAILED) - 1)

struct buffer {
	unsigned char *buf;
	size_t len;
};
#define BUFFER_INIT(buf)						\
	struct buffer buf = { NULL, 0 };

struct buffer_array {
#define MAX_BUFFER_ARRAY	5
	unsigned int arraysize;
	struct buffer buffers[MAX_BUFFER_ARRAY];
};

struct cipher_array {
#define MAX_CIPHER_ARRAY	16
	unsigned int arraysize;
	uint64_t cipher[MAX_CIPHER_ARRAY];
};

struct mpint {
	const char len[8];
	const char value[];
};

struct cavs_tester {
	uint64_t mask;
	int (*process_req) (struct json_object *in, struct json_object *out,
			    uint64_t cipher);
	struct cavs_tester *next;
};

void register_tester(struct cavs_tester *curr_tester, const char *log);
uint64_t convert_algo_cipher(const char *algo, uint64_t cipher);
int convert_cipher_algo(uint64_t cipher, const char **algo);

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_H */
