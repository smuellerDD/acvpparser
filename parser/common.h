/*
 * Copyright (C) 2017 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef _COMMON_H
#define _COMMON_H

#include "algorithms.h"
#include "logger.h"

#ifdef __cplusplus
extern "C"
{
#endif

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

/*
 * Maximum amount of data that one test vector has. This is based on the
 * consideration that a data entry is never larger than 2**16 bytes. We allow
 * auxiliary data of size 16kBytes.
 */
#define ACVP_MAXDATA ((1 << 16) + (1 << 16))

#define register_backend(backend, definition, log)			\
	if (backend) {							\
		logger(LOGGER_ERR,					\
		       "Backend %s already registered\n", log);		\
		exit(-EFAULT);						\
	}								\
	backend = definition;						\
	logger(LOGGER_VERBOSE, "Backend %s registered\n", log);

#ifdef __cplusplus
}
#endif

#endif /* _COMMON_H */
