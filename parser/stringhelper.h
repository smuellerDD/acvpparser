/*
 * Copyright (C) 2015 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef _STRINGHELPER_H
#define _STRINGHELPER_H

#include "frontend_headers.h"

#include "common.h"
#include "logger.h"
#include "ret_checkers.h"

#ifdef __cplusplus
extern "C"
{
#endif

static inline void free_buf(struct buffer *buf)
{
	if (!buf)
		return;
	if (buf->buf) {
		acvp_free(buf->buf);
		buf->buf = NULL;
	}
	if (buf->len)
		buf->len = 0;
}

static inline int alloc_buf(size_t size, struct buffer *buf)
{
	if (buf->buf) {
		logger(LOGGER_WARN, "Allocate an already allocated buffer!\n");
		return -EFAULT;
	}
	if (!size)
		return 0;

	buf->buf = acvp_calloc(1, size);
	if (!buf->buf)
		return -ENOMEM;

	buf->len = size;

	return 0;
}

static inline void copy_ptr_buf(struct buffer *dst, struct buffer *src)
{
	dst->buf = src->buf;
	dst->len = src->len;
}

int read_complete(int fd, uint8_t *buf, size_t buflen);
char* get_val(char *str, const char *delim);
int get_intval(char *str, const char *delim, uint32_t *val);
int get_hexval(char *str, const char *delim, uint32_t *val);
int get_binval(char *str, const char *delim, struct buffer *buf);
void copy_ptr_buf(struct buffer *dst, struct buffer *src);
int left_pad_buf(struct buffer *buf, size_t required_len);
int remove_leading_zeroes(struct buffer *buf);
int mpi_remove_pad(struct buffer *buf, size_t required_len);

#ifdef __cplusplus
}
#endif

#endif /* _STRINGHELPER_H */
