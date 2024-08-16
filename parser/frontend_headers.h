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

#ifndef PROTO_FRONTEND_HEADERS_H
#define PROTO_FRONTEND_HEADERS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __KERNEL__

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>

void __init linux_kernel_constructor(void);

const char *getenv(const char *name);

#define _logger(severity, file, func, line, fmt, ...)
#define _logger_binary(severity, bin, binlen, str, file, func, line)
#define free kfree

#define calloc(nmemb, size)						\
	kmalloc(nmemb * size, __GFP_ZERO | GFP_KERNEL)
#define malloc(size)							\
	kmalloc(size, GFP_KERNEL)

#define exit(n)		WARN_ON(n)
#ifndef assert
#define assert(n)	WARN_ON(!(n))
#endif

int posix_memalign(void **memptr, size_t alignment, size_t size);

/* Constructor functions */
void _init_register_proto_aead(void);
void _init_register_proto_cshake(void);
void _init_register_proto_drbg(void);
void _init_register_proto_ecdh(void);
void _init_register_proto_ecdsa(void);
void _init_register_proto_eddsa(void);
void _init_register_proto_hkdf(void);
void _init_register_proto_hmac(void);
void _init_register_proto_kdf108(void);
void _init_register_proto_kmac(void);
void _init_register_proto_ml_dsa(void);
void _init_register_proto_ml_kem(void);
void _init_register_proto_pbkdf(void);
void _init_register_proto_rsa(void);
void _init_register_proto_sha(void);
void _init_register_proto_sym(void);

#else /* __KERNEL__ */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#endif /* __KERNEL__ */

#ifdef __cplusplus
}
#endif

#endif /* PROTO_FRONTEND_HEADERS_H */
