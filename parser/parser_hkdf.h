/*
 * Copyright (C) 2015 - 2019, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT HKDFLL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _PARSER_HKDF_H
#define _PARSER_HKDF_H

#include "parser.h"
#include "parser_flags.h"

/**
 * @brief RFC5869 KDF data structure
 *
 * @var mac [in] HMAC to be used for the KDF
 * @var okmlen [in] Length of output keying material in bits
 * @var ikm [in] input key material
 * @var salt [out] salt for the HKDF - the HKDF implementation shall provide
 *		   the used salt
 * @var info [out] Additional information for the HKDF - the HKDF implementation
 *		   shall provide the used salt
 * @var okm [out] The output keying material
 */
struct hkdf_data {
	uint64_t mac;
	uint32_t okmlen;
	struct buffer ikm;
	struct buffer salt;
	struct buffer info;
	struct buffer okm;
};

/**
 * @brief Callback data structure that must be implemented by the backend.
 *
 * All functions return 0 on success or != 0 on error.
 *
 * @var hkdf Perform an SP800-108 key derivation
 */
struct hkdf_backend {
	int (*hkdf)(struct hkdf_data *data, flags_t parsed_flags);
};

void register_hkdf_impl(struct hkdf_backend *implementation);

#endif /* _PARSER_HKDF_H */
