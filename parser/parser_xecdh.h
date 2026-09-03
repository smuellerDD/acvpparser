/*
 * Copyright (C) 2026, Joachim Vandersmissen <joachim.vandersmissen@atsec.com>
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

#ifndef _PARSER_XECDH_H
#define _PARSER_XECDH_H

#include "parser_flags.h"
#include "stringhelper.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief XECDH key generation data structure holding the data for the cipher
 *	  operations specified in xecdh_keygen.
 *
 * @var cipher [in] Cipher pointing to the curve
 * @var private_key [out] XECDH private key
 * @var public_key [out] XECDH public key
 */
struct xecdh_keygen_data {
	uint64_t cipher;
	struct buffer private_key;
	struct buffer public_key;
};

/**
 * @brief XECDH key verification data structure holding the data for the cipher
 *	  operations specified in xecdh_keyver.
 *
 * @var cipher [in] Cipher pointing to the curve
 * @var public_key [in] XECDH public key
 * @var keyver_success [out] Is XECDH key verification with given parameters
 *			     successful (1) or whether it failed (0).
 */
struct xecdh_keyver_data {
	uint64_t cipher;
	struct buffer public_key;
	uint32_t keyver_success;
};

/**
 * @brief XECDH shared secret computation
 *
 * @var cipher [in] Cipher pointing to the curve
 * @var public_server [in] Server's public key
 * @var public_iut [out] IUT's public key
 * @var z [out] raw shared secret for XECDH
 */
struct xecdh_ssc_data {
	uint64_t cipher;
	struct buffer public_server;
	struct buffer public_iut;
	struct buffer z;
};

/**
 * @brief Callback data structure that must be implemented by the backend. Some
 *	  callbacks only need to be implemented if the respective cipher support
 *	  shall be tested.
 *
 * All functions return 0 on success or != 0 on error. Note, a failure in the
 * XECDH key verification @var xecdh_keyver due to problematic input
 * parameters is expected. In such cases, an XECDH key verification error is
 * still considered to be a successful operation and the return code should be
 * 0. Only if some general error is detected a return code != must be returned.
 *
 * @var xecdh_keygen XECDH key generation
 * @var xecdh_keyver XECDH key verification
 * @var xecdh_ssc XECDH shared secret computation
 */
struct xecdh_backend {
	int (*xecdh_keygen)(struct xecdh_keygen_data *data, flags_t parsed_flags);
	int (*xecdh_keyver)(struct xecdh_keyver_data *data, flags_t parsed_flags);
	int (*xecdh_ssc)(struct xecdh_ssc_data *data, flags_t parsed_flags);
};

void register_xecdh_impl(struct xecdh_backend *implementation);

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_XECDH_H */
