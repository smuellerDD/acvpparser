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

#ifndef _PARSER_LMS_H
#define _PARSER_LMS_H

#include "parser.h"
#include "parser_flags.h"

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief LMS signature verification data structure holding the data for the
 *	  signature verification operation. The IUT shall use the data and
 *	  and return the indicator whether the signature was verified or not.
 *	  Note, it is permissible that the signature verification fails because
 *	  the key is not acceptable. In this case, the signature verification
 *	  shall be marked as fail, too.
 *
 * This data structure is also used for the LMS signature verification
 * primitive testing.
 *
 * The caller may obtain
 *
 * @var msg [in] Plaintext message to be signature verified.
 * @var pub [in] LMS public key to be used for signature verification
 * @var sig [in] LMS signature to be verified
 * @var lmsMode [in] Applicable valid LMS mode which is one NULL-terminated
 *		     string out of:
 *			* LMS_SHA256_M24_H5
 *			* LMS_SHA256_M24_H10
 *			* LMS_SHA256_M24_H15
 *			* LMS_SHA256_M24_H20
 *			* LMS_SHA256_M24_H25
 *			* LMS_SHA256_M32_H5
 *			* LMS_SHA256_M32_H10
 *			* LMS_SHA256_M32_H15
 *			* LMS_SHA256_M32_H20
 *			* LMS_SHA256_M32_H25
 *			* LMS_SHAKE_M24_H5
 *			* LMS_SHAKE_M24_H10
 *			* LMS_SHAKE_M24_H15
 *			* LMS_SHAKE_M24_H20
 *			* LMS_SHAKE_M24_H25
 *			* LMS_SHAKE_M32_H5
 *			* LMS_SHAKE_M32_H10
 *			* LMS_SHAKE_M32_H15
 *			* LMS_SHAKE_M32_H20
 *			* LMS_SHAKE_M32_H25
 * @var lmOtsMode [in] Applicable valid  LMOTS mode which is one NULL-terminated
 *		       string out of:
 *			* LMOTS_SHA256_N24_W1
 *			* LMOTS_SHA256_N24_W2
 *			* LMOTS_SHA256_N24_W4
 *			* LMOTS_SHA256_N24_W8
 *			* LMOTS_SHA256_N32_W1
 *			* LMOTS_SHA256_N32_W2
 *			* LMOTS_SHA256_N32_W4
 *			* LMOTS_SHA256_N32_W8
 *			* LMOTS_SHAKE_N24_W1
 *			* LMOTS_SHAKE_N24_W2
 *			* LMOTS_SHAKE_N24_W4
 *			* LMOTS_SHAKE_N24_W8
 *			* LMOTS_SHAKE_N32_W1
 *			* LMOTS_SHAKE_N32_W2
 *			* LMOTS_SHAKE_N32_W4
 *			* LMOTS_SHAKE_N32_W8
 * @var sigver_success [out] Is LMS signature verification with given
 *			     parameters successful (1) or whether it
 *			     failed (0).
 */
struct lms_sigver_data {
	struct buffer msg;
	struct buffer pub;
	struct buffer sig;
	struct buffer lmsMode;
	struct buffer lmOtsMode;
	uint32_t sigver_success;
};

/**
 * @brief Callback data structure that must be implemented by the backend. Some
 *	  callbacks only need to be implemented if the respective cipher support
 *	  shall be tested.
 *
 * All functions return 0 on success or != 0 on error. Note, the signature
 * verification callback @var lms_sigver shall return 0 if the signature
 * verification fails. Only if some general error is detected a return code
 * != must be returned.
 *
 * @var lms_sigver LMS signature verification
 */
struct lms_backend {
	int (*lms_sigver)(struct lms_sigver_data *data, flags_t parsed_flags);
};

void register_lms_impl(struct lms_backend *implementation);

#ifdef __cplusplus
}
#endif

#endif /* _PARSER_LMS_H */
