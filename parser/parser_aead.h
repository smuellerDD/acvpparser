/*
 * Copyright (C) 2017 - 2019, Stephan Mueller <smueller@chronox.de>
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

#ifndef _PARSER_AEAD_H
#define _PARSER_AEAD_H

#include "parser.h"
#include "parser_flags.h"

/**
 * @brief AEAD cipher data structure holding the data for the cipher
 *	  operations specified in aead_backend
 *
 * @param key [in] Symmetric key for cipher operation in binary form
 * @param iv [in/out] IV for the cipher operation in binary form. It may be
 *		      empty for ciphers that do not support IVs (like AES-ECB or
 *		      AES-KW). For GCM with internal IV generation, the backend
 *		      must allocate the buffer, and fill it appropriately.
 * @param ivlen [in] If @param iv is NULL, but @param ivlen is set, the
 *		     cipher implementation is requested to invoke GCM with
 *		     internal IV generation. The IV of the given length shall
 *		     be generated. The size is given in bits.
 * @param assoc [in] Buffer holding the associated authenticated data.
 * @param tag [in/out] Buffer holding the tag value. This value contains NULL
 *		       for encryption operations. The backend must allocate the
 *		       buffer of the size given in @param taglen. This buffer
 *		       released by the parser. For decryption, this buffer
 *		       contains the tag value to be used for decryption.
 * @param taglen [in] For encryption, this value specifies the size of the
 *		      tag that shall be created. The value is in bits. This
 *		      value is irrelevant for decryption.
 * @param cipher [in] Cipher specification as defined in cipher_definitions.h
 * @param ptlen [in] Length of plaintext (for decryption, this is the expected)
 *		     data length.
 * @param data [in/out] Buffer with input data that is also expected to hold
 *			the result data. Note, this buffer will
 *			receive the resulting data from the decryption operation
 *			without tag or AAD.
 * @param integrity_error [out] This variable is to be filled by the backend
 *				during a decryption operation to indicate
 *				whether the decryption was successful (0 value)
 *				or whether an integrity error occurred (value
 *				of 1). Note, in this case, the @param data
 *				buffer should be released.
 * @param priv [storage] This pointer allows the backend to store private data
 *			 like a pointer to a cipher handle allocated during
 *			 the init call and used during update or fini calls.
 *			 The backend must deallocate the resources during fini
 *			 call.
 */
struct aead_data {
	struct buffer key;
	struct buffer iv;
	uint32_t ivlen;
	struct buffer assoc;
	struct buffer tag;
	uint32_t taglen;
	uint64_t cipher;
	uint32_t ptlen;
	struct buffer data;
	uint32_t integrity_error;
	void *priv;
};

/**
 * @brief Callback data structure that must be implemented by the backend. Some
 *	  callbacks only need to be implemented if the respective cipher support
 *	  shall be tested.
 *
 * All functions return 0 on success or != 0 on error. Note, if an
 * authenticating cipher returns an integrity error during decryption, the data
 * buffer with the return value must be 0 and the @param integrity_error
 * must be set appropriately.
 *
 * @param gcm_encrypt Callback implementing the GCM encrypt operation using the
 *		      @param data buffer. The @param parsed_flags point to
 *		      flags specified in parser_flags.h.
 * @param gcm_decrypt Callback implementing the GCM decrypt operation using the
 *		      @param data buffer. The @param parsed_flags point to flags
 *		      specified in parser_flags.h.
 *
 * @param ccm_encrypt Callback implementing the CCM encrypt operation using the
 *		      @param data buffer. The @param parsed_flags point to
 *		      flags specified in parser_flags.h.
 * @param ccm_decrypt Callback implementing the CCM decrypt operation using the
 *		      @param data buffer. The @param parsed_flags point to flags
 *		      specified in parser_flags.h.
 */
struct aead_backend {
	int (*gcm_encrypt)(struct aead_data *data, flags_t parsed_flags);
	int (*gcm_decrypt)(struct aead_data *data, flags_t parsed_flags);

	int (*ccm_encrypt)(struct aead_data *data, flags_t parsed_flags);
	int (*ccm_decrypt)(struct aead_data *data, flags_t parsed_flags);
};

void register_aead_impl(struct aead_backend *implementation);

#endif /* _PARSER_AEAD_H */
