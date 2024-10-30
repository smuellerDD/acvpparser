/*************************************************************************
* Copyright (C) 2024 Intel Corporation
*
* Licensed under the Apache License,  Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* 	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law  or agreed  to  in  writing,  software
* distributed under  the License  is  distributed  on  an  "AS IS"  BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the  specific  language  governing  permissions  and
* limitations under the License.
*************************************************************************/

#include "ippcp.h"
#include "backend_common.h"
#include "backend_ippcrypto_common.h"

/************************************************************************************************
 * Symmetric cipher interface functions - AES-CBC, AES-CBC_CS1/2/3, AES-CTR, AES-OFB, AES_OFB128
 ************************************************************************************************/
static Ipp8u savedIV[32];
static int ippcp_mct_init(struct sym_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

    IppStatus sts = ippStsNoErr;
	int ret = 0;

    BUFFER_INIT(rawCtx)
    int ctx_size;
    if(data->cipher == ACVP_XTS) {
        /* init context */
        sts = ippsAES_XTSGetSize(&ctx_size);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_XTSGetSize")

        CKINT(alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &rawCtx));
        IppsAES_XTSSpec* spec = (IppsAES_XTSSpec*)(IPP_ALIGNED_PTR(rawCtx.buf, IPPCP_DATA_ALIGNMENT));
        sts = ippsAES_XTSInit(data->key.buf, IPPCP_BYTES2BITS(data->key.len), data->data_len_bits, spec, ctx_size);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_XTSInit")
    }
    else {
        /* init context */
        sts = ippsAESGetSize(&ctx_size);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAESGetSize")

        CKINT(alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &rawCtx));
        IppsAESSpec* spec = (IppsAESSpec*)(IPP_ALIGNED_PTR(rawCtx.buf, IPPCP_DATA_ALIGNMENT));

        sts = ippsAESInit(data->key.buf, data->key.len, spec, ctx_size);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAESInit")

        memcpy(savedIV, data->iv.buf, data->iv.len);
    }
	data->priv = rawCtx.buf;

out:
	return ret;
}

static int ippcp_mct_update(struct sym_data *data, flags_t parsed_flags)
{
    IppStatus sts = ippStsNoErr;
	int ret = 0;

    IppsAESSpec* spec = NULL;
    IppsAES_XTSSpec* xtsSpec = NULL;

    if(data->cipher == ACVP_XTS) {
        xtsSpec = (IppsAES_XTSSpec*)(IPP_ALIGNED_PTR(data->priv, IPPCP_DATA_ALIGNMENT));
    }
    else {
        spec = (IppsAESSpec*)(IPP_ALIGNED_PTR(data->priv, IPPCP_DATA_ALIGNMENT));
    }

    BUFFER_INIT(cipherTxt)
    alloc_buf(data->data.len, &cipherTxt);
    memcpy(cipherTxt.buf, data->data.buf, data->data.len);

    int bitLenLeft = data->data_len_bits;
    int dataUnitByteLen = IPPCP_BITS2BYTES(data->xts_data_unit_len);
    int procBitLen;

    if (parsed_flags & FLAG_OP_ENC) {
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");
        switch(data->cipher) {
            case  ACVP_CBC: sts = ippsAESEncryptCBC(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CBC_CS1: sts = ippsAESEncryptCBC_CS1(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CBC_CS2: sts = ippsAESEncryptCBC_CS2(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CBC_CS3: sts = ippsAESEncryptCBC_CS3(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CFB128: sts = ippsAESEncryptCFB(data->data.buf, data->data.buf, data->data.len, data->iv.len , spec, data->iv.buf); break;
            case  ACVP_CTR: sts = ippsAESEncryptCTR(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf, data->iv.len); break;
            case  ACVP_OFB: sts = ippsAESEncryptOFB(data->data.buf, data->data.buf, data->data.len, data->iv.len, spec, data->iv.buf); break;
            case  ACVP_XTS: {
                int position = 0;
                while(bitLenLeft > 0 && sts == ippStsNoErr) {
                    procBitLen = (bitLenLeft > (int)data->xts_data_unit_len)? (int)data->xts_data_unit_len : bitLenLeft;
                    Ipp8u* currentData = ((Ipp8u*)data->data.buf) + dataUnitByteLen*position;
                    sts = ippsAES_XTSEncrypt(currentData, currentData, procBitLen, xtsSpec, data->iv.buf, position);
                    bitLenLeft -= procBitLen;
                    position++;
                }
                break;
            }
            default: break;
        }

        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAESEncrypt")
        logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "ciphertext");

        // Special handling for OFB mode
        if(data->cipher != ACVP_OFB && data->cipher != ACVP_XTS)
            memcpy(data->iv.buf, data->data.buf, data->iv.len);
	}
    else {
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "ciphertext");
        switch(data->cipher) {
            case  ACVP_CBC: sts = ippsAESDecryptCBC(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CBC_CS1: sts = ippsAESDecryptCBC_CS1(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CBC_CS2: sts = ippsAESDecryptCBC_CS2(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CBC_CS3: sts = ippsAESDecryptCBC_CS3(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf); break;
            case  ACVP_CFB128: sts = ippsAESDecryptCFB(data->data.buf, data->data.buf, data->data.len, data->iv.len , spec, data->iv.buf); break;
            case  ACVP_CTR: sts = ippsAESDecryptCTR(data->data.buf, data->data.buf, data->data.len, spec, data->iv.buf, data->iv.len); break;
            case  ACVP_OFB: sts = ippsAESDecryptOFB(data->data.buf, data->data.buf, data->data.len, data->iv.len, spec, data->iv.buf); break;
            case  ACVP_XTS: {
                const int aesXtsStartBlock = 0;
                sts = ippsAES_XTSDecrypt(data->data.buf, data->data.buf,  data->xts_data_unit_len, xtsSpec, data->iv.buf, aesXtsStartBlock);
                break;
            }
            default: break;
        }

        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAESDecrypt")
		logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");

        // Special handling for OFB mode
        if(data->cipher != ACVP_OFB && data->cipher != ACVP_XTS)
            memcpy(data->iv.buf, cipherTxt.buf, data->iv.len);
	}

out:
    free_buf(&cipherTxt);

	return ret;
}

static int ippcp_mct_fini(struct sym_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;
	(void)data;

    if(data->cipher != ACVP_XTS) {
        memcpy(data->iv.buf, savedIV, data->iv.len);
    }

    free(data->priv);
    data->priv = NULL;

	return 0;
}

static int ippcp_crypt(struct sym_data *data, flags_t parsed_flags)
{
	int ret = 0;

	ret = ippcp_mct_init(data, parsed_flags);
    CKINT_LOG(ret, "Error in ippcp_mct_init")
	ret = ippcp_mct_update(data, parsed_flags);
    CKINT_LOG(ret, "Error in ippcp_mct_update")
	ret = ippcp_mct_fini(data, parsed_flags);
    CKINT_LOG(ret, "Error in ippcp_mct_fini")

out:
	return ret;
}

static struct sym_backend ippcp_sym =
{
	ippcp_crypt,		/* encrypt */
	ippcp_crypt,		/* decrypt */
	ippcp_mct_init,		/* mct_init */
	ippcp_mct_update,	/* mct_update */
	ippcp_mct_fini,		/* mct_fini */
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_sym_backend)
static void ippcp_sym_backend(void)
{
	register_sym_impl(&ippcp_sym);
}

/**********************************************************
 * Symmetric cipher interface functions - AES-CCM, AES-GCM
 **********************************************************/
static int ippcp_gcm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

    IppStatus sts = ippStsNoErr;
	int ret = 0;

 	uint32_t tagByteLen = IPPCP_BITS2BYTES(data->taglen);
	alloc_buf(tagByteLen, &data->tag);

    int ctx_size;
    sts = ippsAES_GCMGetSize(&ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMGetSize")

    BUFFER_INIT(gcmCtx)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &gcmCtx);
    IppsAES_GCMState* state = (IppsAES_GCMState*)(IPP_ALIGNED_PTR(gcmCtx.buf, IPPCP_DATA_ALIGNMENT));

    sts = ippsAES_GCMInit(data->key.buf, data->key.len, state, ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMInit")

    sts = ippsAES_GCMStart(data->iv.buf, data->iv.len, data->assoc.buf, data->assoc.len, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMStart")

    if(data->data.buf != NULL) {
        logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");
        sts = ippsAES_GCMEncrypt(data->data.buf, data->data.buf, data->data.len, state);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMEncrypt")
    }

    sts = ippsAES_GCMGetTag(data->tag.buf, tagByteLen, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMGetTag")

out:
    free_buf(&gcmCtx);
	return ret;
}

static int ippcp_gcm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

    IppStatus sts = ippStsNoErr;
	int ret = 0;

 	uint32_t tagByteLen = IPPCP_BITS2BYTES(data->taglen);

    int ctx_size;
    sts = ippsAES_GCMGetSize(&ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMGetSize")

    BUFFER_INIT(gcmCtx)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &gcmCtx);
    IppsAES_GCMState* state = (IppsAES_GCMState*)(IPP_ALIGNED_PTR(gcmCtx.buf, IPPCP_DATA_ALIGNMENT));

    sts = ippsAES_GCMInit(data->key.buf, data->key.len, state, ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMInit")

    sts = ippsAES_GCMStart(data->iv.buf, data->iv.len, data->assoc.buf, data->assoc.len, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMStart")

    logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");
    if(data->data.buf != NULL) {
        sts = ippsAES_GCMDecrypt(data->data.buf, data->data.buf, data->data.len, state);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMDecrypt")
    }

    BUFFER_INIT(ippcpTag)
    alloc_buf(tagByteLen, &ippcpTag);

    sts = ippsAES_GCMGetTag(ippcpTag.buf, tagByteLen, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_GCMGetTag")

    data->integrity_error = 0;
    if(memcmp(ippcpTag.buf, data->tag.buf, tagByteLen)) {
        data->integrity_error = 1;
    }

out:
    free_buf(&ippcpTag);
    free_buf(&gcmCtx);
	return ret;
}

static int ippcp_ccm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

    IppStatus sts = ippStsNoErr;
	int ret = 0;

 	uint32_t tagByteLen = IPPCP_BITS2BYTES(data->taglen);
	alloc_buf(tagByteLen, &data->tag);

    int ctx_size;
    sts = ippsAES_CCMGetSize(&ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMGetSize")

    BUFFER_INIT(ccmCtx)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &ccmCtx);
    IppsAES_CCMState* state = (IppsAES_CCMState*)(IPP_ALIGNED_PTR(ccmCtx.buf, IPPCP_DATA_ALIGNMENT));

    sts = ippsAES_CCMInit(data->key.buf, data->key.len, state, ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMInit")

    sts = ippsAES_CCMMessageLen(data->data.len, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMMessageLen")

    sts = ippsAES_CCMTagLen(tagByteLen, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMTagLen")

    sts = ippsAES_CCMStart(data->iv.buf, data->iv.len, data->assoc.buf, data->assoc.len, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMStart")
    logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");

    if(data->data.buf != NULL) {
        sts = ippsAES_CCMEncrypt(data->data.buf, data->data.buf, data->data.len, state);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMEncrypt")
    }

    sts = ippsAES_CCMGetTag(data->tag.buf, tagByteLen, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMGetTag")

out:
    free_buf(&ccmCtx);
	return ret;
}

static int ippcp_ccm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

    IppStatus sts = ippStsNoErr;
	int ret = 0;

 	uint32_t tagByteLen = IPPCP_BITS2BYTES(data->taglen);

    int ctx_size;
    sts = ippsAES_CCMGetSize(&ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMGetSize")

    BUFFER_INIT(ccmCtx)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &ccmCtx);
    IppsAES_CCMState* state = (IppsAES_CCMState*)(IPP_ALIGNED_PTR(ccmCtx.buf, IPPCP_DATA_ALIGNMENT));

    sts = ippsAES_CCMInit(data->key.buf, data->key.len, state, ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMInit")

    sts = ippsAES_CCMMessageLen(data->data.len, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMMessageLen")

    sts = ippsAES_CCMTagLen(tagByteLen, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMTagLen")

    sts = ippsAES_CCMStart(data->iv.buf, data->iv.len, data->assoc.buf, data->assoc.len, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMStart")

    if(data->data.buf != NULL) {
        logger_binary(LOGGER_DEBUG, data->data.buf, data->data.len, "plaintext");
        sts = ippsAES_CCMDecrypt(data->data.buf, data->data.buf, data->data.len, state);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMDecrypt")
    }

    BUFFER_INIT(ippcpTag)
    alloc_buf(tagByteLen, &ippcpTag);

    sts = ippsAES_CCMGetTag(ippcpTag.buf, tagByteLen, state);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CCMGetTag")

    data->integrity_error = 0;
    if(memcmp(ippcpTag.buf, data->tag.buf, tagByteLen)) {
        data->integrity_error = 1;
    }

out:
    free_buf(&ippcpTag);
    free_buf(&ccmCtx);
	return ret;
}

static struct aead_backend ippcp_aead =
{
	ippcp_gcm_encrypt,	/* gcm_encrypt */
	ippcp_gcm_decrypt,	/* gcm_decrypt */
	ippcp_ccm_encrypt,	/* ccm_encrypt */
	ippcp_ccm_decrypt,	/* ccm_decrypt */
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_aead_backend)
static void ippcp_aead_backend(void)
{
	register_aead_impl(&ippcp_aead);
}


/************************************************
 * CMAC/HMAC cipher interface functions
 ************************************************/
static int ippcp_hmac_generate(struct hmac_data *data)
{
    IppStatus sts = ippStsNoErr;
	int ret = 0;

    int ctx_size;
    sts = ippsHMACGetSize_rmf(&ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHMACGetSize_rmf")

    BUFFER_INIT(hmacCtx)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &hmacCtx);

    int macByteLen = IPPCP_BITS2BYTES(data->maclen);
    BUFFER_INIT(tag1)
    alloc_buf(macByteLen, &tag1);
    BUFFER_INIT(tag2)
    alloc_buf(macByteLen, &tag2);

    IppsHMACState_rmf* pCtx = (IppsHMACState_rmf*)(IPP_ALIGNED_PTR(hmacCtx.buf, IPPCP_DATA_ALIGNMENT));

    sts = ippsHMACInit_rmf(data->key.buf, data->key.len, pCtx, ippsHashMethod_SHA256());
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHMACInit_rmf")

    sts = ippsHMACUpdate_rmf(data->msg.buf, data->msg.len, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHMACUpdate_rmf")

    sts = ippsHMACGetTag_rmf(tag1.buf, macByteLen, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHMACGetTag_rmf")

    sts = ippsHMACFinal_rmf(tag2.buf, macByteLen, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHMACFinal_rmf")

    alloc_buf(macByteLen, &data->mac);
    if(!memcmp(tag1.buf, tag2.buf, macByteLen)) {
        memcpy(data->mac.buf, tag1.buf, macByteLen);
    }

out:
    free_buf(&tag1);
    free_buf(&tag2);
    free_buf(&hmacCtx);
    return ret;
}

static int ippcp_cmac_generate(struct hmac_data *data)
{
    IppStatus sts = ippStsNoErr;
	int ret = 0;

    int ctx_size;
    sts = ippsAES_CMACGetSize(&ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CMACGetSize")

    BUFFER_INIT(cmacCtx)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &cmacCtx);

    int macByteLen = IPPCP_BITS2BYTES(data->maclen);
    BUFFER_INIT(tag1)
    alloc_buf(macByteLen, &tag1);
    BUFFER_INIT(tag2)
    alloc_buf(macByteLen, &tag2);

    IppsAES_CMACState* pCtx = (IppsAES_CMACState*)(IPP_ALIGNED_PTR(cmacCtx.buf, IPPCP_DATA_ALIGNMENT));

    sts = ippsAES_CMACInit(data->key.buf, data->key.len, pCtx, ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CMACInit")

    sts = ippsAES_CMACUpdate(data->msg.buf, data->msg.len, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CMACUpdate")

    sts = ippsAES_CMACGetTag(tag1.buf, macByteLen, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CMACGetTag")

    sts = ippsAES_CMACFinal(tag2.buf, macByteLen, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsAES_CMACFinal")

    alloc_buf(macByteLen, &data->mac);
    if(!memcmp(tag1.buf, tag2.buf, macByteLen)) {
        memcpy(data->mac.buf, tag1.buf, macByteLen);
    }
    else {
		ret = EINVAL;
    }

out:
    free_buf(&tag1);
    free_buf(&tag2);
    free_buf(&cmacCtx);
    return ret;
}

static int ippcp_mac_generate(struct hmac_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;
	int ret = 0;

    switch(data->cipher) {
	case ACVP_AESCMAC: {
		return ippcp_cmac_generate(data);
        break;
    }
    case ACVP_HMACSHA2_256: {
		return ippcp_hmac_generate(data);
        break;
    }
	default: {
		ret = EINVAL;
        break;
    }
    }

	return ret;
}

static struct hmac_backend ippcp_mac =
{
	ippcp_mac_generate,
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_mac_backend)
static void ippcp_mac_backend(void)
{
	register_hmac_impl(&ippcp_mac);
}

/************************************************
 * HASH interface functions
 ************************************************/
static int ippcp_hash_generate(struct sha_data *data, flags_t parsed_flags)
{
	(void)parsed_flags;

    IppStatus sts = ippStsNoErr;
	int ret = 0;

    int ctx_size;
    sts = ippsHashGetSize_rmf(&ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHashGetSize_rmf")

    BUFFER_INIT(hashCtx)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &hashCtx);

    int macByteLen = 0;
    IppsHashMethod* method = NULL;

    switch (data->cipher) {
        case ACVP_SHA256: method = (IppsHashMethod*)ippsHashMethod_SHA256(); macByteLen = 32; break;
        case ACVP_SHA384: method = (IppsHashMethod*)ippsHashMethod_SHA384(); macByteLen = 48; break;
        case ACVP_SHA512: method = (IppsHashMethod*)ippsHashMethod_SHA512(); macByteLen = 64; break;
        default: break;
    }

    BUFFER_INIT(tag1)
    alloc_buf(macByteLen, &tag1);
    BUFFER_INIT(tag2)
    alloc_buf(macByteLen, &tag2);
    BUFFER_INIT(tag3)
    alloc_buf(macByteLen, &tag3);

    IppsHashState_rmf* pCtx = (IppsHashState_rmf*)(IPP_ALIGNED_PTR(hashCtx.buf, IPPCP_DATA_ALIGNMENT));

    sts = ippsHashInit_rmf(pCtx, method);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHashInit_rmf")

    sts = ippsHashUpdate_rmf(data->msg.buf, data->msg.len, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHashUpdate_rmf")

    sts = ippsHashGetTag_rmf(tag1.buf, macByteLen, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHashGetTag_rmf")

    sts = ippsHashFinal_rmf(tag2.buf, pCtx);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHashFinal_rmf")

    sts = ippsHashMessage_rmf(data->msg.buf, data->msg.len, tag3.buf, method);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsHashMessage_rmf")

    alloc_buf(macByteLen, &data->mac);
    if(!memcmp(tag1.buf, tag2.buf, macByteLen) || !memcmp(tag1.buf, tag3.buf, macByteLen)) {
        memcpy(data->mac.buf, tag1.buf, macByteLen);
    }
    else {
		ret = EINVAL;
    }

out:
    free_buf(&tag1);
    free_buf(&tag2);
    free_buf(&tag3);
    return ret;
}

static struct sha_backend ippcp_sha =
{
	ippcp_hash_generate,	/* hash_generate */
	NULL
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_sha_backend)
static void ippcp_sha_backend(void)
{
	register_sha_impl(&ippcp_sha);
}

/************************************************
 * RSA interface functions
 ************************************************/
typedef struct  {
    IppsRSAPrivateKeyState* pPrvKey;
    IppsRSAPublicKeyState* pPubKey;
} cpRsaKeyPair;

static int ippcp_rsa_keygen_en(struct buffer *ebuf, uint32_t modulus, void **privkey, struct buffer *nbuf)
{
    (void)ebuf; (void)nbuf;

    IppStatus sts = ippStsNoErr;
    int ret = 0;

    int pBitSize = modulus / 2;
    int qBitSize = modulus / 2;
    int modulusWordSize = modulus >> 3;

    // Fixed public exponent is supported
    const int pubExpWordSize = 1;
    Ipp32u e0_data = 0x10001;

    /* Initialize private key */
    int privKeyByteSize = 0;
    sts = ippsRSA_GetSizePrivateKeyType2(pBitSize, qBitSize, &privKeyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetSizePrivateKeyType2")
    BUFFER_INIT(buffPrivKey)
    alloc_buf(privKeyByteSize + IPPCP_DATA_ALIGNMENT, &buffPrivKey);
    IppsRSAPrivateKeyState* pPrvKey = (IppsRSAPrivateKeyState*)buffPrivKey.buf;
    sts = ippsRSA_InitPrivateKeyType2(pBitSize, qBitSize, pPrvKey, privKeyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_InitPrivateKeyType2")

    /* Initialize BigNumber-s */
    int e0ByteSize;
    sts = ippsBigNumGetSize(pubExpWordSize, &e0ByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffE0)
    alloc_buf(e0ByteSize + IPPCP_DATA_ALIGNMENT, &buffE0);
    IppsBigNumState* E0 = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffE0.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippcp_init_set_bn(E0, pubExpWordSize,  ippBigNumPOS, &e0_data,  pubExpWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    int nByteSize;
    sts = ippsBigNumGetSize(modulusWordSize, &nByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffN)
    alloc_buf(nByteSize + IPPCP_DATA_ALIGNMENT, &buffN);
    IppsBigNumState* N = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffN.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(modulusWordSize, N);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    int eByteSize;
    sts = ippsBigNumGetSize(pubExpWordSize, &eByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffE)
    alloc_buf(eByteSize + IPPCP_DATA_ALIGNMENT, &buffE);
    IppsBigNumState* E = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffE.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(pubExpWordSize, E);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    int dByteSize;
    sts = ippsBigNumGetSize(modulusWordSize, &dByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffD)
    alloc_buf(dByteSize + IPPCP_DATA_ALIGNMENT, &buffD);
    IppsBigNumState* D = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffD.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(modulusWordSize, D);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    /* Generate key pair */
    int size;
    sts = ippsRSA_GetBufferSizePrivateKey(&size, pPrvKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetBufferSizePrivateKey")
    BUFFER_INIT(buffScratch)
    alloc_buf(size + IPPCP_DATA_ALIGNMENT, &buffScratch);

    sts = ippsPrimeGetSize(modulus, &size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsPrimeGetSize")
    BUFFER_INIT(buffPrimeGen)
    alloc_buf(size + IPPCP_DATA_ALIGNMENT, &buffPrimeGen);
    IppsPrimeState* pPrimeG = (IppsPrimeState*)( buffPrimeGen.buf );
    sts = ippsPrimeInit(modulus, pPrimeG);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsPrimeInit")

    IppsPRNGState* pPRNG = newPRNG();

    for(int n = 0; n < 10; n++) {
        for(int m = 0; m < 10; m++) {
            sts = ippcp_init_set_bn(E0, pubExpWordSize,  ippBigNumPOS, &e0_data,  pubExpWordSize);
            CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

            sts = ippsRSA_GenerateKeys(E0, N, E, D, pPrvKey, buffScratch.buf,
                                       0, pPrimeG, ippsPRNGenRDRAND, pPRNG);
            if(ippStsInsufficientEntropy == sts) {
			    logger(LOGGER_WARN, "ippStsInsufficientEntropy\n");
                continue;
            }
            else {
                if(sts != ippStsNoErr) { return sts;}
            }
        }

        if(ippStsNoErr == sts) {
            int bitSize;
            ippsRef_BN(0, &bitSize, NULL, N);
            if(bitSize == (int)modulus) {
			    logger(LOGGER_DEBUG, "modulus bitsize: %d\n ", bitSize);
                break;
            }
            else
			    logger(LOGGER_WARN, "%d modulus generated instead of %d\n ", bitSize, modulus);
        }
    }

    /* Initialize public key */
    int pubKeySize;
    ippsRSA_GetSizePublicKey(modulus, 17, &pubKeySize);
    BUFFER_INIT(buffPubKey)
    CKINT(alloc_buf(pubKeySize + IPPCP_DATA_ALIGNMENT, &buffPubKey));
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)buffPubKey.buf; // ALIGNEMENT here!
    sts = ippsRSA_InitPublicKey(modulus, 17, pPubKey, pubKeySize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_InitPublicKey")
    // set public key
    sts = ippsRSA_SetPublicKey(N, E, pPubKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_SetPublicKey")

    /* Propagate the generated key pair */
    cpRsaKeyPair* locKeyPair = (cpRsaKeyPair*)malloc(sizeof(cpRsaKeyPair));
    locKeyPair->pPrvKey = pPrvKey;
    locKeyPair->pPubKey = pPubKey;

    *privkey = locKeyPair;

out:
    free_buf(&buffE0);
    free_buf(&buffN);
    free_buf(&buffE);
    free_buf(&buffD);
    free_buf(&buffScratch);
    free_buf(&buffPrimeGen);

	return ret;
}

static int ippcp_rsa_siggen(struct rsa_siggen_data *data, flags_t parsed_flags)
{
    IppStatus sts = ippStsNoErr;
    int ret = 0;
    (void)parsed_flags;

    int modulusWordSize = data->modulus >> 3;
    int modulusByteSize = IPPCP_BITS2BYTES(data->modulus);
    const int pubExpWordSize = 1;

    cpRsaKeyPair* locKeyPair = (cpRsaKeyPair*)data->privkey;

    IppsRSAPrivateKeyState* pPrvKey = locKeyPair->pPrvKey;
    IppsRSAPublicKeyState* pPubKey  = locKeyPair->pPubKey;

    //calculate scratch buffer size
    int buffSizePubKey = 0;
    sts = ippsRSA_GetBufferSizePublicKey(&buffSizePubKey, pPubKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetBufferSizePublicKey")

    // private
    int buffSizePrivKey = 0;
    sts = ippsRSA_GetBufferSizePrivateKey(&buffSizePrivKey, pPrvKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetBufferSizePrivateKey")

    // resize buffer
    int signBuffSize = (buffSizePubKey > buffSizePrivKey) ? buffSizePubKey : buffSizePrivKey;
    BUFFER_INIT(pLocSignBuffer)
    CKINT(alloc_buf(signBuffSize + IPPCP_DATA_ALIGNMENT, &pLocSignBuffer));

    // set the necessary method
    IppsHashMethod* method = NULL;
    switch (data->cipher) {
	case ACVP_HMACSHA2_256:
	case ACVP_SHA256:
		method = (IppsHashMethod*)ippsHashMethod_SHA256_TT();
		break;
	case ACVP_HMACSHA2_384:
	case ACVP_SHA384:
		method = (IppsHashMethod*)ippsHashMethod_SHA384();
		break;
	case ACVP_HMACSHA2_512:
	case ACVP_SHA512:
		method = (IppsHashMethod*)ippsHashMethod_SHA512();
		break;
    }

    CKINT(alloc_buf(modulusByteSize, &data->sig));
    Ipp8u* salt = NULL;
    if(data->saltlen) {
        salt = malloc(data->saltlen);
    }

    // RSA sign
    if(parsed_flags &FLAG_OP_RSA_SIG_PKCS1PSS) {
        sts = ippsRSASign_PSS_rmf(data->msg.buf,data->msg.len, salt, data->saltlen, data->sig.buf, pPrvKey,
                                    pPubKey, method, pLocSignBuffer.buf);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSASign_PSS_rmf")
    }
    else {
        sts = ippsRSASign_PKCS1v15_rmf(data->msg.buf,data->msg.len, data->sig.buf, pPrvKey, pPubKey,
                                        method, pLocSignBuffer.buf);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSASign_PKCS1v15_rmf")
    }

    int eByteSize;
    sts = ippsBigNumGetSize(pubExpWordSize, &eByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffE)
    alloc_buf(eByteSize + IPPCP_DATA_ALIGNMENT, &buffE);
    IppsBigNumState* E = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffE.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(pubExpWordSize, E);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    int nByteSize;
    sts = ippsBigNumGetSize(modulusWordSize, &nByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffN)
    alloc_buf(nByteSize + IPPCP_DATA_ALIGNMENT, &buffN);
    IppsBigNumState* N = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffN.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(modulusWordSize, N);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    sts = ippsRSA_GetPublicKey(N, E, pPubKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetPublicKey")

    IppsBigNumSGN tmpSgn;
    int tmpSize;
    // Get E
    ippsRef_BN(NULL, &tmpSize, NULL, E);
    tmpSize = IPPCP_BITS2BYTES(tmpSize);
    alloc_buf(tmpSize, &data->e);
    sts = ippsGet_BN(&tmpSgn, &tmpSize, (Ipp32u*)data->e.buf, E);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGet_BN")

    // Get N
    ippsRef_BN(NULL, &tmpSize, NULL, N);
    (alloc_buf(IPPCP_BITS2BYTES(tmpSize), &data->n));
    BUFFER_INIT(tmpNNNN);
    alloc_buf(IPPCP_BITS2BYTES(tmpSize), &tmpNNNN);
    ippsRef_BN(&tmpSgn, &tmpSize, (Ipp32u**)&(tmpNNNN.buf), N);
    dataReverse(data->n.buf, (const char *)tmpNNNN.buf, IPPCP_BITS2BYTES(tmpSize));

out:
    free_buf(&buffN);
    free_buf(&buffE);
    free_buf(&pLocSignBuffer);
    if(salt) {
        free(salt);
    }

    return ret;
}

/* Supported public exponent value is 0x10001 */
static int ippcp_rsa_sigver(struct rsa_sigver_data *data, flags_t parsed_flags)
{
    IppStatus sts = ippStsNoErr;
    int ret = 0;

    int pubExpWordSize  = (data->e.len + 3) / 4;
    int modulusWordSize = (data->n.len + 3) / 4;
    int modulusBitSize  = IPPCP_BYTES2BITS(data->n.len);
    int pubExpBitSize   = IPPCP_BYTES2BITS(data->e.len);

    /* Initialize BigNumber-s */
    int eByteSize;
    sts = ippsBigNumGetSize(pubExpWordSize, &eByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")

    BUFFER_INIT(buffE)
    alloc_buf(eByteSize + IPPCP_DATA_ALIGNMENT, &buffE);
    IppsBigNumState* bnE = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffE.buf, IPPCP_DATA_ALIGNMENT));

    int nByteSize;
    sts = ippsBigNumGetSize(modulusWordSize, &nByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")

    BUFFER_INIT(buffN)
    alloc_buf(nByteSize + IPPCP_DATA_ALIGNMENT, &buffN);
    IppsBigNumState* bnN = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffN.buf, IPPCP_DATA_ALIGNMENT));

    BUFFER_INIT(reversedN)
    alloc_buf(data->n.len, &reversedN);
    dataReverse(/* pBuf = */reversedN.buf,/* str = */(const char*)data->n.buf, data->n.len);

    sts = ippcp_init_set_bn(bnE, pubExpWordSize,  ippBigNumPOS, (const Ipp32u *)data->e.buf,  pubExpWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")
    sts = ippcp_init_set_bn(bnN, modulusWordSize, ippBigNumPOS, (const Ipp32u *)reversedN.buf, modulusWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    /* Initialize public key */
    int pubKeyByteSize = 0;
    ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &pubKeyByteSize);
    BUFFER_INIT(buffPubKey)
    alloc_buf(pubKeyByteSize + IPPCP_DATA_ALIGNMENT, &buffPubKey);
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState*)(IPP_ALIGNED_PTR(buffPubKey.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsRSA_InitPublicKey(modulusBitSize, pubExpBitSize, pPubKey, pubKeyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_InitPublicKey")

    /* Set public and private keys */
    sts = ippsRSA_SetPublicKey(bnN, bnE, pPubKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_SetPublicKey")

    /* RSA signature and verification buffers */
    int buffSize = 0;
    sts = ippsRSA_GetBufferSizePublicKey(&buffSize, pPubKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetBufferSizePublicKey")

    BUFFER_INIT(buffWork)
    alloc_buf(buffSize + IPPCP_DATA_ALIGNMENT, &buffWork);
    Ipp8u* pLocVerifBuffer = (IPP_ALIGNED_PTR(buffWork.buf, IPPCP_DATA_ALIGNMENT));

    IppsHashMethod* method = NULL;

    switch (data->cipher) {
	case ACVP_HMACSHA2_256:
	case ACVP_SHA256:
		method = (IppsHashMethod*)ippsHashMethod_SHA256_TT();
		break;
	case ACVP_HMACSHA2_384:
	case ACVP_SHA384:
		method = (IppsHashMethod*)ippsHashMethod_SHA384();
		break;
	case ACVP_HMACSHA2_512:
	case ACVP_SHA512:
		method = (IppsHashMethod*)ippsHashMethod_SHA512();
		break;
    }

    /* RSA Signature Verification */
    int isValid = 1;
    if(parsed_flags & FLAG_OP_RSA_SIG_PKCS1PSS){
        sts = ippsRSAVerify_PSS_rmf(data->msg.buf,data->msg.len, data->sig.buf, &isValid, pPubKey,
                                    method, pLocVerifBuffer);
    }
    else{
        sts = ippsRSAVerify_PKCS1v15_rmf(data->msg.buf,data->msg.len, data->sig.buf, &isValid, pPubKey,
                                         method, pLocVerifBuffer);
    }

    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSAVerify_PSS_rmf or ippsRSAVerify_PKCS1v15_rmf")

    data->sig_result = 1;
    if(isValid == 0)  {
        data->sig_result = 0;
    }

out:
    free_buf(&buffE);
    free_buf(&buffN);
    free_buf(&reversedN);
    free_buf(&buffPubKey);
    free_buf(&buffWork);
	return ret;
}

static void ippcp_rsa_free_key(void *privkey)
{
    cpRsaKeyPair* locKeyPair = (cpRsaKeyPair*)privkey;

	if (locKeyPair) {
	    free(locKeyPair->pPrvKey);
	    free(locKeyPair->pPubKey);
        free(locKeyPair);
    }
}

static struct rsa_backend ippcp_rsa =
{
	NULL,                 /* rsa_keygen */
	ippcp_rsa_siggen,     /* rsa_siggen */
	ippcp_rsa_sigver,     /* rsa_sigver */
	NULL,                 /* rsa_keygen_prime */
	NULL,		          /* rsa_keygen_prov_prime */
    ippcp_rsa_keygen_en,  /* rsa_keygen_en*/
    ippcp_rsa_free_key,   /* rsa_free_key */
	NULL,
	NULL,
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_rsa_backend)
static void ippcp_rsa_backend(void)
{
	register_rsa_impl(&ippcp_rsa);
}

/********************************
 * RSA OAEP functions
 ********************************/
static int ippcp_rsa_kas_ifc_encrypt_common(struct kts_ifc_data *data, uint32_t *validation_success)
{
    (void)validation_success;

    IppStatus sts = ippStsNoErr;
    int ret = 0;

    struct kts_ifc_init_data *init = &data->u.kts_ifc_init;

    /* Get the necessary lengths */
    int modulusBitSize  = data->modulus;
    int modulusByteSize = IPPCP_BITS2BYTES(data->modulus);
    int modulusWordSize = (modulusBitSize + 31)/32;

    int pubExpByteSize  = init->e.len;
    int pubExpBitSize   = IPPCP_BYTES2BITS(pubExpByteSize);
    int pubExpWordSize  = (pubExpByteSize + 3)/4;

    int keyBitlen = data->keylen;
	struct buffer *dkm_p, *c_p;

    left_pad_buf(&init->n, data->modulus >> 3);
    if (!init->dkm.len) {
        alloc_buf(IPPCP_BITS2BYTES(keyBitlen), &init->dkm);
        RAND_bytes(init->dkm.buf, (int)init->dkm.len);

        /*
        * Ensure that in case of raw encryption, the value is
        * not too large.
        */
        init->dkm.buf[0] &= ~0x80;
    }
    dkm_p = &init->dkm; (void)dkm_p;
    c_p = &init->iut_c; (void)c_p;

    /* Initialize BigNumber-s */
    int nByteSize;
    sts = ippsBigNumGetSize(modulusWordSize, &nByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffN)
    alloc_buf(nByteSize + IPPCP_DATA_ALIGNMENT, &buffN);
    IppsBigNumState* bnN = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffN.buf, IPPCP_DATA_ALIGNMENT));

    BUFFER_INIT(reversedN)
    alloc_buf(modulusByteSize, &reversedN);
    dataReverse(/* pBuf = */reversedN.buf,/* str = */(const char*)init->n.buf, init->n.len);

    sts = ippcp_init_set_bn(bnN, modulusWordSize, ippBigNumPOS, (const Ipp32u *)reversedN.buf, modulusWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    int eByteSize;
    sts = ippsBigNumGetSize(pubExpWordSize, &eByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffE)
    alloc_buf(eByteSize + IPPCP_DATA_ALIGNMENT, &buffE);
    IppsBigNumState* bnE = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffE.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippcp_init_set_bn(bnE, pubExpWordSize,  ippBigNumPOS, (const Ipp32u *)init->e.buf, pubExpWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    /* Initialize public key */
    int pubKeyByteSize = 0;
    sts = ippsRSA_GetSizePublicKey(modulusBitSize, pubExpBitSize, &pubKeyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetSizePublicKey")
    BUFFER_INIT(buffPubKey)
    alloc_buf(pubKeyByteSize + IPPCP_DATA_ALIGNMENT, &buffPubKey);
    IppsRSAPublicKeyState* pPubKey = (IppsRSAPublicKeyState *)(IPP_ALIGNED_PTR(buffPubKey.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsRSA_InitPublicKey(modulusBitSize, pubExpBitSize, pPubKey, pubKeyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_InitPublicKey")

    /* Set public key */
    sts = ippsRSA_SetPublicKey(bnN, bnE, pPubKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_SetPublicKey")

    /* RSA encryption */
    int encBufSize;
    sts = ippsRSA_GetBufferSizePublicKey(&encBufSize, pPubKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_SetPublicKey")
    BUFFER_INIT(buffSgn)
    alloc_buf(encBufSize + IPPCP_DATA_ALIGNMENT, &buffSgn);
    Ipp8u* encScratchBuffer = (IPP_ALIGNED_PTR(buffSgn.buf, IPPCP_DATA_ALIGNMENT));

	alloc_buf(modulusByteSize, c_p);
    sts = ippsRSAEncrypt_OAEP_rmf(dkm_p->buf, dkm_p->len, NULL, 0, seed0, c_p->buf, pPubKey,
                                  ippsHashMethod_SHA256(), encScratchBuffer);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSAEncrypt_OAEP_rmf")

out:
    free_buf(&buffN);
    free_buf(&reversedN);
    free_buf(&buffE);
    free_buf(&buffPubKey);
    free_buf(&buffSgn);

    return ret;
}

static int ippcp_rsa_kas_ifc_set_key(IppsRSAPrivateKeyState *pPrivKey, struct buffer *n_buf,
                                     struct buffer *e_buf, struct buffer *d_buf,
                                     struct buffer *p_buf, struct buffer *q_buf,
                                     struct buffer *dmp1_buf, struct buffer *dmq1_buf,
                                     struct buffer *iqmp_buf)
{
    (void)e_buf; (void)p_buf; (void)q_buf; (void)dmp1_buf; (void)dmq1_buf; (void)iqmp_buf;

    IppStatus sts = ippStsNoErr;
    int ret = 0;

    int privExpByteSize = d_buf->len;
    int privExpWordSize = (privExpByteSize + 3)/4;

    int modulusByteSize = n_buf->len;
    int modulusWordSize = (modulusByteSize + 3)/4;

    /* Initialize BigNumber-s */
    int dByteSize;
    sts = ippsBigNumGetSize(privExpWordSize, &dByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffD)
    alloc_buf(dByteSize + IPPCP_DATA_ALIGNMENT, &buffD);
    BUFFER_INIT(reversedD)
    alloc_buf(modulusByteSize, &reversedD);
    dataReverse(/* pBuf = */reversedD.buf,/* str = */(const char*)d_buf->buf, d_buf->len);
    IppsBigNumState* bnD = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffD.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippcp_init_set_bn(bnD, privExpWordSize, ippBigNumPOS, (const Ipp32u *)reversedD.buf, privExpWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    int nByteSize;
    sts = ippsBigNumGetSize(modulusWordSize, &nByteSize);
    BUFFER_INIT(buffN)
    alloc_buf(nByteSize + IPPCP_DATA_ALIGNMENT, &buffN);
    IppsBigNumState* bnN = (IppsBigNumState *)(IPP_ALIGNED_PTR(buffN.buf, IPPCP_DATA_ALIGNMENT));
    BUFFER_INIT(reversedN)
    alloc_buf(modulusByteSize, &reversedN);
    dataReverse(/* pBuf = */reversedN.buf,/* str = */(const char*)n_buf->buf, n_buf->len);
    sts = ippcp_init_set_bn(bnN, modulusWordSize, ippBigNumPOS, (const Ipp32u *)reversedN.buf, modulusWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    /* Set private key */
    sts = ippsRSA_SetPrivateKeyType1(bnN, bnD, pPrivKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_SetPrivateKeyType1")

out:
    free_buf(&buffD);
    free_buf(&reversedD);
    free_buf(&buffN);
    free_buf(&reversedN);

	return ret;
}

static int ippcp_rsa_kas_ifc_decrypt_common(struct kts_ifc_data *data, int validation)
{
    (void)validation;
    IppStatus sts = ippStsNoErr;
	int ret = 0;

    struct kts_ifc_resp_data *resp = &data->u.kts_ifc_resp;
	struct buffer *c_p=&resp->c;

    left_pad_buf(&resp->n, data->modulus >> 3);

    int privExpByteSize = resp->n.len;
    int privExpBitSize  = IPPCP_BYTES2BITS(privExpByteSize);
    int modulusByteSize = resp->n.len;
    int modulusBitSize  = IPPCP_BYTES2BITS(modulusByteSize);

    /* Initialize private key */
    int privKeyByteSize = 0;
    ippsRSA_GetSizePrivateKeyType1(modulusBitSize, privExpBitSize, &privKeyByteSize);
    BUFFER_INIT(buffPrivKey)
    alloc_buf(privKeyByteSize + IPPCP_DATA_ALIGNMENT, &buffPrivKey);
    IppsRSAPrivateKeyState* pPrivKey = (IppsRSAPrivateKeyState*)(IPP_ALIGNED_PTR(buffPrivKey.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsRSA_InitPrivateKeyType1(modulusBitSize, privExpBitSize, pPrivKey, privKeyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_InitPrivateKeyType1")

    ret = ippcp_rsa_kas_ifc_set_key(pPrivKey, &resp->n, &resp->e, &resp->d, &resp->p,
                                    &resp->q,&resp->dmp1, &resp->dmq1, &resp->iqmp);
    CKNULL_LOG((ret == 0), sts, "Error in ippcp_rsa_kas_ifc_set_key")

	size_t outlen = data->modulus;
    size_t keylen = (data->keylen) ? data->keylen : data->modulus;
	BUFFER_INIT(tmp);
	alloc_buf(outlen, &tmp);
    int tmp_len = (int)tmp.len;

    /* RSA decryption */
    int decBufSize;
    sts = ippsRSA_GetBufferSizePrivateKey(&decBufSize, pPrivKey);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetBufferSizePrivateKey")
    BUFFER_INIT(buffScratch)
    alloc_buf(decBufSize + IPPCP_DATA_ALIGNMENT, &buffScratch);
    Ipp8u* decScratchBuffer = IPP_ALIGNED_PTR(buffScratch.buf, IPPCP_DATA_ALIGNMENT);

    sts = ippsRSADecrypt_OAEP_rmf(c_p->buf, NULL, 0, tmp.buf, &tmp_len, pPrivKey,
                                  ippsHashMethod_SHA256(), decScratchBuffer);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRSA_GetBufferSizePrivateKey")

    CKNULL_LOG((tmp.len >= IPPCP_BITS2BYTES(keylen)), -EINVAL, "RSA decrypted data has insufficient size")

    alloc_buf(IPPCP_BITS2BYTES(keylen), &resp->dkm);
    memcpy(resp->dkm.buf, tmp.buf, resp->dkm.len);

out:
    free_buf(&buffPrivKey);
	free_buf(&tmp);
    free_buf(&buffScratch);

	return ret;
}

static int ippcp_kts_ifc_generate(struct kts_ifc_data *data,
				    flags_t parsed_flags)
{
	int ret = 0;
    (void)data; (void)parsed_flags;
    if ((parsed_flags & FLAG_OP_KAS_ROLE_INITIATOR) &&
	    (parsed_flags & FLAG_OP_AFT)) {
		ippcp_rsa_kas_ifc_encrypt_common(data, NULL);
    }
    else if ((parsed_flags & FLAG_OP_KAS_ROLE_RESPONDER) &&
		   (parsed_flags & FLAG_OP_AFT)) {
        ippcp_rsa_kas_ifc_decrypt_common(data, 0);
    }

	return ret;
}

static struct kts_ifc_backend ippcp_kts_ifc =
{
	ippcp_kts_ifc_generate,
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_kts_ifc_backend)
static void ippcp_kts_ifc_backend(void)
{
	register_kts_ifc_impl(&ippcp_kts_ifc);
}

/************************************************
 * ECDSA interface functions
 ************************************************/
typedef IppStatus (*InitStdFunction_t)(const IppsGFpState*, IppsGFpECState*);

static int ippcp_ecdsa_keygen_en(uint64_t curve, struct buffer *Qx_buf, struct buffer *Qy_buf, void **privkey)
{
    IppStatus sts = ippStsNoErr;
    int ret = 0;

    int primeBitSize = 0, primeWordSize=0;
    const IppsGFpMethod *pGFpMethod = NULL;
    InitStdFunction_t initStdF      = NULL;
    switch (curve & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
            primeBitSize = 256;
            primeWordSize = 8;
			pGFpMethod = ippsGFpMethod_p256r1();
            initStdF = ippsGFpECInitStd256r1;
			break;
		case ACVP_NISTP521:
            primeBitSize = 521;
            primeWordSize = 17;
			pGFpMethod = ippsGFpMethod_p521r1();
            initStdF = ippsGFpECInitStd521r1;
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
	}

    int ctx_size = 0;
    sts = ippsGFpGetSize(primeBitSize, &ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpGetSize")
    BUFFER_INIT(buffGFp)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &buffGFp);
    IppsGFpState* pGF = (IppsGFpState*)(IPP_ALIGNED_PTR(buffGFp.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsGFpInitFixed(primeBitSize, pGFpMethod, pGF);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpInitFixed")

    /* GFpEC context */
    ctx_size = 0;
    sts = ippsGFpECGetSize(pGF, &ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECGetSize")
    BUFFER_INIT(buffGFpEC)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &buffGFpEC);
    IppsGFpECState* pEC = (IppsGFpECState*)(IPP_ALIGNED_PTR(buffGFpEC.buf, IPPCP_DATA_ALIGNMENT));
    sts = initStdF(pGF, pEC);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in initStdF")

    /* Private key */
    int privKeyCtxByteSize;
    sts = ippsBigNumGetSize(primeWordSize, &privKeyCtxByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(bufPriv)
    alloc_buf(privKeyCtxByteSize + IPPCP_DATA_ALIGNMENT, &bufPriv);
    memset(bufPriv.buf, 0, privKeyCtxByteSize + IPPCP_DATA_ALIGNMENT);
    IppsBigNumState* bnPrivate = (IppsBigNumState*)bufPriv.buf;
    sts = ippsBigNumInit(primeWordSize, bnPrivate);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    IppsPRNGState* pRand = newPRNG();
    Ipp32u isZeroRes;
    do {
        // get regular private key
        sts = ippsGFpECPrivateKey(bnPrivate, pEC, ippsPRNGenRDRAND, pRand);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECPrivateKey")

        ippsCmpZero_BN(bnPrivate, &isZeroRes);
    } while (isZeroRes == IS_ZERO);

    *privkey = bnPrivate;

    /* Tmp buffer */
    int srcatchSize;
    sts = ippsGFpECScratchBufferSize(2, pEC, &srcatchSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECScratchBufferSize")
    BUFFER_INIT(buffScratch)
    alloc_buf(srcatchSize + IPPCP_DATA_ALIGNMENT, &buffScratch);

    /* Init public key */
    int pubKeyCtxSize;
    sts = ippsGFpECPointGetSize(pEC, &pubKeyCtxSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECPointGetSize")
    BUFFER_INIT(buffPubKey)
    alloc_buf(pubKeyCtxSize + IPPCP_DATA_ALIGNMENT, &buffPubKey);
    memset(buffPubKey.buf, 0, pubKeyCtxSize + IPPCP_DATA_ALIGNMENT);
    IppsGFpECPoint* regPublic = (IppsGFpECPoint*)(IPP_ALIGNED_PTR(buffPubKey.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsGFpECPointInit(NULL, NULL, regPublic, pEC);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECPointInit")

    /* Generate public key */
    sts = ippsGFpECPublicKey(bnPrivate, regPublic, pEC, buffScratch.buf);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECPublicKey")

    /* Get components of pub key */
    int xyByteSize;
    sts = ippsBigNumGetSize(primeWordSize, &xyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffX)
    alloc_buf(xyByteSize + IPPCP_DATA_ALIGNMENT, &buffX);
    memset(buffX.buf, 0, xyByteSize + IPPCP_DATA_ALIGNMENT);
    IppsBigNumState* bnX = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffX.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(primeWordSize, bnX);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    sts = ippsBigNumGetSize(primeWordSize, &xyByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffY)
    alloc_buf(xyByteSize + IPPCP_DATA_ALIGNMENT, &buffY);
    memset(buffY.buf, 0, xyByteSize + IPPCP_DATA_ALIGNMENT);
    IppsBigNumState* bnY = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffY.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(primeWordSize, bnY);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumInit")

    sts = ippsGFpECGetPointRegular(regPublic, bnX, bnY, pEC);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECGetPointRegular")

    int tmpSize;

    /* Get X component size */
    ippsRef_BN(NULL, &tmpSize, NULL, bnX);
    tmpSize = IPPCP_BITS2BYTES(tmpSize);
    alloc_buf(tmpSize, Qx_buf);
    memset(Qx_buf->buf, 0, tmpSize);
    BUFFER_INIT(buffQxRevert);
    alloc_buf(tmpSize, &buffQxRevert);
    memset(buffQxRevert.buf, 0, tmpSize);
    sts = ippsRef_BN(NULL, NULL, (Ipp32u**)&(buffQxRevert.buf), bnX);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRef_BN")
    dataReverse(Qx_buf->buf, (const char *)buffQxRevert.buf, tmpSize);

    /* Get Y component size */
    ippsRef_BN(NULL, &tmpSize, NULL, bnY);
    tmpSize = IPPCP_BITS2BYTES(tmpSize);
    alloc_buf(tmpSize, Qy_buf);
    memset(Qy_buf->buf, 0, tmpSize);
    BUFFER_INIT(buffQyRevert);
    alloc_buf(tmpSize, &buffQyRevert);
    memset(buffQyRevert.buf, 0, tmpSize);
    sts = ippsRef_BN(NULL, NULL, (Ipp32u**)&(buffQyRevert.buf), bnY);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRef_BN")
    dataReverse(Qy_buf->buf, (const char *)buffQyRevert.buf, tmpSize);

out:
    free_buf(&buffGFp);
    free_buf(&buffGFpEC);
    free_buf(&buffScratch);
    free_buf(&buffPubKey);
    free_buf(&buffX);
    free_buf(&buffY);

	return ret;
}

static void ippcp_ecdsa_free_key(void *privkey)
{
	IppsBigNumState *pPrivKey = (IppsBigNumState *)privkey;

	if (pPrivKey)
		free((Ipp8u*)pPrivKey);
}

static int ippcp_ecdsa_siggen(struct ecdsa_siggen_data *data, flags_t parsed_flags)
{
    (void)parsed_flags;
    IppStatus sts = ippStsNoErr;
    int ret = 0;

    int primeBitSize = 0, primeWordSize = 0, primeByteSize = 0;
    const IppsGFpMethod *pGFpMethod = NULL;
    InitStdFunction_t initStdF      = NULL;
    switch (data->cipher & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
            primeBitSize = 256;
            primeWordSize = 8;
            primeByteSize = 32;
			pGFpMethod = ippsGFpMethod_p256r1();
            initStdF = ippsGFpECInitStd256r1;
			break;
		case ACVP_NISTP384:
            primeBitSize = 384;
            primeWordSize = 12;
            primeByteSize = 48;
			pGFpMethod = ippsGFpMethod_p384r1();
            initStdF = ippsGFpECInitStd384r1;
			break;
		case ACVP_NISTP521:
            primeBitSize = 521;
            primeWordSize = 17;
            primeByteSize = 66;
			pGFpMethod = ippsGFpMethod_p521r1();
            initStdF = ippsGFpECInitStd521r1;
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
	}

    int ctx_size = 0;
    sts = ippsGFpGetSize(primeBitSize, &ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpGetSize")
    BUFFER_INIT(buffGFp)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &buffGFp);
    IppsGFpState* pGF = (IppsGFpState*)(IPP_ALIGNED_PTR(buffGFp.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsGFpInitFixed(primeBitSize, pGFpMethod, pGF);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpInitFixed")

    /* GFpEC context */
    ctx_size = 0;
    sts = ippsGFpECGetSize(pGF, &ctx_size);
    BUFFER_INIT(buffGFpEC)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &buffGFpEC);
    IppsGFpECState* pEC = (IppsGFpECState*)(IPP_ALIGNED_PTR(buffGFpEC.buf, IPPCP_DATA_ALIGNMENT));
    sts = initStdF(pGF, pEC);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in initStdF")

    /* message */
    int msgByteSize = data->msg.len;
    int msgWordSize = (msgByteSize + 3)/4;
    int msgCtxByteSize;
    sts = ippsBigNumGetSize(msgWordSize, &msgCtxByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffMsg)
    alloc_buf(msgCtxByteSize + IPPCP_DATA_ALIGNMENT, &buffMsg);
    memset(buffMsg.buf, 0, msgCtxByteSize + IPPCP_DATA_ALIGNMENT);
    IppsBigNumState* bnMsgDigest = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffMsg.buf, IPPCP_DATA_ALIGNMENT));

    BUFFER_INIT(buffMsgTmp)
    alloc_buf(msgByteSize, &buffMsgTmp);
    memset(buffMsgTmp.buf, 0, msgByteSize);

    dataReverse(buffMsgTmp.buf, (const char *)data->msg.buf, msgByteSize);

    sts = ippcp_init_set_bn(bnMsgDigest, msgWordSize, ippBigNumPOS, (const Ipp32u *)buffMsgTmp.buf, msgWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    /* Reg and Eph private keys */
    IppsBigNumState* bnRegPrivate = (IppsBigNumState*)data->privkey;
    int ephKeyCtxByteSize;
    sts = ippsBigNumGetSize(primeWordSize, &ephKeyCtxByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffEphKey)
    alloc_buf(ephKeyCtxByteSize + IPPCP_DATA_ALIGNMENT, &buffEphKey);
    memset(buffEphKey.buf, 0, ephKeyCtxByteSize + IPPCP_DATA_ALIGNMENT);

    IppsBigNumState* bnEphPrivate = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffEphKey.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsBigNumInit(primeWordSize, bnEphPrivate);

    IppsPRNGState* pRand = newPRNG();

    Ipp32u isZeroRes, isEquRes;
    do { // get new ephemeral private key
        sts = ippsGFpECPrivateKey(bnEphPrivate, pEC, ippsPRNGenRDRAND, pRand);
        CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECPrivateKey")
        ippsCmpZero_BN(bnEphPrivate, &isZeroRes);
        ippsCmp_BN(bnEphPrivate, bnRegPrivate, &isEquRes);
    } while (isZeroRes == IS_ZERO || isEquRes == IPP_IS_EQ);

    /* signature */
    int ordWordSize = primeWordSize;
    int sByteSize;
    sts = ippsBigNumGetSize(ordWordSize, &sByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffS)
    alloc_buf(sByteSize + IPPCP_DATA_ALIGNMENT, &buffS);
    memset(buffS.buf, 0, sByteSize + IPPCP_DATA_ALIGNMENT);
    IppsBigNumState* bnS = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffS.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippcp_init_set_bn(bnS, ordWordSize, ippBigNumPOS, (const Ipp32u *)data->msg.buf, ordWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    int rByteSize;
    sts = ippsBigNumGetSize(ordWordSize, &rByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffR)
    alloc_buf(rByteSize + IPPCP_DATA_ALIGNMENT, &buffR);
    memset(buffR.buf, 0, rByteSize + IPPCP_DATA_ALIGNMENT);
    IppsBigNumState* bnR = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffR.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippcp_init_set_bn(bnR, ordWordSize, ippBigNumPOS, (const Ipp32u *)data->msg.buf, ordWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    /* Tmp buffer */
    int srcatchSize;
    sts = ippsGFpECScratchBufferSize(2, pEC, &srcatchSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECScratchBufferSize")
    BUFFER_INIT(buffScratch)
    alloc_buf(srcatchSize + IPPCP_DATA_ALIGNMENT, &buffScratch);

    /* RSA Signature Generation */
    sts = ippsGFpECSignDSA(bnMsgDigest, bnRegPrivate, bnEphPrivate,
                           bnR, bnS, pEC, buffScratch.buf);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECSignDSA")

    int tmpSize;
    /* Get S component */
    ippsRef_BN(NULL, &tmpSize, NULL, bnS);
    tmpSize = IPPCP_BITS2BYTES(tmpSize);
    alloc_buf(primeByteSize, &data->S);
    memset(data->S.buf, 0, primeByteSize);
    BUFFER_INIT(buffSRevert);
    alloc_buf(primeByteSize, &buffSRevert);
    memset(buffSRevert.buf, 0, primeByteSize);

    sts = ippsRef_BN(NULL, NULL, (Ipp32u**)&(buffSRevert.buf), bnS);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRef_BN")
    dataReverse(data->S.buf, (const char *)buffSRevert.buf, primeByteSize);

    /* Get R component */
    sts = ippsRef_BN(NULL, &tmpSize, NULL, bnR);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRef_BN")
    tmpSize = IPPCP_BITS2BYTES(tmpSize);
    alloc_buf(primeByteSize, &data->R);
    memset(data->R.buf, 0, primeByteSize);
    BUFFER_INIT(buffRRevert);
    alloc_buf(primeByteSize, &buffRRevert);
    memset(buffRRevert.buf, 0, primeByteSize);
    sts = ippsRef_BN(NULL, NULL, (Ipp32u**)&(buffRRevert.buf), bnR);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsRef_BN")
    dataReverse(data->R.buf, (const char *)buffRRevert.buf, primeByteSize);

out:
    free_buf(&buffScratch);
    free_buf(&buffR);
    free_buf(&buffS);
    free_buf(&buffEphKey);
    free_buf(&buffMsgTmp);
    free_buf(&buffMsg);
    free_buf(&buffGFp);
    free_buf(&buffGFpEC);

    return ret;
}

static int ippcp_ecdsa_sigver(struct ecdsa_sigver_data *data, flags_t parsed_flags) {
    int ret = 0;
    (void)parsed_flags;
    IppStatus sts = ippStsNoErr;

    int primeBitSize = 0, primeWordSize = 0;
    const IppsGFpMethod *pGFpMethod = NULL;
    InitStdFunction_t initStdF      = NULL;
    switch (data->cipher & ACVP_CURVEMASK) {
		case ACVP_NISTP256:
            primeBitSize = 256;
            primeWordSize = 8;
			pGFpMethod = ippsGFpMethod_p256r1();
            initStdF = ippsGFpECInitStd256r1;
			break;
		case ACVP_NISTP384:
            primeBitSize = 384;
            primeWordSize = 12;
			pGFpMethod = ippsGFpMethod_p384r1();
            initStdF = ippsGFpECInitStd384r1;
			break;
		case ACVP_NISTP521:
            primeBitSize = 521;
            primeWordSize = 17;
			pGFpMethod = ippsGFpMethod_p521r1();
            initStdF = ippsGFpECInitStd521r1;
			break;
		default:
			logger(LOGGER_ERR, "Unknown curve\n");
	}

    int ctx_size = 0;
    sts = ippsGFpGetSize(primeBitSize, &ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpGetSize")
    BUFFER_INIT(buffGFp)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &buffGFp);
    IppsGFpState* pGF = (IppsGFpState*)(IPP_ALIGNED_PTR(buffGFp.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsGFpInitFixed(primeBitSize, pGFpMethod, pGF);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpInitFixed")

    /* GFpEC context */
    ctx_size = 0;
    sts = ippsGFpECGetSize(pGF, &ctx_size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECGetSize")
    BUFFER_INIT(buffGFpEC)
    alloc_buf(ctx_size + IPPCP_DATA_ALIGNMENT, &buffGFpEC);
    IppsGFpECState* pEC = (IppsGFpECState*)(IPP_ALIGNED_PTR(buffGFpEC.buf, IPPCP_DATA_ALIGNMENT));
    sts = initStdF(pGF, pEC);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in initStdF")

    /* message */
    int msgByteSize = data->msg.len;
    int msgWordSize = (msgByteSize + 3)/4;
    int msgCtxByteSize;
    sts = ippsBigNumGetSize(msgWordSize, &msgCtxByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffMsg)
    alloc_buf(msgCtxByteSize + IPPCP_DATA_ALIGNMENT, &buffMsg);
    IppsBigNumState* bnMsgDigest = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffMsg.buf, IPPCP_DATA_ALIGNMENT));

    BUFFER_INIT(buffMsgTmp)
    alloc_buf(msgByteSize, &buffMsgTmp);
    dataReverse(buffMsgTmp.buf, (const char *)data->msg.buf, msgByteSize);
    sts = ippcp_init_set_bn(bnMsgDigest, msgWordSize, ippBigNumPOS, (const Ipp32u *)buffMsgTmp.buf, msgWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    /* signature component S */
    int ordWordSize = primeWordSize;
    int sByteSize;
    sts = ippsBigNumGetSize(ordWordSize, &sByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffS)
    alloc_buf(sByteSize + IPPCP_DATA_ALIGNMENT, &buffS);
    IppsBigNumState* bnS = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffS.buf, IPPCP_DATA_ALIGNMENT));
    BUFFER_INIT(buffSRevert)
    alloc_buf(data->S.len, &buffSRevert);
    dataReverse(buffSRevert.buf, (const char *)data->S.buf, data->S.len);
    sts = ippcp_init_set_bn(bnS, ordWordSize, ippBigNumPOS, (const Ipp32u *)buffSRevert.buf, ordWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    /* signature component R */
    int rByteSize;
    sts = ippsBigNumGetSize(ordWordSize, &rByteSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsBigNumGetSize")
    BUFFER_INIT(buffR)
    alloc_buf(rByteSize + IPPCP_DATA_ALIGNMENT, &buffR);
    IppsBigNumState* bnR = (IppsBigNumState*)(IPP_ALIGNED_PTR(buffR.buf, IPPCP_DATA_ALIGNMENT));
    BUFFER_INIT(buffRRevert)
    alloc_buf(data->R.len, &buffRRevert);
    dataReverse(buffRRevert.buf, (const char *)data->R.buf, data->R.len);
    sts = ippcp_init_set_bn(bnR, ordWordSize, ippBigNumPOS, (const Ipp32u *)buffRRevert.buf, ordWordSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippcp_init_set_bn")

    int size;
    sts = ippsGFpElementGetSize(pGF, &size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpElementGetSize")
    BUFFER_INIT(buffGFpElemX)
    alloc_buf(size, &buffGFpElemX);
    IppsGFpElement* pubGx = (IppsGFpElement*)buffGFpElemX.buf;
    BUFFER_INIT(buffGxTmp)
    alloc_buf(data->Qx.len, &buffGxTmp);
    dataReverse(buffGxTmp.buf, (const char *)data->Qx.buf, data->Qx.len);
    int len32 = (data->Qx.len + 3)/4;
    sts = ippsGFpElementInit((const Ipp32u *)buffGxTmp.buf, len32, pubGx, pGF);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpElementInit")

    sts = ippsGFpElementGetSize(pGF, &size);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpElementGetSize")
    BUFFER_INIT(buffGFpElemY)
    alloc_buf(size, &buffGFpElemY);
    IppsGFpElement* pubGy = (IppsGFpElement*)buffGFpElemY.buf;
    BUFFER_INIT(buffGyTmp)
    alloc_buf(data->Qy.len, &buffGyTmp);
    dataReverse(buffGyTmp.buf, (const char *)data->Qy.buf, data->Qy.len);
    len32 = (data->Qy.len + 3)/4;
    sts = ippsGFpElementInit((const Ipp32u *)buffGyTmp.buf, len32, pubGy, pGF);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpElementInit")

    /* Init public key */
    int pubKeyCtxSize;
    sts = ippsGFpECPointGetSize(pEC, &pubKeyCtxSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECPointGetSize")
    BUFFER_INIT(buffPubKey)
    alloc_buf(pubKeyCtxSize + IPPCP_DATA_ALIGNMENT, &buffPubKey);
    IppsGFpECPoint* regPublic = (IppsGFpECPoint*)(IPP_ALIGNED_PTR(buffPubKey.buf, IPPCP_DATA_ALIGNMENT));
    sts = ippsGFpECPointInit(pubGx, pubGy, regPublic, pEC);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECPointInit")

    /* Tmp  buffer */
    int srcatchSize;
    sts = ippsGFpECScratchBufferSize(2, pEC, &srcatchSize);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECScratchBufferSize")
    BUFFER_INIT(buffScratch)
    alloc_buf(srcatchSize + IPPCP_DATA_ALIGNMENT, &buffScratch);

    /* RSA Signature Generation */
    data->sigver_success = 1;
    IppECResult verifRes;
    sts = ippsGFpECVerifyDSA(bnMsgDigest, regPublic, bnR,
                             bnS, &verifRes, pEC, buffScratch.buf);
    CKNULL_LOG((sts == ippStsNoErr), sts, "Error in ippsGFpECVerifyDSA")

    if(ippECValid != verifRes) {
        data->sigver_success = 0;
    }

out:
    free_buf(&buffGFp);
    free_buf(&buffGFpEC);
    free_buf(&buffMsg);
    free_buf(&buffMsgTmp);
    free_buf(&buffS);
    free_buf(&buffSRevert);
    free_buf(&buffR);
    free_buf(&buffRRevert);
    free_buf(&buffGFpElemX);
    free_buf(&buffGxTmp);
    free_buf(&buffGFpElemY);
    free_buf(&buffGyTmp);
    free_buf(&buffPubKey);
    free_buf(&buffScratch);

    return ret;
}

static struct ecdsa_backend ippcp_ecdsa =
{
	NULL,                 /* ecdsa_keygen_testing */
	NULL,
	NULL,                 /* ecdsa_pkvver */
	ippcp_ecdsa_siggen,   /* ecdsa_siggen */
	ippcp_ecdsa_sigver,   /* ecdsa_sigver */
	ippcp_ecdsa_keygen_en,
	ippcp_ecdsa_free_key,
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_ecdsa_backend)
static void ippcp_ecdsa_backend(void)
{
	register_ecdsa_impl(&ippcp_ecdsa);
}

/************************************************
 * LMS interface functions
 ************************************************/
// fixed value
#define IPPCP_LMS_PK_I_BYTESIZE (16)

// stuff functions
static IppsLMSAlgo getIppsLMSAlgo(const struct buffer lmsMode, Ipp32u* hashByteSize) {
    const char * lmsTypeStr = (const char *)lmsMode.buf;
    if(strcmp(lmsTypeStr, "LMS_SHA256_M24_H5") == 0) {
        *hashByteSize = 24;
        return LMS_SHA256_M24_H5;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M24_H10") == 0) {
        *hashByteSize = 24;
        return LMS_SHA256_M24_H10;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M24_H15") == 0) {
        *hashByteSize = 24;
        return LMS_SHA256_M24_H15;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M24_H20") == 0) {
        *hashByteSize = 24;
        return LMS_SHA256_M24_H20;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M24_H25") == 0) {
        *hashByteSize = 24;
        return LMS_SHA256_M24_H25;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M32_H5") == 0) {
        *hashByteSize = 32;
        return LMS_SHA256_M32_H5;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M32_H10") == 0) {
        *hashByteSize = 32;
        return LMS_SHA256_M32_H10;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M32_H15") == 0) {
        *hashByteSize = 32;
        return LMS_SHA256_M32_H15;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M32_H20") == 0) {
        *hashByteSize = 32;
        return LMS_SHA256_M32_H20;
    }
    else if(strcmp(lmsTypeStr, "LMS_SHA256_M32_H25") == 0) {
        *hashByteSize = 32;
        return LMS_SHA256_M32_H25;
    }
    else {
        *hashByteSize = 0;
        return 0;
    }
}

static IppsLMOTSAlgo getIppsLMOTSAlgo(const struct buffer lmOtsMode, Ipp32u* pCount) {
    const char * lmotsTypeStr = (const char *)lmOtsMode.buf;
    if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N24_W1") == 0) {
        *pCount = 200;
        return LMOTS_SHA256_N24_W1;
    }
    else if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N24_W2") == 0) {
        *pCount = 101;
        return LMOTS_SHA256_N24_W2;
    }
    else if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N24_W4") == 0) {
        *pCount = 51;
        return LMOTS_SHA256_N24_W4;
    }
    else if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N24_W8") == 0) {
        *pCount = 26;
        return LMOTS_SHA256_N24_W8;
    }
    else if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N32_W1") == 0) {
        *pCount = 265;
        return LMOTS_SHA256_N32_W1;
    }
    else if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N32_W2") == 0) {
        *pCount = 133;
        return LMOTS_SHA256_N32_W2;
    }
    else if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N32_W4") == 0) {
        *pCount = 67;
        return LMOTS_SHA256_N32_W4;
    }
    else if(strcmp(lmotsTypeStr, "LMOTS_SHA256_N32_W8") == 0) {
        *pCount = 34;
        return LMOTS_SHA256_N32_W8;
    }
    else {
        *pCount = 0;
        return 0;
    }
}

static int ippcp_lms_sigver(struct lms_sigver_data *data, flags_t parsed_flags)
{
    (void)parsed_flags;
    IppStatus status = ippStsNoErr;
    int ret = 0;

    Ipp32u hashByteSize = 0;
    Ipp32u pCount = 0;
    const Ipp32s msgLen = data->msg.len;

    Ipp8u* pScratchBuffer = NULL;
    IppsLMSPublicKeyState* pPubKey = NULL;
    IppsLMSSignatureState* pSignature = NULL;

    IppsLMSAlgo lmsType = getIppsLMSAlgo(data->lmsMode, &hashByteSize);
    IppsLMOTSAlgo lmotsType = getIppsLMOTSAlgo(data->lmOtsMode, &pCount);
    const IppsLMSAlgoType lmsAlgType = { lmotsType, lmsType };
    
    /* Allocate memory for the scratch buffer */
    int buffSize;
    status = ippsLMSBufferGetSize(&buffSize, msgLen, lmsAlgType);
    CKNULL_LOG((status == ippStsNoErr), status, "Error in ippsLMSBufferGetSize")
    pScratchBuffer = malloc(buffSize);

    /* Parse public key vector */
    IppsLMSAlgo lmsTypePk;
    dataReverse((Ipp8u*)&lmsTypePk, (const char *)data->pub.buf, sizeof(Ipp32u));
    
    IppsLMOTSAlgo lmotsTypePk;
    dataReverse((Ipp8u*)&lmotsTypePk, (const char *)data->pub.buf+sizeof(Ipp32u), sizeof(Ipp32u));
    const IppsLMSAlgoType lmsAlgTypePk = { lmotsTypePk, lmsTypePk };
    
    const Ipp8u* pI = (const Ipp8u*)data->pub.buf + 2*sizeof(Ipp32u);
    const Ipp8u* pK = pI + IPPCP_LMS_PK_I_BYTESIZE;
    
    /* Allocate memory for the LMS public key state */
    int ippcpPubKeySize;
    status = ippsLMSPublicKeyStateGetSize(&ippcpPubKeySize, lmsAlgType);
    CKNULL_LOG((status == ippStsNoErr), status, "Error in ippsLMSPublicKeyStateGetSize")
    pPubKey = (IppsLMSPublicKeyState*)malloc(ippcpPubKeySize);

    /* Set the LMS public key */
    status = ippsLMSSetPublicKeyState(lmsAlgTypePk, pI, pK, pPubKey);
    CKNULL_LOG((status == ippStsNoErr), status, "Error in ippsLMSSetPublicKeyState")

    /* Parse signature vector */
    Ipp32u q = 0;
    dataReverse((Ipp8u*)&q, (const char *)data->sig.buf, sizeof(Ipp32u));
    
    IppsLMOTSAlgo lmotsTypeSig;
    dataReverse((Ipp8u*)&lmotsTypeSig, (const char *)data->sig.buf+sizeof(Ipp32u), sizeof(Ipp32u));
    
    const Ipp8u* pC = (const Ipp8u*)data->sig.buf + 2*sizeof(Ipp32u);
    const Ipp8u* pY = pC + hashByteSize;

    IppsLMSAlgo lmsTypeSig;
    dataReverse((Ipp8u*)&lmsTypeSig, (const char *)pY+hashByteSize*pCount, sizeof(Ipp32u));
    
    const IppsLMSAlgoType lmsAlgTypeSig = { lmotsTypeSig, lmsTypeSig };   
    const Ipp8u* pAuthPath = pY + sizeof(Ipp32u) + hashByteSize*pCount;

    /* Allocate memory for the LMS signature state */
    int sigBuffSize;
    status = ippsLMSSignatureStateGetSize(&sigBuffSize, lmsAlgTypeSig);
    if(status != ippStsNoErr) { // Do not throw error, passed parameter in dataset may be intentionally invalid
        data->sigver_success = 0;
        goto out;
    }
    pSignature = (IppsLMSSignatureState*)malloc(sigBuffSize);

    /* Set the LMS signature */
    status = ippsLMSSetSignatureState(lmsAlgTypeSig, q, pC, pY, pAuthPath, pSignature);
    if(status != ippStsNoErr) {  // Do not throw error, passed parameter in dataset may be intentionally invalid
        data->sigver_success = 0;
        goto out;
    }

    int is_valid = 0;
    /* Verify the LMS signature */
    status = ippsLMSVerify(data->msg.buf, msgLen, pSignature, &is_valid, pPubKey, pScratchBuffer);
    data->sigver_success = is_valid;

out:
    free(pScratchBuffer);
    free((Ipp8u*)pPubKey);
    free((Ipp8u*)pSignature);

    return ret;
}

static struct lms_backend ippcp_lms =
{
	ippcp_lms_sigver     /* lms_sigver */
};

ACVP_DEFINE_CONSTRUCTOR(ippcp_lms_backend)
static void ippcp_lms_backend(void)
{
	register_lms_impl(&ippcp_lms);
}
