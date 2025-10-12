/*
 * Copyright (C) 2019 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "frontend_headers.h"

#include "cipher_definitions.h"
#include "logger.h"
#include "algorithms.h"

static const struct { char *algo; char *mode; uint64_t cipher; } conv[] = {
	{"ACVP-AES-ECB", NULL, ACVP_ECB},
	{"ACVP-AES-CBC-CS1", NULL, ACVP_CBC_CS1 },
	{"ACVP-AES-CBC-CS2", NULL, ACVP_CBC_CS2 },
	{"ACVP-AES-CBC-CS3", NULL, ACVP_CBC_CS3 },
	{"ACVP-AES-CBC", NULL, ACVP_CBC},
	{"ACVP-AES-OFB", NULL, ACVP_OFB},
	{"ACVP-AES-CFB8", NULL, ACVP_CFB8},
	{"ACVP-AES-CFB128", NULL, ACVP_CFB128},
	{"ACVP-AES-CFB1", NULL, ACVP_CFB1},
	{"ACVP-AES-CTR", NULL, ACVP_CTR},
	{"ACVP-AES-GCM-SIV", NULL, ACVP_GCMSIV},
	{"ACVP-AES-GCM", NULL, ACVP_GCM},
	{"ACVP-AES-GMAC", NULL, ACVP_GMAC},
	{"ACVP-AES-CCM", NULL, ACVP_CCM},
	{"ACVP-AES-XTS", NULL, ACVP_XTS},
	{"ACVP-AES-KWP", NULL, ACVP_KWP},
	{"ACVP-AES-KWP-INV", NULL, ACVP_KWP_INV},
	{"ACVP-AES-KW", NULL, ACVP_KW},
	{"ACVP-AES-KW-INV", NULL, ACVP_KW_INV},
	{"AES-128", NULL, ACVP_AES128},
	{"AES-192", NULL, ACVP_AES192},
	{"AES-256", NULL, ACVP_AES256},

	{"ACVP-TDES-ECB", NULL, ACVP_TDESECB},
	{"ACVP-TDES-CBC", NULL, ACVP_TDESCBC},
	{"ACVP-TDES-OFB", NULL, ACVP_TDESOFB},
	{"ACVP-TDES-CFB1", NULL, ACVP_TDESCFB1},
	{"ACVP-TDES-CFB8", NULL, ACVP_TDESCFB8},
	{"ACVP-TDES-CFB64", NULL, ACVP_TDESCFB64},
	{"ACVP-TDES-CTR", NULL, ACVP_TDESCTR},
	{"ACVP-TDES-KW", NULL, ACVP_TDESKW},
	/* CTR DRBG */
	{"3keyTDEA", NULL, ACVP_TDESECB},

	{"CMAC-AES", NULL, ACVP_AESCMAC},
	{"CMAC-AES128", NULL, ACVP_AESCMAC},
	{"CMAC-AES192", NULL, ACVP_AESCMAC},
	{"CMAC-AES256", NULL, ACVP_AESCMAC},
	{"CMAC-TDES", NULL, ACVP_TDESCMAC},
	{"HMAC-SHA-1", NULL, ACVP_HMACSHA1},
	{"HMAC-SHA2-224", NULL, ACVP_HMACSHA2_224},
	{"HMAC-SHA2-256", NULL, ACVP_HMACSHA2_256},
	{"HMAC-SHA2-384", NULL, ACVP_HMACSHA2_384},
	{"HMAC-SHA2-512/224", NULL, ACVP_HMACSHA2_512224},
	{"HMAC-SHA2-512/256", NULL, ACVP_HMACSHA2_512256},
	{"HMAC-SHA2-512\\/224", NULL, ACVP_HMACSHA2_512224},
	{"HMAC-SHA2-512\\/256", NULL, ACVP_HMACSHA2_512256},
	{"HMAC-SHA2-512", NULL, ACVP_HMACSHA2_512},
	{"HMAC-SHA3-224", NULL, ACVP_HMACSHA3_224},
	{"HMAC-SHA3-256", NULL, ACVP_HMACSHA3_256},
	{"HMAC-SHA3-384", NULL, ACVP_HMACSHA3_384},
	{"HMAC-SHA3-512", NULL, ACVP_HMACSHA3_512},
	{"KMAC-256", NULL, ACVP_KMAC256},
	{"KMAC-128", NULL, ACVP_KMAC128},

	{"RSA", NULL, ACVP_RSA},
	{"ECDSA", NULL, ACVP_ECDSA},
	{"DetECDSA", NULL, ACVP_DET_ECDSA},
	{"EDDSA", NULL, ACVP_EDDSA},
	{"DSA", NULL, ACVP_DSA},
	{"safePrimes", NULL, ACVP_SAFEPRIMES},

	{"SHA-1", NULL, ACVP_SHA1},

	{"SHA3-224", NULL, ACVP_SHA3_224},
	{"SHA3-256", NULL, ACVP_SHA3_256},
	{"SHA3-384", NULL, ACVP_SHA3_384},
	{"SHA3-512", NULL, ACVP_SHA3_512},
	{"CSHAKE-128", NULL, ACVP_CSHAKE128},
	{"CSHAKE-256", NULL, ACVP_CSHAKE256},
	{"SHAKE-128", NULL, ACVP_SHAKE128},
	{"SHAKE-256", NULL, ACVP_SHAKE256},
	{"SHA2-224", NULL, ACVP_SHA224},
	{"SHA2-256", NULL, ACVP_SHA256},
	{"SHA2-384", NULL, ACVP_SHA384},
	{"SHA2-512/224", NULL, ACVP_SHA512224},
	{"SHA2-512/256", NULL, ACVP_SHA512256},
	{"SHA2-512\\/224", NULL, ACVP_SHA512224},
	{"SHA2-512\\/256", NULL, ACVP_SHA512256},
	{"SHA2-512", NULL, ACVP_SHA512},
	{"ctrDRBG", NULL, ACVP_DRBGCTR},
	{"hashDRBG", NULL, ACVP_DRBGHASH},
	{"hmacDRBG", NULL, ACVP_DRBGHMAC},

	{"KAS-ECC-SSC", NULL, ACVP_KAS_ECC_R3_SSC},
	{"KAS-ECC", NULL, ACVP_ECDH},
	{"KAS-FFC-SSC", NULL, ACVP_KAS_FFC_R3_SSC},
	{"KAS-FFC", NULL, ACVP_DH},
	{"KAS-IFC-SSC", NULL, ACVP_KAS_IFC_SSC},
	{"KAS-ED", NULL, ACVP_ECDH_ED},

	{"kdf-components", NULL, ACVP_KDF_COMPONENT},
	{"PBKDF", NULL, ACVP_PBKDF},
	{"KAS-KDF", NULL, ACVP_KDA},
	{"KDA", NULL, ACVP_KDA},
	{"KDF", NULL, ACVP_KDF_800_108},
	{"TLS-v1.3", NULL, ACVP_KDF_TLS13},
	{"TLS-v1.2", NULL, ACVP_KDF_TLS12},
	{"double pipeline iteration", NULL, ACVP_KDF_108_DOUBLE_PIPELINE},
	{"feedback", NULL, ACVP_KDF_108_FEEDBACK},
	{"counter", NULL, ACVP_KDF_108_COUNTER},
	{"after fixed data", NULL, ACVP_KDF_108_AFTER_FIXED},
	{"before fixed data", NULL, ACVP_KDF_108_BEFORE_FIXED},
	{"middle fixed data", NULL, ACVP_KDF_108_MIDDLE_FIXED},
	{"before iterator", NULL, ACVP_KDF_108_BEFORE_ITERATOR},
	{"HKDF", NULL, ACVP_KDA_HKDF},
	{"OneStep", NULL, ACVP_KDA_ONESTEP},
	{"OneStepNoCounter", NULL, ACVP_KDA_ONESTEP_NO_COUNTER},
	{"TwoStep", NULL, ACVP_KDA_TWOSTEP},

	{"P-192", NULL, ACVP_NISTP192},
	{"P-224", NULL, ACVP_NISTP224},
	{"P-256", NULL, ACVP_NISTP256},
	{"P-384", NULL, ACVP_NISTP384},
	{"P-521", NULL, ACVP_NISTP521},
	{"K-163", NULL, ACVP_NISTK163},
	{"K-233", NULL, ACVP_NISTK233},
	{"K-283", NULL, ACVP_NISTK283},
	{"K-409", NULL, ACVP_NISTK409},
	{"K-571", NULL, ACVP_NISTK571},
	{"B-163", NULL, ACVP_NISTB163},
	{"B-233", NULL, ACVP_NISTB233},
	{"B-283", NULL, ACVP_NISTB283},
	{"B-409", NULL, ACVP_NISTB409},
	{"B-571", NULL, ACVP_NISTB571},

	{"ED-25519", NULL, ACVP_ED25519},
	{"ED-448", NULL, ACVP_ED448},

	{"KTS-IFC", NULL, ACVP_KTS_IFC},
	/* KTS schema */
	{"KTS-OAEP-basic", NULL, ACVP_KTS_SCHEMA_OAEP_BASIC},
	{"KTS-OAEP-Party_V-confirmation", NULL, ACVP_KTS_SCHEMA_OAEP_PARTY_V_CONF},
	{"KAS1", NULL, ACVP_KAS1_SCHEMA_BASIC},
	{"KAS1-basic", NULL, ACVP_KAS1_SCHEMA_BASIC},
	{"KAS1-Party_V-confirmation", NULL, ACVP_KAS1_SCHEMA_PARTY_V_CONF},
	{"KAS2", NULL, ACVP_KAS2_SCHEMA_BASIC},
	{"KAS2-basic", NULL, ACVP_KAS2_SCHEMA_BASIC},
	{"KAS2-bilateral-confirmation", NULL, ACVP_KAS2_SCHEMA_BILATERAL_CONF},
	{"KAS2-Party_U-confirmation", NULL, ACVP_KAS2_SCHEMA_PARTY_U_CONF},
	{"KAS2-Party_V-confirmation", NULL, ACVP_KAS2_SCHEMA_PARTY_V_CONF},
	/* KTS key generation method */
	{"rsakpg1-basic", NULL, ACVP_KAS_KEYGEN_RSAKPG1_BASIC},
	{"rsakpg1-prime-factor", NULL, ACVP_KAS_KEYGEN_RSAKPG1_PRIME_FACTOR},
	{"rsakpg1-crt", NULL, ACVP_KAS_KEYGEN_RSAKPG1_CRT},
	{"rsakpg2-basic", NULL, ACVP_KAS_KEYGEN_RSAKPG2_BASIC},
	{"rsakpg2-prime-factor", NULL, ACVP_KAS_KEYGEN_RSAKPG2_PRIME_FACTOR},
	{"rsakpg2-crt", NULL, ACVP_KAS_KEYGEN_RSAKPG2_CRT},
	{"None", NULL, ACVP_KAS_ENCODING_NONE},
	{"concatenation", NULL, ACVP_KAS_ENCODING_CONCATENATION},

	/* SSH */
	{"TDES", NULL, ACVP_TDESECB},

	/* Conversion from uint64_t back to a name */
	{"ctrDRBG_AES128", NULL, ACVP_DRBGCTR | ACVP_AES128},
	{"ctrDRBG_AES192", NULL, ACVP_DRBGCTR | ACVP_AES192},
	{"ctrDRBG_AES256", NULL, ACVP_DRBGCTR | ACVP_AES256},
	{"ctrDRBG_TDES", NULL, ACVP_DRBGCTR | ACVP_TDESECB},
	{"hashDRBG_SHA-1", NULL, ACVP_DRBGHASH | ACVP_SHA1},
	{"hashDRBG_SHA-224", NULL, ACVP_DRBGHASH | ACVP_SHA224},
	{"hashDRBG_SHA-256", NULL, ACVP_DRBGHASH | ACVP_SHA256},
	{"hashDRBG_SHA-384", NULL, ACVP_DRBGHASH | ACVP_SHA384},
	{"hashDRBG_SHA-512", NULL, ACVP_DRBGHASH | ACVP_SHA512},
	{"hashDRBG_SHA-512224", NULL, ACVP_DRBGHASH | ACVP_SHA512224},
	{"hashDRBG_SHA-512256", NULL, ACVP_DRBGHASH | ACVP_SHA512256},
	{"hmacDRBG_SHA-1", NULL, ACVP_DRBGHMAC | ACVP_SHA1},
	{"hmacDRBG_SHA-224", NULL, ACVP_DRBGHMAC | ACVP_SHA224},
	{"hmacDRBG_SHA-256", NULL, ACVP_DRBGHMAC | ACVP_SHA256},
	{"hmacDRBG_SHA-384", NULL, ACVP_DRBGHMAC | ACVP_SHA384},
	{"hmacDRBG_SHA-512", NULL, ACVP_DRBGHMAC | ACVP_SHA512},
	{"hmacDRBG_SHA-512224", NULL, ACVP_DRBGHMAC | ACVP_SHA512224},
	{"hmacDRBG_SHA-512256", NULL, ACVP_DRBGHMAC | ACVP_SHA512256},

	{"MODP-2048", NULL, ACVP_DH_MODP_2048},
	{"MODP-3072", NULL, ACVP_DH_MODP_3072},
	{"MODP-4096", NULL, ACVP_DH_MODP_4096},
	{"MODP-6144", NULL, ACVP_DH_MODP_6144},
	{"MODP-8192", NULL, ACVP_DH_MODP_8192},
	{"ffdhe2048", NULL, ACVP_DH_FFDHE_2048},
	{"ffdhe3072", NULL, ACVP_DH_FFDHE_3072},
	{"ffdhe4096", NULL, ACVP_DH_FFDHE_4096},
	{"ffdhe6144", NULL, ACVP_DH_FFDHE_6144},
	{"ffdhe8192", NULL, ACVP_DH_FFDHE_8192},
	{"FB", NULL, ACVP_DH_FB},
	{"FC", NULL, ACVP_DH_FC},

	{"LMS", NULL, ACVP_LMS},

	{"ML-DSA", NULL, ACVP_ML_DSA},
	{"ML-DSA-44", NULL, ACVP_ML_DSA_44},
	{"ML-DSA-65", NULL, ACVP_ML_DSA_65},
	{"ML-DSA-87", NULL, ACVP_ML_DSA_87},

	{"ML-KEM", NULL, ACVP_ML_KEM},
	{"ML-KEM-512", NULL, ACVP_ML_KEM_512},
	{"ML-KEM-768", NULL, ACVP_ML_KEM_768},
	{"ML-KEM-1024", NULL, ACVP_ML_KEM_1024},

	{"SLH-DSA", NULL, ACVP_SLH_DSA},
	{"SLH-DSA-SHA2-128s", NULL, ACVP_SLH_DSA_SHA2_128S},
	{"SLH-DSA-SHA2-128f", NULL, ACVP_SLH_DSA_SHA2_128F},
	{"SLH-DSA-SHA2-192s", NULL, ACVP_SLH_DSA_SHA2_192S},
	{"SLH-DSA-SHA2-192f", NULL, ACVP_SLH_DSA_SHA2_192F},
	{"SLH-DSA-SHA2-256s", NULL, ACVP_SLH_DSA_SHA2_256S},
	{"SLH-DSA-SHA2-256f", NULL, ACVP_SLH_DSA_SHA2_256F},
	{"SLH-DSA-SHAKE-128s", NULL, ACVP_SLH_DSA_SHAKE_128S},
	{"SLH-DSA-SHAKE-128f", NULL, ACVP_SLH_DSA_SHAKE_128F},
	{"SLH-DSA-SHAKE-192s", NULL, ACVP_SLH_DSA_SHAKE_192S},
	{"SLH-DSA-SHAKE-192f", NULL, ACVP_SLH_DSA_SHAKE_192F},
	{"SLH-DSA-SHAKE-256s", NULL, ACVP_SLH_DSA_SHAKE_256S},
	{"SLH-DSA-SHAKE-256f", NULL, ACVP_SLH_DSA_SHAKE_256F},

	{"Ascon", "AEAD128", ACVP_ASCON_AEAD_128},
	{"Ascon", "Hash256", ACVP_ASCON_HASH_256},
	{"Ascon", "XOF128", ACVP_ASCON_XOF_128},

};

uint64_t convert_algo_cipher(const char *algo, const char *mode,
			     uint64_t cipher)
{
	uint64_t p_res = 0;
	unsigned int i;

	logger(LOGGER_DEBUG, "Convert cipher %s into internal representation\n",
	       algo);

	if (!algo) return ACVP_UNKNOWN;

	for (i = 0; i < ARRAY_SIZE(conv); i++) {
		if (conv[i].mode) {
			size_t len_algo = strlen(conv[i].algo);
			size_t len_mode = strlen(conv[i].mode);

			if (!mode)
				continue;

			if ((strlen(algo) == len_algo) &&
			    (strlen(mode) == len_mode) &&
			    !strncasecmp(algo, conv[i].algo, len_algo) &&
			    !strncasecmp(mode, conv[i].mode, len_mode)) {
				p_res = conv[i].cipher;
				break;
			}
		} else {
			size_t len = strlen(conv[i].algo);

			if ((strlen(algo) == len) &&
			!strncasecmp(algo, conv[i].algo, len)) {
				p_res = conv[i].cipher;
				break;
			}
		}
	}
	if (p_res == 0)
		return ACVP_UNKNOWN;

	return (cipher | p_res);
}

int convert_cipher_match(uint64_t cipher1, uint64_t cipher2,
			 uint64_t cipher_type_mask)
{
	uint64_t typemask = cipher_type_mask | ACVP_CIPHERDEF;

	return ((cipher1 & typemask) == (cipher2 & typemask));
}

int convert_cipher_contain(uint64_t cipher1, uint64_t cipher2,
			   uint64_t cipher_type_mask)
{
	uint64_t typemask = cipher_type_mask ? cipher_type_mask :
					       ACVP_CIPHERTYPE;

	return ((cipher1 & typemask) & ((cipher2) & typemask) &&
	        (cipher1 & ACVP_CIPHERDEF) & ((cipher2) & ACVP_CIPHERDEF));
}

int convert_cipher_algo(uint64_t cipher, uint64_t cipher_type_mask,
			const char **algo, const char **mode)
{
	unsigned int i;
	unsigned int found = 0;

	if (!algo)
		return -EINVAL;

	for (i = 0; i < ARRAY_SIZE(conv); i++) {
		if (convert_cipher_match(cipher, conv[i].cipher,
					 cipher_type_mask)) {
			*algo = conv[i].algo;
			if (mode)
				*mode = conv[i].mode;

			found = 1;
			break;
		}
	}

	if (!found)
		return -EINVAL;

	return 0;
}

void ecdsa_get_bufferlen(uint64_t curve, size_t *dlen,
			 size_t *xlen, size_t *ylen)
{
	switch (curve & ACVP_CURVEMASK) {
		case ACVP_NISTB163:
		case ACVP_NISTK163:
			*xlen = 163 / 8 + 1;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTB233:
		case ACVP_NISTK233:
			*xlen = 233 / 8 + 1;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTB283:
		case ACVP_NISTK283:
			*xlen = 283 / 8 + 1;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTB409:
		case ACVP_NISTK409:
			*xlen = 409 / 8 + 1;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTB571:
		case ACVP_NISTK571:
			*xlen = 571 / 8 + 1;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTP192:
			*xlen = 192 / 8;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTP224:
			*xlen = 224 / 8;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTP256:
			*xlen = 256 / 8;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTP384:
			*xlen = 384 / 8;
			*dlen = *xlen;
			*ylen = *xlen;
			break;
		case ACVP_NISTP521:
			*dlen = 66;
			*xlen = 66;
			*ylen = 66;
			break;
		default:
			logger(LOGGER_WARN,
			       "ECDSA: Unknown curve to determine bufferlen\n");
			break;
	}
}
