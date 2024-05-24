#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <kcapi.h>
#include <unistd.h>
#include <time.h>
#include "backend_common.h"
#include "parser_sha_mct_helper.h"
#include "logger.h"

#define CIPHERMAXNAME 63
#define ECDH_CURVE_STR_P192 "ecdh-nist-p192"
#define ECDH_CURVE_STR_P256 "ecdh-nist-p256"
#define ECDH_CURVE_STR_P384 "ecdh-nist-p384"
#define ECDH_CURVE_ID_P192 1
#define ECDH_CURVE_ID_P256 2
#define ECDH_CURVE_ID_P384 3
#define ECDH_CURVE_NUM_P192 192
#define ECDH_CURVE_NUM_P256 256
#define ECDH_CURVE_NUM_P384 384
#define ECDH_SS_KEYLEN_P192 24
#define ECDH_SS_KEYLEN_P256 32
#define ECDH_SS_KEYLEN_P384 48
#define GCM_IV_SIZE 12
#define CCM_IV_SIZE 16

extern char n1[];
extern char e1[];
extern char d1[];
extern char p1[];
extern char q1[];
extern char dp1[];
extern char dq1[];
extern char qinv1[];
extern char n2[];
extern char e2[];
extern char d2[];
extern char p2[];
extern char q2[];
extern char dp2[];
extern char dq2[];
extern char qinv2[];
extern char n3[];
extern char e3[];
extern char d3[];
extern char p3[];
extern char q3[];
extern char dp3[];
extern char dq3[];
extern char qinv3[];
extern char n4[];
extern char e4[];
extern char d4[];
extern char p4[];
extern char q4[];
extern char dp4[];
extern char dq4[];
extern char qinv4[];

unsigned char * write_field(unsigned char *ptr, unsigned char *src, unsigned short int len)
{
        /* actual length of a field = 0x02 and len */
        unsigned char *tmp;
        tmp = (unsigned char *)(&len);
        ptr[0] = 0x02;
        if(len <= 127)
        {
                if(tmp)
                        memcpy(ptr + 1, tmp, 1);
                ptr = ptr + 2;
        }
        else if(len > 127 && len <=255)
        {
                ptr[1] = 0x81;
                if(tmp)
                        memcpy(ptr + 2, tmp, 1);
                ptr = ptr + 3;
        }
        else if(len > 255)
        {
                ptr[1] = 0x82;
                if(tmp)
                {
                        memcpy(ptr + 2, tmp + 1, 1);
                        memcpy(ptr + 3, tmp, 1);
                }
                ptr = ptr + 4;
        }

        if(src)
                memcpy(ptr, src, len);
        ptr = ptr + len;
        return ptr;
}

extern int rsa_private_key_ber_encode(struct rsa_siggen_data *data, struct buffer *d,
                                struct buffer *p, struct buffer *q, struct buffer *dp,
                                struct buffer *dq, struct buffer *qinv,
                                struct buffer *pk);

int rsa_public_key_ber_encode(struct rsa_sigver_data *data, struct buffer *pk) {
        /*
        BER encoding for public key
        1. Calculate total length of Public key

        Metadata for complete key = 0x30 and sum of length of all fields

        2. BER encoding the length of any field
        actual length of a field = 0x02 and len

        if length <= 127 - 1 byte (actual length)
        if length > 127 and length <= 255 - 2 bytes (Byte1 = 0x81, Byte2 = actual length)
        if length > 255 - 3 bytes (Byte1 = 0x82, Byte2 and Byte3 = actual length)
        */

        unsigned short int nlen;
        unsigned short int elen, total=0, extra;
        unsigned char *ptr;
        unsigned char *tmp;
        int ret = 0;

        if(!data)
        {
                logger(LOGGER_ERR, "rsa: rsa_sigver_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }

        nlen = data->n.len;
        elen = data->e.len;
        total =  nlen;
        if(nlen <= 127)
                total = total + 2;
        else if(nlen >= 128 && nlen <= 255)
                total = total + 3;
        else
                total = total + 4;
        total = total + elen;

        if(elen <= 127)
                total = total + 2;
        else if(elen >= 128 && elen <= 255)
                total = total + 3;
        else
                total = total + 4;

        if(total <= 127)
                extra = 2;
        else if(total >= 128 && total <= 255)
                extra = 3;
        else
                extra = 4;

/*Calculated total length and extra bytes*/
/*Start Prepare buffer*/
        CKINT_LOG(alloc_buf(total + extra + 1, pk), "rsa: public key buffer could not be allocated\n");
        ptr = pk->buf;
        ptr[0] = 0x30;
        if(extra == 2)
                memcpy(ptr + 1, &total, 1);
        if(extra == 3)
        {
                ptr[1] = 0x81;
                memcpy(ptr + 2, &total, 1);
        }
        if(extra == 4)
        {
                tmp =(unsigned char*)(&total);
                ptr[1] = 0x82;
                memcpy(ptr + 2, tmp + 1, 1);
                memcpy(ptr + 3, tmp , 1);
        }
        ptr = ptr + extra;
        ptr = write_field(ptr, data->n.buf, nlen);
        ptr = write_field(ptr, data->e.buf, elen);
out:
        return ret;
}

static int rsa_sigver(struct rsa_sigver_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        char cipher[CIPHERMAXNAME];
        struct kcapi_handle *handle1 = NULL;
        char cipher1[CIPHERMAXNAME];
        int ret = 0;
        int ret1 = 0;
        struct buffer pk;
        struct buffer dgst;
        struct buffer mac;
        struct buffer in;
        int dgst_len=0;
        pk.len = 0;
        pk.buf = NULL;
        dgst.len = 0;
        dgst.buf = NULL;
        mac.len = 0;
        mac.buf = NULL;
        in.len = 0;
        in.buf = NULL;

        if(!data)
        {
                logger(LOGGER_ERR,"rsa: rsa_sigver_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(!(parsed_flags & FLAG_OP_RSA_SIG_PKCS15))
        {
                logger(LOGGER_ERR, "rsa: invalid cipher\n");
                return -EFAULT;
        }
        strcpy(cipher,"pkcs1pad(rsa,");
        switch(data->cipher & ACVP_HASHMASK)
        {
                case ACVP_SHA1:
                        strcat(cipher, "sha1)");
                        strcpy(cipher1, "sha1");
                        dgst_len = 20;
                        break;
                case ACVP_SHA224:
                        strcat(cipher, "sha224)");
                        strcpy(cipher1, "sha224");
                        dgst_len = 28;
                        break;
                case ACVP_SHA256:
                        strcat(cipher, "sha256)");
                        strcpy(cipher1, "sha256");
                        dgst_len = 32;
                        break;
                case ACVP_SHA384:
                        strcat(cipher, "sha384)");
                        strcpy(cipher1, "sha384");
                        dgst_len = 48;
                        break;
                case ACVP_SHA512:
                        strcat(cipher, "sha512)");
                        strcpy(cipher1, "sha512");
                        dgst_len = 64;
                        break;
        }

        if (kcapi_akcipher_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "rsa: allocation of %s cipher failed\n", cipher);
                return -EFAULT;
        }
        if (kcapi_md_init(&handle1, cipher1, 0))
        {
                logger(LOGGER_ERR, "rsa: allocation of hash %s failed\n", cipher);
                kcapi_akcipher_destroy(handle1);
                ret = -EFAULT;
        }

        CKINT_LOG(alloc_buf(dgst_len, &mac), "rsa: mac buffer could not be allocated\n");
        ret = kcapi_md_digest(handle1, data->msg.buf, data->msg.len, mac.buf, mac.len);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "rsa: message digest generation failed\n");
                goto out;
        }

	if(rsa_public_key_ber_encode(data, &pk) < 0)
	{
		logger(LOGGER_ERR, "rsa: BER encoding of public key failed\n");
		ret = -EFAULT;
		goto out;
	}	

        ret1 = kcapi_akcipher_setpubkey(handle, pk.buf, pk.len);
        if (ret1 <= 0)
        {
                logger(LOGGER_ERR, "rsa: public key setting failed\n");
                ret = -EFAULT;
                goto out;
        }

        CKINT_LOG(alloc_buf(ret, &dgst), "rsa: digest buffer could not be allocated\n");
        CKINT_LOG(alloc_buf(data->sig.len + mac.len, &in), "rsa: in buffer could not be allocated\n");

        if(data->sig.buf)
                memcpy(in.buf, data->sig.buf, data->sig.len);

        if(mac.buf)
                memcpy(in.buf + data->sig.len, mac.buf, mac.len);

        ret1 = kcapi_akcipher_verify(handle,
                                        in.buf, in.len,
                                        dgst.buf, dgst.len, 0);

        if(ret1 < 0)
        {
                logger(LOGGER_ERR, "rsa: signature verification failed with error = %d\n", ret1);
                data->sig_result = 0;
                goto out;
        }
        data->sig_result = 1;

out:
        if(dgst.buf)
                free_buf(&dgst);
        if(in.buf)
                free_buf(&in);
        if(pk.buf)
                free_buf(&pk);
        if(mac.buf)
                free_buf(&mac);

        kcapi_akcipher_destroy(handle);
        kcapi_md_destroy(handle1);
        return ret;
}

static int rsa_siggen(struct rsa_siggen_data *data,
                              flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        char cipher[CIPHERMAXNAME];
        struct kcapi_handle *handle1 = NULL;
        char cipher1[CIPHERMAXNAME];
        int ret = 0;
        int ret1 = 0;
        char *n_ptr;
        char *e_ptr;
        char *d_ptr;
        char *p_ptr;
        char *q_ptr;
        char *dp_ptr;
        char *dq_ptr;
        char *qinv_ptr;
        struct buffer d;
        struct buffer p;
        struct buffer q;
        struct buffer dp;
        struct buffer dq;
        struct buffer qinv;
        struct buffer pk;
        struct buffer dgst;
        struct buffer mac;
        int dgst_len=0;
        pk.len = 0;
        pk.buf = NULL;
        dgst.len = 0;
        dgst.buf = NULL;
        mac.len = 0;
        mac.buf = NULL;
        d.len = 0;
        d.buf = NULL;
        p.len = 0;
        p.buf = NULL;
        q.len = 0;
        q.buf = NULL;
        dp.len = 0;
        dp.buf = NULL;
        dq.len = 0;
        dq.buf = NULL;
        qinv.len = 0;
        qinv.buf = NULL;

        if(!data)
        {
                logger(LOGGER_ERR, "rsa: rsa_siggen_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(!(parsed_flags & FLAG_OP_RSA_SIG_PKCS15))
        {
                logger(LOGGER_ERR, "rsa: invalid cipher\n");
                return -EFAULT;
        }

        strcpy(cipher,"pkcs1pad(rsa,");
        switch(data->cipher & ACVP_HASHMASK)
        {
                case ACVP_SHA1:
                        strcat(cipher, "sha1)");
                        strcpy(cipher1, "sha1");
                        dgst_len = 20;
                        break;
                case ACVP_SHA224:
                        strcat(cipher, "sha224)");
                        strcpy(cipher1, "sha224");
                        dgst_len = 28;
                        break;
                case ACVP_SHA256:
                        strcat(cipher, "sha256)");
                        strcpy(cipher1, "sha256");
                        dgst_len = 32;
                        break;
                case ACVP_SHA384:
                        strcat(cipher, "sha384)");
                        strcpy(cipher1, "sha384");
                        dgst_len = 48;
                        break;
                case ACVP_SHA512:
                        strcat(cipher, "sha512)");
                        strcpy(cipher1, "sha512");
                        dgst_len = 64;
                        break;
        }

        if (kcapi_akcipher_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "rsa: allocation of %s cipher failed\n", cipher);
                return -EFAULT;
        }
        if (kcapi_md_init(&handle1, cipher1, 0))
        {
                logger(LOGGER_ERR, "rsa: allocation of hash %s failed\n", cipher1);
                kcapi_akcipher_destroy(handle1);
                ret = -EFAULT;
        }

        CKINT_LOG(alloc_buf(dgst_len, &mac), "rsa: mac buffer cannot be allocated\n");
        ret = kcapi_md_digest(handle1, data->msg.buf, data->msg.len, mac.buf, mac.len);

        if (ret < 0)
        {
                logger(LOGGER_ERR, "rsa: message digest generation failed\n");
                goto out;
        }

        /*
        definition for the array n1, n1[] = "n = 00b67b1cee2ff9f99f94478a23200816e0449845....."
        the actual value that is needed is starting from index 4
        therefore, we do n1 + 4
        the same logic is followed for the other attributes
        */

        if(data->modulus == 1024)
        {
                n_ptr = n1 + 4;
                e_ptr = e1 + 4;
                d_ptr = d1 + 4;
                p_ptr = p1 + 4;
                q_ptr = q1 + 4;
                dp_ptr = dp1 + 5;
                dq_ptr = dq1 + 5;
                qinv_ptr = qinv1 + 7;
        }
        if(data->modulus == 2048)
        {
                n_ptr = n2 + 4;
                e_ptr = e2 + 4;
                d_ptr = d2 + 4;
                p_ptr = p2 + 4;
                q_ptr = q2 + 4;
                dp_ptr = dp2 + 5;
                dq_ptr = dq2 + 5;
                qinv_ptr = qinv2 + 7;
        }
        if(data->modulus == 3072)
        {
                n_ptr = n3 + 4;
                e_ptr = e3 + 4;
                d_ptr = d3 + 4;
                p_ptr = p3 + 4;
                q_ptr = q3 + 4;
                dp_ptr = dp3 + 5;
                dq_ptr = dq3 + 5;
                qinv_ptr = qinv3 + 7;
        }
        if(data->modulus == 4096)
        {
                n_ptr = n4 + 4;
                e_ptr = e4 + 4;
                d_ptr = d4 + 4;
                p_ptr = p4 + 4;
                q_ptr = q4 + 4;
                dp_ptr = dp4 + 5;
                dq_ptr = dq4 + 5;
                qinv_ptr = qinv4 + 7;
        }

        hex2bin_alloc((char*)n_ptr, strlen(n_ptr), &data->n.buf, &data->n.len);
        hex2bin_alloc((char*)e_ptr, strlen(e_ptr), &data->e.buf, &data->e.len);
        hex2bin_alloc((char*)d_ptr, strlen(d_ptr), &d.buf, &d.len);
        hex2bin_alloc((char*)p_ptr, strlen(p_ptr), &p.buf, &p.len);
        hex2bin_alloc((char*)q_ptr, strlen(q_ptr), &q.buf, &q.len);
        hex2bin_alloc((char*)dp_ptr, strlen(dp_ptr), &dp.buf, &dp.len);
        hex2bin_alloc((char*)dq_ptr, strlen(dq_ptr), &dq.buf, &dq.len);
        hex2bin_alloc((char*)qinv_ptr, strlen(qinv_ptr), &qinv.buf, &qinv.len);

        if(rsa_private_key_ber_encode(data, &d, &p, &q, &dp, &dq, &qinv, &pk) < 0)
        {
                logger(LOGGER_ERR, "rsa: BER encoding of private key failed\n");
		ret = -EFAULT;
                goto out;
        }

        ret1 = kcapi_akcipher_setkey(handle, pk.buf, pk.len);
        if (ret1 <= 0)
        {
                logger(LOGGER_ERR, "rsa: pivate key setting failed with error = %d\n", ret1);
                ret = -EFAULT;
                goto out;
        }

        CKINT_LOG(alloc_buf(ret1, &(data->sig)), "rsa: signature buffer could not be allocated\n");
        ret = kcapi_akcipher_sign(handle,
                                        mac.buf, mac.len,
                                        data->sig.buf, data->sig.len, 0);
out:
        if(dgst.buf)
                free_buf(&dgst);
        if(pk.buf)
                free_buf(&pk);
        if(mac.buf)
                free_buf(&mac);
        if(d.buf)
                free_buf(&d);
        if(p.buf)
                free_buf(&p);
        if(q.buf)
                free_buf(&q);
        if(dp.buf)
                free_buf(&dp);
        if(dq.buf)
                free_buf(&dq);
        if(qinv.buf)
                free_buf(&qinv);

        kcapi_akcipher_destroy(handle);
        kcapi_md_destroy(handle1);
        return ret;
}

static struct rsa_backend kcapi_rsa =
{
        NULL,
        rsa_siggen,
        rsa_sigver,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_rsa_backend)
static void kcapi_rsa_backend(void)
{
        register_rsa_impl(&kcapi_rsa);
}

static int sym_cipher(uint64_t acvp_cipher, char* cipher)
{
        switch (acvp_cipher)
        {
                case ACVP_ECB:
                        strcpy(cipher, "ecb(aes)");
                        break;
                case ACVP_CBC:
                        strcpy(cipher, "cbc(aes)");
                        break;
                case ACVP_CBC_CS3:
                        strcpy(cipher, "cts(cbc(aes))");
                        break;
                case ACVP_CFB128:
                        strcpy(cipher, "cfb(aes)");
                        break;
                case ACVP_CTR:
                        strcpy(cipher, "ctr(aes)");
                        break;
                case ACVP_XTS:
                        strcpy(cipher, "xts(aes)");
                        break;
                case ACVP_GCM:
                        strcpy(cipher, "gcm(aes)");
                        break;
                case ACVP_CCM:
                        strcpy(cipher, "ccm(aes)");
                        break;
                case ACVP_TDESECB:
                        strcpy(cipher, "ecb(des3_ede)");
                        break;
                case ACVP_TDESCBC:
                        strcpy(cipher, "cbc(des3_ede)");
                        break;
                case ACVP_TDESCTR:
                        strcpy(cipher, "ctr(des3_ede)");
                        break;
                default:
                        return -EINVAL;
        }

        return 0;
}

static int sym_encrypt(struct sym_data *data, flags_t parsed_flags)
{
        int ret=0;
        struct kcapi_handle *handle = NULL;
        struct buffer pt;
        char cipher[CIPHERMAXNAME];

        if(!data)
        {
                logger(LOGGER_ERR,"sym: sym_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(sym_cipher(data->cipher,cipher))
        {
                logger(LOGGER_ERR, "sym: invalid cipher\n");
                return -EINVAL;
        }

        pt.len = data->data.len;
        pt.buf = data->data.buf;

        if(kcapi_cipher_init(&handle, cipher, 0)) {
                logger(LOGGER_ERR, "sym: cipher init failed\n");
                return -EINVAL;
        }

        data->data.len = 0;
        data->data.buf = NULL;
        CKINT_LOG(alloc_buf(pt.len, &data->data), "sym: buffer for plain text could not be allocated\n");

        if (!data->key.len ||
                !data->key.buf ||
                (ret = kcapi_cipher_setkey(handle, data->key.buf, data->key.len)))
        {
                logger(LOGGER_ERR, "sym: setting key failed with error = %d\n", ret);
                goto out;
        }

        ret = kcapi_cipher_encrypt(handle,
                        pt.buf, pt.len,
                        data->iv.buf,
                        data->data.buf, data->data.len,
                        KCAPI_ACCESS_SENDMSG);

        /* error only when ret < 0, success in all other cases */
        if(ret > 0)
                ret=0;

out:
        if(pt.buf)
                free_buf(&pt);
        kcapi_cipher_destroy(handle);
        return ret;
}

static int sym_decrypt(struct sym_data *data, flags_t parsed_flags)
{
        int ret = 0;
        struct kcapi_handle *handle = NULL;
        struct buffer ct;
        char cipher[CIPHERMAXNAME];

        if(!data)
        {
                logger(LOGGER_ERR, "sym: sym_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(sym_cipher(data->cipher, cipher))
        {
                logger(LOGGER_ERR, "sym: invalid cipher\n");
                return -EINVAL;
        }

        ct.len = data->data.len;
        ct.buf = data->data.buf;

        data->data.len = 0;
        data->data.buf = NULL;
        CKINT_LOG(alloc_buf(ct.len, &data->data), "sym: buffer for cipher text could not be allocated\n");

        if(kcapi_cipher_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "sym: cipher init Failed\n");
                return -EINVAL;
        }

        if (!data->key.len ||
                !data->key.buf ||
                (ret = kcapi_cipher_setkey(handle, data->key.buf, data->key.len)))
        {
                logger(LOGGER_ERR, "sym: setting key failed with error = %d\n", ret);
                goto out;
        }

        ret = kcapi_cipher_decrypt(handle,
                        ct.buf, ct.len,
                        data->iv.buf,
                        data->data.buf, data->data.len,
                        KCAPI_ACCESS_SENDMSG);

        /* error only when ret < 0, success in all other cases */
        if(ret > 0)
                ret = 0;

out:
        if(ct.buf)
                free_buf(&ct);
        kcapi_cipher_destroy(handle);
        return ret;
}

struct buffer old;
char orig_iv[500];
int orig_iv_len;

static int sym_mct_init(struct sym_data *data, flags_t parsed_flags)
{
        int ret=0;
        struct kcapi_handle *handle = NULL;
        char cipher[CIPHERMAXNAME];

        if(!data)
        {
                logger(LOGGER_ERR, "sym: sym_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(old.buf)
                free_buf(&old);

        old.buf = NULL;
        old.len = 0;

        if(sym_cipher(data->cipher, cipher))
        {
                logger(LOGGER_ERR, "sym: invalid cipher\n");
                return -EINVAL;
        }

        if(kcapi_cipher_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "sym: cipher init Failed\n");
                return -EINVAL;
        }

        if (!data->key.len || !data->key.buf ||
                (ret = kcapi_cipher_setkey(handle, data->key.buf, data->key.len)))
        {
                logger(LOGGER_ERR, "sym: setting key failed with error = %d\n", ret);
                kcapi_cipher_destroy(handle);
                goto out;
        }

        if(data->iv.buf)
                memcpy(orig_iv, data->iv.buf, data->iv.len);

        data->priv = (void*)handle;

out:
        return ret;
}

static int sym_mct_update(struct sym_data *data, flags_t parsed_flags)
{
        int ret=0;
        struct kcapi_handle *handle = NULL;
        struct buffer in;
        size_t origlen = data->data.len;

        if(!data)
        {
                logger(LOGGER_ERR, "sym: sym_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        handle = (struct kcapi_handle *)(data->priv);
        in.len = data->data.len;
        in.buf = data->data.buf;

        if(!(old.buf) && (data->iv.len != 0))
        {
                CKINT_LOG(alloc_buf(data->data.len, &old), "sym: old buffer could not be allocated\n");
                if(data->iv.buf)
                        memcpy(old.buf, data->iv.buf, old.len);
        }

        data->data.len = 0;
        data->data.buf = NULL;
        CKINT_LOG(alloc_buf(in.len, &data->data), "sym: data buffer could not be allocated\n");

        if (parsed_flags & FLAG_OP_ENC)
        {
                ret = kcapi_cipher_encrypt(handle,
                                in.buf, in.len,
                                old.buf,
                                data->data.buf, data->data.len,
                                KCAPI_ACCESS_SENDMSG);
                if(old.buf && data->data.buf)
                        memcpy(old.buf, data->data.buf, old.len);
        }
        else
        {
                ret = kcapi_cipher_decrypt(handle,
                                in.buf, in.len,
                                old.buf,
                                data->data.buf, data->data.len,
                                KCAPI_ACCESS_SENDMSG);
                if(old.buf && in.buf)
                        memcpy(old.buf, in.buf, in.len);
        }

        if (data->data.len != origlen)
                data->data.len = origlen;

out:
        if(in.buf)
                free_buf(&in);
        return ret;
}

static int sym_mct_fini(struct sym_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;

        if(!data)
        {
                logger(LOGGER_ERR, "sym: sym_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        handle = (struct kcapi_handle *)(data->priv);

        if(handle)
                kcapi_cipher_destroy(handle);

        if(old.buf)
                free_buf(&old);

        return 0;
}

static struct sym_backend kcapi_sym =
{
        sym_encrypt,
        sym_decrypt,
        sym_mct_init,
        sym_mct_update,
        sym_mct_fini
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_sym_backend)
static void kcapi_sym_backend(void)
{
        register_sym_impl(&kcapi_sym);
}

int sha_mac_cipher(char *cipher, uint64_t acvp_cipher, size_t *len)
{
        switch(acvp_cipher)
        {

                case ACVP_HMACSHA1:
                        strcpy(cipher, "hmac(sha1)");
                        *len = 20;
                        break;
                case ACVP_HMACSHA2_224:
                        strcpy(cipher, "hmac(sha224)");
                        *len = 28;
                        break;
                case ACVP_HMACSHA2_256:
                        strcpy(cipher, "hmac(sha256)");
                        *len = 32;
                        break;
                case ACVP_HMACSHA2_384:
                        strcpy(cipher, "hmac(sha384)");
                        *len = 48;
                        break;
                case ACVP_HMACSHA2_512:
                        strcpy(cipher, "hmac(sha512)");
                        *len = 64;
                        break;
                case ACVP_HMACSHA3_224:
                        strcpy(cipher, "hmac(sha3-224)");
                        *len = 28;
                        break;
                case ACVP_HMACSHA3_256:
                        strcpy(cipher, "hmac(sha3-256)");
                        *len = 32;
                        break;
                case ACVP_HMACSHA3_384:
                        strcpy(cipher, "hmac(sha3-384)");
                        *len = 48;
                        break;
                case ACVP_HMACSHA3_512:
                        strcpy(cipher, "hmac(sha3-512)");
                        *len = 64;
                        break;
                case ACVP_AESCMAC:
                        strcpy(cipher, "cmac(aes)");
                        *len=128;
                        break;
                case ACVP_SHA1:
                        strcpy(cipher, "sha1");
                        *len = 20;
                        break;
                case ACVP_SHA224:
                        strcpy(cipher, "sha224");
                        *len = 28;
                        break;
                case ACVP_SHA256:
                        strcpy(cipher, "sha256");
                        *len = 32;
                        break;
                case ACVP_SHA384:
                        strcpy(cipher, "sha384");
                        *len = 48;
                        break;
                case ACVP_SHA512:
                        strcpy(cipher, "sha512");
                        *len = 64;
                        break;
                case ACVP_SHA3_224:
                        strcpy(cipher, "sha3-224");
                        *len = 28;
                        break;
                case ACVP_SHA3_256:
                        strcpy(cipher, "sha3-256");
                        *len = 32;
                        break;
                case ACVP_SHA3_384:
                        strcpy(cipher, "sha3-384");
                        *len = 48;
                        break;
                case ACVP_SHA3_512:
                        strcpy(cipher, "sha3-512");
                        *len = 64;
                        break;
                default:
                        return -EINVAL;
        }
        return 0;
}

static int sha_generate(struct sha_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        int ret = 0;
        BUFFER_INIT(msg_p);
        size_t len = 0;

        if(!data)
        {
                logger(LOGGER_ERR, "sha: sha_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        char cipher[CIPHERMAXNAME];
        int rc = 0;

        if(sha_mac_cipher(cipher, data->cipher, &len))
        {
                return -EINVAL;
        }

        CKINT(sha_ldt_helper(data, &msg_p));
        if (kcapi_md_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "sha: allocation of hash %s failed\n", cipher);
                return 1;
        }

        CKINT_LOG(alloc_buf(len, &data->mac), "sha: mac buffer could not be allocated\n");
        rc = kcapi_md_digest(handle, msg_p.buf, msg_p.len, data->mac.buf, data->mac.len);

        if (rc < 0)
        {
                logger(LOGGER_ERR, "sha: message digest generation failed: %d\n", rc);
                sha_ldt_clear_buf(data, &msg_p);
                kcapi_md_destroy(handle);
                return 1;
        }

out:
        sha_ldt_clear_buf(data, &msg_p);
        kcapi_md_destroy(handle);
        return 0;
}

static struct sha_backend kcapi_sha =
{
        sha_generate,
        NULL
};
ACVP_DEFINE_CONSTRUCTOR(kcapi_sha_backend)
static void kcapi_sha_backend(void)
{
        register_sha_impl(&kcapi_sha);
}

static int mac_generate(struct hmac_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        int ret = 0;
        size_t len = 0;

        if(!data)
        {
                logger(LOGGER_ERR,"mac: hmac_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        switch(data->cipher) {
                case ACVP_AESCMAC:
                case ACVP_TDESCMAC:
                        break;
                default:
                        break;
        }

#define MAXMD 64
        uint8_t md[MAXMD];
#define MAXMDHEX (MAXMD * 2 + 1)
        char mdhex[MAXMDHEX];
        char cipher[CIPHERMAXNAME];
        int rc = 0;

        if(sha_mac_cipher(cipher, data->cipher, &len))
        {
                return -EINVAL;
        }

        memset(md, 0, MAXMD);
        memset(mdhex, 0, MAXMDHEX);

        if (kcapi_md_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "mac: allocation of hash %s failed\n", cipher);
                return 1;
        }

        CKINT_LOG(alloc_buf(len, &data->mac), "mac: mac buffer could not be allocated\n");

        if (data->key.len)
        {
                if ((ret = kcapi_md_setkey(handle, data->key.buf, data->key.len)))
                {
                        logger(LOGGER_ERR, "mac: setting key failed with error = %d\n", ret);
                        kcapi_md_destroy(handle);
                        return -EINVAL;
                }
        }

        rc = kcapi_md_digest(handle, data->msg.buf, data->msg.len, md, MAXMD);
        if (rc < 0)
        {
                logger(LOGGER_ERR, "mac: message digest generation failed\n");
                kcapi_md_destroy(handle);
                return 1;
        }

        bin2hex(md, rc, mdhex, data->mac.len, 0);
        memcpy(data->mac.buf, md, data->mac.len);
        data->mac.len = (data->maclen)/8;

out:
        kcapi_md_destroy(handle);
        return 0;
}

static struct hmac_backend kcapi_mac =
{
        mac_generate,
};
ACVP_DEFINE_CONSTRUCTOR(kcapi_mac_backend)
static void kcapi_mac_backend(void)
{
        register_hmac_impl(&kcapi_mac);
}

static int ecdsa_keygen(struct ecdsa_keygen_extra_data *data, flags_t parsed_flags)
{
        if(!data)
        {
                logger(LOGGER_ERR, "ecdsa: ecdsa_keygen_extra_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        struct kcapi_handle *handle = NULL;
        struct kcapi_handle *ecdh = NULL;
        struct buffer key;
        size_t dlen, qxlen, qylen;
        int ret=0;
        char *curve_str = NULL;
        int curve_num = 0;
        int curve_id = 0;

        if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
        {
                curve_str = ECDH_CURVE_STR_P384;
                curve_num = ECDH_CURVE_NUM_P384;
                curve_id = ECDH_CURVE_ID_P384;
        }
        else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
        {
                curve_str = ECDH_CURVE_STR_P256;
                curve_num = ECDH_CURVE_NUM_P256;
                curve_id = ECDH_CURVE_ID_P256;
        }
        else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
        {
                curve_str = ECDH_CURVE_STR_P192;
                curve_num = ECDH_CURVE_NUM_P192;
                curve_id = ECDH_CURVE_ID_P192;
        }
        else
        {
                logger(LOGGER_ERR, "ecdsa: curve is not supported\n");
                return -EINVAL;
        }

        key.len = 0;
        key.buf = NULL;

        if (kcapi_ecc_init(&handle, curve_str))
        {
                ret = -EINVAL;
                logger(LOGGER_ERR, "ecdsa: allocation of cipher failed\n");
                goto out;
        }

        if(curve_num == 384)
                ecdsa_get_bufferlen(ACVP_NISTP384, &dlen, &qxlen, &qylen);
        else
                ecdsa_get_bufferlen(ACVP_NISTP256, &dlen, &qxlen, &qylen);

        CKINT_LOG(alloc_buf(qxlen, &data->Qx), "ecdsa: Qx could not be allocated\n");
        CKINT_LOG(alloc_buf(qylen, &data->Qy), "ecdsa: Qy could not be allocated\n");
        CKINT_LOG(alloc_buf(dlen, &data->d), "ecdaa: private Key buffer could not be allocated\n");
        ret = kcapi_ecc_keygen(handle, curve_num, data->d.buf, data->d.len, data->Qx.buf,
                                        data->Qx.len, data->Qy.buf, data->Qy.len);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdsa: key generation failed with error = %d\n", ret);
                goto out;
        }

        if (kcapi_kpp_init(&ecdh, curve_str, 0))
        {
                ret = -EINVAL;
                logger(LOGGER_ERR, "ecdh: allocation of cipher failed\n");
                goto out;
        }

        ret = kcapi_kpp_ecdh_setcurve(ecdh, curve_id);

        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: curve setting failed with error: %d\n", ret);
                goto out;
        }

        ret = kcapi_kpp_setkey(ecdh, data->d.buf, data->d.len);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: key setting failed with error: %d\n", ret);
                goto out;
        }

        CKINT_LOG(alloc_buf(qxlen + qylen, &key), "ecdh: local public Key buffer could not be allocated\n");

        ret = kcapi_kpp_keygen(ecdh, key.buf, key.len, 0);
        if(ret < 0)
        {
                ret = -EINVAL;
                logger(LOGGER_ERR, "ecdsa: public keygen failed\n");
                goto out;
        }
        else if(memcmp(data->Qx.buf, key.buf, qxlen) == 0 && memcmp(data->Qy.buf, key.buf+qxlen, qylen) == 0)
        {
                logger(LOGGER_DEBUG, "ecdsa: public keygen success\n");
        }
        else
        {
                logger(LOGGER_ERR, "ecdsa: public keygen failed\n");
                ret = -EINVAL;
		goto out;
        }

out:
        kcapi_kpp_destroy(ecdh);
        kcapi_ecc_destroy(handle);
	if(key.buf)
		free_buf(&key);
        return ret;
}

static int ecdsa_keyver(struct ecdsa_pkvver_data *data, flags_t parsed_flags)
{
        if(!data)
        {
                logger(LOGGER_ERR, "ecdsa: ecdsa_pkvver_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }

        struct kcapi_handle *handle = NULL;
        int ret =0 , re;
        char *curve_str = NULL;
        int curve_num = 0;
        (void) parsed_flags;

        if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
        {
                curve_str = ECDH_CURVE_STR_P384;
                curve_num = ECDH_CURVE_NUM_P384;
        }
        else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
        {
                curve_str = ECDH_CURVE_STR_P256;
                curve_num = ECDH_CURVE_NUM_P256;
        }
        else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
        {
                curve_str = ECDH_CURVE_STR_P192;
                curve_num = ECDH_CURVE_NUM_P192;
        }
        else
        {
                logger(LOGGER_ERR, "ecdsa: curve is not supported.\n");
                return -EINVAL;
        }

        if (kcapi_ecc_init(&handle, curve_str))
        {
                logger(LOGGER_ERR, "ecdsa: allocation of cipher failed\n");
                ret = -EINVAL;
                goto out;
        }
        re = kcapi_ecc_verify(handle, curve_num, data->Qx.buf,
                        data->Qx.len, data->Qy.buf, data->Qy.len);
        if(re < 0)
        {
                logger(LOGGER_ERR, "ecdsa: public keyver failed\n");
                data->keyver_success = 0;
        }
        else
        {
                logger(LOGGER_DEBUG, "ecdsa: public keyVer success\n");
                data->keyver_success = 1;
        }
out:
        kcapi_ecc_destroy(handle);
        return ret;
}

static int ecdsa_sigver(struct ecdsa_sigver_data *data, flags_t parsed_flags)
{
        if(!data)
        {
                logger(LOGGER_ERR, "ecdsa: ecdsa_sigver_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }

        struct kcapi_handle *handle = NULL, *hash_handle = NULL;
        int ret = 0, rc = 0;
        size_t len = 0;
        char *curve_str = NULL;
        (void) parsed_flags;

        if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
        {
                curve_str = "ecdsa-nist-p384";
        }
        else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
        {
                curve_str = "ecdsa-nist-p256";
        }
        else
        {
                logger(LOGGER_ERR, "ecdsa: curve not FIPS supported.\n");
                return -EINVAL;
        }

        if(!data->component)
        {
                /* We need to generate the msg hash */
                struct buffer msg = data->msg;
                data->msg.buf = NULL;
                data->msg.len = 0;
                char cipher[CIPHERMAXNAME];

                if(sha_mac_cipher(cipher, data->cipher & ACVP_HASHMASK, &len))
                {
                        return -EINVAL;
                }

                if (kcapi_md_init(&hash_handle, cipher, 0))
                {
                        logger(LOGGER_ERR, "ecdsa: allocation of hash %s failed\n", cipher);
                        return 1;
                }

                CKINT_LOG(alloc_buf(len, &data->msg), "ecdsa: msg hash buffer could not be allocated\n");
                rc = kcapi_md_digest(hash_handle, msg.buf, msg.len, data->msg.buf, data->msg.len);
                if (rc < 0)
                {
                        logger(LOGGER_ERR, "ecdsa: message digest generation failed\n");
                        kcapi_md_destroy(hash_handle);
                        return 1;
                }

                kcapi_md_destroy(hash_handle);
                if(msg.buf)
                        free_buf(&msg);
        }

        if (kcapi_akcipher_init(&handle, curve_str, 0))
        {
                logger(LOGGER_ERR, "ecdsa: allocation of %s cipher failed\n", curve_str);
                return -EFAULT;
        }

        /* Encoding and setting public key */
        struct buffer pk;
        unsigned char *ptr;
        pk.len = 0;
        pk.buf = NULL;

        CKINT_LOG(alloc_buf(data->Qx.len + data->Qy.len + 1, &pk), "ecdsa: public key buffer could not be allocated\n");
        ptr = (&pk)->buf;

        ptr[0] = 0x04;
        ptr = ptr + 1;

        if(data->Qx.buf)
                memcpy(ptr, data->Qx.buf, data->Qx.len);
        ptr = ptr + data->Qx.len;

        if(data->Qy.buf)
                memcpy(ptr, data->Qy.buf, data->Qy.len);

        ret = kcapi_akcipher_setpubkey(handle, pk.buf, pk.len);
        if (ret <= 0)
        {
                logger(LOGGER_ERR, "ecdsa: asymmetric cipher set public key failed\n");
                ret = -EFAULT;
                goto out;
        }

        /* BER Encoding signature */
        struct buffer in;
        struct buffer dgst;
        unsigned short int rlen;
        unsigned short int slen;
        unsigned short int total = 0, extra;
        unsigned char *tmp;

        in.len = 0;
        in.buf = NULL;
        dgst.len = 0;
        dgst.buf = NULL;
        ptr = NULL;

        CKINT_LOG(alloc_buf(rc, &dgst), "ecdsa: dgst buffer could not be allocated\n");

        rlen = data->R.len;
        slen = data->S.len;

        /*
        Metadata for complete key = 0x30 and sum of length of all fields

        BER encoding the length of any field
        actual length of a field = 0x02 and len

        if length <= 127 - 1 byte (actual length)
        if length > 127 and length <= 255 - 2 bytes (Byte1 = 0x81, Byte2 = actual length)
        if length > 255 - 3 bytes (Byte1 = 0x82, Byte2 and Byte3 = actual length)
        */


        total = rlen;
        if(rlen <= 127)
                total = total + 2;
        else if(rlen >= 128 && rlen <= 255)
                total = total + 3;
        else
                total = total + 4;

        total = total + slen;
        if(slen <= 127)
                total = total + 2;
        else if(slen >= 128 && slen <= 255)
                total = total + 3;
        else
                total = total + 4;

        if(total <= 127)
                extra = 2;
        else if(total >= 128 && total <= 255)
                extra = 3;
        else
                extra = 4;

        CKINT_LOG(alloc_buf(total + extra + data->msg.len + 1, &in), "ecdsa: in buffer could not be allocated\n");
        ptr = (&in)->buf;
        ptr[0] = 0x30;
        if(extra == 2)
                memcpy(ptr + 1, &total, 1);
        if(extra == 3)
        {
                ptr[1] = 0x81;
                memcpy(ptr + 2, &total, 1);
        }
        if(extra == 4)
        {
                tmp =(unsigned char*) (&total);
                ptr[1] = 0x82;
                memcpy(ptr + 2, tmp + 1, 1);
                memcpy(ptr + 3, tmp , 1);
        }

        ptr = ptr + extra;
        ptr = write_field(ptr, data->R.buf, rlen);
        ptr = write_field(ptr, data->S.buf, slen);

        if(data->msg.buf)
                memcpy(ptr + 1, data->msg.buf, data->msg.len);

        ret = kcapi_akcipher_verify(handle, in.buf, in.len, dgst.buf, dgst.len, 0);

        if(ret < 0)
        {
                data->sigver_success = 0;
                logger(LOGGER_ERR, "ecdsa: SigVer Failed\n");
        }
        else
        {
                data->sigver_success = 1;
                logger(LOGGER_DEBUG, "ecdsa: SigVer Success\n");
        }
        ret = 0;

out:
        kcapi_akcipher_destroy(handle);
        if(in.buf)
                free_buf(&in);
        if(dgst.buf)
                free_buf(&dgst);
        if(pk.buf)
                free_buf(&pk);
        return ret;
}

static struct ecdsa_backend kcapi_ecdsa =
{
        NULL,
        ecdsa_keygen,
        ecdsa_keyver,
        NULL,
        ecdsa_sigver,
        NULL,
        NULL
};
ACVP_DEFINE_CONSTRUCTOR(kcapi_ecdsa_backend)
static void kcapi_ecdsa_backend(void)
{
        register_ecdsa_impl(&kcapi_ecdsa);
}

static int gcm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        char cipher[CIPHERMAXNAME];
        uint8_t *buf = NULL, *newiv = NULL;
        uint32_t outbuflen = 0, inbuflen = 0;
        uint32_t newivlen = GCM_IV_SIZE;
        uint8_t *assoc = NULL, *o_data = NULL, *tag = NULL;
        size_t assoclen = 0, datalen = 0, taglen = 0;
        int ret = -EINVAL;

        if(!data)
        {
                logger(LOGGER_ERR, "aead_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(sym_cipher(data->cipher,cipher))
        {
                logger(LOGGER_ERR, "sym: invalid cipher\n");
                return -EINVAL;
        }

        taglen = data->taglen/8;
        datalen = data->data.len;
        assoclen = data->assoc.len;

        /* Allocation of aead cipher handle */
        if (kcapi_aead_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "gcm: allocation of cipher failed\n");
                return -EFAULT;
        }

        /* Setting tag value */
        if (kcapi_aead_settaglen(handle, taglen))
        {
                logger(LOGGER_ERR, "gcm: setting of authentication tag length failed\n");
                goto out;
        }

        /* Setting length of associated data */
        kcapi_aead_setassoclen(handle, assoclen);

        /* Padding IV to a size of 12 bytes */
        ret = kcapi_pad_iv(handle, data->iv.buf, data->iv.len, &newiv, &newivlen);
        if (ret)
        {
                logger(LOGGER_ERR, "gcm: iv padding failed\n");
                goto out;
        }

        ret = -ENOMEM;
        outbuflen = kcapi_aead_outbuflen_enc(handle, datalen, assoclen, taglen);
        inbuflen = kcapi_aead_inbuflen_enc(handle, datalen, assoclen, taglen);
        buf = calloc(1, outbuflen);
        if (!buf)
        {
                logger(LOGGER_ERR, "gcm: allocation of buf failed\n");
                goto out;
        }

        kcapi_aead_getdata_output(handle, buf, outbuflen, 1,
                                        &assoc, &assoclen,
                                        &o_data, &datalen,
                                        &tag, &taglen);

        /* Seting key */
        if (!data->key.len || !data->key.buf || kcapi_aead_setkey(handle, data->key.buf, data->key.len))
        {
                logger(LOGGER_ERR, "gcm: key setting failed\n");
                goto out;
        }

        if(data->assoc.buf)
                memcpy(assoc, data->assoc.buf, assoclen);

        if(data->data.buf)
                memcpy(o_data, data->data.buf, datalen);

        /* Performing encryption */
        ret = kcapi_aead_encrypt(handle, buf, inbuflen,
                                        newiv,
                                        buf, outbuflen,
                                        KCAPI_ACCESS_SENDMSG);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "gcm: cipher operation of buffer failed: %d %d\n", errno, ret);
                goto out;
        }
        else if ((uint32_t)ret != outbuflen)
        {
                logger(LOGGER_ERR, "gcm: received data length %d does not match expected length %u\n", ret, outbuflen);
                goto out;
        }

        free_buf(&(data->iv));

        if(data->data.buf)
                free_buf(&(data->data));
        if(data->tag.buf)
                free_buf(&(data->tag));

        CKINT_LOG(alloc_buf(datalen, &data->data), "gcm: ct buffer could not be allocated\n");

        if(o_data)
                memcpy(data->data.buf, o_data, datalen);

        CKINT_LOG(alloc_buf(taglen, &data->tag), "gcm: tag buffer could not be allocated\n");

        if(tag)
                memcpy(data->tag.buf, tag, taglen);
out:
        kcapi_aead_destroy(handle);
        if (newiv)
                free(newiv);
        if (buf)
                free(buf);
        return ret;
}

static int gcm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        char cipher[CIPHERMAXNAME];
        uint8_t *buf = NULL, *newiv = NULL;;
        uint32_t outbuflen = 0, inbuflen = 0;
        /* Only IV size of 12 bytes is supported by the kernel */
        uint32_t newivlen = GCM_IV_SIZE;
        uint8_t *assoc = NULL, *o_data = NULL, *tag = NULL;
        size_t assoclen = 0, datalen = 0, taglen = 0;
        int ret = -EINVAL;

        if(!data)
        {
                logger(LOGGER_ERR, "gcm: aead_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(sym_cipher(data->cipher,cipher))
        {
                logger(LOGGER_ERR, "sym: invalid cipher\n");
                return -EINVAL;
        }

        assoclen = data->assoc.len;
        datalen = data->data.len;
        taglen = data->tag.len;
        data->integrity_error = 0;

        if (!data->ivlen || !data->iv.buf)
                return -EINVAL;

        /* Allocation of aead cipher handle */
        if (kcapi_aead_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "gcm: allocation of cipher failed\n");
                return -EFAULT;
        }

        /* Setting tag value */
        if (kcapi_aead_settaglen(handle, taglen))
        {
                logger(LOGGER_ERR, "gcm: setting of authentication tag length failed\n");
                goto out;
        }

        /* Setting length of associated data */
        kcapi_aead_setassoclen(handle, assoclen);

        /* Padding IV to a size of 12 bytes */
        ret = kcapi_pad_iv(handle, data->iv.buf, data->iv.len, &newiv, &newivlen);
        if (ret)
        {
                logger(LOGGER_ERR, "gcm: iv padding failed\n");
                goto out;
        }

        ret = -ENOMEM;
        outbuflen = kcapi_aead_outbuflen_dec(handle, datalen, assoclen, taglen);
        inbuflen = kcapi_aead_inbuflen_dec(handle, datalen, assoclen, taglen);

        buf = calloc(1, inbuflen);
        if (!buf)
        {
                logger(LOGGER_ERR, "gcm: allocation of buf failed\n");
                goto out;
        }

        kcapi_aead_getdata_input(handle, buf, inbuflen, 0,
                                        &assoc, &assoclen, &o_data, &datalen,
                                        &tag, &taglen);

        /* Set key */
        if (!data->key.len ||
                        !data->key.buf ||
                        kcapi_aead_setkey(handle, data->key.buf, data->key.len))
        {
                logger(LOGGER_ERR, "gcm: symmetric cipher setkey failed\n");
                goto out;
        }

        if(data->assoc.buf)
                memcpy(assoc, data->assoc.buf, assoclen);
        if(data->data.buf)
                memcpy(o_data, data->data.buf, datalen);
        if (data->tag.buf)
                memcpy(tag, data->tag.buf, taglen);

        /* Performing decryption */
        ret = kcapi_aead_decrypt(handle, buf, inbuflen,
                                                newiv,
                                                buf, outbuflen,
                                                KCAPI_ACCESS_SENDMSG);

        if (ret < 0 && ret != -EBADMSG)
        {
                logger(LOGGER_ERR, "gcm: cipher operation of buffer failed: %d %d\n", errno, ret);
                goto out;
        }
        else if (ret == -EBADMSG)
        {
                logger(LOGGER_DEBUG, "gcm: EBADMSG\n");
                data->integrity_error = 1;
                ret = 0;
                goto out;
        }
        else if ((uint32_t)ret != outbuflen)
        {
                logger(LOGGER_ERR, "gcm: received data length %d does not match expected length %u\n", ret, outbuflen);
                goto out;
        }

        if(data->iv.buf)
                free_buf(&(data->iv));
        if(data->data.buf)
                free_buf(&(data->data));
        if(data->tag.buf)
                free_buf(&(data->tag));

        CKINT_LOG(alloc_buf(datalen, &data->data), "gcm: pt buffer could not be allocated\n");
        if(o_data)
                memcpy(data->data.buf, o_data, datalen);

out:
        kcapi_aead_destroy(handle);
        if (newiv)
                free(newiv);
        if (buf)
                free(buf);
        return ret;
}

static int ccm_encrypt(struct aead_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
	char cipher[CIPHERMAXNAME];
        uint8_t *outbuf = NULL, *newiv = NULL;
        uint32_t outbuflen = 0, inbuflen = 0;
        /* Only IV size of 16 bytes is supported by the kernel */
        uint32_t newivlen = CCM_IV_SIZE;
        uint8_t *assoc = NULL, *o_data = NULL, *tag = NULL;
        size_t assoclen = 0, datalen = 0, taglen = 0;
        int ret = -EINVAL;

        if(!data)
        {
                logger(LOGGER_ERR, "ccm: aead_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(sym_cipher(data->cipher,cipher))
        {
                logger(LOGGER_ERR, "sym: invalid cipher\n");
                return -EINVAL;
        }

        taglen = data->taglen/8;
        datalen = data->data.len;
        assoclen = data->assoc.len;

        if (!data->ivlen || !data->iv.buf)
                return -EINVAL;

        /* Allocation of aead cipher handle */
        if (kcapi_aead_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "ccm: allocation of cipher failed\n");
                return -EFAULT;
        }

        /* Setting tag value */
        if (kcapi_aead_settaglen(handle, taglen))
        {
                logger(LOGGER_ERR, "ccm: setting of authentication tag length failed\n");
                goto out;
        }

        /* Setting length of associated data */
        kcapi_aead_setassoclen(handle, assoclen);

        /* Convert CCM nonce into IV of size of 16 bytes */
        ret = kcapi_aead_ccm_nonce_to_iv(data->iv.buf, data->iv.len, &newiv, &newivlen);
        if (ret)
        {
                logger(LOGGER_ERR, "ccm: nonce conversion to IV failed\n");
                goto out;
        }

        ret = -ENOMEM;
        outbuflen = kcapi_aead_outbuflen_enc(handle, datalen, assoclen, taglen);
        inbuflen = kcapi_aead_inbuflen_enc(handle, datalen, assoclen, taglen);
        outbuf = calloc(1, outbuflen);
        if (!outbuf)
        {
                logger(LOGGER_ERR, "ccm: allocation of buf failed\n");
                goto out;
        }

        kcapi_aead_getdata_output(handle, outbuf, outbuflen, 1,
                                        &assoc, &assoclen, &o_data, &datalen,
                                        &tag, &taglen);

        /* Seting key */
        if (!data->key.len ||
                !data->key.buf ||
                kcapi_aead_setkey(handle, data->key.buf, data->key.len))
        {
                logger(LOGGER_ERR, "ccm: symmetric cipher setkey failed\n");
                goto out;
        }

        if(data->assoc.buf)
                memcpy(assoc, data->assoc.buf, assoclen);
        if(data->data.buf)
                memcpy(o_data, data->data.buf, datalen);

        /* Performing encryption */
        ret = kcapi_aead_encrypt(handle, outbuf, inbuflen,
                                                newiv,
                                                outbuf, outbuflen,
                                                KCAPI_ACCESS_SENDMSG);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ccm: cipher operation of buffer failed: %d %d\n", errno, ret);
                goto out;
        }
        else if ((uint32_t)ret != outbuflen)
        {
                logger(LOGGER_ERR, "ccm: received data length %d does not match expected length %u\n", ret, outbuflen);
                goto out;
        }

        if(data->iv.buf)
                free_buf(&(data->iv));
        if(data->data.buf)
                free_buf(&(data->data));
        if(data->tag.buf)
                free_buf(&(data->tag));

        CKINT_LOG(alloc_buf(datalen, &data->data), "ccm: ct buffer could not be allocated\n");

        if(o_data)
                memcpy(data->data.buf, o_data, datalen);

        CKINT_LOG(alloc_buf(taglen, &data->tag), "ccm: tag buffer could not be allocated\n");

        if(tag)
                memcpy(data->tag.buf, tag, taglen);
out:
        kcapi_aead_destroy(handle);
        if (newiv)
                free(newiv);
        if (outbuf)
                free(outbuf);
        return ret;
}


static int ccm_decrypt(struct aead_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
	char cipher[CIPHERMAXNAME];
        uint8_t *buf = NULL, *newiv = NULL;
        uint32_t outbuflen = 0, inbuflen = 0;
        /* Only IV size of 16 bytes is supported by the kernel */
        uint32_t newivlen = CCM_IV_SIZE;
        uint8_t *assoc = NULL, *o_data = NULL, *tag = NULL;
        size_t assoclen = 0, datalen = 0, taglen = 0;
        int ret = -EINVAL;

        if(!data)
        {
                logger(LOGGER_ERR, "ccm: aead_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        if(sym_cipher(data->cipher,cipher))
        {
                logger(LOGGER_ERR, "sym: invalid cipher\n");
                return -EINVAL;
        }

        assoclen = data->assoc.len;
        datalen = data->data.len;
        taglen = data->tag.len;

        data->integrity_error = 0;

        if (!data->ivlen || !data->iv.buf)
                return -EINVAL;

        /* Allocation of aead cipher handle */
        if (kcapi_aead_init(&handle, cipher, 0))
        {
                logger(LOGGER_ERR, "ccm: allocation of cipher failed\n");
                return -EFAULT;
        }

        /* Setting tag value */
        if (kcapi_aead_settaglen(handle, taglen))
        {
                logger(LOGGER_ERR, "ccm: Setting of authentication tag length failed\n");
                goto out;
        }

        /* Setting length of associated data */
        kcapi_aead_setassoclen(handle, assoclen);

        /* Converting CCM nonce into an IV of size 16 bytes */
        ret = kcapi_aead_ccm_nonce_to_iv(data->iv.buf, data->iv.len, &newiv, &newivlen);
        if (ret)
        {
                logger(LOGGER_ERR, "ccm: nonce conversion to IV failed\n");
                goto out;
        }

        ret = -ENOMEM;
        outbuflen = kcapi_aead_outbuflen_dec(handle, datalen, assoclen, taglen);
        inbuflen = kcapi_aead_inbuflen_dec(handle, datalen, assoclen, taglen);
        buf = calloc(1, inbuflen);
        if (!buf)
        {
                logger(LOGGER_ERR, "ccm: allocation of buf failed\n");
                goto out;
        }

        kcapi_aead_getdata_input(handle, buf, inbuflen, 0,
                                        &assoc, &assoclen, &o_data, &datalen,
                                        &tag, &taglen);

        /* Set key */
        if (!data->key.len ||
                !data->key.buf ||
                kcapi_aead_setkey(handle, data->key.buf, data->key.len))
        {
                logger(LOGGER_ERR, "ccm: symmetric cipher setkey failed\n");
                goto out;
        }

        if(data->assoc.buf)
                memcpy(assoc, data->assoc.buf, assoclen);
        if(data->data.buf)
                memcpy(o_data, data->data.buf, datalen);
        if(data->tag.buf)
                memcpy(tag, data->tag.buf, taglen);

        /* Performing decryption */
        ret = kcapi_aead_decrypt(handle, buf, inbuflen,
                                                newiv,
                                                buf, outbuflen,
                                                KCAPI_ACCESS_SENDMSG);
        if (ret < 0 && ret != -EBADMSG)
        {
                logger(LOGGER_ERR, "ccm: cipher operation of buffer failed: %d %d\n", errno, ret);
                goto out;
        }

        if (ret == -EBADMSG)
        {
                logger(LOGGER_DEBUG, "ccm: EBADMSG\n");
                data->integrity_error = 1;
                ret = 0;
                goto out;
        }
        else if ((uint32_t)ret != outbuflen)
        {
                logger(LOGGER_ERR, "ccm: received data length %d does not match expected length %u\n", ret, outbuflen);
                goto out;
        }

        if(data->iv.buf)
                free_buf(&(data->iv));
        if(data->data.buf)
                free_buf(&(data->data));

        CKINT_LOG(alloc_buf(datalen, &data->data), "ccm: pt buffer could not be allocated\n");

        if(o_data)
                memcpy(data->data.buf, o_data, datalen);

out:
        kcapi_aead_destroy(handle);
        if (newiv)
                free(newiv);
        if (buf)
                free(buf);
        return ret;
}

static struct aead_backend kcapi_aead =
{
        gcm_encrypt,
        gcm_decrypt,
        ccm_encrypt,
        ccm_decrypt
};
ACVP_DEFINE_CONSTRUCTOR(kcapi_aead_backend)
static void kcapi_aead_backend(void)
{
        register_aead_impl(&kcapi_aead);
}

static int ecdh_ss_ver(struct ecdh_ss_ver_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        int ret = 0;
        struct buffer key;       //IUT Public Key
        struct buffer rkey;      //Remote Public Key
        struct buffer secret;    //Shared Secret
        char *curve;
        int curve_id, ss_key_len;

        if(!data)
        {
                logger(LOGGER_ERR, "ecdh: ecdh_ss_ver_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        key.len = 0;
        key.buf = NULL;
        rkey.len = 0;
        rkey.buf = NULL;
        secret.len = 0;
        secret.buf = NULL;

        if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
        {
                curve = ECDH_CURVE_STR_P384;
                curve_id = ECDH_CURVE_ID_P384;
                ss_key_len = ECDH_SS_KEYLEN_P384;
        }
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
        {
                curve = ECDH_CURVE_STR_P256;
                curve_id = ECDH_CURVE_ID_P256;
                ss_key_len = ECDH_SS_KEYLEN_P256;
        }
        else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
        {
                curve = ECDH_CURVE_STR_P192;
                curve_id = ECDH_CURVE_ID_P192;
                ss_key_len = ECDH_SS_KEYLEN_P192;
        }
        else
        {
                logger(LOGGER_ERR, "ecdh: curve not supported\n");
                return -EINVAL;
        }

        if (kcapi_kpp_init(&handle, curve, 0))
        {
                ret = -EINVAL;
                logger(LOGGER_ERR, "ecdh: allocation of cipher failed\n");
                goto out1;
        }

        ret = kcapi_kpp_ecdh_setcurve(handle, curve_id);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: setting ecdh curve failed with error: %d\n", ret);
                goto out1;
        }

        ret = kcapi_kpp_setkey(handle, data->privloc.buf, data->privloc.len);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: kernel keys generation failed with error: %d\n", ret);
                goto out;
        }

        CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &key), "ecdh: local pub Key buffer could not be allocated\n");
        ret = kcapi_kpp_keygen(handle, key.buf, key.len, 0);
        if(ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: public keygen failed\n");
		goto out;
        }
        if(memcmp(data->Qxloc.buf, key.buf, data->Qxrem.len))
        {
                logger(LOGGER_ERR, "ecdh: key not matching\n");
                data->validity_success=0;
                goto out;
        }
        if(memcmp(data->Qyloc.buf, key.buf + data->Qxrem.len, data->Qyrem.len))
        {
                logger(LOGGER_ERR, "ecdh: key not matching\n");
                data->validity_success=0;
                goto out;
        }

        CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &rkey), "ecdh: remote key buffer could not be allocated\n");

        if(data->Qxrem.buf)
                memcpy(rkey.buf, data->Qxrem.buf, data->Qxrem.len);

        if(data->Qyrem.buf)
                memcpy(rkey.buf + data->Qxrem.len, data->Qyrem.buf, data->Qyrem.len);

        CKINT_LOG(alloc_buf(ss_key_len * 2, &secret), "ecdh: shared secret buffer could not be allocated\n");
        ret = kcapi_kpp_ssgen(handle, rkey.buf, rkey.len, secret.buf, ss_key_len * 2, 0);
        if(ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: ssgen failed\n");
                goto out;
        }

        if(memcmp(data->hashzz.buf, secret.buf, ss_key_len))
        {
                logger(LOGGER_ERR, "ecdh: ssver failed\n");
                data->validity_success=0;
        }
        else
        {
                data->validity_success=1;
        }
out:
        if(key.buf)
                free_buf(&key);
        if(rkey.buf)
                free_buf(&rkey);
        if(secret.buf)
                free_buf(&secret);
out1:
        kcapi_kpp_destroy(handle);
        return ret;
}

static int ecdh_ss(struct ecdh_ss_data *data, flags_t parsed_flags)
{
        struct kcapi_handle *handle = NULL;
        int ret = 0;
        char *curve;
        int curve_id, ss_key_len;
        struct buffer key;       //IUT Pub Key
        struct buffer rkey;      //Remote Pub Key
        struct buffer pkey;      //Private Key
        struct buffer secret;    //Shared Secret

        if(!data)
        {
                logger(LOGGER_ERR, "ecdh: ecdh_ss_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        key.len = 0;
        key.buf = NULL;
        pkey.len = 0;
        pkey.buf = NULL;
        rkey.len = 0;
        rkey.buf = NULL;
        secret.len = 0;
        secret.buf = NULL;

	if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP384)
        {
                curve = ECDH_CURVE_STR_P384;
                curve_id = ECDH_CURVE_ID_P384;
                ss_key_len = ECDH_SS_KEYLEN_P384;
        }
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP256)
        {
                curve = ECDH_CURVE_STR_P256;
                curve_id = ECDH_CURVE_ID_P256;
                ss_key_len = ECDH_SS_KEYLEN_P256;
        }
	else if((data->cipher & ACVP_CURVEMASK) == ACVP_NISTP192)
        {
                curve = ECDH_CURVE_STR_P192;
                curve_id = ECDH_CURVE_ID_P192;
                ss_key_len = ECDH_SS_KEYLEN_P192;
        }
        else
        {
                logger(LOGGER_ERR, "ecdh: curve not supported\n");
                return -EINVAL;
        }

        if (kcapi_kpp_init(&handle, curve, 0))
        {
                ret = -EINVAL;
                logger(LOGGER_ERR, "ecdh: allocation of cipher failed\n");
                goto out1;
        }

        ret = kcapi_kpp_ecdh_setcurve(handle, curve_id);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: setting ecdh curve failed: %d\n", ret);
                goto out1;
        }

        CKINT_LOG(alloc_buf(ss_key_len, &pkey), "ecdh: private key buffer could not be allocated\n");
        ret = kcapi_rng_get_bytes(pkey.buf, ss_key_len);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: get RNG failed with error: %d\n", ret);
                goto out;
        }

        ret = kcapi_kpp_setkey(handle, pkey.buf, ss_key_len);
        if (ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: private key setting failed with error: %d\n", ret);
                goto out;
        }

        CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &key), "ecdh: local public key buffer could not be allocated\n");
        ret = kcapi_kpp_keygen(handle, key.buf, key.len, 0);
        if(ret<0)
        {
                logger(LOGGER_ERR, "ecdh: public keygen failed\n");
		goto out;
        }

        CKINT_LOG(alloc_buf(data->Qxrem.len , &data->Qxloc), "ecdh: local x key buffer could not be allocated\n");
        CKINT_LOG(alloc_buf(data->Qyrem.len , &data->Qyloc), "ecdh: local y key buffer could not be allocated\n");

        if(key.buf)
                memcpy(data->Qxloc.buf, key.buf, data->Qxrem.len);

        if(key.buf)
                memcpy(data->Qyloc.buf, key.buf + data->Qxrem.len, data->Qyrem.len);

        CKINT_LOG(alloc_buf(data->Qxrem.len + data->Qyrem.len, &rkey), "ecdh: remote key buffer could not be allocated\n");

        if(data->Qxrem.buf)
                memcpy(rkey.buf, data->Qxrem.buf, data->Qxrem.len);

        if(data->Qyrem.buf)
                memcpy(rkey.buf + data->Qxrem.len, data->Qyrem.buf, data->Qyrem.len);

        CKINT_LOG(alloc_buf(ss_key_len * 2, &secret), "ecdh: shared secret buffer could not be allocated\n");
        ret = kcapi_kpp_ssgen(handle, rkey.buf, rkey.len, secret.buf, ss_key_len * 2, 0);
        if(ret < 0)
        {
                logger(LOGGER_ERR, "ecdh: siggen failed\n");
                goto out;
        }

        CKINT_LOG(alloc_buf(ss_key_len, &data->hashzz), "ecdh: shared secret buffer could not be allocated\n");

        if(secret.buf)
                memcpy(data->hashzz.buf, secret.buf, ss_key_len);
out:
        if(key.buf)
                free_buf(&key);
        if(pkey.buf)
                free_buf(&pkey);
        if(rkey.buf)
                free_buf(&rkey);
        if(secret.buf)
                free_buf(&secret);
out1:
        kcapi_kpp_destroy(handle);
        return ret;
}

static struct ecdh_backend kcapi_ecdh =
{
        ecdh_ss,
        ecdh_ss_ver,
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_ecdh_backend)
static void kcapi_ecdh_backend(void)
{
        register_ecdh_impl(&kcapi_ecdh);
}

static int drbg_cipher(uint64_t acvp_cipher, uint64_t type, uint32_t pr, char* cipher)
{
        if(pr)
                strcpy(cipher, "drbg_pr");
        else
                strcpy(cipher, "drbg_nopr");

        switch(acvp_cipher & ACVP_HASHMASK)
        {
                case ACVP_SHA1:
                        if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
                                strcat(cipher, "_hmac");
                        strcat(cipher, "_sha1");
                        break;
                case ACVP_SHA224:
                        if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
                                strcat(cipher, "_hmac");
                        strcat(cipher, "_sha224");
                        break;
                case ACVP_SHA256:
                        if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
                                strcat(cipher, "_hmac");
                        strcat(cipher, "_sha256");
                        break;
                case ACVP_SHA384:
                        if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
                                strcat(cipher, "_hmac");
                        strcat(cipher, "_sha384");
                        break;
                case ACVP_SHA512:
                        if((type & ACVP_DRBGMASK) == ACVP_DRBGHMAC)
                                strcat(cipher, "_hmac");
                        strcat(cipher, "_sha512");
                        break;
        }

        switch(acvp_cipher & ACVP_AESMASK)
        {
                case ACVP_AES128:
                        strcat(cipher, "_ctr_aes128");
                        break;
                case ACVP_AES192:
                        strcat(cipher, "_ctr_aes192");
                        break;
                case ACVP_AES256:
                        strcat(cipher, "_ctr_aes256");
                        break;
        }
        return 0;
}

static int drbg_generate(struct drbg_data *data, flags_t parsed_flags)
{
        char cipher[CIPHERMAXNAME];
        int ret = 0;
        unsigned int i;
        static struct kcapi_handle *rng = NULL;
        struct buffer ent = {NULL, 0};

        if(!data)
        {
                logger(LOGGER_ERR, "drbg: drbg_data is empty, returning -EINVAL...\n");
                return -EINVAL;
        }
        (void)parsed_flags;

        drbg_cipher(data->cipher, data->type, data->pr, cipher);

        ret = kcapi_rng_init(&rng, cipher, 0);
        if (ret)
                return ret;

        CKINT_LOG(alloc_buf(data->entropy.len + data->nonce.len, &ent), "drbg: entropy buffer could not be allocated\n");

        if(data->entropy.buf)
                memcpy(ent.buf, data->entropy.buf, data->entropy.len);

        if(data->nonce.buf)
                memcpy(ent.buf + data->entropy.len, data->nonce.buf, data->nonce.len);

        ret = kcapi_rng_set_entropy(rng, ent.buf, ent.len);
        if(ret)
                logger(LOGGER_ERR, "drbg: setting entropy failed with error = %d\n", ret);

        ret = kcapi_rng_seed(rng, data->pers.buf, data->pers.len);
        if (ret)
                goto out;
        CKINT_LOG(alloc_buf(data->rnd_data_bits_len/8, &data->random), "drbg: data->random buffer could not be allocated\n");

        for(i = 1; i <= data->entropy_reseed.arraysize; i++)
        {
                unsigned char *addn =  data->addtl_reseed.buffers[i-1].buf;
                int len = data->addtl_reseed.buffers[i-1].len;
                struct buffer ent1;
                ent1.buf = data->entropy_reseed.buffers[i-1].buf;
                ent1.len = data->entropy_reseed.buffers[i-1].len;
                ret = kcapi_rng_set_entropy(rng, ent1.buf, ent1.len);

                if(ret < 0)
                {
                        logger(LOGGER_ERR, "drbg: entropy setting failed with error = %d \n", ret);
                        goto out;
                }

                ret = kcapi_rng_seed(rng, addn, len);
                if (ret)
                {
                        logger(LOGGER_ERR, "drbg: reseed failed with error = %d\n",ret);
                        goto out;
                }
        }

        for(i = 1; i <= data->addtl_generate.arraysize; i++)
        {
                // calling generate twice is not the same as calling it with 2 * num_bytes
                unsigned char *addn =  data->addtl_generate.buffers[i-1].buf;
                int len = data->addtl_generate.buffers[i-1].len;

                if(data->pr)
                {
                        struct buffer ent1;
                        ent1.buf = data->entropy_generate.buffers[i-1].buf;
                        ent1.len = data->entropy_generate.buffers[i-1].len;
                        ret = kcapi_rng_set_entropy(rng, ent1.buf, ent1.len);
                        if(ret < 0)
                        {
                                logger(LOGGER_ERR, "drbg: entropy set failed with error = %d\n", ret);
                                goto out;
                        }
                }

                ret = kcapi_rng_send_addtl(rng, addn, len);
                if (ret < 0)
                {
                        logger(LOGGER_ERR, "drbg: setting additional data failed with error = %d\n", ret);
                        goto out;
                }

                ret = kcapi_rng_generate(rng, data->random.buf, data->random.len);
                if (ret < 0)
                {
                        logger(LOGGER_ERR, "drbg: generation failed with error = %d\n", ret);
                        goto out;
                }
        }
out:
        if (rng)
                kcapi_rng_destroy(rng);
        if(ent.buf)
                free_buf(&ent);
        return ret;
}

static struct drbg_backend kcapi_drbg =
{
        drbg_generate,
};

ACVP_DEFINE_CONSTRUCTOR(kcapi_drbg_backend)
static void kcapi_drbg_backend(void)
{
        register_drbg_impl(&kcapi_drbg);
}
