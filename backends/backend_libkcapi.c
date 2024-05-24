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
