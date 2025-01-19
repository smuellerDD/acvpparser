/*
 * Copyright (C) 2015 - 2024, Stephan Mueller <smueller@chronox.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL2
 * are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
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

#include "includes.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>

#include <openssl/bn.h>

#include "xmalloc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "packet.h"

static int bin_char(unsigned char hex)
{
	if (48 <= hex && 57 >= hex)
		return (hex - 48);
	if (65 <= hex && 70 >= hex)
		return (hex - 55);
	if (97 <= hex && 102 >= hex)
		return (hex - 87);
	return 0;
}

/*
 * Convert hex representation into binary string
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin output buffer with binary data
 * @binlen length of already allocated bin buffer (should be at least
 *	   half of hexlen -- if not, only a fraction of hexlen is converted)
 */
static void hex2bin(const char *hex, size_t hexlen,
		    unsigned char *bin, size_t binlen)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		bin[i] = bin_char(hex[(i*2)]) << 4;
		bin[i] |= bin_char(hex[((i*2)+1)]);
	}
}

/*
 * Allocate sufficient space for binary representation of hex
 * and convert hex into bin
 *
 * Caller must free bin
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin return value holding the pointer to the newly allocated buffer
 * @binlen return value holding the allocated size of bin
 *
 * return: 0 on success, !0 otherwise
 */
static int hex2bin_alloc(const char *hex, size_t hexlen,
			 unsigned char **bin, size_t *binlen)
{
	unsigned char *out = NULL;
	size_t outlen = 0;

	if (!hexlen)
		return -EINVAL;

	outlen = (hexlen + 1) / 2;

	out = calloc(1, outlen);
	if (!out)
		return -errno;

	hex2bin(hex, hexlen, out, outlen);
	*bin = out;
	*binlen = outlen;
	return 0;
}

static char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static char hex_char(unsigned int bin, int u)
{
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/*
 * Convert binary string into hex representation
 * @bin input buffer with binary data
 * @binlen length of bin
 * @hex output buffer to store hex data
 * @hexlen length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u case of hex characters (0=>lower case, 1=>upper case)
 */
static void bin2hex(const unsigned char *bin, size_t binlen,
		    char *hex, size_t hexlen, int u)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

struct kdf_cavs {
	unsigned char *K;
	size_t Klen;
	unsigned char *H;
	size_t Hlen;
	unsigned char *session_id;
	size_t session_id_len;

	unsigned int iv_len;
	unsigned int ek_len;
	unsigned int ik_len;
};

static int sshkdf_cavs(struct kdf_cavs *test)
{
	int ret = 0;
	struct kex kex;
	struct sshbuf *shared_secret;
	int mode = 0;
	struct newkeys *ctoskeys;
	struct newkeys *stockeys;
	struct ssh *ssh = NULL;

#define HEXOUTLEN 500
	char hex[HEXOUTLEN];

	memset(&kex, 0, sizeof(struct kex));

	shared_secret = sshbuf_from(test->K, test->Klen);
	if (!shared_secret) {
		printf("cannot allocate shared_secret\n");
		ret = 1;
		goto out;
	}

	kex.session_id = test->session_id;
	kex.session_id_len = test->session_id_len;

	/* setup kex */

	/* select the right hash based on struct ssh_digest digests */
	switch (test->ik_len) {
		case 20:
			kex.hash_alg = 1;
			break;
		case 32:
			kex.hash_alg = 2;
			break;
		case 48:
			kex.hash_alg = 3;
			break;
		case 64:
			kex.hash_alg = 4;
			break;
		default:
			printf("Wrong hash type %u\n", test->ik_len);
			ret = 1;
			goto out;
	}

	/* implement choose_enc */
	for (mode = 0; mode < 2; mode++) {
		kex.newkeys[mode] = calloc(1, sizeof(struct newkeys));
		if (!kex.newkeys[mode]) {
			printf("allocation of newkeys failed\n");
			ret = 1;
			goto out;
		}
		kex.newkeys[mode]->enc.iv_len = test->iv_len;
		kex.newkeys[mode]->enc.key_len = test->ek_len;
		kex.newkeys[mode]->enc.block_size = (test->iv_len == 64) ? 8 : 16;
		kex.newkeys[mode]->mac.key_len = test->ik_len;
	}

	/* implement kex_choose_conf */
	kex.we_need = kex.newkeys[0]->enc.key_len;
	if (kex.we_need < kex.newkeys[0]->enc.block_size)
		kex.we_need = kex.newkeys[0]->enc.block_size;
	if (kex.we_need < kex.newkeys[0]->enc.iv_len)
		kex.we_need = kex.newkeys[0]->enc.iv_len;
	if (kex.we_need < kex.newkeys[0]->mac.key_len)
		kex.we_need = kex.newkeys[0]->mac.key_len;

	/* MODE_OUT (1) -> server to client
	 * MODE_IN (0) -> client to server */
	kex.server = 1;

	/* do it */
	if ((ssh = ssh_packet_set_connection(NULL, -1, -1)) == NULL){
		printf("Allocation error\n");
		goto out;
	}
	ssh->kex = &kex;
	kex_derive_keys(ssh, test->H, test->Hlen, shared_secret);

	ctoskeys = kex.newkeys[0];
	stockeys = kex.newkeys[1];

	/* get data */
	memset(hex, 0, HEXOUTLEN);
	bin2hex(ctoskeys->enc.iv, (size_t)ctoskeys->enc.iv_len,
		hex, HEXOUTLEN, 0);
	printf("Initial IV (client to server) = %s\n", hex);
	memset(hex, 0, HEXOUTLEN);
	bin2hex(stockeys->enc.iv, (size_t)stockeys->enc.iv_len,
		hex, HEXOUTLEN, 0);
	printf("Initial IV (server to client) = %s\n", hex);

	memset(hex, 0, HEXOUTLEN);
	bin2hex(ctoskeys->enc.key, (size_t)ctoskeys->enc.key_len,
		hex, HEXOUTLEN, 0);
	printf("Encryption key (client to server) = %s\n", hex);
	memset(hex, 0, HEXOUTLEN);
	bin2hex(stockeys->enc.key, (size_t)stockeys->enc.key_len,
		hex, HEXOUTLEN, 0);
	printf("Encryption key (server to client) = %s\n", hex);

	memset(hex, 0, HEXOUTLEN);
	bin2hex(ctoskeys->mac.key, (size_t)ctoskeys->mac.key_len,
		hex, HEXOUTLEN, 0);
	printf("Integrity key (client to server) = %s\n", hex);
	memset(hex, 0, HEXOUTLEN);
	bin2hex(stockeys->mac.key, (size_t)stockeys->mac.key_len,
		hex, HEXOUTLEN, 0);
	printf("Integrity key (server to client) = %s\n", hex);

out:
	if (shared_secret)
		sshbuf_free(shared_secret);
	if (ssh)
		ssh_packet_close(ssh);
	return ret;
}

static void usage(void)
{
	fprintf(stderr, "\nOpenSSH KDF CAVS Test\n\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-K\tShared secret string\n");
	fprintf(stderr, "\t-H\tHash string\n");
	fprintf(stderr, "\t-s\tSession ID string\n");
	fprintf(stderr, "\t-i\tIV length to be generated\n");
	fprintf(stderr, "\t-e\tEncryption key length to be generated\n");
	fprintf(stderr, "\t-m\tMAC key length to be generated\n");
}

/*
 * Test command example:
 * ./ssh-cavs -K 0000010100a46eb79792954a188a12b22a19dc964b6803f8b70de5bbc05217de295cb29bd6a43f52c64db1945dd10a9a52106deb26b15f5668a3cdcff634044926f31c232464c297050247abbe6c9b84dddcf0c59c3ed1467fd6ff983c44550ef86f01f956e77742d50929f8f8de2c683c0a144c43fdb828ec730b9ba798a12ffb4089ebd5d78ff12934c25467beb98b72a731de73504f825ad6d0e5d9a077985e91b6b2699f106de8879c927f13febd58e43c1e3000c0b1f2f38be5457879c6c74168667b126faec662de33024175e5bc165d52663ed9c7f732c4d94ed7d0c7bb9fd4f5f9bbd4b637a25d0ac7b7e4b7cdd9bc153f34659b36622150c9a751236ca6ebe7f9 -H 4d00a8bf7b45aaae6a2d3db64e0130301cd57c630f46930e49c4352a8e7d414d08bb8548df432888237a257630014990651afcb4964f1ad3488702a3cdcd2890 -s 3a6ab9ac6d5f38f4f2c9e8f9982839e9438c4b1cfecaa6f5a39c62331cb0f993668949f080e012130f526c8417ae27520cc06adee221b7845a3a8c7f7248465f -i 8 -e 24 -m 64
 *
 * Initial IV (client to server) = b10a8d8f987285c6
 * Initial IV (server to client) = b853e1612c3bec23
 * Encryption key (client to server) = 0cd987771f42504fad8cf3e4daad9cd5789b0b5ee6375b15
 * Encryption key (server to client) = 0977d9ee59ddd8765e92cbc23456eb4cb382c98d00d6dae5
 * Integrity key (client to server) = 4c97b347723b8f667fd0c587b7fca79fba6c22e3ee2476173388139431b04b1be675a18cf031251456002e77aa5065561063dc200214a878ab53f715120d8e37
 * Integrity key (server to client) = f17d06a98695d3a557e8a9aba586e921cb59994718750aa11d5ce36f00c76b78a198617ffa7681d2127cfd6a119f4a9f69df5116be62743c5fa9e0bd4cc1b79d
 */
int main(int argc, char *argv[])
{
	struct kdf_cavs test;
	int ret = 1;
	int opt = 0;

	memset(&test, 0, sizeof(struct kdf_cavs));
	while((opt = getopt(argc, argv, "K:H:s:i:e:m:")) != -1)
	{
		size_t len = 0;
		switch(opt)
		{
			case 'K':
				len = strlen(optarg);
				ret = hex2bin_alloc(optarg, len,
						    &test.K, &test.Klen);
				if (ret)
					goto out;
				break;
			case 'H':
				len = strlen(optarg);
				ret = hex2bin_alloc(optarg, len,
						    &test.H, &test.Hlen);
				if (ret)
					goto out;
				break;
			case 's':
				len = strlen(optarg);
				ret = hex2bin_alloc(optarg, len,
						    &test.session_id,
						    &test.session_id_len);
				if (ret)
					goto out;
				break;
			case 'i':
				test.iv_len = strtoul(optarg, NULL, 10);
				break;
			case 'e':
				test.ek_len = strtoul(optarg, NULL, 10);
				break;
			case 'm':
				test.ik_len = strtoul(optarg, NULL, 10);
				break;
			default:
				usage();
				goto out;
		}
	}

	ret = sshkdf_cavs(&test);

out:
	if (test.session_id)
		free(test.session_id);
	if (test.K)
		free(test.K);
	if (test.H)
		free(test.H);
	return ret;

}
