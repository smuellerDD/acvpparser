// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "frontend_headers.h"

#include "proto.h"
#include "stringhelper.h"

/* debug macro */
#if 0
#define dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define dbg(fmt, ...)
#endif

/*
 * This data structure holds the dentry's of the debugfs files establishing
 * the interface to user space.
 */
struct proto_debugfs {
	struct dentry *proto_debugfs_root; /* root dentry */
	struct dentry *proto_debugfs_data; /* .../name */
};

static struct proto_debugfs proto_debugfs;

typedef struct acvp_proto_data {
	struct buffer in;
	struct buffer out;
	pb_header_t header;
	loff_t out_offset;
} acvp_proto_data_t;

static acvp_proto_data_t acvp_proto_data = { 0 };

/******************************************************************************
 * Helper code
 ******************************************************************************/
int __eqsf2(float a, float b);
int __eqsf2(float a, float b)
{
	/*
	 * The kernel does not support float types.
	 *
	 * This call is added by compiler due to protobuf-c.c float code.
	 */
	WARN_ON(1);
	return 0;
}

int __eqdf2(double a, double b);
int __eqdf2(double a, double b)
{
	/*
	 * The kernel does not support double types.
	 *
	 * This call is added by compiler due to protobuf-c.c double code.
	 */
	WARN_ON(1);
	return 0;
}

int posix_memalign(void **memptr, size_t alignment, size_t size)
{
	void *mem;

	/* kmalloc is guaranteed to be aligned to power of 2 */
	if (ARCH_KMALLOC_MINALIGN < alignment) {
		if (size < alignment)
			size = alignment;
		mem = kmalloc(__roundup_pow_of_two(size), GFP_KERNEL);
	} else {
		mem = kmalloc(size, GFP_KERNEL);
	}

	if (!mem)
		return -ENOMEM;

	*memptr = mem;
	return -0;
}
/******************************************************************************
 * Kernel module code
 ******************************************************************************/
static void proto_scrub(void)
{
	if (acvp_proto_data.in.buf) {
		kvfree(acvp_proto_data.in.buf);
		acvp_proto_data.in.buf = NULL;
		acvp_proto_data.in.len = 0;
	}
	if (acvp_proto_data.out.buf) {
		kvfree(acvp_proto_data.out.buf);
		acvp_proto_data.out.buf = NULL;
		acvp_proto_data.out.len = 0;
	}
	memset(&acvp_proto_data.header, 0, sizeof(acvp_proto_data.header));
	acvp_proto_data.out_offset = 0;
}

static uint32_t proto_implementation = 0;
const char *getenv(const char *name)
{
	if (!strncmp(name, "LC_AES", 6)) {
		if (proto_implementation == 1) {
			static const char out[] = "C";

			return out;
		} else if (proto_implementation == 2) {
			static const char out[] = "AESNI";

			return out;
		} else if (proto_implementation == 3) {
			static const char out[] = "ARM_CE";

			return out;
		} else if (proto_implementation == 11) {
			static const char out[] = "RISCV64";

			return out;
		} else {
			return NULL;
		}
	} else if (!strncmp(name, "LC_SHA3", 7)) {
		if (proto_implementation == 1) {
			static const char out[] = "C";

			return out;
		} else if (proto_implementation == 4) {
			static const char out[] = "AVX2";

			return out;
		} else if (proto_implementation == 5) {
			static const char out[] = "AVX512";

			return out;
		} else if (proto_implementation == 6) {
			static const char out[] = "ARM_NEON";

			return out;
		} else if (proto_implementation == 7) {
			static const char out[] = "ARM_ASM";

			return out;
		} else if (proto_implementation == 3) {
			static const char out[] = "ARM_CE";

			return out;
		} else {
			return NULL;
		}
	} else if (!strncmp(name, "LC_SHAKE", 8)) {
		if (proto_implementation == 9) {
			static const char out[] = "AVX2-4X";

			return out;
		} else if (proto_implementation == 10) {
			static const char out[] = "ARM-2X";

			return out;
		} else {
			return NULL;
		}
	} else if (!strncmp(name, "LC_DILITHIUM", 12)) {
		if (proto_implementation == 1) {
			static const char out[] = "C";

			return out;
		} else {
			return NULL;
		}
	} else if (!strncmp(name, "LC_KYBER", 8)) {
		if (proto_implementation == 1) {
			static const char out[] = "C";

			return out;
		} else {
			return NULL;
		}
	} else {
		return NULL;
	}
}

/* DebugFS operations and definition of the debugfs files */
static ssize_t proto_data_read(struct file *file, char __user *buf,
			       size_t nbytes, loff_t *ppos)
{
	if (!acvp_proto_data.out.buf)
		return -EOPNOTSUPP;

	return simple_read_from_buffer(buf, nbytes, &acvp_proto_data.out_offset,
				       acvp_proto_data.out.buf,
				       acvp_proto_data.out.len);
}

static ssize_t proto_data_write(struct file *file, const char __user *buf,
				size_t nbytes, loff_t *ppos)
{
	ssize_t ret = 0, rc;
	loff_t bufoff = 0;

	if (nbytes < PB_BUF_WRITE_HEADER_SZ)
		return -EINVAL;

	proto_scrub();

	rc = simple_write_to_buffer(&acvp_proto_data.header,
				    PB_BUF_WRITE_HEADER_SZ, &bufoff, buf,
				    nbytes);
	if (rc < 0)
		return rc;
	if (rc < PB_BUF_WRITE_HEADER_SZ)
		return -EMSGSIZE;

	bufoff = 0;

	ret += rc;

	if (acvp_proto_data.header.datalen > ACVP_MAXDATA)
		return -EOVERFLOW;

	if (acvp_proto_data.header.datalen == 0)
		return acvp_proto_data.header.datalen;

	if (acvp_proto_data.header.datalen != nbytes - PB_BUF_WRITE_HEADER_SZ)
		return -EINVAL;

	acvp_proto_data.in.buf = vzalloc(acvp_proto_data.header.datalen);
	if (IS_ERR(acvp_proto_data.in.buf))
		return -PTR_ERR(acvp_proto_data.out.buf);
	acvp_proto_data.in.len = acvp_proto_data.header.datalen;

	rc = simple_write_to_buffer(acvp_proto_data.in.buf,
				    acvp_proto_data.in.len, &bufoff,
				    buf + PB_BUF_WRITE_HEADER_SZ,
				    acvp_proto_data.header.datalen);
	if (rc < 0)
		return rc;

	ret += rc;

	proto_implementation = acvp_proto_data.header.implementation;

	rc = proto_test_algo(&acvp_proto_data.in, &acvp_proto_data.out,
			     &acvp_proto_data.header);

	return (rc < 0) ? rc : ret;
}

/* Module init: allocate memory, register the debugfs files */
static int proto_debugfs_init(void)
{
	proto_debugfs.proto_debugfs_root =
		debugfs_create_dir(KBUILD_MODNAME, NULL);
	return 0;
}

static struct file_operations proto_data_fops = {
	.owner = THIS_MODULE,
	.read = proto_data_read,
	.write = proto_data_write,
};

static int proto_debugfs_init_data(void)
{
	proto_debugfs.proto_debugfs_data =
	debugfs_create_file("data", S_IRUGO|S_IWUSR,
			    proto_debugfs.proto_debugfs_root,
			    NULL, &proto_data_fops);
	return 0;
}

static int __init proto_init(void)
{
	int ret;

	/* Register the marshallers */
	_init_register_proto_aead();
	_init_register_proto_cshake();
	_init_register_proto_drbg();
	_init_register_proto_ecdh();
	_init_register_proto_ecdsa();
	_init_register_proto_eddsa();
	_init_register_proto_hkdf();
	_init_register_proto_hmac();
	_init_register_proto_kdf108();
	_init_register_proto_kmac();
	_init_register_proto_ml_dsa();
	_init_register_proto_ml_kem();
	_init_register_proto_pbkdf();
	_init_register_proto_rsa();
	_init_register_proto_sha();
	_init_register_proto_sym();

	/* Call the constructors inside the backend */
	linux_kernel_constructor();

	/* Initialize the debugfs interface */
	ret = proto_debugfs_init();

	if (ret)
		return ret;

	ret = proto_debugfs_init_data();
	if (ret)
		goto outfs;

	return 0;
outfs:
	debugfs_remove_recursive(proto_debugfs.proto_debugfs_root);
	return ret;
}

static void __exit proto_exit(void)
{
	proto_scrub();
	debugfs_remove_recursive(proto_debugfs.proto_debugfs_root);
}

module_init(proto_init);
module_exit(proto_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("ACVP-Proto kernel module");

