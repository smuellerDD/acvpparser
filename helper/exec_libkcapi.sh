#!/bin/bash
#
# CAVS test executor
# Written and Copyright (c) by: Stephan Müller <smueller@chronox.de>
#
# License: see LICENSE file
#
#                            NO WARRANTY
#
#    BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
#    FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
#    OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
#    PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
#    OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#    MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
#    TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
#    PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
#    REPAIR OR CORRECTION.
#
#    IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
#    WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
#    REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
#    INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
#    OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
#    TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
#    YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
#    PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
#    POSSIBILITY OF SUCH DAMAGES.

. $(dirname $0)/exec_lib.sh

TARGET="libkcapi"

build_tool ${TARGET}

MODULE_PREFIX="libkcapi__"
MODULE_POSTFIX="_"

# check whether a given kernel version is present
# returns true for yes, false for no
check_min_kernelver() {
	major=$1
	minor=$2

	local our_major=$(uname -r | cut -d"." -f1)

	if [ $our_major -gt $major ]; then
		return 0
	elif [ $our_major -ge $major ]; then
		if [ $(uname -r | cut -d"." -f2) -ge $minor ]; then
			return 0
		fi
	fi
	return 1
}

# The names MUST be consistent with the acvp-retriever code
if [ $(uname -m) = "i686" ]; then
	EXEC="C_C X86ASM_C"
	PROC="X86"

	if $(check_min_kernelver 4 17); then
		EXEC="$EXEC CFB_C_C CFB_X86ASM_C"
	fi

	if $(check_min_kernelver 4 8); then
		EXEC="$EXEC SHA3_C_C"
	fi

elif [ $(uname -m) = "s390x" ]; then
	PROC="S390"
	EXEC="C_C CPACF_C CPACF_ASM"

	if $(check_min_kernelver 4 17); then
		EXEC="$EXEC CFB_C_C CFB_CPACF_C"
	fi

	if $(check_min_kernelver 4 8); then
		EXEC="$EXEC SHA3_C_C"
	fi

else
	PROC="X86"
	EXEC="C_C AESNI_ASM AESNI_C X86ASM_C X86ASM_ASM X86ASM_ASM_NO_TDES_CTR SSSE3"

	# Intel SHA implementations are now directly callable
	if $(check_min_kernelver 4 4); then
		if $(grep -q avx /proc/cpuinfo) ; then
			EXEC="$EXEC AVX"
		fi
		if $(grep -q avx2 /proc/cpuinfo) ; then
			EXEC="$EXEC AVX2"
		fi
	fi

	if $(check_min_kernelver 4 8); then
		if $(grep -q avx2 /proc/cpuinfo) ; then
			EXEC="$EXEC MB"
		fi
	elif $(check_min_kernelver 3 18); then
		if $(grep -q avx2 /proc/cpuinfo) ; then
			EXEC="$EXEC MB"
		fi
	fi

	if $(check_min_kernelver 4 11); then
		EXEC="$EXEC CTI_C CFB_CTI_C"
	fi

	if $(check_min_kernelver 4 17); then
		EXEC="$EXEC CFB_C_C CFB_AESNI_C CFB_X86ASM_C"
	fi

	if $(check_min_kernelver 4 8); then
		EXEC="$EXEC SHA3_C_C"
	fi
fi

iiv_name() {
	name=$1

	# New name with 4.2
	if $(check_min_kernelver 4 2); then
		name="seqiv($name)"
	fi

	echo $name
}

xts_name() {
	name=$1

	# New with 4.9
	if $(check_min_kernelver 4 9); then
		name="xts(ecb($name))"
	else
		name="xts($name)"
	fi

	echo $name
}

cbcmac_name() {
	name=$1

	# New with 4.11
	if $(check_min_kernelver 4 11); then
		name="cbcmac($name)"
	else
		name="$name"
	fi

	echo $name
}

################### AES TESTS #######################
AES_TESTS="AES AES_GCM CCM CMAC XTS DRBG800-90A KeyWrap38F"

# x86 Assembler cipher and C block chaining modes
CIPHER_CALL_X86ASM_C="KCAPI_GCM_AES=\"gcm_base(ctr(aes-asm),ghash-generic)\" \
		KCAPI_CCM_AES=\"ccm_base(ctr(aes-asm),$(cbcmac_name "aes-asm"))\" \
		KCAPI_CBC_AES=\"cbc(aes-asm)\" \
		KCAPI_CTR_AES=\"ctr(aes-asm)\" \
		KCAPI_ECB_AES=\"ecb(aes-asm)\" \
		KCAPI_XTS_AES=\"$(xts_name "aes-asm")\" \
		KCAPI_KW_AES=\"kw(aes-asm)\" \
		KCAPI_CMAC_AES=\"cmac(aes-asm)\" \
		KCAPI_ECB_TDES=\"ecb(des3_ede-asm)\" \
		KCAPI_CBC_TDES=\"cbc(des3_ede-asm)\" \
		KCAPI_CTR_TDES=\"ctr(des3_ede-asm)\" \
		KCAPI_CMAC_TDES=\"cmac(des3_ede-asm)\""
CIPHER_CALL_CFB_X86ASM_C="
		KCAPI_CFB8_AES=\"cfb(aes-asm)\" \
		KCAPI_CFB128_AES=\"cfb(aes-asm)\""
CIPHER_CALL_RFC4106IIV_X86ASM_C="KCAPI_CBC_AES=\"cbc(aes-asm)\" \
		KCAPI_ECB_AES=\"ecb(aes-asm)\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106(gcm_base(ctr(aes-asm),ghash-generic))")\""
CIPHER_CALL_RFC4106EIV_X86ASM_C="KCAPI_CBC_AES=\"cbc(aes-asm)\" \
		KCAPI_ECB_AES=\"ecb(aes-asm)\" \
		KCAPI_GCM_AES=\"rfc4106(gcm_base(ctr(aes-asm),ghash-generic))\""

# s390 CPACF assembler cipher and C block chaining modes
CIPHER_CALL_s390x_CPACF_C="KCAPI_GCM_AES=\"gcm_base(ctr(aes-s390),ghash-generic)\" \
		KCAPI_CCM_AES=\"ccm_base(ctr(aes-s390),$(cbcmac_name "aes-s390"))\" \
		KCAPI_CBC_AES=\"cbc(aes-s390)\" \
		KCAPI_CTR_AES=\"ctr(aes-s390)\" \
		KCAPI_ECB_AES=\"ecb(aes-s390)\" \
		KCAPI_XTS_AES=\"$(xts_name "aes-s390")\" \
		KCAPI_KW_AES=\"kw(aes-s390)\" \
		KCAPI_CMAC_AES=\"cmac(aes-s390)\" \
		KCAPI_CBC_TDES=\"cbc(des3_ede-s390)\" \
		KCAPI_CTR_TDES=\"ctr(des3_ede-s390)\" \
		KCAPI_ECB_TDES=\"ecb(des3_ede-s390)\" \
		KCAPI_CMAC_TDES=\"cmac(des3_ede-s390)\" \
		KCAPI_SHA1=\"sha1-s390\" \
		KCAPI_SHA224=\"sha224-s390\" \
		KCAPI_SHA256=\"sha256-s390\" \
		KCAPI_SHA384=\"sha384-s390\" \
		KCAPI_SHA512=\"sha512-s390\""
CIPHER_CALL_CFB_CPACF_C="
		KCAPI_CFB8_AES=\"cfb(aes-s390)\" \
		KCAPI_CFB128_AES=\"cfb(aes-s390)\""
CIPHER_CALL_RFC4106IIV_CPACF_C="KCAPI_CBC_AES=\"cbc(aes-s390)\" \
		KCAPI_ECB_AES=\"ecb(aes-s390)\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106(gcm_base(ctr-aes-s390,ghash-generic))")\""
CIPHER_CALL_RFC4106EIV_CPACF_C="KCAPI_CBC_AES=\"cbc(aes-s390)\" \
		KCAPI_ECB_AES=\"ecb(aes-s390)\" \
		KCAPI_GCM_AES=\"rfc4106(gcm_base(ctr-aes-s390,ghash-generic))\""

# s390 CPACF assembler cipher and assembler block chaining modes
CIPHER_CALL_CPACF_ASM="KCAPI_GCM_AES=\"gcm_base(ctr-aes-s390,ghash-s390)\" \
		KCAPI_CCM_AES=\"ccm_base(ctr-aes-s390,$(cbcmac_name "aes-s390"))\" \
		KCAPI_CBC_AES=\"cbc-aes-s390\" \
		KCAPI_CTR_AES=\"ctr-aes-s390\" \
		KCAPI_ECB_AES=\"ecb-aes-s390\" \
		KCAPI_XTS_AES=\"xts-aes-s390\" \
		KCAPI_CBC_TDES=\"cbc-des3_ede-s390\" \
		KCAPI_ECB_TDES=\"ecb-des3_ede-s390\" \
		KCAPI_CTR_TDES=\"ctr-des3_ede-s390\""
CIPHER_CALL_RFC4106IIV_CPACF_ASM="KCAPI_CBC_AES=\"cbc-aes-s390\" \
		KCAPI_ECB_AES=\"ecb-aes-s390\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106(gcm_base(ctr-aes-s390,ghash-s390))")\""
CIPHER_CALL_RFC4106EIV_CPACF_ASM="KCAPI_CBC_AES=\"cbc-aes-s390\" \
		KCAPI_ECB_AES=\"ecb-aes-s390\" \
		KCAPI_GCM_AES=\"rfc4106(gcm_base(ctr-aes-s390,ghash-s390))\""

# AESNI cipher and C block chaining modes
CIPHER_CALL_AESNI_C="KCAPI_GCM_AES=\"gcm_base(ctr-aes-aesni,ghash-clmulni)\" \
		KCAPI_CCM_AES=\"ccm_base(ctr-aes-aesni,$(cbcmac_name "aes-aesni"))\" \
		KCAPI_CBC_AES=\"cbc(aes-aesni)\" \
		KCAPI_CTR_AES=\"ctr(aes-aesni)\" \
		KCAPI_ECB_AES=\"ecb(aes-aesni)\" \
		KCAPI_XTS_AES=\"$(xts_name "aes-aesni")\" \
		KCAPI_KW_AES=\"kw(aes-aesni)\" \
		KCAPI_CMAC_AES=\"cmac(aes-aesni)\""
CIPHER_CALL_CFB_AESNI_C="
		KCAPI_CFB8_AES=\"cfb(aes-aesni)\" \
		KCAPI_CFB128_AES=\"cfb(aes-aesni)\""
CIPHER_CALL_RFC4106IIV_AESNI_C="KCAPI_CBC_AES=\"cbc(aes-aesni)\" \
		KCAPI_ECB_AES=\"ecb(aes-aesni)\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106(gcm_base(ctr(aes-aesni),ghash-clmulni))")\""
CIPHER_CALL_RFC4106EIV_AESNI_C="KCAPI_CBC_AES=\"cbc(aes-aesni)\" \
		KCAPI_ECB_AES=\"ecb(aes-aesni)\" \
		KCAPI_GCM_AES=\"rfc4106(gcm_base(ctr(aes-aesni),ghash-clmulni))\""

# AESNI cipher and assembler block chaining modes
CIPHER_CALL_AESNI_ASM="KCAPI_GCM_AES=\"rfc4106-gcm-aesni\" \
		KCAPI_CBC_AES=\"cbc-aes-aesni\" \
		KCAPI_CTR_AES=\"ctr-aes-aesni\" \
		KCAPI_ECB_AES=\"ecb-aes-aesni\" \
		KCAPI_XTS_AES=\"xts-aes-aesni\""

# AESNI GCM tests with internal IV generation
CIPHER_CALL_RFC4106IIV_AESNI_ASM="KCAPI_CBC_AES=\"cbc-aes-aesni\" \
		KCAPI_ECB_AES=\"ecb-aes-aesni\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106-gcm-aesni")\""

# AESNI GCM tests with external IV generation
CIPHER_CALL_RFC4106EIV_AESNI_ASM="KCAPI_CBC_AES=\"cbc-aes-aesni\" \
		KCAPI_ECB_AES=\"ecb-aes-aesni\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106-gcm-aesni")\""

CIPHER_CALL_RFC4106IIV_C_C="KCAPI_CBC_AES=\"cbc(aes-generic)\" \
		KCAPI_ECB_AES=\"ecb(aes-generic)\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106(gcm_base(ctr(aes-generic),ghash-generic))")\""
CIPHER_CALL_RFC4106EIV_C_C="KCAPI_CBC_AES=\"cbc(aes-generic)\" \
		KCAPI_ECB_AES=\"ecb(aes-generic)\" \
		KCAPI_GCM_AES=\"rfc4106(gcm_base(ctr(aes-generic),ghash-generic))\""

# C cipher using constant time AES with C block chaining modes
CIPHER_CALL_CTI_C="KCAPI_GCM_AES=\"gcm_base(ctr(aes-fixed-time),ghash-generic)\" \
		KCAPI_CCM_AES=\"ccm_base(ctr(aes-fixed-time),$(cbcmac_name "aes-fixed-time"))\" \
		KCAPI_CBC_AES=\"cbc(aes-fixed-time)\" \
		KCAPI_CTR_AES=\"ctr(aes-fixed-time)\" \
		KCAPI_ECB_AES=\"ecb(aes-fixed-time)\" \
		KCAPI_XTS_AES=\"$(xts_name "aes-fixed-time")\" \
		KCAPI_KW_AES=\"kw(aes-fixed-time)\" \
		KCAPI_CMAC_AES=\"cmac(aes-fixed-time)\""
CIPHER_CALL_CFB_CTI_C="
		KCAPI_CFB8_AES=\"cfb(aes-fixed-time)\" \
		KCAPI_CFB128_AES=\"cfb(aes-fixed-time)\""
CIPHER_CALL_RFC4106IIV_CTI_C="KCAPI_CBC_AES=\"cbc(aes-fixed-time)\" \
		KCAPI_ECB_AES=\"ecb(aes-fixed-time)\" \
		KCAPI_GCM_AES=\"$(iiv_name "rfc4106(gcm_base(ctr(aes-fixed-time),ghash-generic))")\"="
CIPHER_CALL_RFC4106EIV_CTI_C="KCAPI_CBC_AES=\"cbc(aes-fixed-time)\" \
		KCAPI_ECB_AES=\"ecb(aes-fixed-time)\" \
		KCAPI_GCM_AES=\"rfc4106(gcm_base(ctr(aes-fixed-time),ghash-generic))\""

################### SHA TESTS #######################

CIPHER_CALL_SSSE3="KCAPI_SHA1=\"sha1-ssse3\" \
		KCAPI_SHA224=\"sha224-ssse3\" \
		KCAPI_SHA256=\"sha256-ssse3\" \
		KCAPI_SHA384=\"sha384-ssse3\" \
		KCAPI_SHA512=\"sha512-ssse3\" \
		KCAPI_HMAC_SHA1=\"hmac(sha1-ssse3)\" \
		KCAPI_HMAC_SHA224=\"hmac(sha224-ssse3)\" \
		KCAPI_HMAC_SHA256=\"hmac(sha256-ssse3)\" \
		KCAPI_HMAC_SHA384=\"hmac(sha384-ssse3)\" \
		KCAPI_HMAC_SHA512=\"hmac(sha512-ssse3)\""

CIPHER_CALL_AVX="KCAPI_SHA1=\"sha1-avx\" \
		KCAPI_SHA224=\"sha224-avx\" \
		KCAPI_SHA256=\"sha256-avx\" \
		KCAPI_SHA384=\"sha384-avx\" \
		KCAPI_SHA512=\"sha512-avx\" \
		KCAPI_HMAC_SHA1=\"hmac(sha1-avx)\" \
		KCAPI_HMAC_SHA224=\"hmac(sha224-avx)\" \
		KCAPI_HMAC_SHA256=\"hmac(sha256-avx)\" \
		KCAPI_HMAC_SHA384=\"hmac(sha384-avx)\" \
		KCAPI_HMAC_SHA512=\"hmac(sha512-avx)\""

CIPHER_CALL_AVX2="KCAPI_SHA1=\"sha1-avx2\" \
		KCAPI_SHA224=\"sha224-avx2\" \
		KCAPI_SHA256=\"sha256-avx2\" \
		KCAPI_SHA384=\"sha384-avx2\" \
		KCAPI_SHA512=\"sha512-avx2\" \
		KCAPI_HMAC_SHA1=\"hmac(sha1-avx2)\" \
		KCAPI_HMAC_SHA224=\"hmac(sha224-avx2)\" \
		KCAPI_HMAC_SHA256=\"hmac(sha256-avx2)\" \
		KCAPI_HMAC_SHA384=\"hmac(sha384-avx2)\" \
		KCAPI_HMAC_SHA512=\"hmac(sha512-avx2)\""

CIPHER_CALL_MB="KCAPI_SHA1=\"sha1_mb\" \
		KCAPI_SHA256=\"sha256_mb\" \
		KCAPI_SHA512=\"sha512_mb\""

################### TDES TESTS #####################

CIPHER_CALL_X86ASM_ASM="KCAPI_ECB_TDES=\"ecb-des3_ede-asm\" \
		KCAPI_CBC_TDES=\"cbc-des3_ede-asm\" \
		KCAPI_CTR_TDES=\"ctr-des3_ede-asm\""

CIPHER_CALL_X86ASM_ASM_NO_TDES_CTR=${CIPHER_CALL_X86ASM_ASM}

################### Catchall #####################

# C ciphers with C block chaining modes
CIPHER_CALL_C_C="KCAPI_GCM_AES=\"gcm_base(ctr(aes-generic),ghash-generic)\" \
		KCAPI_CCM_AES=\"ccm_base(ctr(aes-generic),$(cbcmac_name "aes-generic"))\" \
		KCAPI_CBC_AES=\"cbc(aes-generic)\" \
		KCAPI_CTR_AES=\"ctr(aes-generic)\" \
		KCAPI_ECB_AES=\"ecb(aes-generic)\" \
		KCAPI_XTS_AES=\"$(xts_name "aes-generic")\" \
		KCAPI_KW_AES=\"kw(aes-generic)\" \
		KCAPI_CMAC_AES=\"cmac(aes-generic)\" \
		KCAPI_CBC_TDES=\"cbc(des3_ede-generic)\" \
		KCAPI_CTR_TDES=\"ctr(des3_ede-generic)\" \
		KCAPI_ECB_TDES=\"ecb(des3_ede-generic)\" \
		KCAPI_CMAC_TDES=\"cmac(des3_ede-generic)\" \
		KCAPI_SHA1=\"sha1-generic\" \
		KCAPI_SHA224=\"sha224-generic\" \
		KCAPI_SHA256=\"sha256-generic\" \
		KCAPI_SHA384=\"sha384-generic\" \
		KCAPI_SHA512=\"sha512-generic\" \
		KCAPI_HMAC_SHA1=\"hmac(sha1-generic)\" \
		KCAPI_HMAC_SHA224=\"hmac(sha224-generic)\" \
		KCAPI_HMAC_SHA256=\"hmac(sha256-generic)\" \
		KCAPI_HMAC_SHA384=\"hmac(sha384-generic)\" \
		KCAPI_HMAC_SHA512=\"hmac(sha512-generic)\""

CIPHER_CALL_CFB_C_C="
		KCAPI_CFB8_AES=\"cfb(aes-generic)\" \
		KCAPI_CFB128_AES=\"cfb(aes-generic)\""

CIPHER_CALL_SHA3_C_C="
		KCAPI_SHA3_224=\"sha3-224-generic\" \
		KCAPI_SHA3_256=\"sha3-256-generic\" \
		KCAPI_SHA3_384=\"sha3-384-generic\" \
		KCAPI_SHA3_512=\"sha3-512-generic\" \
		KCAPI_HMAC_SHA3_224=\"hmac(sha3-224-generic)\" \
		KCAPI_HMAC_SHA3_256=\"hmac(sha3-256-generic)\" \
		KCAPI_HMAC_SHA3_384=\"hmac(sha3-384-generic)\" \
		KCAPI_HMAC_SHA3_512=\"hmac(sha3-512-generic)\""

################### Heavy Lifting #######################

failures=0
do_test() {
	PATH=.:$PATH

	for exec in $EXEC; do
		eval CIPHER_CALL=\$CIPHER_CALL_$exec

		if [ -z "$CIPHER_CALL" ]
		then
			echo "WARNING, no definitions for $exec!"
		fi

		local modulename="${MODULE_PREFIX}${exec}${MODULE_POSTFIX}"

		eval "$CIPHER_CALL exec_module ${modulename} X ${PROC}"
	done
}

for i in sha1-ssse3 sha256-ssse3 sha512-ssse3 sha1_mb sha512_mb sha256_mb des3_ede-x86_64 aes_ti; do
	sudo modprobe $i > /dev/null 2>&1
done

optmem_max=$(cat /proc/sys/net/core/optmem_max)
if [ $optmem_max -lt 81920 ]; then
	id=$(id -u)
	if [ $id -ne 0 ]
	then
		echo "Either execute as root or set /proc/sys/net/core/optmem_max to 81920"
		exit 1
	fi
	trap "echo $optmem_max | sudo tee /proc/sys/net/core/optmem_max > /dev/null" 0 1 2 3 15
	echo 81920 | sudo tee /proc/sys/net/core/optmem_max > /dev/null
	# Make sure to reset it back to normal after the program exits
fi

do_test
exit $failures
