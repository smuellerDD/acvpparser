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

TARGET="openssl"

MODULE_PREFIX="OpenSSL_"
MODULE_POSTFIX="_"

if $(echo $0 | grep -q "_openssl_3")
then
       MODULE_PREFIX="OpenSSL_3_"
fi

if [[ "$(openssl version | awk '{print $2}')" =~ 3\..* ]]; then
	MODULE_PREFIX="OpenSSL_3_"
fi

EXEC_TYPES_DRBG10X__64_bit___="CFLAGS=-DOPENSSL_DRBG_10X"
EXEC_TYPES_DRBG10X__32_bit___="CFLAGS=\"-m32 -DOPENSSL_DRBG_10X\" LDFLAGS=-m32"

#	Algorithm Implementations for supported platforms

# Environment variable evaluated by ACVP Parser
CIPHER_CALL_FFC_DH="OPENSSL_ACVP_DH_KEYGEN=1"

#	Common implementations

# See lib/module_implementations/definition_impl_openssl.c in acvpproxy
EXEC_COMMON="TDES_C KBKDF KBKDF_3_1 KDA ECDSA_K_B ECDSA_SHA3_K_B ECDH_K_B TLS_v1_3 FFC_DH DRBG_3 EDDSA EDDSA_3_2"

if [ $(uname -m) = "s390x" ]; then
	#	Implementations for s390x

	EXEC="$EXEC_COMMON
		AES_CPACF AESASM AESGCM_CPACF
		AESGCM_ASM_CPACF AESGCM_ASM_ASM
		SHA_CPACF SSH_CPACF SHA_ASM SSH_ASM
		SHA3_CPACF SHA3_ASM"

	# See https://www.openssl.org/docs/man3.0/man3/OPENSSL_s390xcap.html
	CM_s390x_KIMD_SHA="kimd:~0x70000000FC000000:~0x0"
	CM_s390x_KIMD_GHASH="kimd:~0x0:~0x4000000000000000"
	CM_s390x_KIMD="kimd:~0x70000000FC000000:~0x4000000000000000"
	CM_s390x_KLMD="klmd:~0x00000000FC000000:~0x0"
	CM_s390x_KM="km:~0x0000380000002800:~0x0"
	CM_s390x_KMC="kmc:~0x0000380000000000:~0x0"
	CM_s390x_KMAC="kmac:~0x0000380000000000:~0x0"
	CM_s390x_KMO="kmo:~0x0000380000000000:~0x0"
	CM_s390x_KMF="kmf:~0x0000380000000000:~0x0"
	CM_s390x_KMA="kma:~0x0000380000000000:~0x0"
	CM_s390x_PCC="pcc:~0xE0C0C00000000000:~0x0"
	CM_s390x_KDSA="kdsa:~0x7070000088880000:~0x0"
	CM_s390x_NOPAI="$CM_s390x_KIMD;$CM_s390x_KLMD;$CM_s390x_KM;$CM_s390x_KMC;$CM_s390x_KMAC;$CM_s390x_KMO;$CM_s390x_KMF;$CM_s390x_KMA;$CM_s390x_PCC;$CM_s390x_KDSA"

	CIPHER_CALL_AES_CPACF=""
	CIPHER_CALL_AESASM="OPENSSL_s390xcap=\"$CM_s390x_NOPAI\""

	CIPHER_CALL_AESGCM_CPACF=""
	# Turns off KMA capabilities (CPACF AES GCM) and leave KIMD (CPACF GHASH) enabled.
	CIPHER_CALL_AESGCM_ASM_CPACF="OPENSSL_s390xcap=\"$CM_s390x_KMA\""
	# Turns off all CPACF capabilities.
	CIPHER_CALL_AESGCM_ASM_ASM="OPENSSL_s390xcap=\"$CM_s390x_NOPAI\""

	CIPHER_CALL_SHA_CPACF=""
	CIPHER_CALL_SSH_CPACF=""
	CIPHER_CALL_SHA_ASM="OPENSSL_s390xcap=\"$CM_s390x_NOPAI\""
	CIPHER_CALL_SSH_ASM="OPENSSL_s390xcap=\"$CM_s390x_NOPAI\""

	CIPHER_CALL_SHA3_CPACF=""
	CIPHER_CALL_SHA3_ASM="OPENSSL_s390xcap=\"$CM_s390x_NOPAI\""
	
elif [ $(uname -m) = "aarch64" -o $(uname -m) = "arm64" ]; then
	#	Implementations for ARM

	EXEC="$EXEC_COMMON
		CE VPAES AES_C
		CE_GCM_UNROLL8_EOR3 CE_GCM VPAES_GCM AES_C_GCM
		SHA_CE NEON SHA_ASM SSH_ASM
		SHA3_CE SHA3_ASM"

	# Unlike for s390x and x86, OPENSSL_armcap is taken at face value.
	# Note that we can't simply set the bits in the environment variable and pass it to OpenSSL, as this would cause invalid instruction errors.
	# Therefore, we first construct OPENSSL_armcap as OpenSSL would see it, and then mask off bits.
	# See crypto/arm_arch.h.
	armcap=0
	if [ $(uname -m) = "aarch64" ]; then
		lscpu | grep "Flags" | grep -q "asimd" && armcap=$((armcap | (1 << 0)))
		lscpu | grep "Flags" | grep -q "neon" && armcap=$((armcap | (1 << 0)))
		lscpu | grep "Flags" | grep -q "aes" && armcap=$((armcap | (1 << 2)))
		lscpu | grep "Flags" | grep -q "sha1" && armcap=$((armcap | (1 << 3)))
		lscpu | grep "Flags" | grep -q "sha2" && armcap=$((armcap | (1 << 4)))
		lscpu | grep "Flags" | grep -q "pmull" && armcap=$((armcap | (1 << 5)))
		lscpu | grep "Flags" | grep -q "sha512" && armcap=$((armcap | (1 << 6)))
		lscpu | grep "Flags" | grep -q "cpuid" && armcap=$((armcap | (1 << 7)))
		lscpu | grep "Flags" | grep -q "rng" && armcap=$((armcap | (1 << 8)))
		lscpu | grep "Flags" | grep -q "sm3" && armcap=$((armcap | (1 << 9)))
		lscpu | grep "Flags" | grep -q "sm4" && armcap=$((armcap | (1 << 10)))
		if lscpu | grep "Flags" | grep -q "sha3"; then
			armcap=$((armcap | (1 << 11)))
			# The CPUs below support ARMV8_UNROLL8_EOR3.
			cat /proc/cpuinfo | grep "CPU part" | grep -q "0xd40" && armcap=$((armcap | (1 << 12)))
			cat /proc/cpuinfo | grep "CPU part" | grep -q "0xd49" && armcap=$((armcap | (1 << 12)))
			cat /proc/cpuinfo | grep "CPU part" | grep -q "0xd4f" && armcap=$((armcap | (1 << 12)))
		fi
		lscpu | grep "Flags" | grep -q "sve" && armcap=$((armcap | (1 << 13)))
		lscpu | grep "Flags" | grep -q "sve2" && armcap=$((armcap | (1 << 14)))
	else
		# Apple Silicon has had all of these since the start.
		armcap=$((armcap | (1 << 0)))
		armcap=$((armcap | (1 << 0)))
		armcap=$((armcap | (1 << 2)))
		armcap=$((armcap | (1 << 3)))
		armcap=$((armcap | (1 << 4)))
		armcap=$((armcap | (1 << 5)))
		sysctl -n "hw.optional.armv8_2_sha512" | grep -q "1" && armcap=$((armcap | (1 << 6)))
		if sysctl -n "hw.optional.armv8_2_sha3" | grep -q "1"; then
			armcap=$((armcap | (1 << 11)))
			# The CPUs below support ARMV8_UNROLL8_EOR3.
			sysctl -n "machdep.cpu.brand_string" | grep -q "Apple M1" && armcap=$((armcap | (1 << 12)))
			sysctl -n "machdep.cpu.brand_string" | grep -q "Apple M2" && armcap=$((armcap | (1 << 12)))
			# The CPUs below support ARMv8.2 SHA-3 and it is used by OpenSSL.
			sysctl -n "machdep.cpu.brand_string" | grep -q "Apple M1" && armcap=$((armcap | (1 << 15)))
			sysctl -n "machdep.cpu.brand_string" | grep -q "Apple M2" && armcap=$((armcap | (1 << 15)))
		fi
	fi

	# IMPORTANT: The OPENSSL_armcap environment variable does NOT support hex!

	# Used by default.
	CIPHER_CALL_CE="OPENSSL_armcap=$((armcap))"
	# Remove bit 2 (AES).
	CIPHER_CALL_VPAES="OPENSSL_armcap=$((armcap & ~0x04))"
	# Remove bit 2 (AES) and 0 (NEON).
	CIPHER_CALL_AES_C="OPENSSL_armcap=$((armcap & ~0x05))"

	# Used by default.
	CIPHER_CALL_CE_GCM_UNROLL8_EOR3="OPENSSL_armcap=$((armcap))"
	# Remove bit 12 (UNROLL8_EOR3).
	CIPHER_CALL_CE_GCM="OPENSSL_armcap=$((armcap & ~0x1000))"
	# Remove bit 12 (UNROLL8_EOR3), 2 (AES), and 5 (PMULL).
	CIPHER_CALL_VPAES_GCM="OPENSSL_armcap=$((armcap & ~0x1024))"
	# Remove bit 12 (UNROLL8_EOR3), 2 (AES), 5 (PMULL), and 0 (NEON).
	CIPHER_CALL_AES_C_GCM="OPENSSL_armcap=$((armcap & ~0x1025))"

	# Used by default.
	CIPHER_CALL_SHA_CE="OPENSSL_armcap=$((armcap))"
	# Remove bit 3 (SHA1), 4 (SHA256), and 6 (SHA512).
	CIPHER_CALL_NEON="OPENSSL_armcap=$((armcap & ~0x58))"
	# Remove bit 3 (SHA1), 4 (SHA256), 6 (SHA512), and 0 (NEON).
	CIPHER_CALL_SHA_ASM="OPENSSL_armcap=$((armcap & ~0x59))"
	CIPHER_CALL_SSH_ASM=$CIPHER_CALL_SHA_ASM

	# Used by default.
	CIPHER_CALL_SHA3_CE="OPENSSL_armcap=$((armcap))"
	# Remove bit 15 (SHA3_AND_WORTH_USING), 11 (SHA3), and 0 (NEON).
	CIPHER_CALL_SHA3_ASM="OPENSSL_armcap=$((armcap & ~0x8801))"

elif [ $(uname -m) = "ppc" -o $(uname -m) = "ppc64" -o $(uname -m) = "ppcle" -o $(uname -m) = "ppc64le" ]; then
	#	Implementations for PPC

	EXEC="$EXEC_COMMON 
		AESASM AESASM_ASM SHA_ASM SSH_ASM SHA3_ASM
		AES_ISA AES_ISA_ASM SHA_ISA SSH_ISA
		AES_Altivec AES_Altivec_ASM"

	# IMPORTANT: The OPENSSL_ppccap environment variable does NOT support hex!

	# Used by default.
	CIPHER_CALL_AES_ISA_ASM="OPENSSL_ppccap=22"
	CIPHER_CALL_AES_ISA="OPENSSL_ppccap=6"
	CIPHER_CALL_SHA_ISA="OPENSSL_ppccap=6"
	CIPHER_CALL_SSH_ISA="OPENSSL_ppccap=6"
	CIPHER_CALL_AES_Altivec="OPENSSL_ppccap=2"
	CIPHER_CALL_AES_Altivec_ASM="OPENSSL_ppccap=2"
	CIPHER_CALL_AESASM="OPENSSL_ppccap=0"
	CIPHER_CALL_AESASM_ASM="OPENSSL_ppccap=0"
	CIPHER_CALL_SHA_ASM="OPENSSL_ppccap=0"
	CIPHER_CALL_SSH_ASM="OPENSSL_ppccap=0"
	CIPHER_CALL_SHA3_ASM="OPENSSL_ppccap=0"

else
	#	Implementations for x86

	EXEC="$EXEC_COMMON
		AESNI BAES_CTASM AESASM
		AESNI_AVX AESNI_CLMULNI AESNI_ASM
		BAES_CTASM_AVX BAES_CTASM_CLMULNI BAES_CTASM_ASM
		AESASM_AVX AESASM_CLMULNI AESASM_ASM
		SHA_SHANI SSH_SHANI SHA_AVX2 SSH_AVX2 SHA_AVX SSH_AVX SHA_SSSE3 SSH_SSSE3 SHA_ASM SSH_ASM
		SHA3_AVX512VL SHA3_AVX512 SHA3_AVX2 SHA3_ASM"

	# See https://www.openssl.org/docs/man3.0/man3/OPENSSL_ia32cap.html

	# Used by default.
	CIPHER_CALL_AESNI=""
	# Remove bit 57 (AES-NI).
	CIPHER_CALL_BAES_CTASM="OPENSSL_ia32cap=~0x0200000000000000:~0x0"
	# Remove bit 57 (AES-NI) and 41 (SSSE3).
	CIPHER_CALL_AESASM="OPENSSL_ia32cap=~0x0200020000000000:~0x0"

	# Used by default.
	CIPHER_CALL_AESNI_AVX=""
	# Remove bit 54 (MOVBE), 60 (AVX), 64+16/17/21/30/31 (AVX512), 64+41 (VAES), and 64+42(VPCLMULQDQ).
	CIPHER_CALL_AESNI_CLMULNI="OPENSSL_ia32cap=~0x1040000000000000:~0x00000600C0230000"
	# Remove bit 54 (MOVBE), 60 (AVX), 33 (PCLMULQDQ), 64+16/17/21/30/31 (AVX512), 64+41 (VAES), and 64+42(VPCLMULQDQ).
	CIPHER_CALL_AESNI_ASM="OPENSSL_ia32cap=~0x1040000200000000:~0x00000600C0230000"
	# Remove bit 57 (AES-NI).
	CIPHER_CALL_BAES_CTASM_AVX="OPENSSL_ia32cap=~0x0200000000000000:~0x0"
	# Remove bit 57 (AES-NI), 54 (MOVBE), 60 (AVX), 64+16/17/21/30/31 (AVX512), 64+41 (VAES), and 64+42(VPCLMULQDQ).
	CIPHER_CALL_BAES_CTASM_CLMULNI="OPENSSL_ia32cap=~0x1240000000000000:~0x00000600C0230000"
	# Remove bit 57 (AES-NI), 54 (MOVBE), 60 (AVX), 33 (PCLMULQDQ), 64+16/17/21/30/31 (AVX512), 64+41 (VAES), and 64+42(VPCLMULQDQ).
	CIPHER_CALL_BAES_CTASM_ASM="OPENSSL_ia32cap=~0x1240000200000000:~0x00000600C0230000"
	# Remove bit 57 (AES-NI) and 41 (SSSE3).
	CIPHER_CALL_AESASM_AVX="OPENSSL_ia32cap=~0x0200020000000000:~0x0"
	# Remove bit 57 (AES-NI), 41 (SSSE3), 54 (MOVBE), 60 (AVX), 64+16/17/21/30/31 (AVX512), 64+41 (VAES), and 64+42(VPCLMULQDQ).
	CIPHER_CALL_AESASM_CLMULNI="OPENSSL_ia32cap=~0x1240020000000000:~0x00000600C0230000"
	# Remove bit 57 (AES-NI), 41 (SSSE3), 54 (MOVBE), 60 (AVX), 33 (PCLMULQDQ), 64+16/17/21/30/31 (AVX512), 64+41 (VAES), and 64+42(VPCLMULQDQ).
	CIPHER_CALL_AESASM_ASM="OPENSSL_ia32cap=~0x1240020200000000:~0x00000600C0230000"

	# Used by default.
	CIPHER_CALL_SHA_SHANI=""
	CIPHER_CALL_SSH_SHANI=$CIPHER_CALL_SHA_SHANI
	# Remove bit 64+29 (SHA-NI) and 64+16/17/21/30/31 (AVX512).
	CIPHER_CALL_SHA_AVX2="OPENSSL_ia32cap=~0x0:~0x00000000E0230000"
	CIPHER_CALL_SSH_AVX2=$CIPHER_CALL_SHA_AVX2
	# Remove bit 64+29 (SHA-NI), 64+16/17/21/30/31 (AVX512), 64+5 (AVX2), and 64+3/8 (BMI).
	CIPHER_CALL_SHA_AVX="OPENSSL_ia32cap=~0x0:~0x00000000E0230128"
	CIPHER_CALL_SSH_AVX=$CIPHER_CALL_SHA_AVX
	# Remove bit 64+29 (SHA-NI), 64+16/17/21/30/31 (AVX512), 64+5 (AVX2), 64+3/8 (BMI), and 60 (AVX).
	CIPHER_CALL_SHA_SSSE3="OPENSSL_ia32cap=~0x1000000000000000:~0x00000000E0230128"
	CIPHER_CALL_SSH_SSSE3=$CIPHER_CALL_SHA_SSSE3
	# Remove bit 64+29 (SHA-NI), 64+16/17/21/30/31 (AVX512), 64+5 (AVX2), 64+3/8 (BMI), 60 (AVX), and 41 (SSSE3).
	CIPHER_CALL_SHA_ASM="OPENSSL_ia32cap=~0x1000020000000000:~0x00000000E0230128"
	CIPHER_CALL_SSH_ASM=$CIPHER_CALL_SHA_ASM

	# OpenSSL doesn't actually use acceleration for SHA-3 yet.
	# Still, we can imagine a kind of precedence as follows:
	# Used by default.
	CIPHER_CALL_SHA3_AVX512VL=""
	# Remove bit 64+31 (AVX512VL).
	CIPHER_CALL_SHA3_AVX512="OPENSSL_ia32cap=~0x0:~0x0000000080000000"
	# Remove bit 64+29 (SHA-NI) and 64+16/17/21/30/31 (AVX512).
	CIPHER_CALL_SHA3_AVX2="OPENSSL_ia32cap=~0x0:~0x00000000E0230000"
	# Remove bit 64+29 (SHA-NI), 64+16/17/21/30/31 (AVX512), 64+5 (AVX2), 64+3/8 (BMI), 60 (AVX), and 41 (SSSE3).
	CIPHER_CALL_SHA3_ASM="OPENSSL_ia32cap=~0x1000020000000000:~0x00000000E0230128"

fi

################### Heavy Lifting #######################

do_test() {
	PATH=.:$PATH

	for type in $EXEC_TYPES; do
		eval BUILD_FLAGS=\$EXEC_TYPES_$type

		eval "$BUILD_FLAGS build_tool ${TARGET}"

		for exec in $EXEC; do
			echo "Processing [$exec]"
			eval CIPHER_CALL=\${CIPHER_CALL_${exec}} 2> /dev/null

			local modulename="${MODULE_PREFIX}${type}${exec}${MODULE_POSTFIX}"

			eval "$CIPHER_CALL exec_module ${modulename}"
		done

		clean_tool
	done
}

do_test_drbg10x() {
	PATH=.:$PATH

	for type in $EXEC_TYPES; do
		eval BUILD_FLAGS=\$EXEC_TYPES_DRBG10X_$type

		eval "$BUILD_FLAGS build_tool ${TARGET}"

		local modulename="${MODULE_PREFIX}${type}DRBG_10X${MODULE_POSTFIX}"

		eval "exec_module ${modulename}"

		clean_tool
	done
}

do_test
do_test_drbg10x
exit $failures
