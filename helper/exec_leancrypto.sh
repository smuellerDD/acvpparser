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

MODULE_PREFIX="leancrypto__"
MODULE_POSTFIX="_"

EXEC="without_PAA_-_C_implementation"

if [ $(uname -m) = "aarch64" -o $(uname -m) = "arm64" ]; then
	EXEC="$EXEC
	      with_PAA_-_ARM_CE_implementation without_PAA_-_ARM_ASM_implementation without_PAA_-_ARM_2X_implementation"
elif [ $(uname -m) = "riscv64" ]; then
	EXEC="$EXEC
	      without_PAA_-_RISCV64_implementation without_PAA_-_RISCV64_ZBB_implementation without_PAA_-_RISCV64_RVV_implementation"
elif (uname -m | grep -q armv7 ); then
	EXEC="$EXEC
	      without_PAA_-_ARM_NEON_implementation"
elif [ $(uname -m) = "x86_64" ]; then
	EXEC="$EXEC
	      without_PAA_-_AVX2_implementation without_PAA_-_AVX512_implementation without_PAA_-_AVX2_4X_implementation with_PAA_-_AESNI_implementation"
fi

CIPHER_CALL_without_PAA__C_implementation="LC_AES=\"C\" LC_AES_GCM=\"C\" LC_SHA3=\"C\" LC_DILITHIUM=\"C\" LC_KYBER=\"C\""
CIPHER_CALL_without_PAA__AVX2_implementation="LC_SHA3=\"AVX2\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_without_PAA__AVX512_implementation="LC_SHA3=\"AVX512\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_with_PAA__AESNI_implementation="LC_SHA3=\"AESNI\" LC_AES=\"AESNI\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_without_PAA__ARM_NEON_implementationN="LC_SHA3=\"ARM_NEON\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_with_PAA__ARM_CE_implementation="LC_AES=\"ARM_CE\" LC_SHA3=\"ARM_CE\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_without_PAA__ARM_ASM_implementation="LC_AES=\"ARM_ASM\" LC_SHA3=\"ARM_ASM\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_without_PAA__AVX2_4X_implementation="LC_SHAKE=\"AVX2-4X\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_without_PAA__ARM_2X_implementation="LC_SHAKE=\"ARM-2X\" LC_DILITHIUM=\"common\" LC_KYBER=\"common\""
CIPHER_CALL_without_PAA__RISCV64_implementation="LC_AES=\"RISCV64\" LC_SHA3=\"RISCV64\" LC_DILITHIUM=\"C\" LC_KYBER=\"C\""
CIPHER_CALL_without_PAA__RISCV64_ZBB_implementation="LC_SHA3=\"RISCV64_ZBB\""
CIPHER_CALL_without_PAA__RISCV64_RVV_implementation="LC_DILITHIUM=\"common\" LC_KYBER=\"common\""

do_test() {
	PATH=.:$PATH

	for exec in $EXEC; do

		eval CIPHER_CALL=\$CIPHER_CALL_$(echo $exec | sed 's/-//g')

		local modulename="${MODULE_PREFIX}${exec}${MODULE_POSTFIX}"
		eval "$CIPHER_CALL exec_module ${modulename}"
	done
}

build_tool "leancrypto"
do_test

########################################################

exit $failures
