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

EXEC="without_PAA_-_Kernel_C_implementation"

if [ $(uname -m) = "aarch64" -o $(uname -m) = "arm64" ]; then
	EXEC="$EXEC
	      with_PAA_-_Kernel_ARM_CE_implementation without_PAA_-_Kernel_ARM_ASM_implementation without_PAA_-_Kernel_ARM_2X_implementation"
elif [ $(uname -m) = "riscv64" ]; then
	EXEC="$EXEC
	      without_PAA_-_Kernel_RISCV64_implementation without_PAA_-_Kernel_RISCV64_ZBB_implementation without_PAA_-_Kernel_RISCV64_RVV_implementation"
elif (uname -m | grep -q armv7 ); then
	EXEC="$EXEC
	      without_PAA_-_Kernel_ARM_NEON_implementation"
elif [ $(uname -m) = "x86_64" ]; then
	EXEC="$EXEC
	      without_PAA_-_Kernel_AVX2_implementation without_PAA_-_Kernel_AVX512_implementation without_PAA_-_Kernel_AVX2_4X_implementation with_PAA_-_Kernel_AESNI_implementation"
fi

# The integer values must be consistent
# with proto_frontend_linux_kernel.c:getenv()
CIPHER_CALL_without_PAA__Kernel_C_implementation="ACVPPARSER_PROTOBUF_IMPL=\"1\""
CIPHER_CALL_without_PAA__Kernel_AVX2_implementation="ACVPPARSER_PROTOBUF_IMPL=\"4\""
CIPHER_CALL_without_PAA__Kernel_AVX512_implementation="ACVPPARSER_PROTOBUF_IMPL=\"5\""
CIPHER_CALL_with_PAA__Kernel_AESNI_implementation="ACVPPARSER_PROTOBUF_IMPL=\"2\""
CIPHER_CALL_without_PAA__Kernel_ARM_NEON_implementation="ACVPPARSER_PROTOBUF_IMPL=\"6\""
CIPHER_CALL_with_PAA__Kernel_ARM_CE_implementation="ACVPPARSER_PROTOBUF_IMPL=\"3\""
CIPHER_CALL_without_PAA__Kernel_ARM_ASM_implementation="ACVPPARSER_PROTOBUF_IMPL=\"7\""
CIPHER_CALL_without_PAA__Kernel_AVX2_4X_implementation="ACVPPARSER_PROTOBUF_IMPL=\"9\""
CIPHER_CALL_without_PAA__Kernel_ARM_2X_implementation="ACVPPARSER_PROTOBUF_IMPL=\"10\""
CIPHER_CALL_without_PAA__Kernel_RISCV64_implementation="ACVPPARSER_PROTOBUF_IMPL=\"11\""
CIPHER_CALL_without_PAA__Kernel_RISCV64_ZBB_implementation="ACVPPARSER_PROTOBUF_IMPL=\"12\""
CIPHER_CALL_without_PAA__Kernel_RISCV64_RVV_implementation="ACVPPARSER_PROTOBUF_IMPL=\"13\""

do_test() {
	PATH=.:$PATH

	for exec in $EXEC; do

		eval CIPHER_CALL=\$CIPHER_CALL_$(echo $exec | sed 's/-//g')

		local modulename="${MODULE_PREFIX}${exec}${MODULE_POSTFIX}"
		eval "$CIPHER_CALL exec_module ${modulename}"
	done
}

# To test the Linux kernel implementation, the protobuf backend has to be used.
# The following test system setup must be achieved:
# 1. compile the leancrypto kernel module and insmod it
# 2. compile the kernel version of ACVP-Proto and insmod it (make sure you have
#    enabled PROTOBUF_BACKEND_EXIM_DEBUGFS in backend_protobuf.c.
# 3. compile ACVP-Parser execute it with this very script - mind you it needs
#    access to DebugFS which today is typically mounted 0700 root:root. Either
#    change the permissions or execute this very script as root.
build_tool "protobuf"
do_test

########################################################

exit $failures
