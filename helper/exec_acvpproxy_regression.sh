#!/bin/bash
#
# Process all test vectors
#

. $(dirname $0)/exec_lib.sh

TARGET="acvpproxy"

build_tool ${TARGET}

MODULE_PREFIX="ACVPProxy__"
MODULE_POSTFIX="_"

EXEC="Common"

################### Heavy Lifting #######################

do_test() {
	PATH=.:$PATH

	for exec in $EXEC; do
		eval CIPHER_CALL=\$CIPHER_CALL_$exec

		local modulename="${MODULE_PREFIX}${exec}${MODULE_POSTFIX}"

		eval "$CIPHER_CALL regression_test ${modulename}"
	done
}

do_test
