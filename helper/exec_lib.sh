#!/bin/bash
#
# Execution helper library
#

_LIB_EXEC="./acvp-parser"
_LIB_IUT="testvectors"
_LIB_REQ="testvector-request.json"
_LIB_RESP="testvector-response.json"
#_LIB_OE="operational_environment.json"
_LIB_REGRESSION="${_LIB_RESP}.regression.$$"

failures=0

color()
{
	bg=0
	echo -ne "\033[0m"
	while [[ $# -gt 0 ]]; do
		code=0
		case $1 in
			black) code=30 ;;
			red) code=31 ;;
			green) code=32 ;;
			yellow) code=33 ;;
			blue) code=34 ;;
			magenta) code=35 ;;
			cyan) code=36 ;;
			white) code=37 ;;
			background|bg) bg=10 ;;
			foreground|fg) bg=0 ;;
			reset|off|default) code=0 ;;
			bold|bright) code=1 ;;
		esac
		[[ $code == 0 ]] || echo -ne "\033[$(printf "%02d" $((code+bg)))m"
		shift
	done
}

echo_pass()
{
	echo $(color "green")[PASSED]$(color off) $@
}

echo_fail()
{
	echo $(color "red")[FAILED]$(color off) $@
	failures=$(($failures+1))
}

echo_deact()
{
	echo $(color "yellow")[DEACTIVATED]$(color off) $@
}

build_tool()
{
	local target=$1

	if [ -z "$target" ]
	then
		echo "No module name provided, skipping"
		return
	fi

	make clean
	make -s $target
	ret=$?
	if [ $ret -ne 0 ]
	then
		echo "Build failed"
		exit $ret
	fi
}

get_proc_family() {
	local file=$1

	if [ -z "$file" ]
	then
		return
	fi

	if [ ! -f $file ]
	then
		return
	fi

	family=$(grep family $file | cut -d ":" -f 2 | cut -d"\"" -f 2)

	echo $family
}

# List of JSON keyword:value pairs to search for JSON test vectors known
# to be no known answer test and thus are unfit for regression testing
REGRESSION_VECTOR_SKIP="
	mode:keyGen
	mode:sigGen
	mode:pqgGen
	algorithm:KAS-FFC
	algorithm:KAS-ECC
	ivGen:internal"

#
# Execute testing
# $1 module name to be executed
# $2 if present, apply a regression test
# $3 if present, requested processor family
# $4 if present, search criteria for regression test (commonly an array of
#    vsIds)
exec_module()
{
	local module=$1
	shift
	local regression=$1
	shift
	local req_proc=$1
	shift
	local vsid=${@}

	local vendordir
	local i
	local j

	# If the script name contains "_regression" we switch into regression
	# mode transparently
	if $(echo $0 | grep -q "_regression")
       	then
	       regression="regression"
	fi

	if [ -z "$module" ]
	then
		echo "No module name provided, skipping"
		return
	fi

	if [ ! -d "${_LIB_IUT}" ]
	then
		echo "Test vector base directory ${_LUB_IUT} not found"
		return
	fi

	for vendordir in ${_LIB_IUT}/*
	do
		if [ ! -d "$vendordir" ]
		then
			continue
		fi

		local iutdir="$vendordir/$module"

		if [ ! -d "${iutdir}" ]
		then
			echo "No test vectors found for module $iutdir"
			continue
		fi

		for i in $(find ${iutdir} -name ${_LIB_REQ})
		do
			local dir=$(dirname $i)
			local vsid_dir=$(basename $dir)
			local testid_dir=$(dirname $dir)
			local found=0

			for j in $vsid
			do
				if [ "$j" = "$vsid_dir" ]
				then
					found=1
					break
				fi
			done

			# If no search vsids are given, execute testing
			if [ -z "$vsid" ]
			then
				found=1
			fi

			if [ $found -eq 0  ]
			then
				echo_deact "Skipping vsId $vsid_dir as it does not match search criteria"
				continue
			fi

#			if [ -n "$req_proc" -a x"$req_proc" != x"X" ]
#			then
#				local proc_family=$(get_proc_family "${testid_dir}/${_LIB_OE}")
#
#				if [ x"$req_proc" != x"$proc_family" ]
#				then
#					echo_deact "Skipping vsId $vsid_dir as requested processor type does not match defined processor"
#					continue
#				fi
#			fi


			if [ -f $dir/$_LIB_RESP -a -z "$regression" ]
			then
				echo_deact "Response file exists - skipping $dir"
				continue
			fi

			if [ -f $dir/$_LIB_RESP -a x"$regression" = x"X" ]
			then
				echo_deact "Response file exists - skipping $dir"
				continue
			fi

			if [ ! -f $dir/$_LIB_RESP -a -n "$regression" -a x"$regression" != x"X" ]
			then
				echo_deact "Response file missing but regression testing requested - skipping $dir"
				continue
			fi

			if [ ! -f $dir/$_LIB_REQ ]
			then
				echo_deact "Request file missing - skipping $dir"
				continue
			fi

			if (grep -q status $dir/$_LIB_REQ)
			then
				echo_deact "Request contains status information - skipping $dir"
				continue
			fi

			if [ -z "$regression" -o x"$regression" = x"X" ]
			then
				# Do real testing

				$_LIB_EXEC $module $dir/$_LIB_REQ $dir/$_LIB_RESP
				local ret=$?
				if [ $ret -eq 95 ]	#EOPNOTSUPP
				then
					echo_deact "Operation not supported for $dir"
				elif [ $ret -ne 0 ]
				then
					echo_fail "Execution for $dir failed (error code $ret) - executed command:"
					echo "$_LIB_EXEC $dir/$_LIB_REQ $dir/$_LIB_RESP"
				else
					echo_pass "Processed $dir"
				fi
			else
				# Do regression testing

				# Skip vectors known to generate random numbers and
				# thus will not work as KAT
				local skip=0
				for j in ${REGRESSION_VECTOR_SKIP}
				do
					keyword=${j%%:*}
					value=${j##*:}

					if [ -z "$keyword" -o -z "$value" ]
					then
						echo "Empty keyword ($keyword) or value ($value)"
						continue
					fi

					if (grep -i \"$keyword\" $dir/$_LIB_REQ | grep -iq $value > /dev/null)
					then
						echo_deact "Key $keyword and value $value found in $dir/$_LIB_REQ"
						skip=1
						break
					fi
				done

				if [ $skip -ne 0 ]
				then
					continue
				fi

				$_LIB_EXEC $module $dir/$_LIB_REQ $dir/$_LIB_REGRESSION
				local ret=$?
				if [ $ret -eq 95 ]	#EOPNOTSUPP
				then
					echo_deact "Operation not supported for $dir"
				elif [ $ret -ne 0 ]
				then
					echo_fail "Execution for $dir failed (error code $ret) - executed command:"
					echo "$_LIB_EXEC $dir/$_LIB_REQ $dir/$_LIB_REGRESSION"
				elif ! $($_LIB_EXEC -e $dir/$_LIB_REGRESSION $dir/$_LIB_RESP > /dev/null); then
					echo_fail "Regression testing for $dir"
				else
					echo_pass "Regression testing for $dir"
				fi
				rm -f $dir/$_LIB_REGRESSION
			fi
		done
	done

	if [ -n "$regression" -a x"$regression" != x"X" ]
	then
		echo "=========================================================="
		if [ $failures -gt 0 ]
		then
			echo $(color "red")[FAILED]$(color off) $@ "$failures failures for module $module"

		else
			echo_pass "no failures for module $module"
		fi
	fi

	failures=0
}

#
# Execute testing
# $1 module name to be executed
# $2 if present, search criteria for regression test (commonly an array of
#    vsIds)
regression_test()
{
	local module=$1
	shift

	exec_module "$module" "regression" ${@}
}

cleanup()
{
	find $_LIB_IUT -name "$_LIB_REGRESSION" | xargs rm -f
	make clean
}

trap "cleanup; exit" 0 1 2 3 15
