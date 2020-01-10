#!/bin/sh
tmpfile=`mktemp ${TMP:-/tmp}/ldifXXXXXX`
if test -z "$tmpfile" ; then
	echo error creating temporary file
fi
trap 'rm -f "$tmpfile"' EXIT
for base in dc=example,dc=com cn=compatpeople uid=tuser1 ; do
	basedn="${base}${basedn:+,${basedn}}"
	for scope in base one sub ; do
		echo '['search -b "$basedn" -s $scope']'
		search -b "$basedn" -s $scope | $LDIFSORT
	done
done
