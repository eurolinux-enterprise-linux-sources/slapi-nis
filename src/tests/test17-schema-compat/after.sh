#!/bin/sh
tmpfile=`mktemp ${TMP:-/tmp}/ldifXXXXXX`
if test -z "$tmpfile" ; then
	echo error creating temporary file
fi
trap 'rm -f "$tmpfile"' EXIT
search -b cn=users,cn=compat,cn=accounts,dc=example,dc=com > $tmpfile
$LDIFSORT $tmpfile
search -b cn=groups,cn=compat,cn=accounts,dc=example,dc=com > $tmpfile
$LDIFSORT $tmpfile
