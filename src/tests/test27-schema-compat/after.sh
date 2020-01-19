#!/bin/sh
tmpfile=`mktemp ${TMP:-/tmp}/ldifXXXXXX`
if test -z "$tmpfile" ; then
	echo error creating temporary file
fi
trap 'rm -f "$tmpfile"' EXIT
search -s one -b cn=groups,cn=compat,dc=example,dc=com > $tmpfile
$LDIFSORT $tmpfile
