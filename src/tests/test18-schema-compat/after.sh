#!/bin/sh
tmpfile=`mktemp ${TMP:-/tmp}/ldifXXXXXX`
if test -z "$tmpfile" ; then
	echo error creating temporary file
fi
trap 'rm -f "$tmpfile"' EXIT
search -b cn=users2,cn=Accounts,dc=example,dc=com "*" memberOf > $tmpfile
$LDIFSORT $tmpfile
search -b cn=Groups,cn=Accounts,dc=example,dc=com "*" memberOf > $tmpfile
$LDIFSORT $tmpfile
search -b cn=users,cn=compat,cn=Accounts,dc=example,dc=com "*" memberOf > $tmpfile
$LDIFSORT $tmpfile
search -b cn=Groups,cn=compat,cn=Accounts,dc=example,dc=com "*" memberOf > $tmpfile
$LDIFSORT $tmpfile
