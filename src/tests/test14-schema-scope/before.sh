#!/bin/sh
tmpfile=`mktemp ${TMP:-/tmp}/ldifXXXXXX`
if test -z "$tmpfile" ; then
	echo error creating temporary file
fi
trap 'rm -f "$tmpfile"' EXIT
for base in \
	cn=bogus_subentry,cn=bogus_entry,cn=bogus_set,cn=compat, \
	cn=bogus_subentry,cn=bogus_entry,ou=passwd,cn=compat, \
	cn=bogus_subentry,uid=user1a,ou=passwd,cn=compat, \
	uid=user1a,ou=passwd,cn=compat, \
	ou=passwd,cn=compat, \
	cn=compat, \
	"" ; do
	for scope in base one sub ; do
		echo \[${base}cn=accounts,dc=example,dc=com:${scope}\]
		search -b ${base}cn=accounts,dc=example,dc=com -s $scope dn > $tmpfile
		grep -i ^result: $tmpfile
		grep -i ^matchedDN: $tmpfile
		$LDIFSORT $tmpfile
		echo ""
	done
done
