#!/bin/sh
search -b cn=compat,cn=accounts,dc=example,dc=com dn memberUids | $LDIFSORT
