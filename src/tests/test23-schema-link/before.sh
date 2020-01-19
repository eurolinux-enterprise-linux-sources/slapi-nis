#!/bin/sh
search -b cn=compat,cn=accounts,dc=example,dc=com dn thingy | $LDIFSORT
search -b cn=compat2,cn=accounts,dc=example,dc=com dn thingy | $LDIFSORT
