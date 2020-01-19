#!/bin/sh
{ search -b cn=compat,cn=accounts,dc=example,dc=com dn ; \
  search -b cn=compat2,cn=accounts,dc=example,dc=com dn; } |\
grep ^dn: | env LANG=C sort
