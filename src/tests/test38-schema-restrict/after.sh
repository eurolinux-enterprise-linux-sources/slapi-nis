#!/bin/sh
echo '[updated]'
search -b "cn=NIS Server,cn=plugins,cn=config" dn nis-domain nis-map | $LDIFSORT
echo '[result]'
search -b cn=compat,cn=accounts,dc=example,dc=com dn gidNumber memberCN | $LDIFSORT
