#!/bin/sh
modify << EOF
dn: cn=g2,cn=groups,cn=accounts,dc=example,dc=com
changetype: modify
replace: gidNumber
gidNumber: 1002
-

EOF
# give memberOf a few seconds to catch up
sleep 10
