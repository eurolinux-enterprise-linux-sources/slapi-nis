#!/bin/sh
modify << EOF
dn: cn=g2,cn=groups,cn=accounts,dc=example,dc=com
changetype: modify
add: member
member: cn=g1,cn=groups,cn=accounts,dc=example,dc=com
-

EOF
# give memberOf a few seconds to catch up
sleep 10
