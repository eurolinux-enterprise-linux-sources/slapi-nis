#!/bin/sh
modify << EOF
dn: cn=g1,cn=groups,cn=accounts,dc=example,dc=com
changetype: modify
add: member
member: uid=tuser3,cn=users,cn=accounts,dc=example,dc=com
-

EOF
