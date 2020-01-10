#!/bin/sh
modify << EOF
dn: cn=group1a,cn=groups,cn=accounts,dc=example,dc=com
changetype: modify
add: memberuid
memberuid: user1a
-

dn: cn=group1b,cn=groups,cn=accounts,dc=example,dc=com
changetype: modify
add: member
member: uid=user1b,cn=users1,cn=accounts,dc=example,dc=com
-

dn: uid=user1c,cn=users1,cn=accounts,dc=example,dc=com
changetype: modify
add: memberof
memberof: cn=group1c,cn=groups,cn=accounts,dc=example,dc=com
-

EOF
