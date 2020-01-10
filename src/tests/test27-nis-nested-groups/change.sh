#!/bin/sh
modify << EOF
dn: cn=group1, cn=Groups1, cn=Accounts, dc=example, dc=com
changetype: modify
add: member
member: uid=user2a, cn=Users2, cn=Accounts, dc=example, dc=com
-

dn: cn=group2, cn=Groups1, cn=Accounts, dc=example, dc=com
changetype: modify
add: member
member: uid=user2b, cn=Users2, cn=Accounts, dc=example, dc=com
-

EOF
