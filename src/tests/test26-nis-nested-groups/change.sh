#!/bin/sh
modify << EOF
dn: uid=user2a, cn=Users2, cn=Accounts, dc=example, dc=com
changetype: modify
add: memberOf
memberOf: cn=group1, cn=Groups1, cn=Accounts, dc=example, dc=com
-

dn:  uid=user2b, cn=Users2, cn=Accounts, dc=example, dc=com
changetype: modify
add: memberOf
memberOf: cn=group2, cn=Groups1, cn=Accounts, dc=example, dc=com
-

EOF
