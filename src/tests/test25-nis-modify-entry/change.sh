#!/bin/sh
modify << EOF
dn: uid=user, cn=Accounts, dc=example, dc=com
changetype: modify
add: uid
uid: user3a
-

EOF
