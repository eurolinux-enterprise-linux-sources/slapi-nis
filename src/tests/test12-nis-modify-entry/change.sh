#!/bin/sh
modify << EOF
dn: uid=user1b, cn=Users1, cn=Accounts, dc=example, dc=com
changetype: modify
delete: loginShell
-

EOF
