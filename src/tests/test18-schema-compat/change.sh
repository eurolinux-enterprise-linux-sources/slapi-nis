#!/bin/sh
modify << EOF
dn: cn=group2b,cn=Groups,cn=Accounts,dc=example,dc=com
changetype: modify
add: member
member: uid=user2b,cn=users2,cn=Accounts,dc=example,dc=com
-

EOF
# give memberOf a few seconds to catch up
sleep 5
