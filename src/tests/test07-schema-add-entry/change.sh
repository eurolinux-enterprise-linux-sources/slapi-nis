#!/bin/sh
add << EOF
dn: uid=user1d,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1d
uidNumber: 1004
gidNumber: 1004
cn: User 1 D
gecos: User 1 D
loginShell: /bin/sh
homeDirectory: /home/user1d

EOF
