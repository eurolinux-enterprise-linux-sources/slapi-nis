#!/bin/sh
add << EOF
dn: uid=user1d,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1d
uidNumber: 1004
gidNumber: 1004
cn: +User 1 D
gecos: User 1 D
loginShell: /bin/sh
homeDirectory: /home/user1d

dn: uid=user1e,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1e
uidNumber: 1005
gidNumber: 1005
cn: -User 1 E
gecos: User 1 E
loginShell: /bin/sh
homeDirectory: /home/user1e

dn: uid=user1f,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1f
uidNumber: 1006
gidNumber: 1006
cn: User 1 F+
gecos: User 1 F
loginShell: /bin/sh
homeDirectory: /home/user1f

dn: uid=user1g,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1g
uidNumber: 1007
gidNumber: 1007
cn: User 1 G-
gecos: User 1 G
loginShell: /bin/sh
homeDirectory: /home/user1g

dn: uid=user1h,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1h
uidNumber: 1008
gidNumber: 1008
cn: User 1+H
gecos: User 1 H
loginShell: /bin/sh
homeDirectory: /home/user1h

dn: uid=user1i,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1i
uidNumber: 1009
gidNumber: 1009
cn: User 1\+I
gecos: User 1 I
loginShell: /bin/sh
homeDirectory: /home/user1i

dn: uid=user1j,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1j
uidNumber: 1010
gidNumber: 1010
cn: CRON, the destroyer
gecos: User 1 J
loginShell: /bin/sh
homeDirectory: /home/user1j

dn: uid=user1k,cn=Users1,cn=Accounts,dc=example,dc=com
objectClass: posixAccount
objectClass: inetUser
uid: user1k
uidNumber: 1011
gidNumber: 1011
cn: You + Me = We
gecos: User 1 K
loginShell: /bin/sh
homeDirectory: /home/user1k

EOF
