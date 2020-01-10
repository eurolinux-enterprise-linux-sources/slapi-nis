#!/bin/sh
modify << EOF
dn: nis-domain=example.com+nis-map=passwd.byname,cn=NIS Server,cn=plugins,cn=config
changetype: modify
add: nis-base
nis-base: cn=Users2, cn=Accounts, dc=example, dc=com
-

dn: nis-domain=example.com+nis-map=passwd.byuid,cn=NIS Server,cn=plugins,cn=config
changetype: modify
add: nis-base
nis-base: cn=Users2, cn=Accounts, dc=example, dc=com
-

EOF
