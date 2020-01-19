#!/bin/sh
modify << EOF
dn: nis-domain=example.com+nis-map=passwd.byname,cn=NIS Server,cn=plugins,cn=config
changetype: modify
add: nis-secure
nis-secure: yes
-

EOF
