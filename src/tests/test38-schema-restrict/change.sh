#!/bin/sh
modify << EOF
dn: nis-domain=example.com+nis-map=name2mac,cn=NIS Server,cn=plugins,cn=config
changetype: modify
add: nis-map
nis-map: name2mac2
-

dn: cn=g2,cn=groups,cn=accounts,dc=example,dc=com
changetype: modify
add: member
member: nis-domain=example.com+nis-map=mac2name,cn=NIS Server,cn=plugins,cn=config
-

EOF
