#!/bin/sh
modify << EOF
dn: nis-domain=example.com+nis-map=passwd.byname,cn=NIS Server,cn=plugins,cn=config
changetype: modify
delete: nis-filter
-

dn: nis-domain=example.com+nis-map=passwd.byuid,cn=NIS Server,cn=plugins,cn=config
changetype: modify
delete: nis-filter
-

EOF
