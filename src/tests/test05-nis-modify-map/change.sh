#!/bin/sh
modify << EOF
dn: nis-domain=example.com+nis-map=passwd.byname,cn=NIS Server,cn=plugins,cn=config
changetype: modify
replace: nis-filter
nis-filter: (&(objectClass=posixAccount)(uid=user2*))
-

dn: nis-domain=example.com+nis-map=passwd.byuid,cn=NIS Server,cn=plugins,cn=config
changetype: modify
replace: nis-filter
nis-filter: (&(objectClass=posixAccount)(uid=user2*))
-

EOF
