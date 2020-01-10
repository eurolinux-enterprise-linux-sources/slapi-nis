#!/bin/sh
add << EOF
dn: nis-domain=example.com+nis-map=passwd.byname,cn=NIS Server,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
nis-domain: example.com
nis-map: passwd.byname
nis-base: cn=Users1, cn=Accounts, dc=example, dc=com

dn: nis-domain=example.com+nis-map=passwd.byuid,cn=NIS Server,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
nis-domain: example.com
nis-map: passwd.byuid
nis-base: cn=Users1, cn=Accounts, dc=example, dc=com

EOF
