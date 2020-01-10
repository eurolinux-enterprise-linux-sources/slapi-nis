#!/bin/sh
modify << EOF
dn: cn=compat-passwd,cn=Schema Compatibility,cn=plugins,cn=config
changetype: modify
add: schema-compat-container-rdn
schema-compat-container-rdn: ou=passwd2
-
add: schema-compat-container-group
schema-compat-container-group: cn=compat2,cn=Accounts,dc=example,dc=com
-

EOF
