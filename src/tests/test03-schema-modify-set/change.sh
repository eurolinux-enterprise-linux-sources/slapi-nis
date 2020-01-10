#!/bin/sh
modify << EOF
dn: cn=compat-passwd,cn=Schema Compatibility,cn=plugins,cn=config
changetype: modify
add: schema-compat-container-rdn
schema-compat-container-rdn: ou=passwd2
-

EOF
