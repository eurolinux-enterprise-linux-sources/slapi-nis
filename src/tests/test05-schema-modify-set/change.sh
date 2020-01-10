#!/bin/sh
modify << EOF
dn: cn=compat-passwd,cn=Schema Compatibility,cn=plugins,cn=config
changetype: modify
replace: schema-compat-search-filter
schema-compat-search-filter: (uid=*c)
-

EOF
