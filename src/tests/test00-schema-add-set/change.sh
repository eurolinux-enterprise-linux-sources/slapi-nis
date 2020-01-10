#!/bin/sh
add << EOF
dn: cn=compat-passwd,cn=Schema Compatibility,cn=plugins,cn=config
objectClass: top
objectClass: extensibleObject
cn: compat-passwd
schema-compat-container-group: cn=compat,cn=Accounts,dc=example,dc=com
schema-compat-container-rdn: ou=passwd
schema-compat-check-access: yes
schema-compat-search-base: cn=Users1,cn=Accounts,dc=example,dc=com
schema-compat-search-filter: (objectClass=posixAccount)
schema-compat-entry-rdn: uid=%{uid}
schema-compat-entry-attribute: uidNumber=%{uidNumber}

EOF
