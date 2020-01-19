#!/bin/sh
modify << EOF
dn: ou=deepgroups, cn=Schema Compatibility, cn=plugins, cn=config
changetype: modify
delete: schema-compat-entry-attribute
schema-compat-entry-attribute: memberUid=%deref_r("member","uid")
-
add: schema-compat-entry-attribute
schema-compat-entry-attribute: memberUid=%deref_rf("member","(|(objectclass=groupofnames)(objectclass=posixaccount))","uid")
-

EOF
