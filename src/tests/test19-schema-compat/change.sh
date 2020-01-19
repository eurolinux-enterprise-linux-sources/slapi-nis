#!/bin/sh
add << EOF
dn: cn=ng,cn=Schema Compatibility,cn=plugins,cn=config
changetype: add
objectClass: top
objectClass: extensibleObject
cn: ng
schema-compat-container-group: cn=compat,dc=example,dc=com
schema-compat-container-rdn: cn=ng
schema-compat-check-access: yes
schema-compat-search-base: cn=ng,cn=alt,dc=example,dc=com
schema-compat-search-filter: !(cn=ng)
schema-compat-entry-rdn: cn=%{cn}
schema-compat-entry-attribute: objectclass=nisNetgroup
schema-compat-entry-attribute: memberNisNetgroup=%deref_r("member","cn")
schema-compat-entry-attribute: memberNisNetgroup=%referred_r("cn=ng","memberOf","cn")
schema-compat-entry-attribute: nisNetgroupTriple=(%link("%{externalHost}", "-", ",", "%deref_r(\"memberUser\",\"uid\")", "-"),%{nisDomainName:-})
schema-compat-entry-attribute: nisNetgroupTriple=(%link("%{externalHost}", "-", ",", "%deref_r(\"memberUser\",\"member\")", "-"),%{nisDomainName:-})

EOF
