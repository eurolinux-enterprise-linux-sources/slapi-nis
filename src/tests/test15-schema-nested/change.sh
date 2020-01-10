#!/bin/sh
modify << EOF
dn: cn=Support,cn=groups,cn=accounts,dc=example,dc=com
changetype: modify
add: member
member: cn=Engineering,cn=groups,cn=accounts,dc=example,dc=com
-

dn: cn=NestedVirtualGuests,cn=hostgroups,cn=accounts,dc=example,dc=com
changetype: modify
add: member
member: fqdn=otherhost.lab.com,cn=computers,cn=accounts,dc=example,dc=com
-

EOF
