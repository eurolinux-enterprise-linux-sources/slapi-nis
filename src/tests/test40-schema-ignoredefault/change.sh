#!/bin/sh
add << EOF
dn: cn=reindex now,cn=index,cn=tasks,cn=config
changetype: add
objectclass: top
objectclass: extensibleObject
cn: reindex now
nsInstance: userRoot
nsIndexAttribute: objectclass
nsIndexAttribute: aci
nsIndexAttribute: cn
nsIndexAttribute: mail
nsIndexAttribute: member
nsIndexAttribute: memberOf
nsIndexAttribute: uid
nis-map: bogus

EOF
