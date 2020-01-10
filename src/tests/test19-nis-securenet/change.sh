#!/bin/sh
modify << EOF
dn: cn=NIS Server,cn=plugins,cn=config
changetype: modify
add: nis-securenet
nis-securenet: 127.0.0.0 255.0.0.0
-

EOF
