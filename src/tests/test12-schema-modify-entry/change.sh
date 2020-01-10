#!/bin/sh
modify << EOF
dn: uid=user1b,cn=Users1,cn=Accounts,dc=example,dc=com
changetype: modify
add: inetUserHttpURL
inetUserHttpURL: http://localhost/
inetUserHttpURL: http://localhost.localdomain/
inetUserHttpURL: http://here/
inetUserHttpURL: http://there/
-

EOF
