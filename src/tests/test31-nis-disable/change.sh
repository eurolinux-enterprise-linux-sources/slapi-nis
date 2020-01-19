#!/bin/sh
modify << EOF
dn: cn=NIS Server, cn=plugins, cn=config
changetype: modify
replace: nsslapd-pluginEnabled
nsslapd-pluginEnabled: off
-

EOF
