#!/bin/sh
sed -i -r -e '/^dn: cn=Schema Compatibility, *cn=plugins, *cn=config$/,/^$/ s/^(nsslapd-pluginenabled:) on$/\1 off/i' "$@"
