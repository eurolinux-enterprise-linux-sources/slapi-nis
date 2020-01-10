#!/bin/sh
modrdn "nis-domain=example.com+nis-map=passwd.byname,cn=NIS Server,cn=plugins,cn=config" nis-domain=example2.com+nis-map=passwd.byname
modrdn "nis-domain=example.com+nis-map=passwd.byuid,cn=NIS Server,cn=plugins,cn=config" nis-domain=example2.com+nis-map=passwd.byuid
