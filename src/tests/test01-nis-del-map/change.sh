#!/bin/sh
delete "nis-domain=nosuchdomain+nis-map=nosuchmap,cn=NIS Server,cn=plugins,cn=config"
delete "nis-domain=example.com+nis-map=nosuchmap,cn=NIS Server,cn=plugins,cn=config"
delete "nis-domain=example.com+nis-map=passwd.byname,cn=NIS Server,cn=plugins,cn=config"
delete "nis-domain=example.com+nis-map=passwd.byuid,cn=NIS Server,cn=plugins,cn=config"
