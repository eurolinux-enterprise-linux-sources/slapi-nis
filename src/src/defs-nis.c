/*
 * Copyright 2008,2009,2011,2012 Red Hat, Inc.
 *
 * This Program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This Program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this Program; if not, write to the
 *
 *   Free Software Foundation, Inc.
 *   59 Temple Place, Suite 330
 *   Boston, MA 02111-1307 USA
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <rpc/xdr.h>
#include <fnmatch.h>
#include <paths.h>
#include <string.h>

#include "defs-nis.h"

#define DEFAULT_ENTRY_FILTER "(&(nisMapName=%m)(objectClass=nisObject))"
#define DEFAULT_KEY_FORMAT NULL
#define DEFAULT_KEYS_FORMAT "%{cn}"
#define DEFAULT_VALUE_FORMAT "%{nisMapEntry}"
#define DEFAULT_VALUES_FORMAT NULL
#define DEFAULT_DISALLOWED_CHARS NULL
#define DEFAULT_MAP_SECURE FALSE
#define DEFAULT_CONFIGURATION_SUFFIX "cn=NIS Server, cn=plugins, cn=config"

static struct configuration {
	char *map;
	enum { config_exact, config_glob } config_match;
	bool_t secure;
	char *base;
	char *filter;
	char *key_format, *keys_format, *value_format, *values_format;
	char *disallowed_chars;
} config[] = {
	{"passwd.byname", config_exact, FALSE, NULL,
	 "(objectClass=posixAccount)",
	 "%{uid}", NULL,
	 "%{uid}:%regsubi(\"%{userPassword}\",\"^\\\\{CRYPT\\\\}(..*)\",\"%1\",\"*\"):%regmatch(\"%{uidNumber}\",\"[0-9]+\"):%regmatch(\"%{gidNumber}\",\"[0-9]+\"):%{gecos:-%{cn:-}}:%{homeDirectory:-/}:%{loginShell:-" _PATH_BSHELL "}", NULL,
	 ":\r\n"},
	{"passwd.byuid", config_exact, FALSE, NULL,
	 "(objectClass=posixAccount)",
	 "%{uidNumber}", NULL,
	 "%{uid}:%regsubi(\"%{userPassword}\",\"^\\\\{CRYPT\\\\}(..*)\",\"%1\",\"*\"):%regmatch(\"%{uidNumber}\",\"[0-9]+\"):%regmatch(\"%{gidNumber}\",\"[0-9]+\"):%{gecos:-%{cn:-}}:%{homeDirectory:-/}:%{loginShell:-" _PATH_BSHELL "}", NULL,
	 ":\r\n"},
	{"group.byname", config_exact, FALSE, NULL,
	 "(objectClass=posixGroup)",
	 "%{cn}", NULL,
	 "%{cn}:%regsubi(\"%{userPassword}\",\"^\\\\{CRYPT\\\\}(..*)\",\"%1\",\"*\"):%regmatch(\"%{gidNumber}\",\"[0-9]+\"):%merge(\",\",\"%{memberUid}\",\"%deref_r(\\\"member\\\",\\\"uid\\\")\",\"%deref_r(\\\"uniqueMember\\\",\\\"uid\\\")\")", NULL,
	 ":,\r\n"},
	{"group.bygid", config_exact, FALSE, NULL,
	 "(objectClass=posixGroup)",
	 "%{gidNumber}", NULL,
	 "%{cn}:%regsubi(\"%{userPassword}\",\"^\\\\{CRYPT\\\\}(..*)\",\"%1\",\"*\"):%{gidNumber}:%merge(\",\",\"%{memberUid}\",\"%deref_r(\\\"member\\\",\\\"uid\\\")\",\"%deref_r(\\\"uniqueMember\\\",\\\"uid\\\")\")", NULL,
	 ":,\r\n"},
	{"netgroup", config_exact, FALSE, NULL,
	 "(objectClass=nisNetgroup)",
	 "%{cn}", NULL,
	 "%merge(\" \",\"%{nisNetgroupTriple}\",\"%{memberNisNetgroup}\")", NULL,
	 NULL},
	{"auto.*", config_glob, FALSE, NULL,
	 "(objectClass=automount)",
	 NULL, "%{automountKey}",
	 "%{automountInformation}", NULL,
	 NULL},

	{"ethers.byaddr", config_exact, FALSE, NULL,
	 "(&(macAddress=*)(cn=*)(objectclass=ieee802device))",
	 NULL,
	 "%mregsub(\"%{macaddress} %{cn}\",\"(..:..:..:..:..:..) (.*)\",\"%2\")",
	 NULL,
	 "%{macaddress} %{cn}",
	 NULL},
	{"ethers.byname", config_exact, FALSE, NULL,
	 "(&(macAddress=*)(cn=*)(objectclass=ieee802device))",
	 NULL,
	 "%mregsub(\"%{macaddress} %{cn}\",\"(..:..:..:..:..:..) (.*)\",\"%1\")",
	 NULL,
	 "%{macaddress} %{cn}",
	 NULL},
	{"hosts.byaddr", config_exact, FALSE, NULL,
	 "(&(ipHostNumber=*)(cn=*))",
	 "%{ipHostNumber}", NULL,
	 "%first(\"%{cn}\") %{ipHostNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"hosts.byname", config_exact, FALSE, NULL,
	 "(&(ipHostNumber=*)(cn=*))",
	 NULL, "%{cn}",
	 "%first(\"%{cn}\") %{ipHostNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"mail.aliases", config_exact, FALSE, NULL,
	 "(objectClass=nisMailAlias)",
	 NULL, "%{cn}",
	 "%merge(\",\",\"%{rfc822MailMember}\")", NULL,
	 NULL},
	{"mail.byaddr", config_exact, FALSE, NULL,
	 "(objectClass=nisMailAlias)",
	 NULL, "%{rfc822MailMember}",
	 "%merge(\",\",\"%{cn}\")", NULL,
	 NULL},
	{"netgroup.byhost", config_exact, FALSE, NULL, /* XXX */
	 "(objectClass=nisNetgroup)",
	 NULL, NULL,
	 NULL, NULL,
	 NULL},
	{"netgroup.byuser", config_exact, FALSE, NULL, /* XXX */
	 "(objectClass=nisNetgroup)",
	 NULL, NULL,
	 NULL, NULL,
	 NULL},
	{"netid.byname", config_exact, FALSE, NULL,
	 "(objectClass=posixAccount)",
	 "unix.%{uidNumber}", NULL,
	 "%{uidNumber}:%merge(\",\",\"%{gidNumber}\",\"%deref_r(\\\"memberOf\\\",\\\"gidNumber\\\")\",\"%referred_r(\\\"group.byname\\\",\\\"member\\\",\\\"gidNumber\\\")\",\"%referred_r(\\\"group.byname\\\",\\\"uniqueMember\\\",\\\"gidNumber\\\")\")", NULL,
	 NULL},
	{"networks.byaddr", config_exact, FALSE, NULL,
	 "(objectClass=ipNetwork)",
	 "%{ipNetworkNumber}", NULL,
	 "%first(\"%{cn}\") %{ipNetworkNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"networks.byname", config_exact, FALSE, NULL,
	 "(objectClass=ipNetwork)",
	 NULL, "%{cn}",
	 "%first(\"%{cn}\") %{ipNetworkNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"protocols.byname", config_exact, FALSE, NULL,
	 "(objectClass=ipProtocol)",
	 NULL, "%{cn}",
	 "%first(\"%{cn}\") %{ipProtocolNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"protocols.bynumber", config_exact, FALSE, NULL,
	 "(objectClass=ipProtocol)",
	 "%{ipProtocolNumber}", NULL,
	 "%first(\"%{cn}\") %{ipProtocolNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"rpc.byname", config_exact, FALSE, NULL,
	 "(objectClass=oncRpc)",
	 NULL, "%{cn}",
	 "%first(\"%{cn}\") %{oncRpcNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"rpc.bynumber", config_exact, FALSE, NULL,
	 "(objectClass=oncRpc)",
	 "%{oncRpcNumber}", NULL,
	 "%first(\"%{cn}\") %{oncRpcNumber} %merge(\" \",\"%{cn}\")", NULL,
	 NULL},
	{"services.byname", config_exact, FALSE, NULL,
	 "(objectClass=ipService)",
	 NULL, "%{ipServicePort}/%{ipServiceProtocol}",
	 NULL, "%first(\"%{cn}\") %{ipServicePort}/%{ipServiceProtocol} %merge(\" \",\"%{cn}\")",
	 NULL},
	{"services.byservicename", config_exact, FALSE, NULL,
	 "(objectClass=ipService)",
	 NULL, "%{cn}/%{ipServiceProtocol}",
	 NULL, "%{cn} %{ipServicePort}/%{ipServiceProtocol} %merge(\" \",\"%{cn}\")",
	 NULL},
	{"ypservers", config_exact, FALSE,
	 "cn=nis-servers, " DEFAULT_CONFIGURATION_SUFFIX,
	 "(&(" NIS_MAP_CONFIGURATION_MAP_ATTR "=nis-servers)"
	 "(" NIS_MAP_CONFIGURATION_DOMAIN_ATTR "=%d)"
	 "(" NIS_PLUGIN_CONFIGURATION_SERVER_ATTR "=*))",
	 NULL, "%{" NIS_PLUGIN_CONFIGURATION_SERVER_ATTR "}",
	 NULL, "%{" NIS_PLUGIN_CONFIGURATION_SERVER_ATTR "}",
	 NULL},
};

void
defaults_get_map_config(const char *mapname,
			bool_t *secure,
			const char **filter,
			const char **key_format,
			const char **keys_format,
			const char **value_format,
			const char **values_format,
			const char **disallowed_chars)
{
	unsigned int i;
	for (i = 0; i < sizeof(config) / sizeof(config[0]); i++) {
		bool_t match;
		match = FALSE;
		switch (config[i].config_match) {
		case config_exact:
			if (strcmp(config[i].map, mapname) == 0) {
				match = TRUE;
			}
			break;
		case config_glob:
			if (fnmatch(config[i].map, mapname,
				    FNM_NOESCAPE) == 0) {
				match = TRUE;
			}
			break;
		}
		if (!match) {
			continue;
		}
		if (secure) {
			*secure = config[i].secure;
		}
		if (filter) {
			*filter = config[i].filter;
		}
		if (key_format) {
			*key_format = config[i].key_format;
		}
		if (keys_format) {
			*keys_format = config[i].keys_format;
		}
		if (value_format) {
			*value_format = config[i].value_format;
		}
		if (values_format) {
			*values_format = config[i].values_format;
		}
		if (disallowed_chars) {
			*disallowed_chars = config[i].disallowed_chars;
		}
		break;
	}
	if (i >= (sizeof(config) / sizeof(config[0]))) {
		if (secure) {
			*secure = DEFAULT_MAP_SECURE;
		}
		if (filter) {
			*filter = DEFAULT_ENTRY_FILTER;
		}
		if (key_format) {
			*key_format = DEFAULT_KEY_FORMAT;
		}
		if (keys_format) {
			*keys_format = DEFAULT_KEYS_FORMAT;
		}
		if (value_format) {
			*value_format = DEFAULT_VALUE_FORMAT;
		}
		if (values_format) {
			*values_format = DEFAULT_VALUES_FORMAT;
		}
		if (disallowed_chars) {
			*disallowed_chars = DEFAULT_DISALLOWED_CHARS;
		}
	}
}

#ifdef DEFS_NIS_MAIN
#include <getopt.h>
static void
usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [-d domain] [-s suffix] [-m map]\n",
		strchr(argv0, '/') ?  strrchr(argv0, '/') + 1 : argv0);
}
int
main(int argc, char **argv)
{
	unsigned int i;
	int c;
	const char *domain, *suffix, *map;
	domain = "@domain@";
	suffix = "@suffix@";
	map = "*";
	while ((c = getopt(argc, argv, "d:s:m:")) != -1) {
		switch (c) {
		case 'd':
			domain = optarg;
			break;
		case 's':
			suffix = optarg;
			break;
		case 'm':
			map = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
			break;
		}
	}
	if (optind != argc) {
		usage(argv[0]);
		return 1;
	}
	for (i = 0; i < sizeof(config) / sizeof(config[0]); i++) {
		if (fnmatch(map, config[i].map, 0) != 0) {
			continue;
		}
		if ((config[i].key_format == NULL) &&
		    (config[i].keys_format == NULL)) {
			continue;
		}
		if ((config[i].value_format == NULL) &&
		    (config[i].values_format == NULL)) {
			continue;
		}
		printf("dn: "
		       NIS_MAP_CONFIGURATION_DOMAIN_ATTR "=%s+"
		       NIS_MAP_CONFIGURATION_MAP_ATTR "=%s, "
		       DEFAULT_CONFIGURATION_SUFFIX "\n",
		       domain, config[i].map);
		printf("%s: %s\n",
		       NIS_MAP_CONFIGURATION_DOMAIN_ATTR, domain);
		printf("%s: %s%s%s\n",
		       NIS_MAP_CONFIGURATION_MAP_ATTR,
		       (config[i].config_match == config_glob) ? "@" : "",
		       config[i].map,
		       (config[i].config_match == config_glob) ? "@" : "");
		if (config[i].base != NULL) {
			printf("%s: %s\n", NIS_MAP_CONFIGURATION_BASE_ATTR,
			       config[i].base);
		} else {
			printf("%s: %s\n", NIS_MAP_CONFIGURATION_BASE_ATTR,
			       suffix);
		}
		printf("%s: %s\n",
		       NIS_MAP_CONFIGURATION_FILTER_ATTR,
		       config[i].filter ? config[i].filter : "");
		if (config[i].keys_format != NULL) {
			printf("%s: %s\n",
			       NIS_MAP_CONFIGURATION_KEYS_ATTR,
			       config[i].keys_format);
		} else {
			printf("%s: %s\n",
			       NIS_MAP_CONFIGURATION_KEY_ATTR,
			       config[i].key_format ?
			       config[i].key_format : "");
		}
		if (config[i].values_format != NULL) {
			printf("%s: %s\n",
			       NIS_MAP_CONFIGURATION_VALUES_ATTR,
			       config[i].values_format);
		} else {
			printf("%s: %s\n",
			       NIS_MAP_CONFIGURATION_VALUE_ATTR,
			       config[i].value_format ?
			       config[i].value_format : "");
		}
		if (config[i].disallowed_chars != NULL) {
			printf("%s: %s\n",
			       NIS_MAP_CONFIGURATION_DISALLOWED_CHARS_ATTR,
			       config[i].disallowed_chars);
		}
		if (config[i].secure) {
			printf("%s: yes\n", NIS_MAP_CONFIGURATION_SECURE_ATTR);
		}
		printf("\n");
	}
	return 0;
}
#endif
