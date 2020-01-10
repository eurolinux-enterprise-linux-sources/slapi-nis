/*
 * Copyright 2008 Red Hat, Inc.
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

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include <rpc/rpc.h>

#include "disp-nis.h"
#include "map.h"
#include "nis.h"
#include "plugin.h"
#include "portmap.h"

struct entry {
	char *id, *key, *value;
};

struct map {
	char *map;
	struct entry *entries;
};

struct domain {
	char *domain;
	struct map *maps;
};

struct entry devel_passwd_byname[] = {
	{"a", "user1", "user1:*:1:1:User Number 1:/home/devel/user1:/bin/tcsh"},
	{"b", "user2", "user2:*:2:2:User Number 2:/home/devel/user2:/bin/tcsh"},
	{"c", "user3", "user3:*:3:3:User Number 3:/home/devel/user3:/bin/tcsh"},
	{"d", "user4", "user4:*:4:4:User Number 4:/home/devel/user4:/bin/tcsh"},
	{"e", "user5", "user5:*:5:5:User Number 5:/home/devel/user5:/bin/tcsh"},
	{NULL, NULL, NULL},
};

struct entry devel_passwd_bynumber[] = {
	{"a", "1", "user1:*:1:1:User Number 1:/home/devel/user1:/bin/tcsh"},
	{"b", "2", "user2:*:2:2:User Number 2:/home/devel/user2:/bin/tcsh"},
	{"c", "3", "user3:*:3:3:User Number 3:/home/devel/user3:/bin/tcsh"},
	{"d", "4", "user4:*:4:4:User Number 4:/home/devel/user4:/bin/tcsh"},
	{"e", "5", "user5:*:5:5:User Number 5:/home/devel/user5:/bin/tcsh"},
	{NULL, NULL, NULL},
};

struct map devel_maps[] = {
	{"passwd.byname", devel_passwd_byname},
	{"passwd.bynumber", devel_passwd_byname},
	{NULL, NULL},
};

struct domain domains[] = {
	{"devel.example.com", devel_maps},
	{NULL, NULL},
};

int
map_startup(struct plugin_state *state)
{
	return 0;
}

int
map_init(struct slapi_pblock *pb, struct plugin_state *state)
{
	return 0;
}

int
map_master_name(struct plugin_state *state, const char **master)
{
	*master = "me, right here";
	return 0;
}

bool_t
map_supports_domain(struct plugin_state *state,
		    const char *domain,
		    bool_t *supported)
{
	int i;
	if (supported != NULL) {
		*supported = FALSE;
		for (i = 0; domains[i].domain != NULL; i++) {
			if (strcmp(domains[i].domain, domain) == 0) {
				*supported = TRUE;
				break;
			}
		}
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"map_supports_domain \"%s\": %s\n", domain,
				*supported ? "YES" : "NO");
	}
	return TRUE;
}

bool_t
map_supports_map(struct plugin_state *state,
		 const char *domain, const char *map, bool_t *supported,
		 bool_t *secure)
{
	int i, j;
	if (supported != NULL) {
		*supported = FALSE;
	}
	for (i = 0; domains[i].domain != NULL; i++) {
		if (strcmp(domains[i].domain, domain) == 0) {
			break;
		}
	}
	if (domains[i].domain != NULL) {
		for (j = 0; domains[i].maps[j].map != NULL; j++) {
			if (strcmp(domains[i].maps[j].map, map) == 0) {
				if (supported != NULL) {
					*supported = TRUE;
				}
				break;
			}
		}
	}
	if (secure != NULL) {
		*secure = FALSE;
	}
	return TRUE;
}

bool_t
map_order(struct plugin_state *state,
	  const char *domain, const char *map, bool_t *secure,
	  unsigned int *order)
{
	*order = 1;
	*secure = FALSE;
	return TRUE;
}

static struct entry *
map_find_entries(const char *domain, const char *map)
{
	int i, j;
	for (i = 0; domains[i].domain != NULL; i++) {
		if (strcmp(domains[i].domain, domain) == 0) {
			break;
		}
	}
	if (domains[i].domain == NULL) {
		return NULL;
	}
	for (j = 0; domains[i].maps[j].map != NULL; j++) {
		if (strcmp(domains[i].maps[j].map, map) == 0) {
			break;
		}
	}
	if (domains[i].maps[j].map == NULL) {
		return NULL;
	}
	return domains[i].maps[j].entries;
}

bool_t
map_match(struct plugin_state *state,
	  const char *domain, const char *map, bool_t *secure,
	  unsigned int key_len, const char *key,
	  unsigned int *value_len, const char **value,
	  const char **id, void **backend_data)
{
	struct entry *entries;
	int i;
	if ((entries = map_find_entries(domain, map)) == NULL) {
		return FALSE;
	}
	for (i = 0; entries[i].key != NULL; i++) {
		if ((strlen(entries[i].key) == key_len) &&
		    (memcmp(entries[i].key, key, key_len) == 0)) {
			break;
		}
	}
	if (entries[i].key == NULL) {
		return FALSE;
	}
	*secure = FALSE;
	*value = entries[i].value;
	*value_len = strlen(entries[i].value);
	*id = entries[i].key;
	if (backend_data != NULL) {
		*backend_data = NULL;
	}
	return TRUE;
}

bool_t
map_match_id(struct plugin_state *state,
	     const char *domain, const char *map, bool_t *secure,
	     const char *in_id, unsigned int in_index,
	     unsigned int *key_len, const char **key,
	     unsigned int *value_len, const char **value,
	     const char **id, void **backend_data)
{
	struct entry *entries;
	int i;
	if (in_index != 0) {
		return FALSE;
	}
	if ((entries = map_find_entries(domain, map)) == NULL) {
		return FALSE;
	}
	for (i = 0; entries[i].id != NULL; i++) {
		if (strcmp(entries[i].id, in_id) == 0) {
			break;
		}
	}
	if (entries[i].id == NULL) {
		return FALSE;
	}
	*secure = FALSE;
	*key = entries[i].key;
	*key_len = strlen(entries[i].key);
	*value = entries[i].value;
	*value_len = strlen(entries[i].value);
	*id = entries[i].id;
	if (backend_data != NULL) {
		*backend_data = NULL;
	}
	return TRUE;
}

bool_t
map_first(struct plugin_state *state,
	  const char *domain, const char *map, bool_t *secure,
	  unsigned int *first_key_len, char **first_key,
	  unsigned int *first_value_len, char **first_value,
	  const char **first_id, int *first_id_index)
{
	struct entry *entries;
	if ((entries = map_find_entries(domain, map)) == NULL) {
		return FALSE;
	}
	if (entries[0].key == NULL) {
		return FALSE;
	}
	*secure = FALSE;
	*first_key = entries[0].key;
	*first_key_len = strlen(entries[0].key);
	*first_value = entries[0].value;
	*first_value_len = strlen(entries[0].value);
	*first_id = entries[0].id;
	*first_id_index = 0;
	return TRUE;
}

bool_t
map_next(struct plugin_state *state,
	 const char *domain, const char *map, bool_t *secure,
	 unsigned int prev_len, const char *prev,
	 unsigned int *next_key_len, char **next_key,
	 unsigned int *next_value_len, char **next_value)
{
	struct entry *entries;
	int i;
	if ((entries = map_find_entries(domain, map)) == NULL) {
		return FALSE;
	}
	for (i = 0; entries[i].key != NULL; i++) {
		if ((strlen(entries[i].key) == prev_len) &&
		    (memcmp(entries[i].key, prev, prev_len) == 0)) {
			break;
		}
	}
	if (entries[i].key == NULL) {
		return FALSE;
	}
	if (entries[i + 1].key == NULL) {
		return FALSE;
	}
	*secure = FALSE;
	*next_key = entries[i + 1].key;
	*next_key_len = strlen(entries[i + 1].key);
	*next_value = entries[i + 1].value;
	*next_value_len = strlen(entries[i + 1].value);
	return TRUE;
}

bool_t
map_next_id(struct plugin_state *state,
	    const char *domain, const char *map, bool_t *secure,
	    const char *prev_id, int prev_id_index,
	    unsigned int *next_key_len, char **next_key,
	    unsigned int *next_value_len, char **next_value,
	    const char **next_id, int *next_id_index)
{
	struct entry *entries;
	int i;
	if ((entries = map_find_entries(domain, map)) == NULL) {
		return FALSE;
	}
	for (i = 0; entries[i].id != NULL; i++) {
		if (strcmp(entries[i].id, prev_id) == 0) {
			break;
		}
	}
	if (entries[i].id == NULL) {
		return FALSE;
	}
	if (entries[i + 1].id == NULL) {
		return FALSE;
	}
	*secure = FALSE;
	*next_key = entries[i + 1].key;
	*next_key_len = strlen(entries[i + 1].key);
	*next_value = entries[i + 1].value;
	*next_value_len = strlen(entries[i + 1].value);
	*next_id = entries[i + 1].id;
	*next_id_index = 0;
	return TRUE;
}
