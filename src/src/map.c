/*
 * Copyright 2008,2012 Red Hat, Inc.
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
#include <search.h>
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

#include "backend.h"
#include "disp-nis.h"
#include "map.h"
#include "portmap.h"
#include "wrap.h"

/* The singleton for the cache. */
static struct {
	char *master;
	struct domain {
		char *name;
		struct map {
			/* Map name and order. */
			char *name;
			time_t last_changed;
			bool_t secure;
			/* Individual map entries. */
			struct map_entry {
				/* Links to previous and next nodes in the
				 * list. */
				struct map_entry *prev, *next;
				/* The name of the backend entry for this
				 * entry. */
				char *id;
				/* Keys and value. */
				unsigned int n_keys;
				char **keys;
				unsigned int *key_len;
				unsigned int n_values;
				char **values;
				unsigned int *value_len;
				/* Key index for comparison.  Used by the
				 * key_trees. */
				int key_index;
				/* Callback data supplied by the map writer. */
				void *backend_data;
				void (*free_backend_data)(void *backend_data);
			} *entries;
			int n_unique_entries;
			/* Search trees to speed up searches for entries. */
			unsigned int n_key_trees;
			void **key_trees;
			void *id_tree;
			/* Callback data supplied by the map writer. */
			void *backend_data;
			void (*free_backend_data)(void *backend_data);
		} *maps;
		int n_maps;
	} *domains;
	int n_domains;
	struct wrapped_rwlock *lock;
} map_data;

static void *
xmemdup(char *region, int size)
{
	char *ret;
	ret = malloc(size + 1);
	if (ret != NULL) {
		memcpy(ret, region, size);
		ret[size] = '\0';
	}
	return ret;
}

/* Comparison functions used by the tree storage facility. */
static int
t_compare_entry_by_id(const void *p1, const void *p2)
{
	const struct map_entry *e1, *e2;
	e1 = p1;
	e2 = p2;
	return strcmp(e1->id, e2->id);
}
static int
t_compare_entry_by_nth_key(const void *p1, const void *p2)
{
	const struct map_entry *e1, *e2;
	unsigned int key_len;
	int eq, i;
	e1 = p1;
	e2 = p2;
	/* Figure out which key index to use for comparison by pulling it out
	 * of the template (whichever one that is) -- real entries have
	 * key_index set to -1. */
	if (e1->key_index >= 0) {
		i = e1->key_index;
	} else {
		i = e2->key_index;
	}
	/* Same length -> straight comparison. */
	if (e1->key_len[i] == e2->key_len[i]) {
		return memcmp(e1->keys[i], e2->keys[i], e1->key_len[i]);
	} else {
		/* Compare the common length. */
		key_len = (e1->key_len[i] < e2->key_len[i]) ?
			   e1->key_len[i] : e2->key_len[i];
		eq = memcmp(e1->keys[i], e2->keys[i], key_len);
		if (eq != 0) {
			return eq;
		} else {
			return (e1->key_len[i] < e2->key_len[i]) ? -1 : 1;
		}
	}
}

/* Utility function - find the domain record for the named domain. */
static struct domain *
map_data_find_domain(struct plugin_state *state, const char *domain_name)
{
	int i;
	for (i = 0; i < map_data.n_domains; i++) {
		if (strcmp(domain_name, map_data.domains[i].name) == 0) {
			return &map_data.domains[i];
		}
	}
	return NULL;
}

/* Utility function - find the map record for the named map in the named
 * domain. */
static struct map *
map_data_find_map(struct plugin_state *state,
		  const char *domain_name, const char *map_name)
{
	int i;
	struct domain *domain;
	domain = map_data_find_domain(state, domain_name);
	if (domain != NULL) {
		for (i = 0; i < domain->n_maps; i++) {
			if (strcmp(map_name, domain->maps[i].name) == 0) {
				return &domain->maps[i];
			}
		}
	}
	return NULL;
}

/* Utility functions - find a specific entry in the named map in the named
 * domain. */
static struct map_entry *
map_data_find_map_entry(struct plugin_state *state,
			struct map *map, unsigned int key_len, const char *key,
			unsigned int *key_index)
{
	struct map_entry **entry, entry_template;
	unsigned int i;
	if ((map == NULL) || (map->entries == NULL)) {
		return NULL;
	}
	for (i = 0; i < map->n_key_trees; i++) {
		entry_template.keys = ((char **) &key) - i;
		entry_template.key_len = (&key_len) - i;
		entry_template.key_index = i;
		entry = tfind(&entry_template, &map->key_trees[i],
			      t_compare_entry_by_nth_key);
		if (entry != NULL) {
			if (key_index != NULL) {
				*key_index = i;
			}
			return *entry;
		}
	}
	return NULL;
}

static struct map_entry *
map_data_find_entry(struct plugin_state *state,
		    const char *domain_name, const char *map_name,
		    unsigned int key_len, const char *key)
{
	struct map *map;
	map = map_data_find_map(state, domain_name, map_name);
	return map_data_find_map_entry(state, map, key_len, key, NULL);
}

static struct map_entry *
map_data_find_map_entry_id(struct plugin_state *state,
			   struct map *map, const char *id)
{
	struct map_entry **entry, entry_template;
	if (map == NULL) {
		return NULL;
	}
	entry_template.id = (char *) id;
	entry = tfind(&entry_template, &map->id_tree, t_compare_entry_by_id);
	return entry ? *entry : NULL;
}

/* Iterate through every entry in every map, calling the callback if "all" is
 * true, or if "id" is not NULL and matches the entry's ID. If the callback
 * returns FALSE, then we abort and return FALSE, otherwise we return TRUE. */
static bool_t
map_data_foreach_entry(struct plugin_state *state,
		       const char *domain_name, const char *map_name,
		       const char *id,
		       bool_t (*fn)(const char *domain, const char *map,
				    bool_t secure,
				    const char *key, unsigned int key_len,
				    const char *value, unsigned int value_len,
				    const char *id, int key_index,
				    void *backend_data,
				    void *cbdata),
		       void *cbdata)
{
	int i, j;
	unsigned int k;
	struct domain *domain;
	struct map *map;
	struct map_entry *entry;
	for (i = 0; i < map_data.n_domains; i++) {
		domain = &map_data.domains[i];
		if ((domain_name != NULL) &&
		    (strcmp(domain_name, domain->name) != 0)) {
			continue;
		}
		for (j = 0; j < domain->n_maps; j++) {
			map = &domain->maps[j];
			if ((map_name != NULL) &&
			    (strcmp(map_name, map->name) != 0)) {
				continue;
			}
			for (entry = map->entries;
			     entry != NULL;
			     entry = entry->next) {
				if ((id == NULL) ||
				    (strcmp(id, entry->id) == 0)) {
					for (k = 0; k < entry->n_keys; k++) {
						if (!(*fn)(domain->name,
							   map->name,
							   map->secure,
							   entry->keys[k],
							   entry->key_len[k],
							   entry->values[k % entry->n_values],
							   entry->value_len[k % entry->n_values],
							   entry->id, k,
							   entry->backend_data,
							   cbdata)) {
							return FALSE;
						}
					}
				}
			}
		}
	}
	return TRUE;
}

/* Iterate over every entry which matches the corresponding ID. */
bool_t
map_data_foreach_entry_id(struct plugin_state *state,
			  const char *domain, const char *map, const char *id,
			  bool_t (*fn)(const char *domain, const char *map,
				       bool_t secure,
				       const char *key,
				       unsigned int key_len,
				       const char *value,
				       unsigned int value_len,
				       const char *id, int key_index,
				       void *backend_data, void *cbdata),
			  void *cbdata)
{
	return map_data_foreach_entry(state, domain, map, id, fn, cbdata);
}

/* Iterate over all domains, calling the callback with information about the
 * domain. */
bool_t
map_data_foreach_domain(struct plugin_state *state,
			bool_t (*fn)(const char *domain, void *cbdata),
			void *cbdata)
{
	int i;
	for (i = 0; i < map_data.n_domains; i++) {
		if (!(*fn)(map_data.domains[i].name, cbdata)) {
			return FALSE;
		}
	}
	return TRUE;
}

/* Iterate over all maps, calling the callback with information about the map
 * and whatever the caller originally told us to keep track of when the map was
 * first set up. */
bool_t
map_data_foreach_map(struct plugin_state *state, const char *domain_name,
		     bool_t (*fn)(const char *domain,
				  const char *map,
				  bool_t secure,
				  void *backend_data,
				  void *cbdata),
		     void *cbdata)
{
	int i, j;
	struct domain *domain;
	struct map *map;
	for (i = 0; i < map_data.n_domains; i++) {
		domain = &map_data.domains[i];
		if ((domain_name != NULL) &&
		    (strcmp(domain->name, domain_name) != 0)) {
			continue;
		}
		for (j = 0; j < domain->n_maps; j++) {
			map = &domain->maps[j];
			if (!(*fn)(domain->name, map->name, map->secure,
				   map->backend_data, cbdata)) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

/* Query function: check if we have a record for the domain.  Return that
 * information in "supported", and return TRUE unless we ran into internal
 * errors. */
bool_t
map_supports_domain(struct plugin_state *state,
		    const char *domain_name,
		    bool_t *supported)
{
	*supported = (map_data_find_domain(state, domain_name) != NULL);
	return TRUE;
}

/* Query function: check if we have a record for the map in the domain.  Return
 * that information in "supported", and return TRUE unless we ran into internal
 * errors. */
bool_t
map_supports_map(struct plugin_state *state,
		 const char *domain_name, const char *map_name,
		 bool_t *supported, bool_t *secure)
{
	struct map *map;
	map = map_data_find_map(state, domain_name, map_name);
	if (supported != NULL) {
		*supported = (map != NULL);
	}
	if (secure != NULL) {
		*secure = map && map->secure;
	}
	return TRUE;
}

/* Query function: return the name of this master. */
int
map_master_name(struct plugin_state *state, const char **master)
{
	char *tmp, hostname[HOST_NAME_MAX + 1];
	Slapi_PBlock *pb;

	pb = slapi_pblock_new();
	if (backend_read_master_name(state, pb, &tmp) == 0) {
		free(map_data.master);
		map_data.master = strdup(tmp);
		backend_free_master_name(state, tmp);
	} else {
		memset(hostname, '\0', sizeof(hostname));
		if (gethostname(hostname, sizeof(hostname)) != 0) {
			snprintf(hostname, sizeof(hostname), "%s", "localhost");
		}
		free(map_data.master);
		map_data.master = strdup(hostname);
	}
	*master = map_data.master;
	slapi_pblock_destroy(pb);
	return 0;
}

/* Query function: return an indication of the map's age.  Should never
 * decrease. */
bool_t
map_order(struct plugin_state *state,
	  const char *domain_name, const char *map_name, bool_t *map_secure,
	  unsigned int *order)
{
	struct map *map;
	map = map_data_find_map(state, domain_name, map_name);
	if (map != NULL) {
		*order = map->last_changed & 0xffffffff;
		*map_secure = map->secure;
		return TRUE;
	} else {
		return FALSE;
	}
}

/* Query function: return the entry value which matches the key.  Return TRUE
 * if we can find a value which corresponds to the key. */
bool_t
map_match(struct plugin_state *state,
	  const char *domain_name, const char *map_name,
	  bool_t *secure,
	  unsigned int key_len, const char *key,
	  unsigned int *value_len, const char **value,
	  const char **id, void **backend_data)
{
	struct map *map;
	struct map_entry *entry;
	unsigned int key_index;
	*value_len = 0;
	*value = NULL;
	*id = NULL;
	if (backend_data != NULL) {
		*backend_data = NULL;
	}
	map = map_data_find_map(state, domain_name, map_name);
	if (map == NULL) {
		return FALSE;
	}
	*secure = map->secure;
	entry = map_data_find_map_entry(state, map, key_len, key, &key_index);
	if (entry == NULL) {
		return FALSE;
	}
	*value_len = entry->value_len[key_index % entry->n_values];
	*value = entry->values[key_index % entry->n_values];
	*id = entry->id;
	if (backend_data != NULL) {
		*backend_data = entry->backend_data;
	}
	return TRUE;
}

bool_t
map_match_id(struct plugin_state *state,
	     const char *domain_name, const char *map_name,
	     bool_t *secure,
	     const char *in_id, unsigned int in_key_index,
	     unsigned int *key_len, const char **key,
	     unsigned int *value_len, const char **value,
	     const char **id, void **backend_data)
{
	struct map *map;
	struct map_entry *entry;
	*key_len = 0;
	*key = NULL;
	*value_len = 0;
	*value = NULL;
	*id = NULL;
	if (backend_data != NULL) {
		*backend_data = NULL;
	}
	map = map_data_find_map(state, domain_name, map_name);
	if (map == NULL) {
		return FALSE;
	}
	*secure = map->secure;
	entry = map_data_find_map_entry_id(state, map, in_id);
	if (entry == NULL) {
		return FALSE;
	}
	if (entry->n_keys < 1) {
		return FALSE;
	}
	if (in_key_index >= entry->n_keys) {
		return FALSE;
	}
	*key_len = entry->key_len[in_key_index];
	*key = entry->keys[in_key_index];
	*value_len = entry->value_len[in_key_index % entry->n_values];
	*value = entry->values[in_key_index % entry->n_values];
	*id = entry->id;
	if (backend_data != NULL) {
		*backend_data = entry->backend_data;
	}
	return TRUE;
}

/* Query function: return the first entry's key and value for a map.  Return
 * FALSE if there's no domain or map. */
bool_t
map_first(struct plugin_state *state,
	  const char *domain_name, const char *map_name,
	  bool_t *secure,
	  unsigned int *first_key_len, char **first_key,
	  unsigned int *first_value_len, char **first_value,
	  const char **first_id, int *first_key_index)
{
	struct map *map;
	struct map_entry *entry;
	*first_key_len = 0;
	*first_key = NULL;
	*first_value_len = 0;
	*first_value = NULL;
	*first_id = NULL;
	*first_key_index = 0;
	map = map_data_find_map(state, domain_name, map_name);
	if (map == NULL) {
		return FALSE;
	}
	*secure = map->secure;
	entry = map->entries;
	if (entry == NULL) {
		return FALSE;
	}
	*first_key_len = entry->key_len[0];
	*first_key = entry->keys[0];
	*first_value_len = entry->value_len[0];
	*first_value = entry->values[0];
	*first_id = entry->id;
	*first_key_index = 0;
	return TRUE;
}

/* Query function: return the successor entry's key and value for a map.
 * Return FALSE if there's no domain or map, or if the predecessor was the last
 * key in the map. */
bool_t
map_next(struct plugin_state *state,
	 const char *domain_name, const char *map_name, bool_t *secure,
	 unsigned int prev_len, const char *prev,
	 unsigned int *next_key_len, char **next_key,
	 unsigned int *next_value_len, char **next_value)
{
	struct map *map;
	struct map_entry *entry;
	unsigned int key_index, last_instance;
	*next_key_len = 0;
	*next_key = NULL;
	*next_value_len = 0;
	*next_value = NULL;
	map = map_data_find_map(state, domain_name, map_name);
	if (map == NULL) {
		return FALSE;
	}
	*secure = map->secure;
	entry = map_data_find_map_entry(state, map, prev_len, prev, &key_index);
	if (entry == NULL) {
		return FALSE;
	}
	last_instance = entry->n_keys - 1;
	while (last_instance > key_index) {
		if ((prev_len != entry->key_len[last_instance]) ||
		    (memcmp(prev, entry->keys[last_instance], prev_len) != 0)) {
			last_instance--;
		} else {
			break;
		}
	}
	if (last_instance > key_index) {
		key_index = last_instance;
	}
	if (key_index + 1 < entry->n_keys) {
		*next_key_len = entry->key_len[key_index + 1];
		*next_key = entry->keys[key_index + 1];
		*next_value_len = entry->value_len[(key_index + 1) %
						   entry->n_values];
		*next_value = entry->values[(key_index + 1) % entry->n_values];
	} else {
		if (entry->next == NULL) {
			return FALSE;
		}
		*next_key_len = entry->next->key_len[0];
		*next_key = entry->next->keys[0];
		*next_value_len = entry->next->value_len[0];
		*next_value = entry->next->values[0];
	}
	return TRUE;
}
bool_t
map_next_id(struct plugin_state *state,
	    const char *domain_name, const char *map_name, bool_t *secure,
	    const char *prev_id, int prev_key_index,
	    unsigned int *next_key_len, char **next_key,
	    unsigned int *next_value_len, char **next_value,
	    const char **next_id, int *next_key_index)
{
	struct map *map;
	struct map_entry *entry;
	*next_key_len = 0;
	*next_key = NULL;
	*next_value_len = 0;
	*next_value = NULL;
	*next_id = NULL;
	*next_key_index = 0;
	map = map_data_find_map(state, domain_name, map_name);
	if (map == NULL) {
		return FALSE;
	}
	*secure = map->secure;
	entry = map_data_find_map_entry_id(state, map, prev_id);
	if (entry == NULL) {
		return FALSE;
	}
	if (prev_key_index + 1 < (int) entry->n_keys) {
		*next_key_len = entry->key_len[prev_key_index + 1];
		*next_key = entry->keys[prev_key_index + 1];
		*next_value_len = entry->value_len[(prev_key_index + 1) %
						   entry->n_values];
		*next_value = entry->values[(prev_key_index + 1) %
					    entry->n_values];
		*next_id = entry->id;
		*next_key_index = prev_key_index + 1;
	} else {
		if (entry->next == NULL) {
			return FALSE;
		}
		*next_key_len = entry->next->key_len[0];
		*next_key = entry->next->keys[0];
		*next_value_len = entry->next->value_len[0];
		*next_value = entry->next->values[0];
		*next_id = entry->next->id;
		*next_key_index = 0;
	}
	return TRUE;
}

/* Check if there's an entry with a specific ID. */
bool_t
map_data_check_entry(struct plugin_state *state,
		     const char *domain_name, const char *map_name,
		     const char *id)
{
	return (map_data_find_map_entry_id(state,
					   map_data_find_map(state,
							     domain_name,
							     map_name),
					   id) != NULL);
}

/* Utility function for creating/updating/clearing a list of length-counted
 * values kept as parallel arrays. */
static unsigned int
map_data_save_list(char ***saved_list, unsigned int **saved_lengths,
		   char **list, unsigned int *lengths)
{
	char **save_list;
	unsigned int *save_lengths, length, i, n;
	/* Delete the old list, if there is one. */
	if (*saved_list != NULL) {
		for (i = 0; (*saved_list)[i] != NULL; i++) {
			free((*saved_list)[i]);
		}
		free(*saved_list);
		*saved_list = NULL;
	}
	if (*saved_lengths != NULL) {
		free(*saved_lengths);
		*saved_lengths = NULL;
	}
	/* Build a copy of the passed-in list. */
	if (list != NULL) {
		for (i = 0; list[i] != NULL; i++) {
			continue;
		}
		n = i;
	} else {
		n = 0;
	}
	save_list = NULL;
	save_lengths = NULL;
	if (n != 0) {
		save_list = malloc((n + 1) * sizeof(char *));
		save_lengths = malloc(sizeof(save_lengths[0]) * n);
		if ((save_list != NULL) && (save_lengths != NULL)) {
			for (i = 0; i < n; i++) {
				if (lengths != NULL) {
					length = lengths[i];
				} else {
					length = (unsigned int) -1;
				}
				if (length == (unsigned int) -1) {
					length = strlen(list[i]);
				}
				save_list[i] = xmemdup(list[i], length);
				save_lengths[i] = length;
			}
			save_list[i] = NULL;
		} else {
			free(save_list);
			save_list = NULL;
			free(save_lengths);
			save_lengths = NULL;
			n = 0;
		}
	}
	*saved_list = save_list;
	*saved_lengths = save_lengths;
	return n;
}

/* Remove all of the entries in a map. */
static void
map_data_clear_map_map(struct plugin_state *state, struct map *map)
{
	struct map_entry *entry, *next;
	unsigned int i;
	/* Clear the entries list. */
	if (map != NULL) {
		for (entry = map->entries; entry != NULL; entry = next) {
			next = entry->next;
			/* Remove every key for this entry from the applicable
			 * key trees, and then the ID tree. */
			for (i = 0; i < entry->n_keys; i++) {
				entry->key_index = i;
				tdelete(entry, &map->key_trees[i],
					t_compare_entry_by_nth_key);
				entry->key_index = -1;
			}
			tdelete(entry, &map->id_tree, t_compare_entry_by_id);
			free(entry->id);
			map_data_save_list(&entry->keys, &entry->key_len,
					   NULL, NULL);
			map_data_save_list(&entry->values, &entry->value_len,
					   NULL, NULL);
			if ((entry->free_backend_data != NULL) &&
			    (entry->backend_data != NULL)) {
				entry->free_backend_data(entry->backend_data);
			}
			free(entry);
		}
		map->n_unique_entries = 0;
		map->entries = NULL;
		map->id_tree = NULL;
		free(map->key_trees);
		map->key_trees = NULL;
		map->n_key_trees = 0;
	}
}

void
map_data_clear_map(struct plugin_state *state,
		   const char *domain_name, const char *map_name)
{
	struct map *map;
	map = map_data_find_map(state, domain_name, map_name);
	map_data_clear_map_map(state, map);
}

/* Remove a map from the configuration, removing its domain record if the map
 * was the only one that the domain contained. */
void
map_data_unset_map(struct plugin_state *state,
		   const char *domain_name,
		   const char *map_name)
{
	struct domain *domain;
	struct map *map;
	int i;
	/* Check that we have a domain record that matches. */
	domain = map_data_find_domain(state, domain_name);
	if (domain == NULL) {
		return;
	}
	/* Locate the map, remove it from the array of maps. */
	map = NULL;
	for (i = 0; i < domain->n_maps; i++) {
		if (strcmp(domain->maps[i].name, map_name) == 0) {
			map = &domain->maps[i];
			/* Free the individual entries. */
			map_data_clear_map_map(state, map);
			/* Free the contents of the map structure itself. */
			free(map->name);
			if ((map->free_backend_data != NULL) &&
			    (map->backend_data != NULL)) {
				map->free_backend_data(map->backend_data);
			}
			/* Close the hole in the array. */
			domain->n_maps--;
			if (i != domain->n_maps) {
				memcpy(&domain->maps[i], &domain->maps[i + 1],
				       sizeof(*map) * (domain->n_maps - i));
			}
			break;
		}
	}
	/* If the domain now contains no maps, remove it, too .*/
	if (domain->n_maps == 0) {
		/* Locate the domain, remove it from the array of domains. */
		for (i = 0; i < map_data.n_domains; i++) {
			if (strcmp(map_data.domains[i].name,
				   domain_name) == 0) {
				domain = &map_data.domains[i];
				/* Free the components. */
				free(domain->name);
				free(domain->maps);
				/* Fill in the hole in the domains array. */
				map_data.n_domains--;
				if (i != map_data.n_domains) {
					memcpy(&map_data.domains[i],
					       &map_data.domains[i + 1],
					       sizeof(*domain) *
					       (map_data.n_domains - i));
				}
				break;
			}
		}
	}
	/* And if we're down to no domains, free the domain list, too. */
	if (map_data.n_domains == 0) {
		free(map_data.domains);
		map_data.domains = NULL;
	}
}

/* Add a map structure, adding a domain for it if necessary. */
void
map_data_set_map(struct plugin_state *state,
		 const char *domain_name,
		 const char *map_name,
		 bool_t secure,
		 void *backend_data,
		 void (*free_backend_data)(void *backend_data))
{
	struct domain *domain, *domains;
	struct map *map, *maps;
	int i;
	/* Locate the domain for this map. */
	domain = NULL;
	for (i = 0; i < map_data.n_domains; i++) {
		if (strcmp(map_data.domains[i].name, domain_name) == 0) {
			domain = &map_data.domains[i];
			break;
		}
	}
	/* If we have to, then add to the domain array. */
	if (domain == NULL) {
		/* Allocate space. */
		domains = malloc(sizeof(*domain) * (map_data.n_domains + 1));
		if (domains != NULL) {
			/* Populate the new domain. */
			domain = &domains[map_data.n_domains];
			memset(domain, 0, sizeof(*domain));
			domain->name = strdup(domain_name);
			if (domain->name != NULL) {
				/* Copy in existing data. */
				memcpy(domains, map_data.domains,
				       sizeof(*domain) * map_data.n_domains);
				/* Switcheroo. */
				free(map_data.domains);
				map_data.domains = domains;
				map_data.n_domains++;
			} else {
				free(domains);
				/* XXX */
				return;
			}
		} else {
			/* XXX */
			return;
		}
	}
	/* Check if the map's already been defined in the domain. */
	map = NULL;
	for (i = 0; i < domain->n_maps; i++) {
		if (strcmp(domain->maps[i].name, map_name) == 0) {
			map = &domain->maps[i];
			break;
		}
	}
	/* We need to either create a new map entry or mess with an old one. */
	if (map == NULL) {
		/* Allocate space. */
		maps = malloc(sizeof(*map) * (domain->n_maps + 1));
		if (maps != NULL) {
			/* Populate the new map. */
			map = &maps[domain->n_maps];
			memset(map, 0, sizeof(*map));
			map->name = strdup(map_name);
			map->key_trees = malloc(sizeof(void *));
			map->n_key_trees = (map->key_trees != NULL) ? 1 : 0;
			map->secure = secure;
			map->backend_data = backend_data;
			map->free_backend_data = free_backend_data;
			map->last_changed = time(NULL);
			if ((map->name != NULL) && (map->key_trees != NULL)) {
				/* Copy in existing data. */
				memcpy(maps, domain->maps,
				       sizeof(*map) * domain->n_maps);
				/* Clear the key tree set. */
				memset(map->key_trees, 0,
				       map->n_key_trees * sizeof(void *));
				/* Switcheroo. */
				free(domain->maps);
				domain->maps = maps;
				domain->n_maps++;
			} else {
				free(maps);
				/* XXX */
				return;
			}
		} else {
			/* XXX */
			return;
		}
	} else {
		/* There's already a map there, we just need to update the
		 * data we're keeping track of for the backend. */
		map->secure = secure;
		if ((map->free_backend_data != NULL) &&
		    (map->backend_data != NULL)) {
			map->free_backend_data(map->backend_data);
		}
		map->backend_data = backend_data;
		map->free_backend_data = free_backend_data;
		map->last_changed = time(NULL);
	}
}

/* Remove an entry from a map. */
static void
map_data_unset_map_entry(struct plugin_state *state,
			 struct map *map,
			 struct map_entry *entry)
{
	struct map_entry *prev, *next;
	unsigned int i;
	if ((map != NULL) && (entry != NULL)) {
		prev = entry->prev;
		next = entry->next;
		if (prev != NULL) {
			prev->next = next;
		}
		if (next != NULL) {
			next->prev = prev;
		}
		if (map->entries == entry) {
			map->entries = next;
		}
		map->n_unique_entries--;
		/* Remove every key for this entry from the applicable key
		 * trees. */
		for (i = 0; i < entry->n_keys; i++) {
			entry->key_index = i;
			tdelete(entry, &map->key_trees[i],
				t_compare_entry_by_nth_key);
			entry->key_index = -1;
		}
		/* Remove the ID from the map's ID tree and free the ID. */
		tdelete(entry, &map->id_tree, t_compare_entry_by_id);
		free(entry->id);
		entry->id = NULL;
		/* Free the keys list. */
		entry->n_keys = map_data_save_list(&entry->keys,
						   &entry->key_len,
						   NULL,
						   NULL);
		/* Free the values list. */
		entry->n_values = map_data_save_list(&entry->values,
						     &entry->value_len,
						     NULL,
						     NULL);
		/* Backend data. */
		if ((entry->free_backend_data != NULL) &&
		    (entry->backend_data != NULL)) {
			entry->free_backend_data(entry->backend_data);
		}
		entry->free_backend_data = NULL;
		entry->backend_data = NULL;
		/* The entry itself. */
		free(entry);
	}
}

/* Remove the entry from the map which matches the passed-in ID. */
void
map_data_unset_entry(struct plugin_state *state,
		     const char *domain_name,
		     const char *map_name,
		     const char *id)
{
	struct map *map;
	struct map_entry *entry;
	map = map_data_find_map(state, domain_name, map_name);
	entry = map_data_find_map_entry_id(state, map, id);
	map_data_unset_map_entry(state, map, entry);
	map->last_changed = time(NULL);
}

/* Add an entry to a map. */
void
map_data_set_entry(struct plugin_state *state,
		   const char *domain_name,
		   const char *map_name,
		   const char *id,
		   unsigned int *key_lengths,
		   char **keys,
		   unsigned int *value_lengths,
		   char **values,
		   void *backend_data,
		   void (*free_backend_data)(void *p))
{
	struct map *map;
	struct map_entry *entry;
	unsigned int i, n_keys, n_values;
	void **key_trees;
	/* Count the number of keys and values. */
	for (n_keys = 0; keys[n_keys] != NULL; n_keys++) {
		continue;
	}
	for (n_values = 0; values[n_values] != NULL; n_values++) {
		continue;
	}
	/* No keys or no values means we should remove any matching entries. */
	if ((n_keys == 0) || (n_values == 0)) {
		map_data_unset_entry(state, domain_name, map_name, id);
		return;
	}
	/* Proceed with the add/update. */
	map = map_data_find_map(state, domain_name, map_name);
	if (map != NULL) {
		if (n_keys > map->n_key_trees) {
			/* Create enough trees to allow us to index for all of
			 * these keys, even if it means more than we started
			 * with. */
			key_trees = malloc(sizeof(void *) * n_keys);
			if (key_trees == NULL) {
				return; /* XXX */
			}
			memcpy(key_trees, map->key_trees,
			       map->n_key_trees * sizeof(void *));
			for (i = map->n_key_trees; i < n_keys; i++) {
				key_trees[i] = NULL;
			}
			free(map->key_trees);
			map->key_trees = key_trees;
			map->n_key_trees = n_keys;
		}
		/* Search for an existing entry with this ID. */
		entry = map_data_find_map_entry_id(state, map, id);
		if (entry != NULL) {
			/* There's already an entry with this ID, so let's
			 * replace its keys and value. */
			/* Clear the keys from the map's key index. */
			for (i = 0; i < entry->n_keys; i++) {
				entry->key_index = i;
				tdelete(entry, &map->key_trees[i],
					t_compare_entry_by_nth_key);
				entry->key_index = -1;
			}
			/* Clear the entry's ID from the map's ID index. */
			tdelete(entry, &map->id_tree, t_compare_entry_by_id);
			/* Replace the keys and values. */
			entry->n_keys = map_data_save_list(&entry->keys,
							   &entry->key_len,
							   keys,
							   key_lengths);
			entry->n_values = map_data_save_list(&entry->values,
							     &entry->value_len,
							     values,
							     value_lengths);
			/* Replace the ID. */
			free(entry->id);
			entry->id = strdup(id);
			/* Add the ID to the map's ID index. */
			tsearch(entry, &map->id_tree, t_compare_entry_by_id);
			/* Add the keys to the map's key index. */
			for (i = 0; i < n_keys; i++) {
				entry->key_index = i;
				tsearch(entry, &map->key_trees[i],
					t_compare_entry_by_nth_key);
				entry->key_index = -1;
			}
			/* Reset the backend data. */
			if ((entry->free_backend_data != NULL) &&
			    (entry->backend_data != NULL)) {
				entry->free_backend_data(entry->backend_data);
			}
			entry->backend_data = backend_data;
			entry->free_backend_data = free_backend_data;
		} else {
			/* There's no entry with this ID, so create one. */
			entry = malloc(sizeof(*entry));
			if (entry != NULL) {
				memset(entry, 0, sizeof(*entry));
				/* Keys and values. */
				entry->n_keys =
					map_data_save_list(&entry->keys,
							   &entry->key_len,
							   keys,
							   key_lengths);
				entry->n_values =
					map_data_save_list(&entry->values,
							   &entry->value_len,
							   values,
							   value_lengths);
				/* The entry ID. */
				entry->id = strdup(id);
				/* Insert the entry into the map's list. */
				entry->next = map->entries;
				if (map->entries != NULL) {
					map->entries->prev = entry;
				}
				map->entries = entry;
				map->n_unique_entries++;
				/* Index the keys. */
				for (i = 0; i < entry->n_keys; i++) {
					entry->key_index = i;
					tsearch(entry, &map->key_trees[i],
						t_compare_entry_by_nth_key);
					entry->key_index = -1;
				}
				/* Index the ID. */
				tsearch(entry, &map->id_tree,
					t_compare_entry_by_id);
				/* Store the backend data. */
				entry->backend_data = backend_data;
				entry->free_backend_data = free_backend_data;
			} else {
				/* XXX */
			}
		}
		map->last_changed = time(NULL);
	}
}

int
map_init(struct slapi_pblock *pb, struct plugin_state *state)
{
	memset(&map_data, 0, sizeof(map_data));
	map_data.lock = wrap_new_rwlock();
	if (map_data.lock == NULL) {
		return -1;
	}
	return 0;
}

struct domain_and_map_name {
	char *domain, *map;
	struct domain_and_map_name *next;
};
static bool_t
map_get_domain_and_map_name(const char *domain, const char *map, bool_t flag,
			    void *backend_data, void *cbdata)
{
	struct domain_and_map_name **names, *this_one;
	this_one = malloc(sizeof(*this_one));
	if (this_one != NULL) {
		this_one->domain = strdup(domain);
		this_one->map = strdup(map);
		names = cbdata;
		this_one->next = *names;
		*names = this_one;
	}
	return TRUE;
}
void
map_done(struct plugin_state *state)
{
	struct domain_and_map_name *names, *next;
	names = NULL;
	map_data_foreach_map(state, NULL, map_get_domain_and_map_name, &names);
	while (names != NULL) {
		next = names->next;
		map_data_unset_map(state, names->domain, names->map);
		free(names->domain);
		free(names->map);
		free(names);
		names = next;
	}
	wrap_free_rwlock(map_data.lock);
	map_data.lock = NULL;
}

int
map_data_get_domain_size(struct plugin_state *state, const char *domain_name)
{
	struct domain *domain;
	domain = map_data_find_domain(state, domain_name);
	if (domain != NULL) {
		return domain->n_maps;
	}
	return 0;
}

int
map_data_get_map_size(struct plugin_state *state,
		      const char *domain_name, const char *map_name)
{
	struct map *map;
	map = map_data_find_map(state, domain_name, map_name);
	if (map != NULL) {
		return map->n_unique_entries;
	}
	return 0;
}

void
map_rdlock(void)
{
	wrap_rwlock_rdlock(map_data.lock);
}

void
map_wrlock(void)
{
	wrap_rwlock_wrlock(map_data.lock);
}

void
map_unlock(void)
{
	wrap_rwlock_unlock(map_data.lock);
}
