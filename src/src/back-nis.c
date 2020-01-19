/*
 * Copyright 2008,2011,2012,2013,2014 Red Hat, Inc.
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
#include <unistd.h>

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include <rpc/xdr.h>
#include "../yp/yp.h"

#ifdef HAVE_TCPD_H
#include <tcpd.h>
#endif

#include "backend.h"
#include "back-shr.h"
#include "defs-nis.h"
#include "disp-nis.h"
#include "format.h"
#include "plugin.h"
#include "map.h"

/* The filter which we use to identify map configurations.  It lists the
 * required attributes. */
#define NIS_MAP_CONFIGURATION_FILTER "(&(objectClass=*)(" NIS_MAP_CONFIGURATION_BASE_ATTR "=*)(" NIS_MAP_CONFIGURATION_DOMAIN_ATTR "=*)(" NIS_MAP_CONFIGURATION_MAP_ATTR "=*))"

/* The data we ask the map cache to keep, for us, for each map. */
struct backend_set_data {
	struct backend_shr_set_data common;
	/* NIS-specific data. */
	char **key_formats, **keys_formats, **value_formats, **values_formats;
	int n_key_formats, n_keys_formats, n_value_formats, n_values_formats;
	char *disallowed_chars;
};

/* Read the name of the NIS master.  Used by the map module on behalf of the
 * NIS service logic. */
void
backend_free_master_name(struct plugin_state *state, char *master)
{
	backend_shr_free_server_name(state, master);
}
int
backend_read_master_name(struct plugin_state *state, Slapi_PBlock *pb,
			 char **master)
{
	return backend_shr_read_server_name(pb, state, master);
}

/* Manipulate map configuration data. */
static void
backend_free_set_data_contents(void *data)
{
	struct backend_set_data *set_data = data;
	if (set_data != NULL) {
		free(set_data->common.group);
		free(set_data->common.set);
		backend_shr_free_strlist(set_data->common.bases);
		backend_shr_free_sdnlist(set_data->common.restrict_subtrees);
		backend_shr_free_sdnlist(set_data->common.ignore_subtrees);
		format_free_attr_list(set_data->common.rel_attrs);
		free(set_data->common.rel_attr_list);
		format_free_attr_list(set_data->common.ref_attrs);
		format_free_inref_attrs(set_data->common.inref_attrs);
		format_free_ref_attr_list(set_data->common.ref_attr_list);
		format_free_ref_attr_list(set_data->common.inref_attr_list);
		free(set_data->common.entry_filter);
		free(set_data->disallowed_chars);
		backend_shr_free_strlist(set_data->key_formats);
		backend_shr_free_strlist(set_data->keys_formats);
		backend_shr_free_strlist(set_data->value_formats);
		backend_shr_free_strlist(set_data->values_formats);
	}
}
void
backend_set_config_free_config(struct backend_shr_set_data *data)
{
	backend_free_set_data_contents(data->self);
	free(data);
}
static struct backend_shr_set_data *
backend_copy_set_data(const struct backend_set_data *data)
{
	struct backend_set_data *ret;

	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->common.self = ret;
	ret->common.state = data->common.state;
	ret->common.group = strdup(data->common.group);
	ret->common.set = strdup(data->common.set);
	ret->common.bases = backend_shr_dup_strlist(data->common.bases);
	ret->common.entry_filter = data->common.entry_filter ?
				   strdup(data->common.entry_filter) :
				   NULL;
	ret->common.restrict_subtrees = backend_shr_dup_sdnlist(data->common.restrict_subtrees);
	ret->common.ignore_subtrees = backend_shr_dup_sdnlist(data->common.ignore_subtrees);
	ret->common.rel_attrs = data->common.rel_attrs ?
				format_dup_attr_list(data->common.rel_attrs) :
				NULL;
	ret->common.rel_attr_list = NULL;
	ret->common.rel_attrs_list = NULL;
	ret->common.ref_attrs = data->common.ref_attrs ?
				format_dup_attr_list(data->common.ref_attrs) :
				NULL;
	ret->common.inref_attrs = data->common.inref_attrs ?
				  format_dup_inref_attrs(data->common.inref_attrs) :
				  NULL;
	ret->common.ref_attr_list = data->common.ref_attr_list ?
				    format_dup_ref_attr_list(data->common.ref_attr_list) :
				    NULL;
	ret->common.inref_attr_list = data->common.inref_attr_list ?
				      format_dup_ref_attr_list(data->common.inref_attr_list) :
				    NULL;
	ret->common.skip_uninteresting_updates =
		data->common.skip_uninteresting_updates;
	ret->disallowed_chars = data->disallowed_chars ?
				strdup(data->disallowed_chars) : NULL;
	ret->key_formats = backend_shr_dup_strlist(data->key_formats);
	ret->keys_formats = backend_shr_dup_strlist(data->keys_formats);
	ret->n_key_formats = data->n_key_formats;
	ret->n_keys_formats = data->n_keys_formats;
	ret->value_formats = backend_shr_dup_strlist(data->value_formats);
	ret->values_formats = backend_shr_dup_strlist(data->values_formats);
	ret->n_value_formats = data->n_value_formats;
	ret->n_values_formats = data->n_values_formats;
	if ((ret->common.group == NULL) ||
	    (ret->common.set == NULL) ||
	    (ret->common.bases == NULL) ||
	    (ret->common.entry_filter == NULL) ||
	    ((ret->key_formats == NULL) && (ret->keys_formats == NULL)) ||
	    ((ret->value_formats == NULL) && (ret->values_formats == NULL))) {
		backend_set_config_free_config(&ret->common);
		return NULL;
	}
	return &ret->common;
}

/* Gather each single result gleaned by evaluating each value in
 * single_formats, and each group of results by evaluating each value in
 * group_formats, and merge them all together. */
static void
backend_free_gathered_data(char **all, unsigned int *all_lengths,
			   unsigned int n_singles,
			   char **singles,
			   unsigned int n_groups,
			   char ***groups, unsigned int **group_lengths)
{
	unsigned int i;
	free(all);
	free(all_lengths);
	if (singles != NULL) {
		for (i = 0; i < n_singles; i++) {
			format_free_data(singles[i]);
		}
	}
	free(singles);
	if (groups != NULL) {
		for (i = 0; i < n_groups; i++) {
			format_free_data_set(groups[i], group_lengths[i]);
		}
	}
	free(groups);
	free(group_lengths);
}
static char **
backend_gather_data(struct plugin_state *state,
		    Slapi_PBlock *pb, Slapi_Entry *e,
		    const char *domain, const char *map,
		    char **single_formats, char **group_formats,
		    const char *disallowed_chars,
		    const struct slapi_dn **restrict_subtrees,
		    const struct slapi_dn **ignore_subtrees,
		    char ***rel_attrs,
		    char ***ref_attrs,
		    struct format_inref_attr ***inref_attrs,
		    struct format_ref_attr_list ***ref_attr_list,
		    struct format_ref_attr_list ***inref_attr_list,
		    unsigned int **ret_lengths,
		    unsigned int *ret_n_singles,
		    char ***ret_singles,
		    unsigned int *ret_n_groups,
		    char ****ret_groups,
		    unsigned int ***ret_group_lengths)
{
	char **ret, **singles, ***groups;
	unsigned int i, j, k, n, n_singles, n_groups;
	unsigned int *lengths, *single_lengths, **group_lengths;
	if (single_formats != NULL) {
		for (n_singles = 0;
		     single_formats[n_singles] != NULL;
		     n_singles++) {
			continue;
		}
		singles = malloc(sizeof(singles[0]) * n_singles);
		single_lengths = malloc(sizeof(single_lengths[0]) * n_singles);
		if ((singles == NULL) || (single_lengths == NULL)) {
			free(singles);
			free(single_lengths);
			n_singles = 0;
			singles = NULL;
			single_lengths = NULL;
		}
	} else {
		n_singles = 0;
		singles = NULL;
		single_lengths = NULL;
	}
	if (group_formats != NULL) {
		for (n_groups = 0;
		     group_formats[n_groups] != NULL;
		     n_groups++) {
			continue;
		}
		groups = malloc(sizeof(groups[0]) * n_groups);
		group_lengths = malloc(sizeof(group_lengths[0]) * n_groups);
		if ((groups == NULL) || (group_lengths == NULL)) {
			free(groups);
			free(group_lengths);
			n_groups = 0;
			groups = NULL;
			group_lengths = NULL;
		}
	} else {
		n_groups = 0;
		groups = NULL;
		group_lengths = NULL;
	}
	n = 0;
	for (i = 0; i < n_singles; i++) {
		singles[i] = format_get_data(state, pb, e, domain, map,
					     single_formats[i],
					     disallowed_chars,
					     restrict_subtrees,
					     ignore_subtrees,
					     rel_attrs, ref_attrs, inref_attrs,
					     ref_attr_list, inref_attr_list,
					     &single_lengths[i]);
		if (singles[i] != NULL) {
			n++;
		} else {
			/* If evaluating any of the single-value formats fails,
			 * then we should fail completely. */
			for (j = 0; j < i; j++) {
				format_free_data(singles[i]);
			}
			free(singles);
			free(single_lengths);
			free(groups);
			free(group_lengths);
			*ret_singles = NULL;
			*ret_n_singles = 0;
			*ret_groups = NULL;
			*ret_group_lengths = NULL;
			*ret_n_groups = 0;
			*ret_lengths = NULL;
			return NULL;
		}
	}
	for (i = 0, j = 0; i < n_groups; i++) {
		groups[j] = format_get_data_set(state, pb, e, domain, map,
						group_formats[i],
						disallowed_chars,
						restrict_subtrees,
						ignore_subtrees,
						rel_attrs, ref_attrs, inref_attrs,
						ref_attr_list, inref_attr_list,
						&group_lengths[j]);
		if (groups[j] != NULL) {
			for (k = 0; groups[j][k] != NULL; k++) {
				n++;
			}
			j++;
		}
	}
	n_groups = j;
	ret = malloc((n + 1) * sizeof(char *));
	lengths = malloc(n * sizeof((*ret_lengths)[0]));
	if ((ret == NULL) || (lengths == NULL) || (ret_lengths == NULL)) {
		free(ret);
		free(lengths);
		free(single_lengths);
		backend_free_gathered_data(NULL, NULL,
					   n_singles, singles,
					   n_groups, groups, group_lengths);
		return NULL;
	}
	k = 0;
	for (i = 0; i < n_singles; i++) {
		ret[k] = singles[i];
		lengths[k] = single_lengths[i];
		k++;
	}
	free(single_lengths);
	for (i = 0; i < n_groups; i++) {
		if (groups[i] != NULL) {
			for (j = 0; groups[i][j] != NULL; j++) {
				ret[k] = groups[i][j];
				lengths[k] = group_lengths[i][j];
				k++;
			}
		}
	}
	ret[k] = NULL;
	*ret_lengths = lengths;
	*ret_n_singles = n_singles;
	*ret_singles = singles;
	*ret_n_groups = n_groups;
	*ret_groups = groups;
	*ret_group_lengths = group_lengths;
	return ret;
}

/* Given a map-entry directory entry, determine which keys it should have,
 * determine which value should be associated with those keys, and add them to
 * the map cache. */
void
backend_set_entry(Slapi_PBlock *pb, Slapi_Entry *e,
		  struct backend_set_data *data)
{
	char **all_keys, **all_values, *ndn, *plugin_id;
	char **key_singles, ***key_groups, **value_singles, ***value_groups;
	unsigned int *all_key_lengths, *all_value_lengths;
	unsigned int n_key_singles, n_key_groups, **key_group_lengths;
	unsigned int n_value_singles, n_value_groups, **value_group_lengths;
	int i, j, n_values;
	plugin_id = data->common.state->plugin_desc->spd_id;
	/* Pull out the NDN of this entry. */
	ndn = slapi_entry_get_ndn(e);
	if (ndn != NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"examining input entry \"%s\"\n", ndn);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"input entry has no name, ignoring\n");
		return;
	}
	/* Pull out the keys and value for the entry. */
	all_keys = backend_gather_data(data->common.state, pb, e,
				       data->common.group,
				       data->common.set,
				       data->key_formats,
				       data->keys_formats,
				       data->disallowed_chars,
				       data->common.restrict_subtrees,
				       data->common.ignore_subtrees,
				       &data->common.rel_attrs,
				       &data->common.ref_attrs,
				       &data->common.inref_attrs,
				       &data->common.ref_attr_list,
				       &data->common.inref_attr_list,
				       &all_key_lengths,
				       &n_key_singles,
				       &key_singles,
				       &n_key_groups,
				       &key_groups,
				       &key_group_lengths);
	all_values = backend_gather_data(data->common.state, pb, e,
				         data->common.group,
				         data->common.set,
				         data->value_formats,
				         data->values_formats,
				         data->disallowed_chars,
					 data->common.restrict_subtrees,
					 data->common.ignore_subtrees,
				         &data->common.rel_attrs,
				         &data->common.ref_attrs,
				         &data->common.inref_attrs,
					 &data->common.ref_attr_list,
					 &data->common.inref_attr_list,
				         &all_value_lengths,
				         &n_value_singles,
				         &value_singles,
				         &n_value_groups,
				         &value_groups,
				         &value_group_lengths);
	/* If we actually generated keys and values, then set it, otherwise
	 * clear it in case there were some there before. */
	if ((all_keys != NULL) && (all_values != NULL)) {
		for (i = 0; all_keys[i] != NULL; i++) {
			for (j = 0; all_values[j] != NULL; j++) {
				continue;
			}
			n_values = j;
			slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
					"setting domain/map/key/value "
					"\"%s\"/\"%s\"/\"%s\"(\"%s\")="
					"\"%.*s\"\n",
					data->common.group, data->common.set,
					all_keys[i], ndn,
					all_value_lengths[i % n_values],
					all_values[i % n_values]);
		}
		map_data_set_entry(data->common.state,
				   data->common.group, data->common.set, ndn,
				   all_key_lengths, all_keys,
				   all_value_lengths, all_values, NULL, NULL);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"no value for %s, unsetting domain/map/id"
				"\"%s\"/\"%s\"/(\"%s\")\n",
				ndn, data->common.group, data->common.set, ndn);
		map_data_unset_entry(data->common.state,
				     data->common.group, data->common.set, ndn);
	}
	/* Clean up. */
	backend_free_gathered_data(all_keys, all_key_lengths,
				   n_key_singles, key_singles,
				   n_key_groups, key_groups,
				   key_group_lengths);
	backend_free_gathered_data(all_values, all_value_lengths,
				   n_value_singles, value_singles,
				   n_value_groups, value_groups,
				   value_group_lengths);
}

/*
 * Generate a copy of the filter string, with specific sequences replaced:
 * %d -> name of the domain
 * %m -> name of the map
 * %% -> literal '%'
 */
static char *
backend_map_config_filter(const char *format,
			  const char *domain, const char *map)
{
	char *ret;
	int i, j, l;

	if (format == NULL) {
		return NULL;
	}
	l = 0;
	for (i = 0; format[i] != '\0'; i++) {
		if (format[i] == '%') {
			switch (format[i + 1]) {
			case 'd':
				l += strlen(domain);
				i++;
				break;
			case 'm':
				l += strlen(map);
				i++;
				break;
			case '%':
				l++;
				i++;
				break;
			default:
				l++;
				break;
			}
		} else {
			l++;
		}
	}
	ret = malloc(l + 1);
	for (i = j = 0; format[i] != '\0'; i++) {
		if (format[i] == '%') {
			switch (format[i + 1]) {
			case 'd':
				strcpy(ret + j, domain);
				i++;
				j += strlen(domain);
				break;
			case 'm':
				strcpy(ret + j, map);
				i++;
				j += strlen(map);
				break;
			case '%':
				i++;
				ret[j++] = format[i];
				break;
			default:
				ret[j++] = format[i];
				break;
			}
		} else {
			ret[j++] = format[i];
		}
	}
	ret[j] = '\0';
	return ret;
}

/* Given a map configuration entry and domain and map names, read the rest of
 * the map configuration settings. */
void
backend_set_config_read_config(struct plugin_state *state, Slapi_Entry *e,
			       const char *domain, const char *map,
			       bool_t *secure,
			       struct backend_shr_set_data **pret)
{
	struct backend_set_data ret;
	const char *default_filter, *default_key_format, *default_keys_format;
	const char *default_value_format, *default_values_format;
	const char *default_disallowed_chars;
	char **bases, *entry_filter;
	char **key_formats, **keys_formats, **value_formats, **values_formats;
	char *disallowed_chars;
	char **use_bases, *use_entry_filter;
	char **use_key_formats, **use_keys_formats;
	char **use_value_formats, **use_values_formats, *use_disallowed_chars;
	const Slapi_DN **restrict_subtrees, **ignore_subtrees;
	int i, j;

	/* Read the hard-coded defaults for a map with this name. */
	defaults_get_map_config(map, secure, &default_filter,
				&default_key_format, &default_keys_format,
				&default_value_format, &default_values_format,
				&default_disallowed_chars);
	/* Read the values from the configuration entry. */
	bases = backend_shr_get_vattr_strlist(state, e,
					      NIS_MAP_CONFIGURATION_BASE_ATTR);
	restrict_subtrees = backend_shr_get_vattr_sdnlist(state, e,
							  NIS_MAP_CONFIGURATION_RESTRICT_SUBTREES_ATTR);
	ignore_subtrees = backend_shr_get_vattr_sdnlist(state, e,
							NIS_MAP_CONFIGURATION_IGNORE_SUBTREES_ATTR);
	if (ignore_subtrees == NULL) {
		backend_shr_add_sdnlist(&ignore_subtrees, DEFAULT_IGNORE_SUBTREE);
	}
	entry_filter = backend_shr_get_vattr_filter(state, e,
						    NIS_MAP_CONFIGURATION_FILTER_ATTR);
	key_formats = backend_shr_get_vattr_strlist(state, e,
						    NIS_MAP_CONFIGURATION_KEY_ATTR);
	keys_formats = backend_shr_get_vattr_strlist(state, e,
						     NIS_MAP_CONFIGURATION_KEYS_ATTR);
	value_formats = backend_shr_get_vattr_strlist(state, e,
						      NIS_MAP_CONFIGURATION_VALUE_ATTR);
	values_formats = backend_shr_get_vattr_strlist(state, e,
						       NIS_MAP_CONFIGURATION_VALUES_ATTR);
	disallowed_chars = backend_shr_get_vattr_str(state, e,
						     NIS_MAP_CONFIGURATION_DISALLOWED_CHARS_ATTR);
	*secure = backend_shr_get_vattr_boolean(state, e,
						NIS_MAP_CONFIGURATION_SECURE_ATTR,
						FALSE);
	/* Build a filter, using either the configured value or the default as
	 * a template, we need to do this because RFC2307bis sometimes stores
	 * the map name in each entry, so it's useful to be able to filter on
	 * it. */
	use_entry_filter = backend_map_config_filter(entry_filter ?
						     entry_filter :
						     default_filter,
						     domain, map);
	/* Use the supplied key-format.  If there is none, and there is also
	 * not a supplied keys-format, use the default. */
	use_key_formats = key_formats ?
			  backend_shr_dup_strlist_unless_empty(key_formats) :
			  (keys_formats ? NULL :
			   (default_key_format ?
			    backend_shr_dup_strlist_n((char **) &default_key_format,
						      1) :
			    NULL));
	/* Use the supplied keys-format.  If there is none, and there is also
	 * not a supplied key-format, use the default. */
	use_keys_formats = keys_formats ?
			   backend_shr_dup_strlist_unless_empty(keys_formats) :
			   (key_formats ? NULL :
			    (default_keys_format ?
			     backend_shr_dup_strlist_n((char **) &default_keys_format,
						       1) :
			     NULL));
	/* Use the supplied value-format.  If there is none, and there is also
	 * not a supplied values-format, use the default. */
	use_value_formats = value_formats ?
			    backend_shr_dup_strlist_unless_empty(value_formats) :
			    (values_formats ? NULL :
			     (default_value_format ?
			      backend_shr_dup_strlist_n((char **) &default_value_format,
						        1) :
			      NULL));
	/* Use the supplied values-format.  If there is none, and there is also
	 * not a supplied value-format, use the default. */
	use_values_formats = values_formats ?
			     backend_shr_dup_strlist_unless_empty(values_formats) :
			     (value_formats ? NULL :
			      (default_values_format ?
			       backend_shr_dup_strlist_n((char **) &default_values_format,
						         1) :
			       NULL));
	/* We don't supply defaults for search locations. */
	use_bases = backend_shr_dup_strlist(bases);
	/* Use explicitly-configured disallowed-characters lists, else use the
	 * defauts. */
	use_disallowed_chars = disallowed_chars ?
			       strdup(disallowed_chars) :
			       (default_disallowed_chars ?
			        strdup(default_disallowed_chars) :
				NULL);
	/* Free the values we read from the entry. */
	free(disallowed_chars);
	backend_shr_free_strlist(value_formats);
	backend_shr_free_strlist(values_formats);
	backend_shr_free_strlist(key_formats);
	backend_shr_free_strlist(keys_formats);
	free(entry_filter);
	backend_shr_free_strlist(bases);
	/* Populate the returned structure. */
	ret.common.state = state;
	ret.common.group = strdup(domain);
	ret.common.set = strdup(map);
	ret.common.bases = use_bases;
	ret.common.restrict_subtrees = restrict_subtrees;
	ret.common.ignore_subtrees = ignore_subtrees;
	ret.common.entry_filter = use_entry_filter;
	ret.common.rel_attrs = NULL;
	ret.common.rel_attr_list = NULL;
	ret.common.rel_attrs_list = NULL;
	ret.common.ref_attrs = NULL;
	ret.common.inref_attrs = NULL;
	ret.common.ref_attr_list = NULL;
	ret.common.inref_attr_list = NULL;
	if ((getenv(NIS_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV) == NULL) ||
	    (atol(getenv(NIS_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV)) == 0)) {
		ret.common.skip_uninteresting_updates = 1;
	} else {
		ret.common.skip_uninteresting_updates = 0;
	}
	ret.disallowed_chars = use_disallowed_chars;
	ret.key_formats = use_key_formats;
	ret.n_key_formats = 0;
	ret.keys_formats = use_keys_formats;
	ret.n_keys_formats = 0;
	ret.value_formats = use_value_formats;
	ret.n_value_formats = 0;
	ret.values_formats = use_values_formats;
	ret.n_values_formats = 0;
	for (i = 0;
	     (use_key_formats != NULL) && (use_key_formats[i] != NULL);
	     i++) {
		for (j = 0;
		     (use_value_formats != NULL) &&
		     (use_value_formats[j] != NULL);
		     j++) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"initializing map %s in %s (3): "
					"filter \"%s\", "
					"key \"%s\", "
					"value \"%s\"\n",
					map, domain,
					use_entry_filter,
					use_key_formats[i],
					use_value_formats[j]);
			ret.n_value_formats++;
		}
		for (j = 0;
		     (use_values_formats != NULL) &&
		     (use_values_formats[j] != NULL);
		     j++) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"initializing map %s in %s (3): "
					"filter \"%s\", "
					"key \"%s\", "
					"values \"%s\"\n",
					map, domain,
					use_entry_filter,
					use_key_formats[i],
					use_values_formats[j]);
			ret.n_values_formats++;
		}
		ret.n_key_formats++;
	}
	for (i = 0;
	     (use_keys_formats != NULL) && (use_keys_formats[i] != NULL);
	     i++) {
		for (j = 0;
		     (use_value_formats != NULL) &&
		     (use_value_formats[j] != NULL);
		     j++) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"initializing map %s in %s (3): "
					"filter \"%s\", "
					"keys \"%s\", "
					"value \"%s\"\n",
					map, domain,
					use_entry_filter,
					use_keys_formats[i],
					use_value_formats[j]);
			ret.n_value_formats++;
		}
		for (j = 0;
		     (use_values_formats != NULL) &&
		     (use_values_formats[j] != NULL);
		     j++) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"initializing map %s in %s (3): "
					"filter \"%s\", "
					"keys \"%s\", "
					"values \"%s\"\n",
					map, domain,
					use_entry_filter,
					use_keys_formats[i],
					use_values_formats[j]);
			ret.n_values_formats++;
		}
		ret.n_keys_formats++;
	}
	*pret = backend_copy_set_data(&ret);
	if (*pret == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"out of memory initializing map %s in %s\n",
				map, domain);
	}
	free(ret.common.group);
	free(ret.common.set);
	backend_shr_free_strlist(ret.common.bases);
	backend_shr_free_sdnlist(ret.common.restrict_subtrees);
	free(ret.disallowed_chars);
	free(ret.common.entry_filter);
	backend_shr_free_strlist(ret.key_formats);
	backend_shr_free_strlist(ret.keys_formats);
	backend_shr_free_strlist(ret.value_formats);
	backend_shr_free_strlist(ret.values_formats);
}

/* Process a map configuration directory entry.  Pull out the domain and map
 * names which are valid for this configuration and configure such a map for
 * each in turn. */
int
backend_set_config_entry_add_cb(Slapi_Entry *e, void *callback_data)
{
	char **domains, **maps;
	int i, j;
	struct backend_set_config_entry_add_cbdata *cbdata;

	cbdata = callback_data;
	domains = backend_shr_get_vattr_strlist(cbdata->state, e,
						NIS_MAP_CONFIGURATION_DOMAIN_ATTR);
	maps = backend_shr_get_vattr_strlist(cbdata->state, e,
					     NIS_MAP_CONFIGURATION_MAP_ATTR);
	for (i = 0; (domains != NULL) && (domains[i] != NULL); i++) {
		for (j = 0; (maps != NULL) && (maps[j] != NULL); j++) {
			backend_shr_set_config_entry_add(cbdata->state,
							 cbdata->pb,
							 e,
							 domains[i],
							 maps[j]);
		}
	}
	backend_shr_free_strlist(maps);
	backend_shr_free_strlist(domains);
	return 0;
}

/* Update/initialize parameters stored in the plugin's configuration entry. */
void
backend_update_params(Slapi_PBlock *pb, struct plugin_state *state)
{
	Slapi_DN *our_dn;
	Slapi_Entry *our_entry;
	char *tmp, **tmpv;
	int i, use_be_txns;

	our_dn = slapi_sdn_new_dn_byval(state->plugin_base);
	if (our_dn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"backend_update_params: "
				"error parsing %s%s%s\n",
				state->plugin_base ? "\"" : "",
				state->plugin_base ?
				state->plugin_base : "NULL",
				state->plugin_base ? "\"" : "");
		return;
	}
	wrap_search_internal_get_entry(pb, our_dn, NULL, NULL, &our_entry,
				       state->plugin_identity);
	slapi_sdn_free(&our_dn);
	our_dn = NULL;
	if (our_entry == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"backend_update_params: failure reading entry "
				"\"%s\"\n", state->plugin_base);
		return;
	}
	/* Pull out the attribute values. */
	state->max_value_size = backend_shr_get_vattr_uint(state, our_entry,
							   NIS_PLUGIN_CONFIGURATION_MAXVALUE_ATTR,
							   DEFAULT_MAX_VALUE_SIZE);
	state->max_dgram_size = backend_shr_get_vattr_uint(state, our_entry,
							   NIS_PLUGIN_CONFIGURATION_MAXDGRAM_ATTR,
							   DEFAULT_MAX_DGRAM_SIZE);
	tmpv = backend_shr_get_vattr_strlist(state, our_entry,
					     NIS_PLUGIN_CONFIGURATION_SECURENET_ATTR);
	dispatch_securenets_clear(state);
	if (tmpv != NULL) {
		for (i = 0; tmpv[i] != NULL; i++) {
			dispatch_securenets_add(state, tmpv[i]);
		}
		backend_shr_free_strlist(tmpv);
	}
#ifdef HAVE_TCPD_H
	tmp = backend_shr_get_vattr_str(state, our_entry,
					NIS_PLUGIN_CONFIGURATION_TCPWRAPNAME_ATTR);
	if (tmp != NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"setting tcp_wrappers context at %p's "
				"name to \"%s\"\n",
				state->request_info, tmp);
		request_set(state->request_info, RQ_DAEMON, tmp);
		free(tmp);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"(re)setting tcp_wrappers context at %p's "
				"name to \"%s\"\n",
				state->request_info, DEFAULT_TCPWRAP_NAME);
		request_set(state->request_info, RQ_DAEMON,
			    DEFAULT_TCPWRAP_NAME);
	}
#endif
	use_be_txns = backend_shr_get_vattr_boolean(state, our_entry,
						    "nsslapd-pluginbetxn",
						    DEFAULT_PLUGIN_USE_BETXNS);
	if (state->use_be_txns && !use_be_txns) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"turning off betxn support\n");
	}
	if (!state->use_be_txns && use_be_txns) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"turning on betxn support\n");
	}
	state->use_be_txns = use_be_txns;
	slapi_entry_free(our_entry);
}

/* Process a map configuration directory entry.  Pull out the domain and map
 * names which are specified in the entry and delete each in turn. */
int
backend_set_config_entry_delete_cb(Slapi_Entry *e, void *callback_data)
{
	struct plugin_state *state;
	state = callback_data;
	return backend_shr_set_config_entry_delete(state, e,
						   NIS_MAP_CONFIGURATION_DOMAIN_ATTR,
						   NIS_MAP_CONFIGURATION_MAP_ATTR);
}

/* Read enough of the map configuration for the formatting code to be able to
 * resolver references correctly. */
struct backend_get_set_config_cb {
	struct plugin_state *state;
	char **bases;
	char *entry_filter;
};

void
backend_free_set_config(char **bases, char *entry_filter)
{
	backend_shr_free_strlist(bases);
	free(entry_filter);
}

static bool_t
backend_get_set_config_entry_cb(Slapi_Entry *e, void *callback_data)
{
	struct backend_get_set_config_cb *cbdata;

	cbdata = callback_data;
	slapi_log_error(SLAPI_LOG_PLUGIN,
			cbdata->state->plugin_desc->spd_id,
			"reading map configuration from \"%s\"\n",
			slapi_entry_get_dn(e));
	cbdata->bases = backend_shr_get_vattr_strlist(cbdata->state, e,
						      NIS_MAP_CONFIGURATION_BASE_ATTR);
	cbdata->entry_filter = backend_shr_get_vattr_filter(cbdata->state, e,
							    NIS_MAP_CONFIGURATION_FILTER_ATTR);
	return TRUE;
}

void
backend_get_set_config(Slapi_PBlock *parent_pb,
		       struct plugin_state *state,
		       const char *domain, const char *map,
		       char ***bases, char **entry_filter)
{
	Slapi_PBlock *pb;
	char *filter;
	char *attrs[] = {NIS_MAP_CONFIGURATION_FILTER_ATTR,
			 NIS_MAP_CONFIGURATION_BASE_ATTR,
			 NULL};
	const char *default_filter;
	bool_t map_secure;
	struct backend_get_set_config_cb cbdata;

	/* Build the search filter. */
	filter = malloc(strlen("(&("
			       NIS_MAP_CONFIGURATION_DOMAIN_ATTR "=)("
			       NIS_MAP_CONFIGURATION_MAP_ATTR "=)("
			       NIS_MAP_CONFIGURATION_BASE_ATTR "=*))") +
			strlen(domain) + strlen(map) +
			strlen(NIS_MAP_CONFIGURATION_FILTER) + 1);
	if (filter == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"out of memory reading configuration for "
				"\"%s\"/\"%s\"!\n", domain, map);
		return;
	}
	sprintf(filter, "(&("
		NIS_MAP_CONFIGURATION_DOMAIN_ATTR "=%s)("
		NIS_MAP_CONFIGURATION_MAP_ATTR "=%s)("
		NIS_MAP_CONFIGURATION_BASE_ATTR "=*)%s)",
		domain, map, NIS_MAP_CONFIGURATION_FILTER);

	/* Perform the search. */
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"searching from \"%s\" for \"%s\" for configuration\n",
			state->plugin_base, filter);
	pb = wrap_pblock_new(parent_pb);
	slapi_search_internal_set_pb(pb,
				     state->plugin_base,
				     LDAP_SCOPE_SUBTREE,
				     filter,
				     attrs, FALSE,
				     NULL,
				     NULL,
				     state->plugin_identity,
				     0);
	cbdata.bases = NULL;
	cbdata.entry_filter = NULL;
	cbdata.state = state;
	map_secure = FALSE;
	slapi_search_internal_callback_pb(pb, &cbdata,
					  NULL,
					  backend_get_set_config_entry_cb,
					  NULL);
	slapi_pblock_destroy(pb);
	defaults_get_map_config(map, &map_secure, &default_filter,
				NULL, NULL, NULL, NULL, NULL);
	if (cbdata.entry_filter == NULL) {
		cbdata.entry_filter = strdup(default_filter);
	}

	/* Return the results. */
	*bases = cbdata.bases;
	*entry_filter = backend_map_config_filter(cbdata.entry_filter,
						  domain, map);
	free(cbdata.entry_filter);

	/* Clean up. */
	free(filter);
}

/* Given an entry, return the filter which will match a container entry beneath
 * the plugin's configuration entry. */
const char *
backend_entry_get_set_config_entry_filter(void)
{
	return NIS_MAP_CONFIGURATION_FILTER;
}

/* Warn if a map is empty. */
void
backend_check_empty(struct plugin_state *state,
		    const char *group, const char *set)
{
	unsigned int first_key_len, first_value_len;
	int first_key_index;
	const char *first_id;
	char *first_key, *first_value;
	bool_t map_secure;
	if (!map_first(state, group, set,
		       &map_secure,
		       &first_key_len, &first_key,
		       &first_value_len, &first_value,
		       &first_id,
		       &first_key_index)) {
		slapi_log_error(SLAPI_LOG_FATAL, state->plugin_desc->spd_id,
				"warning: no entries in domain=%s,map=%s\n",
				group, set);
	}
}

/* Scan for the list of configured domains and maps. */
void
backend_startup(Slapi_PBlock *pb, struct plugin_state *state)
{
	backend_shr_startup(state, pb, NIS_MAP_CONFIGURATION_FILTER);
}

/* Set up our post-op callbacks. */
#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
int
backend_init_betxn_postop(Slapi_PBlock *pb, struct plugin_state *state)
{
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"hooking up betxn postoperation callbacks\n");
	return backend_shr_betxn_postop_init(pb, state);
}
#endif

int
backend_init_postop(Slapi_PBlock *pb, struct plugin_state *state)
{
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"hooking up postoperation callbacks\n");
	return backend_shr_postop_init(pb, state);
}

int
backend_init_internal_postop(Slapi_PBlock *pb, struct plugin_state *state)
{
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"hooking up internal postoperation callbacks\n");
	return backend_shr_internal_postop_init(pb, state);
}
