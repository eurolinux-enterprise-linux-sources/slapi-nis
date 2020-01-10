/*
 * Copyright 2008,2010,2011,2012 Red Hat, Inc.
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
#include "format.h"
#include "plugin.h"
#include "map.h"

/* Check if the caller for the current operation is *us*. */
bool_t
backend_shr_is_caller(struct plugin_state *state, Slapi_PBlock *pb)
{
	Slapi_ComponentId *identity;
	slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &identity);
	return (identity == state->plugin_identity);
}

/* Read the name of this server.  Used by the map module on behalf of the
 * NIS service logic. */
void
backend_shr_free_server_name(struct plugin_state *state, char *master)
{
	free(master);
}
int
backend_shr_read_server_name(Slapi_PBlock *pb, struct plugin_state *state,
			     char **master)
{
	Slapi_DN *config_dn;
	Slapi_Entry *config;
	Slapi_ValueSet *values;
	Slapi_Value *value;
	char *attrs[] = {"nsslapd-localhost", NULL}, *actual_attr;
	const char *cvalue;
	int disposition, buffer_flags;

	*master = NULL;
	/* Try to read our name from the top-level configuration node. */
	config_dn = slapi_sdn_new_dn_byval("cn=config");
	if (config_dn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"backend_master_name: "
				"error parsing \"cn=config\"\n");
		return -1;
	}
	wrap_search_internal_get_entry(pb, config_dn, NULL, attrs, &config,
				       state->plugin_identity);
	if (config == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"backend_master_name: failure reading entry "
				"\"cn=config\"\n");
		slapi_sdn_free(&config_dn);
		return -1;
	}
	slapi_sdn_free(&config_dn);
	/* Pull out the attribute. */
	if (slapi_vattr_values_get(config, attrs[0], &values,
				   &disposition, &actual_attr,
				   0, &buffer_flags) == 0) {
		if (slapi_valueset_first_value(values, &value) == 0) {
			cvalue = slapi_value_get_string(value);
			if (cvalue != NULL) {
				*master = strdup(cvalue);
			}
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"backend_master_name: no \"%s\" value "
					"for \"cn=config\"",
					attrs[0]);
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	}
	slapi_entry_free(config);
	return (*master != NULL) ? 0 : -1;
}

/* Cache the list of relevant attributes, updating if needed, and return its
 * value.  Currently only used for logging. */
static const char *
backend_shr_get_rel_attr_list(struct backend_shr_set_data *data)
{
	int i, length;

	if (data->rel_attrs_list == data->rel_attrs) {
		return data->rel_attr_list;
	} else {
		free(data->rel_attr_list);
		if (data->rel_attrs == NULL) {
			data->rel_attr_list = NULL;
		} else {
			for (i = 0, length = 0;
			     data->rel_attrs[i] != NULL;
			     i++) {
				length += (strlen(data->rel_attrs[i]) + 1);
			}
			if (length > 0) {
				data->rel_attr_list = malloc(length);
				for (i = 0, length = 0;
				     (data->rel_attrs[i] != NULL);
				     i++) {
					if (i > 0) {
						strcpy(data->rel_attr_list + length++, ",");
					}
					strcpy(data->rel_attr_list + length, data->rel_attrs[i]);
					length += strlen(data->rel_attrs[i]);
				}
			} else {
				data->rel_attr_list = NULL;
			}
		}
		data->rel_attrs_list = data->rel_attrs;
	}
	return data->rel_attr_list ? data->rel_attr_list : "";
}

/* Manipulate string lists. */
void
backend_shr_free_strlist(char **strlist)
{
	if (strlist) {
		free(strlist);
	}
}
char **
backend_shr_dup_strlist_n(char **strlist, int n)
{
	int i, l;
	char **ret, *s;
	/* Handle the NULL case. */
	if (strlist == NULL) {
		return NULL;
	}
	/* No strings = no list. */
	if (n == 0) {
		return NULL;
	}
	/* Count the amount of space needed for the strings. */
	for (i = 0, l = 0; i < n; i++) {
		l += (strlen(strlist[i]) + 1);
	}
	/* Allocate space for the array of pointers (with NULL terminator) and
	 * then the string data. */
	ret = malloc(((n + 1) * sizeof(char *)) + l);
	if (ret != NULL) {
		/* Figure out where the string data will start. */
		s = (char *) ret;
		s += ((n + 1) * sizeof(char *));
		for (i = 0; i < n; i++) {
			/* Set the address of this string, copy the data
			 * around, and then prepare the address of the next
			 * string. */
			ret[i] = s;
			strcpy(s, strlist[i]);
			s += (strlen(strlist[i]) + 1);
		}
		/* NULL-terminate the array. */
		ret[i] = NULL;
	}
	return ret;
}
char **
backend_shr_dup_strlist(char **strlist)
{
	int i;
	for (i = 0; (strlist != NULL) && (strlist[i] != NULL); i++) {
		continue;
	}
	return backend_shr_dup_strlist_n(strlist, i);
}
char **
backend_shr_dup_strlist_unless_empty(char **strlist)
{
	int i;
	for (i = 0;
	     (strlist != NULL) &&
	     (strlist[i] != NULL) &&
	     (strlen(strlist[i]) > 0);
	     i++) {
		continue;
	}
	if (i > 0) {
		return backend_shr_dup_strlist_n(strlist, i);
	} else {
		return NULL;
	}
}
void
backend_shr_add_strlist(char ***strlist, const char *value)
{
	int i, elements, length;
	char **ret, *p;

	length = strlen(value) + 1;
	elements = 0;
	if (*strlist != NULL) {
		for (i = 0; (*strlist)[i] != NULL; i++) {
			if (strcmp(value, (*strlist)[i]) == 0) {
				return;
			}
			length += (strlen((*strlist)[i]) + 1);
			elements++;
		}
	}

	ret = malloc(((elements + 2) * sizeof(char *)) + length);
	if (ret != NULL) {
		p = (char *) ret;
		p += (elements + 2) * sizeof(char *);
		for (i = 0; i < elements; i++) {
			ret[i] = p;
			strcpy(p, (*strlist)[i]);
			p += (strlen((*strlist)[i]) + 1);
		}
		ret[i++] = p;
		strcpy(p, value);
		p += (strlen(value) + 1);
		ret[i] = NULL;
		backend_shr_free_strlist(*strlist);
	}
	*strlist = ret;
}

/* Set or unset the entry using information in the callback data. */
static void
backend_shr_set_entry(Slapi_PBlock *pb, Slapi_Entry *e, struct backend_set_data *set_data)
{
	backend_set_entry(pb, e, set_data);
}
struct backend_shr_set_entry_cbdata {
	Slapi_PBlock *pb;
	struct backend_set_data *set_data;
};
static int
backend_shr_set_entry_cb(Slapi_Entry *e, void *callback_data)
{
	struct backend_shr_set_entry_cbdata *cbdata;
	cbdata = callback_data;
	backend_shr_set_entry(cbdata->pb, e, cbdata->set_data);
	return 0;
}

/* Set or unset the named entry using information in the callback data. */
static void
backend_shr_set_config_entry_set_one_dn(struct plugin_state *state,
					Slapi_PBlock *pb,
					const char *dn,
					struct backend_set_data *set_data)
{
	Slapi_DN *sdn;
	Slapi_Entry *entry;
	sdn = slapi_sdn_new_dn_byval(dn);
	if (sdn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"error parsing DN \"%s\"\n", dn);
		return;
	} else {
		wrap_search_internal_get_entry(pb, sdn, NULL, NULL, &entry,
					       state->plugin_identity);
		if (entry == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"failure reading entry \"%s\"\n", dn);
		} else {
			backend_shr_set_entry(pb, entry, set_data);
			slapi_entry_free(entry);
		}
		slapi_sdn_free(&sdn);
	}
}

/* Check if the given entry is somewhere beneath the NDN and matches the
 * filter. */
static bool_t
backend_shr_entry_matches(Slapi_PBlock *pb, Slapi_Entry *e,
			  const char *containing_ndn, int scope,
			  const char *check_filter)
{
	Slapi_DN *entry_sdn, *containing_sdn;
	Slapi_Filter *filter;
	char *filterstr;
	bool_t ret;

	/* First, just do the scope test. The item should be a somewhere
	 * beneath the passed-in entry. */
	entry_sdn = slapi_sdn_new_ndn_byref(slapi_entry_get_ndn(e));
	if (entry_sdn == NULL) {
		return FALSE;
	} else {
		containing_sdn = slapi_sdn_new_dn_byval(containing_ndn);
		if (containing_sdn == NULL) {
			slapi_sdn_free(&entry_sdn);
			return FALSE;
		}
	}
	if (slapi_sdn_scope_test(entry_sdn, containing_sdn, scope) == 0) {
		ret = FALSE;
	} else {
		ret = TRUE;
	}
	slapi_sdn_free(&containing_sdn);
	slapi_sdn_free(&entry_sdn);

	/* If it's actually in our configuration tree, check if it's a valid
	 * entry. */
	if (ret) {
		/* N.B.: slapi_str2filter isn't kidding -- it really wants a
		 * writable string. */
		filterstr = strdup(check_filter);
		if (filterstr != NULL) {
			filter = slapi_str2filter(filterstr);
			if (filter != NULL) {
				if (slapi_vattr_filter_test(pb, e,
							    filter, 0) != 0) {
					ret = FALSE;
				}
				slapi_filter_free(filter, 1);
			}
			free(filterstr);
		}
	}
	return ret;
}

/* Given a directory server entry which represents a set's configuration, set
 * up and populate the set. */
static void
backend_shr_set_config_free_config(void *cb_data)
{
	struct backend_shr_set_data *set_data;
	set_data = cb_data;
	backend_set_config_free_config(set_data);
}
int
backend_shr_set_config_entry_add(struct plugin_state *state,
				 Slapi_PBlock *parent_pb, Slapi_Entry *e,
				 const char *group, const char *set)
{
	Slapi_PBlock *pb;
	int i;
	bool_t flag;
	struct backend_shr_set_data *set_data;
	struct backend_shr_set_entry_cbdata cbdata;
	char **set_bases;
	char *set_entry_filter;

	flag = FALSE;
	backend_set_config_read_config(state, e, group, set, &flag, &set_data);
	if (set_data == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"incomplete definition for %s in %s (2)\n",
				set, group);
		return 0;
	}
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"initializing \"%s\" in %s, flag=%s (2)\n",
			set_data->set, set_data->group, flag ? "yes" : "no");
	map_data_set_map(state, set_data->group, set_data->set, flag,
			 set_data, &backend_shr_set_config_free_config);
	map_data_clear_map(state, set_data->group, set_data->set);
	/* Search under each base in turn, adding the matching directory
	 * entries to the set. */
	set_bases = set_data->bases;
	set_entry_filter = set_data->entry_filter;
	for (i = 0; (set_bases != NULL) && (set_bases[i] != NULL); i++) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"searching '%s' for '%s'\n",
				set_bases[i], set_entry_filter);
		pb = wrap_pblock_new(parent_pb);
		slapi_search_internal_set_pb(pb,
					     set_bases[i],
					     LDAP_SCOPE_SUBTREE,
					     set_entry_filter,
					     NULL, FALSE,
					     NULL,
					     NULL,
					     state->plugin_identity,
					     0);
		cbdata.set_data = set_data->self;
		cbdata.pb = pb;
		slapi_search_internal_callback_pb(pb, &cbdata,
						  NULL,
						  backend_shr_set_entry_cb,
						  NULL);
		slapi_pblock_destroy(pb);
	}
	/* Warn if we didn't put anything into the set. */
	backend_check_empty(state, set_data->group, set_data->set);
	/* Clean up. */
	return 0;
}

/* Read a list of string values for the named attribute. */
char **
backend_shr_get_vattr_strlist(struct plugin_state *state,
			      Slapi_Entry *e, const char *attribute)
{
	Slapi_ValueSet *values;
	Slapi_Value *value;
	int disposition, buffer_flags;
	char *actual_attr, **ret;
	const char **tmp;
	int i, j;
	ret = NULL;
	if (slapi_vattr_values_get(e, (char *) attribute,
				   &values, &disposition, &actual_attr,
				   0, &buffer_flags) == 0) {
		tmp = malloc(sizeof(char *) *
			     (slapi_valueset_count(values) + 1));
		if (tmp != NULL) {
			j = 0;
			for (i = slapi_valueset_first_value(values, &value);
			     i != -1;
			     i = slapi_valueset_next_value(values, i, &value)) {
				if (slapi_value_get_length(value) > 0) {
					tmp[j++] = slapi_value_get_string(value);
				}
			}
			tmp[j] = NULL;
			ret = backend_shr_dup_strlist((char **) tmp);
			free(tmp);
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	}
	return ret;
}
char *
backend_shr_get_vattr_str(struct plugin_state *state,
			  Slapi_Entry *e, const char *attribute)
{
	Slapi_ValueSet *values;
	Slapi_Value *value;
	int disposition, buffer_flags;
	char *actual_attr, *ret;
	int i;
	ret = NULL;
	if (slapi_vattr_values_get(e, (char *) attribute,
				   &values, &disposition, &actual_attr,
				   0, &buffer_flags) == 0) {
		i = slapi_valueset_first_value(values, &value);
		if (i != -1) {
			if (slapi_value_get_length(value) > 0) {
				ret = strdup(slapi_value_get_string(value));
			}
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	}
	return ret;
}
unsigned int
backend_shr_get_vattr_uint(struct plugin_state *state,
			   Slapi_Entry *e, const char *attribute,
			   unsigned int default_value)
{
	Slapi_ValueSet *values;
	Slapi_Value *value;
	int disposition, buffer_flags, i;
	char *actual_attr;
	unsigned int ret;
	ret = default_value;
	if (slapi_vattr_values_get(e, (char *) attribute,
				   &values, &disposition, &actual_attr,
				   0, &buffer_flags) == 0) {
		i = slapi_valueset_first_value(values, &value);
		if (i != -1) {
			ret = slapi_value_get_uint(value);
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	}
	return ret;
}
char *
backend_shr_get_vattr_filter(struct plugin_state *state,
			     Slapi_Entry *e, const char *attribute)
{
	char *tmp, *ret;
	ret = backend_shr_get_vattr_str(state, e, attribute);
	if (ret != NULL) {
		if (strlen(ret) > 0) {
			if ((ret[0] != '(') || (ret[strlen(ret) - 1] != ')')) {
				tmp = malloc(strlen(ret) + 3);
				if (tmp != NULL) {
					sprintf(tmp, "(%s)", ret);
					free(ret);
					ret = tmp;
				}
			}
		}
	}
	return ret;
}
bool_t
backend_shr_get_vattr_boolean(struct plugin_state *state,
			      Slapi_Entry *e, const char *attribute,
			      bool_t default_value)
{
	char *tmp;
	bool_t ret;
	ret = default_value;
	tmp = backend_shr_get_vattr_str(state, e, attribute);
	if (tmp != NULL) {
		/* FIXME: should we use nl_langinfo(YESEXPR) here? */
		if ((strcasecmp(tmp, "yes") == 0) ||
		    (strcasecmp(tmp, "on") == 0) ||
		    (strcasecmp(tmp, "1") == 0)) {
			ret = TRUE;
		} else {
			ret = FALSE;
		}
		free(tmp);
	}
	return ret;
}

/* Scan for the list of configured groups and sets. */
void
backend_shr_startup(struct plugin_state *state,
		    Slapi_PBlock *parent_pb,
		    const char *filter)
{
	Slapi_PBlock *pb;
	struct backend_set_config_entry_add_cbdata set_cbdata;

	backend_update_params(parent_pb, state);

	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"searching under \"%s\" for configuration\n",
			state->plugin_base);
	pb = wrap_pblock_new(parent_pb);
	slapi_search_internal_set_pb(pb,
				     state->plugin_base,
				     LDAP_SCOPE_ONELEVEL,
				     filter,
				     NULL, FALSE,
				     NULL,
				     NULL,
				     state->plugin_identity,
				     0);
	map_wrlock();
	set_cbdata.state = state;
	set_cbdata.pb = pb;
	slapi_search_internal_callback_pb(pb, &set_cbdata,
					  NULL,
					  backend_set_config_entry_add_cb,
					  NULL);
	map_unlock();
	slapi_pblock_destroy(pb);
}

/* Process a set configuration directory entry.  Pull out the group and set
 * names which are specified in the entry and delete each in turn. */
int
backend_shr_set_config_entry_delete(struct plugin_state *state,
				    Slapi_Entry *e,
				    const char *group_attr,
				    const char *set_attr)
{
	char **groups, **sets;
	struct backend_shr_set_data *set_data;
	int i, j;
	bool_t flag;

	groups = slapi_entry_attr_get_charray(e, group_attr);
	sets = slapi_entry_attr_get_charray(e, set_attr);
	for (i = 0; (groups != NULL) && (groups[i] != NULL); i++) {
		for (j = 0; (sets != NULL) && (sets[j] != NULL); j++) {
			backend_set_config_read_config(state, e,
						       groups[i], sets[j],
						       &flag, &set_data);
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"removing set %s in %s\n",
					set_data->set, set_data->group);
			map_data_unset_map(state,
					   set_data->group, set_data->set);
			backend_set_config_free_config(set_data);
		}
	}
	slapi_ch_array_free(sets);
	slapi_ch_array_free(groups);
	return 0;
}

struct backend_get_set_config_cb {
	struct plugin_state *state;
	char **bases;
	char *entry_filter;
};

/* Used by the format functions to read set configuration. */
void
backend_shr_free_set_config(char **bases, char *entry_filter)
{
	backend_shr_free_strlist(bases);
	free(entry_filter);
}

static bool_t
backend_shr_get_set_config_entry_cb(Slapi_Entry *e, void *callback_data,
				    const char *base_attr,
				    const char *filter_attr)
{
	Slapi_ValueSet *values;
	Slapi_Value *value;
	struct backend_get_set_config_cb *cbdata;
	char *actual_attr;
	const char *cvalue;
	int disposition, buffer_flags, i, count;

	cbdata = callback_data;
	slapi_log_error(SLAPI_LOG_PLUGIN,
			cbdata->state->plugin_desc->spd_id,
			"reading set configuration from \"%s\"\n",
			slapi_entry_get_ndn(e));

	values = NULL;
	value = NULL;
	if (slapi_vattr_values_get(e, (char *) base_attr, &values,
				   &disposition, &actual_attr,
				   0, &buffer_flags) == 0) {
		count = slapi_valueset_count(values);
		cbdata->bases = malloc(sizeof(char *) * (count + 1));
		if (cbdata->bases != NULL) {
			for (i = slapi_valueset_first_value(values, &value);
			     i != -1;
			     i = slapi_valueset_next_value(values, i, &value)) {
				cvalue = slapi_value_get_string(value);
				cbdata->bases[i] = strdup(cvalue);
			}
			cbdata->bases[count] = NULL;
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	}
	if (slapi_vattr_values_get(e, (char *) filter_attr, &values,
				   &disposition, &actual_attr,
				   0, &buffer_flags) == 0) {
		if (slapi_valueset_first_value(values, &value) != -1) {
			cvalue = slapi_value_get_string(value);
			if (cvalue != NULL) {
				free(cbdata->entry_filter);
				cbdata->entry_filter = strdup(cvalue);
			}
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	}

	return TRUE;
}

/* Our postoperation callbacks. */

/* Given a map configuration, return true if the entry is supposed to be in the
 * map. */
static bool_t
backend_shr_entry_matches_set(struct backend_shr_set_data *set_data,
			      Slapi_PBlock *pb, Slapi_Entry *e)
{
	char **set_bases;
	char *set_filter;
	int i;
	set_bases = set_data->bases;
	set_filter = set_data->entry_filter;
	if (set_bases != NULL) {
		for (i = 0; set_bases[i] != NULL; i++) {
			if (backend_shr_entry_matches(pb, e,
						      set_bases[i],
						      LDAP_SCOPE_SUBTREE,
						      set_filter)) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

/* Given an entry, return true if it describes a set. */
static bool_t
backend_shr_entry_is_a_set(struct plugin_state *state,
			   Slapi_PBlock *pb, Slapi_Entry *e)
{
	return backend_shr_entry_matches(pb, e,
					 state->plugin_base,
					 LDAP_SCOPE_ONELEVEL,
					 backend_entry_get_set_config_entry_filter());
}

/* Build a filter which includes the basic_filter, if given, and ANDs that
 * with an OR of the elements of attrs exactly matching the entry's DN. */
static char *
backend_build_filter(struct plugin_state *state, Slapi_DN *entry_dn,
		     const char *basic_filter, char **attrs)
{
	char *filter, *tndn;
	int filter_size, i, n_attrs;
	if (basic_filter == NULL) {
		basic_filter = "";
	}
	filter_size = strlen("(&(|))") + strlen(basic_filter) + 1;
	tndn = format_escape_for_filter(slapi_sdn_get_ndn(entry_dn));
	if (tndn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error building filter for "
				"updating entries\n");
		return NULL;
	}
	for (i = 0; (attrs != NULL) && (attrs[i] != NULL); i++) {
		filter_size += (strlen("(=)") +
				strlen(attrs[i]) +
				strlen(tndn));
	}
	n_attrs = i;
	filter = malloc(filter_size);
	if (filter == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"error building filter for "
				"updating entries\n");
		free(tndn);
		return NULL;
	}
	if (n_attrs > 1) {
		if (strlen(basic_filter) > 0) {
			sprintf(filter, "(&%s(|", basic_filter);
		} else {
			sprintf(filter, "(|");
		}
	} else {
		if (strlen(basic_filter) > 0) {
			sprintf(filter, "(&%s", basic_filter);
		} else {
			strcpy(filter, "");
		}
	}
	for (i = 0; (attrs != NULL) && (attrs[i] != NULL); i++) {
		sprintf(filter + strlen(filter),
			"(%s=%s)", attrs[i], tndn);
	}
	free(tndn);
	if (n_attrs > 1) {
		if (strlen(basic_filter) > 0) {
			strcat(filter, "))");
		} else {
			strcat(filter, ")");
		}
	} else {
		if (strlen(basic_filter) > 0) {
			strcat(filter, ")");
		} else {
			strcat(filter, "");
		}
	}
	return filter;
}

/* Add the name of this entry to the DN list in the cbdata. */
struct backend_shr_note_entry_sdn_cbdata {
	struct plugin_state *state;
	Slapi_DN ***sdn_list, ***sdn_list2;
};

static int
backend_shr_note_entry_sdn_cb(Slapi_Entry *e, void *cbdata_ptr)
{
	struct backend_shr_note_entry_sdn_cbdata *cbdata = cbdata_ptr;
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata->state->plugin_desc->spd_id,
			"matched entry \"%s\"\n", slapi_entry_get_dn(e));
	format_add_sdn_list(cbdata->sdn_list, cbdata->sdn_list2,
			    slapi_entry_get_dn(e));
	return 0;
}

/* Build a string representation of the list of attributes being modified by
 * this list of mods, typically for logging purposes. */
static char *
backend_shr_mods_as_string(LDAPMod **mods)
{
	char *ret;
	int i, length;

	ret = NULL;
	for (i = 0, length = 0; (mods != NULL) && (mods[i] != NULL); i++) {
		length += (strlen(mods[i]->mod_type) + 1 + 8);
	}
	if (length > 0) {
		ret = malloc(length);
		for (i = 0, length = 0;
		     (mods != NULL) && (mods[i] != NULL);
		     i++) {
			if (i > 0) {
				strcpy(ret + length++, ",");
			}
			if (SLAPI_IS_MOD_ADD(mods[i]->mod_op)) {
				strcpy(ret + length, "add:");
				length += 4;
			}
			if (SLAPI_IS_MOD_REPLACE(mods[i]->mod_op)) {
				strcpy(ret + length, "replace:");
				length += 8;
			}
			if (SLAPI_IS_MOD_DELETE(mods[i]->mod_op)) {
				strcpy(ret + length, "delete:");
				length += 7;
			}
			strcpy(ret + length, mods[i]->mod_type);
			length += strlen(mods[i]->mod_type);
		}
	}
	return ret;
}

/* Update any entries in the map for which the passed-in entry will affect the
 * values which are derived. */
struct backend_shr_update_references_cbdata {
	Slapi_PBlock *pb;
	Slapi_Entry *e;
	LDAPMod **mods;
	char *modlist;
};

static bool_t
backend_shr_update_references_cb(const char *group, const char *set,
				 bool_t flag,
				 void *backend_data, void *cbdata_ptr)
{
	struct plugin_state *state;
	struct backend_shr_set_data *set_data;
	struct backend_shr_update_references_cbdata *cbdata;
	struct backend_shr_set_entry_cbdata set_cbdata;
	struct backend_shr_note_entry_sdn_cbdata note_cbdata;
	Slapi_DN *referred_to_sdn, **these_entries, **prev_entries;
	Slapi_DN **next_entries, **these_bases, **prev_bases;
	Slapi_DN **these_entries2, **prev_entries2, **next_entries2;
	Slapi_Entry *this_entry;
	Slapi_ValueSet *values;
	Slapi_Value *value;
	Slapi_Filter *next_filter;
	Slapi_PBlock *pb;
	char **ref_attrs, *actual_attr, *filter, **set_bases;
	char *these_attrs[2], *prev_attrs[2], *next_attrs[2];
	const char *these_filter, *prev_filter, *next_filter_str;
	struct format_inref_attr **inref_attrs;
	struct format_ref_attr_list **ref_attr_list, *ref_attr;
	struct format_ref_attr_list **inref_attr_list, *inref_attr;
	struct format_ref_attr_list_link *this_attr_link, *prev_attr_link;
	struct format_ref_attr_list_link *next_attr_link;
	const char *ndn, *dn;
	int i, j, k, l, disposition, buffer_flags, n_ref_attrs, scope;

	set_data = backend_data;
	cbdata = cbdata_ptr;
	state = set_data->state;

#ifdef USE_SLAPI_BE_TXNS
	/* If the backend type is "ldbm database" and we have no transaction,
	 * do nothing, because we'll be called again later post-transaction,
	 * and we'll deal with it then. */
	if (cbdata->pb != NULL) {
		void *txn;
		char *be_type;
		txn = NULL;
		be_type = NULL;
#ifdef SLAPI_TXN
		slapi_pblock_get(cbdata->pb, SLAPI_TXN, &txn);
#endif
#ifdef SLAPI_TXN
		slapi_pblock_get(cbdata->pb, SLAPI_BE_TYPE, &be_type);
#endif
		if ((txn == NULL) && (strcmp(be_type, "ldbm database") == 0)) {
			return 0;
		}
	}
#endif

	/* If the entry didn't change any attributes which are at all relevant
	 * to this map, then we don't need to recompute anything. */
	if (set_data->skip_uninteresting_updates &&
	    (cbdata->mods != NULL) && (set_data->rel_attrs != NULL)) {
		for (i = 0; cbdata->mods[i] != NULL; i++) {
			for (j = 0; set_data->rel_attrs[j] != NULL; j++) {
				if (slapi_attr_types_equivalent(cbdata->mods[i]->mod_type,
								set_data->rel_attrs[j])) {
					break;
				}
			}
			if (set_data->rel_attrs[j] != NULL) {
				break;
			}
		}
		if (cbdata->mods[i] == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"no interesting reference-based "
					"changes for \"%s\"/\"%s\" "
					"made in \"%s\" (%s not in %s)\n",
					set_data->group,
					set_data->set,
					slapi_entry_get_ndn(cbdata->e),
					cbdata->modlist ? cbdata->modlist : "",
					backend_shr_get_rel_attr_list(set_data));
			return TRUE;
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"interesting reference-based "
					"changes for \"%s\"/\"%s\" "
					"made in \"%s\" (%s in %s)\n",
					set_data->group,
					set_data->set,
					slapi_entry_get_ndn(cbdata->e),
					cbdata->modlist ? cbdata->modlist : "",
					backend_shr_get_rel_attr_list(set_data));
		}
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"reference-based changes for "
				"\"%s\"/\"%s\" made in (\"%s\") "
				"(%s in %s or empty)\n",
				set_data->group,
				set_data->set,
				slapi_entry_get_ndn(cbdata->e),
				cbdata->modlist ? cbdata->modlist : "",
				backend_shr_get_rel_attr_list(set_data));
	}

	/* For every entry in this set which refers to this entry using
	 * a DN stored in an attribute, update that entry. */

	/* Build a filter with all of these attributes and this entry's DN. */
	ref_attrs = set_data->ref_attrs;
	for (i = 0; (ref_attrs != NULL) && (ref_attrs[i] != NULL); i++) {
		continue;
	}
	n_ref_attrs = i;
	if (n_ref_attrs > 0) {
		/* Build the search filter: entries in this map which refer to
		 * this entry. */
		filter = backend_build_filter(state,
					      slapi_entry_get_sdn(cbdata->e),
					      set_data->entry_filter,
					      ref_attrs);
		/* Update any matching entry. */
		set_bases = set_data->bases;
		for (i = 0;
		     (set_bases != NULL) && (set_bases[i] != NULL);
		     i++) {
			pb = wrap_pblock_new(cbdata->pb);
			slapi_search_internal_set_pb(pb,
						     set_bases[i],
						     LDAP_SCOPE_SUBTREE,
						     filter,
						     NULL, FALSE,
						     NULL,
						     NULL,
						     state->plugin_identity,
						     0);
			set_cbdata.set_data = set_data->self;
			set_cbdata.pb = pb;
			slapi_search_internal_callback_pb(pb, &set_cbdata,
							  NULL,
							  backend_shr_set_entry_cb,
							  NULL);
			slapi_pblock_destroy(pb);
		}
		free(filter);
	}

	/* For every directory entry to which this directory entry refers and
	 * which also has a corresponding entry in this map, update it. */

	/* Allocate the DN we'll use to hold values for comparison. */
	referred_to_sdn = slapi_sdn_new();
	if (referred_to_sdn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"error updating entries referred to by %s\n",
				slapi_entry_get_ndn(cbdata->e));
		return TRUE;
	}

	inref_attrs = set_data->inref_attrs;
	for (i = 0; (inref_attrs != NULL) && (inref_attrs[i] != NULL); i++) {
		/* Extract the named attribute from the entry. */
		values = NULL;
		if (slapi_vattr_values_get(cbdata->e,
					   inref_attrs[i]->attribute,
					   &values, &disposition, &actual_attr,
					   0, &buffer_flags) != 0) {
			continue;
		}
		/* For each value of this attributes.. */
		for (j = slapi_valueset_first_value(values, &value);
		     j != -1;
		     j = slapi_valueset_next_value(values, j, &value)) {
			/* Pull out the value, which is a referred-to entry's
			 * DN. */
			dn = slapi_value_get_string(value);
			if (dn == NULL) {
				continue;
			}
			/* Normalize the DN. */
			slapi_sdn_set_dn_byref(referred_to_sdn, dn);
			ndn = slapi_sdn_get_ndn(referred_to_sdn);
			/* If the named entry corresponds to an entry that's
			 * already in this map. */
			if (map_data_check_entry(state, group, set, ndn)) {
				/* ...update it. */
				backend_shr_set_config_entry_set_one_dn(state,
									cbdata->pb,
									ndn,
									set_data->self);
			}
		}
		slapi_vattr_values_free(&values, &actual_attr,
					buffer_flags);
	}
	slapi_sdn_free(&referred_to_sdn);

	/* Determine if there are any entries in this map which directly (or
	 * indirectly) pull in data from this entry.  If there are, update
	 * them. */

	/* Walk the set of reference-attribute chains. */
	ref_attr_list = set_data->ref_attr_list;
	for (i = 0;
	     (ref_attr_list != NULL) && (ref_attr_list[i] != NULL);
	     i++) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"updating deref_r[%d] references for \"%s\"\n",
				i, slapi_entry_get_ndn(cbdata->e));
		ref_attr = ref_attr_list[i];
		these_entries = NULL;
		these_entries2 = NULL;
		prev_entries = NULL;
		prev_entries2 = NULL;
		/* Start with this entry. */
		format_add_sdn_list(&these_entries, &these_entries2,
				    slapi_entry_get_dn(cbdata->e));
		/* Walk the chain backwards. */
		for (j = ref_attr->n_links - 1;
		     (j >= 0) && (these_entries != NULL);
		     j--) {
			/* We can populate the "previous links" set using the
			 * information in the previous link in the chain. */
			if (j > 0) {
				prev_attr_link = &ref_attr->links[j - 1];
				prev_attrs[0] = prev_attr_link->attribute;
				prev_attrs[1] = NULL;
				prev_filter = prev_attr_link->filter_str;
				prev_bases = prev_attr_link->base_sdn_list;
			} else {
				prev_attr_link = NULL;
				prev_attrs[0] = NULL;
				prev_attrs[1] = NULL;
				prev_filter = NULL;
				prev_bases = NULL;
			}
			/* We may have entries at this point in the chain
			 * which point to other entries at this point in the
			 * chain -- unless it's the last one, which we know
			 * doesn't contain a DN. */
			if (j < ref_attr->n_links - 1) {
				this_attr_link = &ref_attr->links[j];
				these_attrs[0] = this_attr_link->attribute;
				these_attrs[1] = NULL;
				these_filter = this_attr_link->filter_str;
				these_bases = this_attr_link->base_sdn_list;
			} else {
				this_attr_link = NULL;
				these_attrs[0] = NULL;
				these_attrs[1] = NULL;
				these_filter = NULL;
				these_bases = NULL;
			}
			/* Search for entries which would be predecessors in
			 * the path to this entry. */
			for (k = 0; these_entries[k] != NULL; k++) {
				scope = LDAP_SCOPE_ONELEVEL;
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"searching for references to "
						"\"%s\" (link=%d, "
						"attributes=\"%s\",\"%s\")\n",
						slapi_sdn_get_ndn(these_entries[k]),
						j,
						these_attrs[0] ?
						these_attrs[0] : "",
						prev_attrs[0] ?
						prev_attrs[0] : "");
				/* Search for entries at this point in the
				 * chain which point to this entry in the
				 * chain (which we started with the entry
				 * which has just been modified). */
				filter = backend_build_filter(state,
							      these_entries[k],
							      these_filter,
							      these_attrs);
				for (l = 0;
				     (these_bases != NULL) &&
				     (these_bases[l] != NULL);
				     l++) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"searching under "
							"\"%s\" for \"%s\" "
							"with scope %d\n",
							slapi_sdn_get_ndn(these_bases[l]),
							filter, scope);
					pb = wrap_pblock_new(cbdata->pb);
					slapi_search_internal_set_pb(pb,
								     slapi_sdn_get_ndn(these_bases[l]),
								     scope,
								     filter,
								     NULL,
								     FALSE,
								     NULL,
								     NULL,
								     state->plugin_identity,
								     0);
					note_cbdata.state = state;
					note_cbdata.sdn_list = &these_entries;
					note_cbdata.sdn_list2 = &these_entries2;
					slapi_search_internal_callback_pb(pb,
									  &note_cbdata,
									  NULL,
									  backend_shr_note_entry_sdn_cb,
									  NULL);
					slapi_pblock_destroy(pb);
				}
				free(filter);
				/* Search for entries in the previous link in
				 * the chain which point to this entry in the
				 * chain (which we started with the entry
				 * which has just been modified). */
				filter = backend_build_filter(state,
							      these_entries[k],
							      prev_filter,
							      prev_attrs);
				for (l = 0;
				     (prev_bases != NULL) &&
				     (prev_bases[l] != NULL);
				     l++) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"searching from \"%s\""
							" for \"%s\" with "
							"scope %d\n",
							slapi_sdn_get_ndn(prev_bases[l]),
							filter, scope);
					pb = wrap_pblock_new(cbdata->pb);
					slapi_search_internal_set_pb(pb,
								     slapi_sdn_get_ndn(prev_bases[l]),
								     scope,
								     filter,
								     NULL,
								     FALSE,
								     NULL,
								     NULL,
								     state->plugin_identity,
								     0);
					note_cbdata.state = state;
					note_cbdata.sdn_list = &prev_entries;
					note_cbdata.sdn_list2 = &prev_entries2;
					slapi_search_internal_callback_pb(pb,
									  &note_cbdata,
									  NULL,
									  backend_shr_note_entry_sdn_cb,
									  NULL);
					slapi_pblock_destroy(pb);
				}
				free(filter);
			}
			/* Back up to process the list of predecessors, unless
			 * this was the last link, in which case it's become
			 * our list of candidates. */
			if (j > 0) {
				format_free_sdn_list(these_entries, these_entries2);
				these_entries = prev_entries;
				these_entries2 = prev_entries2;
				prev_entries = NULL;
				prev_entries2 = NULL;
			}
			/* Log a diagnostic if there's no more work to do. */
			if (these_entries == NULL) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"no more references to "
						"chase (link=%d, "
						"attributes=\"%s\",\"%s\")\n",
						j,
						these_attrs[0] ?
						these_attrs[0] : "",
						prev_attrs[0] ?
						prev_attrs[0] : "");
			}
		}
		/* Walk the last list of predecessors and update any related
		 * entries in this map. */
		for (j = 0;
		     (these_entries != NULL) && (these_entries[j] != NULL);
		     j++) {
			ndn = slapi_sdn_get_ndn(these_entries[j]);
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"possible dependent entry: \"%s\"\n",
					ndn);
			if (!map_data_check_entry(state, group, set, ndn)) {
				continue;
			}
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"dependent entry: \"%s\"\n",
					ndn);
			backend_shr_set_config_entry_set_one_dn(state,
								cbdata->pb,
								ndn,
								set_data->self);
		}
		format_free_sdn_list(these_entries, these_entries2);
	}

	/* Determine if there are any entries in this map which are referred to
	 * (directly or indirectly) by this entry.  If there are, update them.
	 */

	/* Walk the set of reference-attribute chains. */
	inref_attr_list = set_data->inref_attr_list;
	for (i = 0;
	     (inref_attr_list != NULL) && (inref_attr_list[i] != NULL);
	     i++) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"updating referred_r[%d] references for "
				"\"%s\"\n",
				i, slapi_entry_get_ndn(cbdata->e));
		inref_attr = inref_attr_list[i];
		these_entries = NULL;
		these_entries2 = NULL;
		next_entries = NULL;
		next_entries2 = NULL;
		/* Start with this entry. */
		format_add_sdn_list(&these_entries, &these_entries2,
				    slapi_entry_get_dn(cbdata->e));
		/* Walk the chain, backwards. */
		for (j = inref_attr->n_links - 2;
		     (j >= 0) && (these_entries != NULL);
		     j--) {
			/* For each link in the chain (except the last, which
			 * we skip because it's not an attribute which is used
			 * to link to other entries), build the set of entries
			 * which are referred to by the entry. */
			this_attr_link = &inref_attr->links[j];
			these_attrs[0] = this_attr_link->attribute;
			these_attrs[1] = NULL;
			if (j > 0) {
				next_attr_link = &inref_attr->links[j - 1];
				next_attrs[0] = next_attr_link->attribute;
				next_attrs[1] = NULL;
				next_filter = next_attr_link->filter;
				next_filter_str = next_attr_link->filter_str;
			} else {
				next_attr_link = NULL;
				next_attrs[0] = NULL;
				next_attrs[1] = NULL;
				next_filter = NULL;
				next_filter_str = NULL;
			}
			/* Read the entries at this stage. */
			for (k = 0;
			     (these_entries != NULL) &&
			     (these_entries[k] != NULL);
			     k++) {
				/* Read the linked-to DN from the named
				 * attribute in the entry. */
				values = NULL;
				wrap_search_internal_get_entry(cbdata->pb,
							       these_entries[k],
							       NULL,
							       these_attrs,
							       &this_entry,
							       state->plugin_identity);
				if (this_entry == NULL) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"failure reading entry "
							"\"%s\"\n",
							slapi_sdn_get_ndn(these_entries[k]));
					continue;
				}
				pb = wrap_pblock_new(cbdata->pb);
				if ((next_filter != NULL) &&
				    (slapi_filter_test(pb, this_entry,
						       next_filter, 0) != 0)) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"entry \"%s\" did not "
							"match filter \"%s\"\n",
							slapi_sdn_get_ndn(these_entries[k]),
							next_filter_str);
					slapi_entry_free(this_entry);
					slapi_pblock_destroy(pb);
					continue;
				}
				slapi_pblock_destroy(pb);
				if (slapi_vattr_values_get(this_entry,
							   these_attrs[0],
							   &values,
							   &disposition,
							   &actual_attr,
							   0, &buffer_flags) != 0) {
					slapi_entry_free(this_entry);
					continue;
				}
				/* For each value of this attribute... */
				for (l = slapi_valueset_first_value(values,
								    &value);
				     l != -1;
				     l = slapi_valueset_next_value(values, l,
								   &value)) {
					/* Pull out the value, which is a
					 * referred-to entry's DN. */
					dn = slapi_value_get_string(value);
					if (dn == NULL) {
						continue;
					}
					/* Add it to the list of entries which
					 * we'll examine this go-round. */
					format_add_sdn_list(&these_entries,
							    &these_entries2, dn);
				}
				slapi_vattr_values_free(&values, &actual_attr,
							buffer_flags);
				slapi_entry_free(this_entry);
			}
			/* Read the entries for the next stage. */
			for (k = 0;
			     (next_attrs[0] != NULL) &&
			     (these_entries != NULL) &&
			     (these_entries[k] != NULL);
			     k++) {
				/* Read the linked-to DN from the named
				 * attribute in the entry. */
				values = NULL;
				wrap_search_internal_get_entry(cbdata->pb,
							       these_entries[k],
							       NULL,
							       next_attrs,
							       &this_entry,
							       state->plugin_identity);
				if (this_entry == NULL) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"failure reading entry "
							"\"%s\"\n",
							slapi_sdn_get_ndn(these_entries[k]));
					continue;
				}
				if (slapi_vattr_values_get(this_entry,
							   next_attrs[0],
							   &values,
							   &disposition,
							   &actual_attr,
							   0, &buffer_flags) != 0) {
					slapi_entry_free(this_entry);
					continue;
				}
				/* For each value of this attribute... */
				for (l = slapi_valueset_first_value(values,
								    &value);
				     l != -1;
				     l = slapi_valueset_next_value(values, l,
								   &value)) {
					/* Pull out the value, which is a
					 * referred-to entry's DN. */
					dn = slapi_value_get_string(value);
					if (dn == NULL) {
						continue;
					}
					/* Add it to the list of entries which
					 * we'll examine next time. */
					format_add_sdn_list(&next_entries,
							    &next_entries2, dn);
				}
				slapi_vattr_values_free(&values, &actual_attr,
							buffer_flags);
				slapi_entry_free(this_entry);
			}
			/* Back up to process the list of predecessors, unless
			 * this was the last link, in which case it's become
			 * our list of candidates. */
			if (j > 0) {
				format_free_sdn_list(these_entries, these_entries2);
				these_entries = next_entries;
				these_entries2 = next_entries2;
				next_entries = NULL;
				next_entries2 = NULL;
			}
			/* Log a diagnostic if there's no more work to do. */
			if (these_entries == NULL) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"no more referrals to chase "
						"(attributes=\"%s\",\"%s\")\n",
						these_attrs[0] ?
						these_attrs[0] : "",
						prev_attrs[0] ?
						prev_attrs[0] : "");
			}
		}
		/* Walk the last list of entries and update any related
		 * entries in this map. */
		for (j = 0;
		     (these_entries != NULL) && (these_entries[j] != NULL);
		     j++) {
			ndn = slapi_sdn_get_ndn(these_entries[j]);
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"possible dependent entry: \"%s\"\n",
					ndn);
			if (!map_data_check_entry(state, group, set, ndn)) {
				continue;
			}
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"dependent entry: \"%s\"\n",
					ndn);
			backend_shr_set_config_entry_set_one_dn(state,
								cbdata->pb,
								ndn,
								set_data->self);
		}
		format_free_sdn_list(these_entries, these_entries2);
	}

	return TRUE;
}

static void
backend_shr_update_references(struct plugin_state *state,
			      Slapi_PBlock *pb,
			      Slapi_Entry *e,
			      LDAPMod **mods,
			      char *modlist)
{
	struct backend_shr_update_references_cbdata cbdata;
	cbdata.pb = pb;
	cbdata.e = e;
	cbdata.mods = mods;
	cbdata.modlist = modlist ? modlist : backend_shr_mods_as_string(mods);
	if (!map_data_foreach_map(state, NULL,
				  backend_shr_update_references_cb, &cbdata)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"error updating references for \"%s\"\n",
				slapi_entry_get_ndn(cbdata.e));
	}
	if (modlist != cbdata.modlist) {
		free(cbdata.modlist);
	}
}

/* Add any map entries which correspond to a directory server entry in this
 * map. */

struct backend_add_entry_cbdata {
	struct plugin_state *state;
	Slapi_PBlock *pb;
	Slapi_Entry *e;
	char *ndn;
};

static bool_t
backend_shr_add_entry_cb(const char *group, const char *set, bool_t secure,
			 void *backend_data, void *cbdata_ptr)
{
	struct backend_shr_set_data *set_data;
	struct backend_add_entry_cbdata *cbdata;

	set_data = backend_data;
	cbdata = cbdata_ptr;

	/* If the entry doesn't match the set, skip it. */
	if (!backend_shr_entry_matches_set(set_data, cbdata->pb, cbdata->e)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"entry \"%s\" does not belong in "
				"\"%s\"/\"%s\"\n",
				cbdata->ndn, group, set);
		return TRUE;
	}

	/* Set the entry in the map which corresponds to this entry, or clear
	 * any that might if this entry doesn't have a key and value. */
	backend_set_entry(cbdata->pb, cbdata->e, set_data->self);

	return TRUE;
}

static int
backend_shr_add_cb(Slapi_PBlock *pb)
{
	struct backend_add_entry_cbdata cbdata;
	struct backend_set_config_entry_add_cbdata set_cbdata;
	char *dn;

	/* If we somehow recursed here from ourselves, just bail. */
	if (wrap_get_call_level() > 0) {
		return 0;
	}

#ifdef USE_SLAPI_BE_TXNS
	/* If the backend type is "ldbm database" and we have no transaction,
	 * do nothing, because we'll be called again later post-transaction,
	 * and we'll deal with it then. */
	if (pb != NULL) {
		void *txn;
		char *be_type;
		txn = NULL;
		be_type = NULL;
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_TXN, &txn);
#endif
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_BE_TYPE, &be_type);
#endif
		if ((txn == NULL) && (strcmp(be_type, "ldbm database") == 0)) {
			return 0;
		}
	}
#endif

	/* Read parameters from the pblock. */
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &cbdata.state);
	if (cbdata.state->plugin_base == NULL) {
		/* The plugin was not actually started. */
		return 0;
	}
	slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &cbdata.e);
	slapi_pblock_get(pb, SLAPI_ADD_TARGET, &dn);
	cbdata.pb = pb;
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata.state->plugin_desc->spd_id,
			"added \"%s\"\n", dn);

	/* Check for NULL entries, indicative of a failure elsewhere (?). */
	if (cbdata.e == NULL) {
		slapi_pblock_get(pb, SLAPI_ADD_EXISTING_DN_ENTRY, &cbdata.e);
		if (cbdata.e == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata.state->plugin_desc->spd_id,
					"added entry is NULL\n");
			return 0;
		}
	}
	cbdata.ndn = slapi_entry_get_ndn(cbdata.e);

	/* Add map entries which corresponded to this directory server
	 * entry. */
	wrap_inc_call_level();
	map_wrlock();
	if (!map_data_foreach_map(cbdata.state, NULL,
				  backend_shr_add_entry_cb, &cbdata)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"error adding set entries corresponding to "
				"\"%s\"\n", cbdata.ndn);
	}

	/* If it's a map configuration entry, add and populate the maps it
	 * describes. */
	if (backend_shr_entry_is_a_set(cbdata.state, pb, cbdata.e)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"new entry \"%s\" is a set\n", cbdata.ndn);
		set_cbdata.state = cbdata.state;
		set_cbdata.pb = pb;
		backend_set_config_entry_add_cb(cbdata.e, &set_cbdata);
	}

	/* Update entries in maps which are affected by this entry. */
	backend_shr_update_references(cbdata.state, pb, cbdata.e, NULL, NULL);

	map_unlock();
	wrap_dec_call_level();
	return 0;
}
static int
backend_shr_internal_add_cb(Slapi_PBlock *pb)
{
	return backend_shr_add_cb(pb);
}

struct backend_shr_modify_entry_cbdata {
	struct plugin_state *state;
	Slapi_PBlock *pb;
	LDAPMod **mods;
	Slapi_Mods *real_mods;
	Slapi_Entry *e_pre, *e_post;
	char *ndn;
	char *modlist;
};

static bool_t
backend_shr_modify_entry_cb(const char *group, const char *set, bool_t flag,
			    void *backend_data, void *cbdata_ptr)
{
	struct backend_shr_set_data *set_data;
	struct backend_shr_modify_entry_cbdata *cbdata;
	int i, j;
	LDAPMod *mod;

	set_data = backend_data;
	cbdata = cbdata_ptr;

	/* If the entry didn't change any attributes which are at all relevant
	 * to the map, and it both was and is still is in the map, then we
	 * don't need to recompute anything. */
	if (!backend_shr_entry_matches_set(set_data, cbdata->pb,
					   cbdata->e_post) &&
	    !backend_shr_entry_matches_set(set_data, cbdata->pb,
					   cbdata->e_pre)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"\"%s\" not in \"%s\"/\"%s\", "
				"before or after modify\n",
				cbdata->ndn,
				set_data->group,
				set_data->set);
		return TRUE;
	}
	if (set_data->skip_uninteresting_updates &&
	    (cbdata->mods != NULL) && (set_data->rel_attrs != NULL)) {
		for (i = 0; (mod = cbdata->mods[i]) != NULL; i++) {
			for (j = 0; set_data->rel_attrs[j] != NULL; j++) {
				if (slapi_attr_types_equivalent(mod->mod_type,
								set_data->rel_attrs[j])) {
					break;
				}
			}
			if (set_data->rel_attrs[j] != NULL) {
				break;
			}
		}
		if (mod == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata->state->plugin_desc->spd_id,
					"no interesting changes for "
					"\"%s\"/\"%s\" made in (\"%s\") "
					"(%s not in %s)\n",
					set_data->group,
					set_data->set,
					cbdata->ndn,
					cbdata->modlist ? cbdata->modlist : "",
					backend_shr_get_rel_attr_list(set_data));
			return TRUE;
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata->state->plugin_desc->spd_id,
					"interesting changes for "
					"\"%s\"/\"%s\" made in (\"%s\") "
					"(%s in %s)\n",
					set_data->group,
					set_data->set,
					cbdata->ndn,
					cbdata->modlist ? cbdata->modlist : "",
					backend_shr_get_rel_attr_list(set_data));
		}
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"changes for "
				"\"%s\"/\"%s\" made in (\"%s\") "
				"(%s in %s or empty)\n",
				set_data->group,
				set_data->set,
				cbdata->ndn,
				cbdata->modlist ? cbdata->modlist : "",
				backend_shr_get_rel_attr_list(set_data));
	}
	/* If the entry used to match the map, remove it. */
	if (backend_shr_entry_matches_set(set_data, cbdata->pb,
					  cbdata->e_pre)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"clearing group/set/id "
				"\"%s\"/\"%s\"/(\"%s\")\n",
				set_data->group,
				set_data->set,
				cbdata->ndn);
		map_data_unset_entry(cbdata->state,
				     set_data->group,
				     set_data->set,
				     cbdata->ndn);
	}
	/* If the entry now matches the map, add it (or re-add it). */
	if (backend_shr_entry_matches_set(set_data, cbdata->pb,
					  cbdata->e_post)) {
		/* Set the entry in the set which corresponds to this entry, or
		 * remove any that might if this entry doesn't produce a useful
		 * value. */
		backend_shr_set_entry(cbdata->pb, cbdata->e_post, set_data->self);
	}
	return TRUE;
}

static Slapi_Mod *
backend_shr_mod_as_smod(LDAPMod *mod)
{
	Slapi_Mod *ret;
	ret = slapi_mod_new();
	slapi_mod_init_byval(ret, mod);
	return ret;
}

/* Walk the list of mods, picking out those which won't have an effect, and
 * adding the rest to the "relevant" list. */
static void
backend_shr_filter_mods(LDAPMod **mods, Slapi_Entry *pre, Slapi_Entry *post,
		        Slapi_Mods *relevant)
{
	LDAPMod *mod;
	Slapi_ValueSet *values;
	Slapi_Value *mval;
	const struct berval *mbv;
	struct berval msv;
	char *actual_attr;
	int i, j, result, disposition, buffer_flags;

	if (mods == NULL) {
		return;
	}
	mval = slapi_value_new();
	for (i = 0; mods[i] != NULL; i++) {
		mod = mods[i];
		if (slapi_vattr_values_get(pre, mod->mod_type, &values,
					   &disposition, &actual_attr,
					   0, &buffer_flags) != 0) {
			/* error of some kind, punt */
			slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
			continue;
		}
		if (SLAPI_IS_MOD_DELETE(mod->mod_op)) {
			/* if the target entry has values, and one of the ones
			 * we're removing is in the entry, keep it */
			if (slapi_valueset_count(values) != 0) {
				if (mod->mod_op & LDAP_MOD_BVALUES) {
					if (mod->mod_vals.modv_bvals == NULL) {
						/* request is to remove all values */
						slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
					} else
					for (j = 0; mod->mod_vals.modv_bvals[j] != NULL; j++) {
						mbv = mod->mod_vals.modv_bvals[j];
						mval = slapi_value_set_berval(mval, mbv);
						if ((slapi_vattr_value_compare(pre, mod->mod_type, mval, &result, 0) == 0) &&
						    (result == 1)) {
							/* request is to remove a value that is present */
							slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
							break;
						}
					}
				} else {
					if (mod->mod_vals.modv_strvals == NULL) {
						/* request is to remove all values */
						slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
					} else
					for (j = 0; mod->mod_vals.modv_strvals[j] != NULL; j++) {
						msv.bv_val = mod->mod_vals.modv_strvals[j];
						msv.bv_len = strlen(msv.bv_val);
						mval = slapi_value_set_berval(mval, &msv);
						if ((slapi_vattr_value_compare(pre, mod->mod_type, mval, &result, 0) == 0) &&
						    (result == 1)) {
							/* request is to remove a value that is present */
							slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
							break;
						}
					}
				}
			}
		} else
		if (SLAPI_IS_MOD_ADD(mod->mod_op)) {
			/* if all of the provided values are already in the
			 * entry, then skip it */
			if (mod->mod_op & LDAP_MOD_BVALUES) {
				if (mod->mod_vals.modv_bvals != NULL) {
					for (j = 0; mod->mod_vals.modv_bvals[j] != NULL; j++) {
						mbv = mod->mod_vals.modv_bvals[j];
						mval = slapi_value_set_berval(mval, mbv);
						if ((slapi_vattr_value_compare(pre, mod->mod_type, mval, &result, 0) != 0) ||
						    (result != 1)) {
							/* request is to add a value that is not present */
							slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
							break;
						}
					}
				}
			} else {
				if (mod->mod_vals.modv_strvals != NULL) {
					for (j = 0; mod->mod_vals.modv_strvals[j] != NULL; j++) {
						msv.bv_val = mod->mod_vals.modv_strvals[j];
						msv.bv_len = strlen(msv.bv_val);
						mval = slapi_value_set_berval(mval, &msv);
						if ((slapi_vattr_value_compare(pre, mod->mod_type, mval, &result, 0) != 0) ||
						    (result != 1)) {
							/* request is to add a value that is not present */
							slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
							break;
						}
					}
				}
			}
		} else
		if (SLAPI_IS_MOD_REPLACE(mod->mod_op)) {
			/* if the value set is the same as the list we're
			 * given, then skip it */
			j = 0;
			if (mod->mod_op & LDAP_MOD_BVALUES) {
				if (mod->mod_vals.modv_bvals != NULL) {
					for (j = 0; mod->mod_vals.modv_bvals[j] != NULL; j++) {
						continue;
					}
				}
				if (slapi_valueset_count(values) != j) {
					/* different number of values */
					slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
				} else {
					for (j = 0;
					     (mod->mod_vals.modv_bvals != NULL) &&
					     (mod->mod_vals.modv_bvals[j] != NULL);
					     j++) {
						mbv = mod->mod_vals.modv_bvals[j];
						mval = slapi_value_set_berval(mval, mbv);
						if ((slapi_vattr_value_compare(pre, mod->mod_type, mval, &result, 0) != 0) ||
						    (result != 1)) {
							/* request includes a value that is not present */
							slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
							break;
						}
					}
				}
			} else {
				if (mod->mod_vals.modv_strvals != NULL) {
					for (j = 0; mod->mod_vals.modv_strvals[j] != NULL; j++) {
						continue;
					}
				}
				if (slapi_valueset_count(values) != j) {
					/* different number of values */
					slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
				} else {
					for (j = 0;
					     (mod->mod_vals.modv_strvals != NULL) &&
					     (mod->mod_vals.modv_strvals[j] != NULL);
					     j++) {
						msv.bv_val = mod->mod_vals.modv_strvals[j];
						msv.bv_len = strlen(msv.bv_val);
						mval = slapi_value_set_berval(mval, &msv);
						if ((slapi_vattr_value_compare(pre, mod->mod_type, mval, &result, 0) != 0) ||
						    (result != 1)) {
							/* request includes a value that is not present */
							slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
							break;
						}
					}
				}
			}
		} else {
			slapi_mods_add_smod(relevant, backend_shr_mod_as_smod(mod));
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	}
	slapi_value_free(&mval);
}

static int
backend_shr_modify_cb(Slapi_PBlock *pb)
{
	Slapi_DN *sdn;
	char *dn, *log_modlist;
	struct backend_shr_modify_entry_cbdata cbdata;
	struct backend_set_config_entry_add_cbdata set_cbdata;

	/* If we somehow recursed here from ourselves, just bail. */
	if (wrap_get_call_level() > 0) {
		return 0;
	}

#ifdef USE_SLAPI_BE_TXNS
	/* If the backend type is "ldbm database" and we have no transaction,
	 * do nothing, because we'll be called again later post-transaction,
	 * and we'll deal with it then. */
	if (pb != NULL) {
		void *txn;
		char *be_type;
		txn = NULL;
		be_type = NULL;
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_TXN, &txn);
#endif
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_BE_TYPE, &be_type);
#endif
		if ((txn == NULL) && (strcmp(be_type, "ldbm database") == 0)) {
			return 0;
		}
	}
#endif

	/* Read parameters from the pblock. */
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &cbdata.state);
	if (cbdata.state->plugin_base == NULL) {
		/* The plugin was not actually started. */
		return 0;
	}
	slapi_pblock_get(pb, SLAPI_MODIFY_TARGET, &dn);
	slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &cbdata.mods);
	slapi_pblock_get(pb, SLAPI_ENTRY_PRE_OP, &cbdata.e_pre);
	slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &cbdata.e_post);
	cbdata.pb = pb;
	cbdata.modlist = NULL;
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata.state->plugin_desc->spd_id,
			"modified \"%s\"\n", dn);
	/* Check for NULL entries, indicative of a failure elsewhere (?). */
	if (cbdata.e_pre == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"pre-modify entry is NULL\n");
		return 0;
	}
	if (cbdata.e_post == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"post-modify entry is NULL\n");
		return 0;
	}
	/* Don't do a lot of work for other plugins which initiated a no-op
	 * modify. */
	cbdata.real_mods = slapi_mods_new();
	backend_shr_filter_mods(cbdata.mods, cbdata.e_pre, cbdata.e_post,
				cbdata.real_mods);
	cbdata.mods = slapi_mods_get_ldapmods_byref(cbdata.real_mods);
	cbdata.ndn = slapi_entry_get_ndn(cbdata.e_pre);
	if (cbdata.mods == NULL) {
		slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &cbdata.mods);
		log_modlist = backend_shr_mods_as_string(cbdata.mods);
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"no substantive changes to %s: "
				"(%s) simplified to ()\n",
				cbdata.ndn,
				log_modlist);
		slapi_mods_free(&cbdata.real_mods);
		free(log_modlist);
		return 0;
	}
	cbdata.modlist = backend_shr_mods_as_string(cbdata.mods);
	/* Modify map entries which corresponded to this directory server
	 * entry. */
	wrap_inc_call_level();
	map_wrlock();
	if (!map_data_foreach_map(cbdata.state, NULL,
				  backend_shr_modify_entry_cb, &cbdata)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"error modifying set entries corresponding to "
				"\"%s\"\n", cbdata.ndn);
	}
	/* Update entries which need to be updated in case they are no longer
	 * affected by this entry. */
	backend_shr_update_references(cbdata.state, pb, cbdata.e_pre,
				      cbdata.mods, cbdata.modlist);
	/* Update entries which need to be updated in case they are now
	 * affected by this entry. */
	backend_shr_update_references(cbdata.state, pb, cbdata.e_post,
				      cbdata.mods, cbdata.modlist);
	/* Done with the "real" mods.  Put the fake ones back. */
	slapi_mods_free(&cbdata.real_mods);
	cbdata.real_mods = NULL;
	slapi_pblock_get(pb, SLAPI_MODIFY_MODS, &cbdata.mods);
	/* If it's a map configuration entry, reconfigure, clear, and
	 * repopulate the map. */
	if (backend_shr_entry_is_a_set(cbdata.state, pb, cbdata.e_pre)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"modified entry \"%s\" was a set\n",
				cbdata.ndn);
		backend_set_config_entry_delete_cb(cbdata.e_pre, cbdata.state);
	}
	if (backend_shr_entry_is_a_set(cbdata.state, pb, cbdata.e_post)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"modified entry \"%s\" is now a set\n",
				cbdata.ndn);
		set_cbdata.state = cbdata.state;
		set_cbdata.pb = pb;
		backend_set_config_entry_add_cb(cbdata.e_post, &set_cbdata);
	}
	/* Lastly, if the entry is our own entry, re-read parameters. */
	sdn = slapi_sdn_new_dn_byref(cbdata.state->plugin_base);
	if (sdn != NULL) {
		if ((strcmp(slapi_entry_get_ndn(cbdata.e_pre),
			    slapi_sdn_get_ndn(sdn)) == 0) ||
		    (strcmp(slapi_entry_get_ndn(cbdata.e_post),
			    slapi_sdn_get_ndn(sdn)) == 0)) {
			backend_update_params(pb, cbdata.state);
		}
		slapi_sdn_free(&sdn);
	}
	map_unlock();
	wrap_dec_call_level();
	free(cbdata.modlist);
	return 0;
}
static int
backend_shr_internal_modify_cb(Slapi_PBlock *pb)
{
	return backend_shr_modify_cb(pb);
}

struct backend_shr_modrdn_entry_cbdata {
	struct plugin_state *state;
	Slapi_PBlock *pb;
	Slapi_Entry *e_pre, *e_post;
	char *ndn_pre, *ndn_post;
};

static bool_t
backend_shr_modrdn_entry_cb(const char *group, const char *set, bool_t secure,
			    void *backend_data, void *cbdata_ptr)
{
	struct backend_shr_set_data *set_data;
	struct backend_shr_modrdn_entry_cbdata *cbdata;
	bool_t matched_pre, matched_post;

	set_data = backend_data;
	cbdata = cbdata_ptr;

	/* Now decide what to set, or unset, in this map. */
	matched_pre = backend_shr_entry_matches_set(set_data,
						    cbdata->pb,
						    cbdata->e_pre);
	if (matched_pre) {
		/* If it was a match for the map, clear the entry. */
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"clearing group/set/id "
				"\"%s\"/\"%s\"/(\"%s\")\n",
				set_data->group,
				set_data->set,
				cbdata->ndn_pre);
		map_data_unset_entry(cbdata->state,
				     set_data->group,
				     set_data->set,
				     cbdata->ndn_pre);
	}
	/* Set the entry in the map which corresponds to this entry, or clear
	 * any that might if this entry doesn't have a key and value. */
	matched_post = backend_shr_entry_matches_set(set_data,
						     cbdata->pb,
						     cbdata->e_post);
	if (matched_post) {
		backend_set_entry(cbdata->pb, cbdata->e_post, set_data->self);
	}
	return TRUE;
}

static int
backend_shr_modrdn_cb(Slapi_PBlock *pb)
{
	struct backend_shr_modrdn_entry_cbdata cbdata;
	struct backend_set_config_entry_add_cbdata set_cbdata;

	/* If we somehow recursed here from ourselves, just bail. */
	if (wrap_get_call_level() > 0) {
		return 0;
	}

#ifdef USE_SLAPI_BE_TXNS
	/* If the backend type is "ldbm database" and we have no transaction,
	 * do nothing, because we'll be called again later post-transaction,
	 * and we'll deal with it then. */
	if (pb != NULL) {
		void *txn;
		char *be_type;
		txn = NULL;
		be_type = NULL;
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_TXN, &txn);
#endif
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_BE_TYPE, &be_type);
#endif
		if ((txn == NULL) && (strcmp(be_type, "ldbm database") == 0)) {
			return 0;
		}
	}
#endif

	/* Read parameters from the pblock. */
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &cbdata.state);
	if (cbdata.state->plugin_base == NULL) {
		/* The plugin was not actually started. */
		return 0;
	}
	slapi_pblock_get(pb, SLAPI_ENTRY_PRE_OP, &cbdata.e_pre);
	slapi_pblock_get(pb, SLAPI_ENTRY_POST_OP, &cbdata.e_post);

	/* Check for NULL entries, indicative of a failure elsewhere (?). */
	if (cbdata.e_pre == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"pre-modrdn entry is NULL\n");
		return 0;
	}
	if (cbdata.e_post == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"post-modrdn entry is NULL\n");
		return 0;
	}
	/* Finish retrieving in the data we'll need. */
	cbdata.ndn_pre = slapi_entry_get_ndn(cbdata.e_pre);
	cbdata.ndn_post = slapi_entry_get_ndn(cbdata.e_post);
	cbdata.pb = pb;
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata.state->plugin_desc->spd_id,
			"renamed \"%s\" to \"%s\"\n",
			cbdata.ndn_pre, cbdata.ndn_post);
	/* Modify map entries which corresponded to this directory server
	 * entry. */
	wrap_inc_call_level();
	map_wrlock();
	if (!map_data_foreach_map(cbdata.state, NULL,
				  backend_shr_modrdn_entry_cb, &cbdata)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"error renaming map entries corresponding to "
				"\"%s\"\n", cbdata.ndn_post);
	}
	/* If it's a set configuration entry, reconfigure, clear, and
	 * repopulate the set. */
	if (backend_shr_entry_is_a_set(cbdata.state, pb, cbdata.e_pre)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"renamed entry \"%s\" was a set\n",
				slapi_entry_get_ndn(cbdata.e_pre));
		backend_set_config_entry_delete_cb(cbdata.e_pre, cbdata.state);
	}
	if (backend_shr_entry_is_a_set(cbdata.state, pb, cbdata.e_post)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"renamed entry \"%s\" is now a set\n",
				slapi_entry_get_ndn(cbdata.e_post));
		set_cbdata.state = cbdata.state;
		set_cbdata.pb = pb;
		backend_set_config_entry_add_cb(cbdata.e_post, &set_cbdata);
	}
	map_unlock();
	wrap_dec_call_level();
	return 0;
}
static int
backend_shr_internal_modrdn_cb(Slapi_PBlock *pb)
{
	return backend_shr_modrdn_cb(pb);
}

/* Delete any map entries which correspond to a directory server entry in this
 * map. */

struct backend_shr_delete_entry_cbdata {
	struct plugin_state *state;
	Slapi_PBlock *pb;
	Slapi_Entry *e;
	char *ndn;
};
static bool_t
backend_shr_delete_entry_cb(const char *group, const char *set, bool_t flag,
			    void *backend_data, void *cbdata_ptr)
{
	struct backend_shr_set_data *set_data;
	struct backend_shr_delete_entry_cbdata *cbdata;
	set_data = backend_data;
	cbdata = cbdata_ptr;
	/* If it was in the map, remove it. */
	if (backend_shr_entry_matches_set(set_data, cbdata->pb, cbdata->e)) {
		/* Remove this entry from the set. */
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"unsetting group/set/id"
				"\"%s\"/\"%s\"=\"%s\"/\"%s\"/(\"%s\")\n",
				group, set, set_data->group, set_data->set,
				cbdata->ndn);
		map_data_unset_entry(cbdata->state, group, set, cbdata->ndn);
	}
	return TRUE;
}

/* Called by the server when a directory server entry is deleted. */
static int
backend_shr_delete_cb(Slapi_PBlock *pb)
{
	struct backend_shr_delete_entry_cbdata cbdata;
	char *dn;

	/* If we somehow recursed here from ourselves, just bail. */
	if (wrap_get_call_level() > 0) {
		return 0;
	}

#ifdef USE_SLAPI_BE_TXNS
	/* If the backend type is "ldbm database" and we have no transaction,
	 * do nothing, because we'll be called again later post-transaction,
	 * and we'll deal with it then. */
	if (pb != NULL) {
		void *txn;
		char *be_type;
		txn = NULL;
		be_type = NULL;
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_TXN, &txn);
#endif
#ifdef SLAPI_TXN
		slapi_pblock_get(pb, SLAPI_BE_TYPE, &be_type);
#endif
		if ((txn == NULL) && (strcmp(be_type, "ldbm database") == 0)) {
			return 0;
		}
	}
#endif

	/* Read parameters from the pblock. */
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &cbdata.state);
	if (cbdata.state->plugin_base == NULL) {
		/* The plugin was not actually started. */
		return 0;
	}
	slapi_pblock_get(pb, SLAPI_ENTRY_PRE_OP, &cbdata.e);
	slapi_pblock_get(pb, SLAPI_DELETE_TARGET, &dn);
	cbdata.pb = pb;
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata.state->plugin_desc->spd_id,
			"deleted \"%s\"\n", dn);
	/* Check for NULL entries, indicative of a failure elsewhere (?). */
	if (cbdata.e == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"deleted entry is NULL\n");
		return 0;
	}
	cbdata.ndn = slapi_entry_get_ndn(cbdata.e);
	/* Remove map entries which corresponded to this directory server
	 * entry. */
	wrap_inc_call_level();
	map_wrlock();
	if (!map_data_foreach_map(cbdata.state, NULL,
				  backend_shr_delete_entry_cb, &cbdata)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"error removing entries corresponding to "
				"\"%s\"\n", cbdata.ndn);
	}
	/* If it's a map configuration entry, remove the map. */
	if (backend_shr_entry_is_a_set(cbdata.state, pb, cbdata.e)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"deleted entry \"%s\" is a set\n", cbdata.ndn);
		backend_set_config_entry_delete_cb(cbdata.e, cbdata.state);
	}
	/* Update entries which need to be updated in case they are no longer
	 * affected by this entry. */
	backend_shr_update_references(cbdata.state, pb, cbdata.e, NULL, NULL);
	map_unlock();
	wrap_dec_call_level();
	return 0;
}
static int
backend_shr_internal_delete_cb(Slapi_PBlock *pb)
{
	return backend_shr_delete_cb(pb);
}

/* Set up our post-op callbacks. */

int
backend_shr_postop_init(Slapi_PBlock *pb, struct plugin_state *state)
{
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_POST_ADD_FN,
			     backend_shr_add_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up add callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODIFY_FN,
			     backend_shr_modify_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up modify callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_POST_MODRDN_FN,
			     backend_shr_modrdn_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up modrdn callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_POST_DELETE_FN,
			     backend_shr_delete_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up delete callback\n");
		return -1;
	}
	return 0;
}

int
backend_shr_internal_postop_init(Slapi_PBlock *pb, struct plugin_state *state)
{
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_ADD_FN,
			     backend_shr_internal_add_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up internal add callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODIFY_FN,
			     backend_shr_internal_modify_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up internal modify callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_MODRDN_FN,
			     backend_shr_internal_modrdn_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up internal modrdn callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_INTERNAL_POST_DELETE_FN,
			     backend_shr_internal_delete_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up internal delete callback\n");
		return -1;
	}
	return 0;
}

#ifdef USE_SLAPI_BE_TXNS
static int
backend_shr_be_txn_post_add_cb(Slapi_PBlock *pb)
{
	return backend_shr_add_cb(pb);
}
static int
backend_shr_be_txn_post_modify_cb(Slapi_PBlock *pb)
{
	return backend_shr_modify_cb(pb);
}
static int
backend_shr_be_txn_post_modrdn_cb(Slapi_PBlock *pb)
{
	return backend_shr_modrdn_cb(pb);
}
static int
backend_shr_be_txn_post_delete_cb(Slapi_PBlock *pb)
{
	return backend_shr_delete_cb(pb);
}
int
backend_shr_be_txn_postop_init(Slapi_PBlock *pb, struct plugin_state *state)
{
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_ADD_FN,
			     backend_shr_be_txn_post_add_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up be-txn-post add callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_MODIFY_FN,
			     backend_shr_be_txn_post_modify_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up be-txn-post modify callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_MODRDN_FN,
			     backend_shr_be_txn_post_modrdn_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up be-txn-post modrdn callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_POST_DELETE_FN,
			     backend_shr_be_txn_post_delete_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up be-txn-post delete callback\n");
		return -1;
	}
	return 0;
}
#endif
