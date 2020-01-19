/*
 * Copyright 2008,2009,2010,2011,2012,2013,2014 Red Hat, Inc.
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
#include <errno.h>

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
#include "backend.h"
#include "back-shr.h"
#include "format.h"
#include "plugin.h"
#include "map.h"
#include "back-sch.h"

#define SCH_CONTAINER_CONFIGURATION_FILTER "(&(" SCH_CONTAINER_CONFIGURATION_GROUP_ATTR "=*)(" SCH_CONTAINER_CONFIGURATION_BASE_ATTR "=*)(" SCH_CONTAINER_CONFIGURATION_FILTER_ATTR "=*)(" SCH_CONTAINER_CONFIGURATION_RDN_ATTR "=*))"

/* Read the name of the NIS master. A dummy function for the schema
 * compatibility plugin. */
void
backend_free_master_name(struct plugin_state *state, char *master)
{
}

int
backend_read_master_name(struct plugin_state *state, Slapi_PBlock *pb,
			 char **master)
{
	*master = "localhost";
	return -1;
}

/* Manipulate a backend map configuration. */
static void
backend_set_config_free_config_contents(void *data)
{
	struct backend_set_data *set_data = data;
	if (set_data != NULL) {
		free(set_data->common.group);
		free(set_data->common.set);
		free(set_data->common.bases);
		backend_shr_free_sdnlist(set_data->common.restrict_subtrees);
		backend_shr_free_sdnlist(set_data->common.ignore_subtrees);
		format_free_attr_list(set_data->common.rel_attrs);
		free(set_data->common.rel_attr_list);
		format_free_attr_list(set_data->common.ref_attrs);
		format_free_inref_attrs(set_data->common.inref_attrs);
		format_free_ref_attr_list(set_data->common.ref_attr_list);
		format_free_ref_attr_list(set_data->common.inref_attr_list);
		free(set_data->common.entry_filter);
		slapi_sdn_free(&set_data->container_sdn);
		free(set_data->rdn_format);
		backend_shr_free_strlist(set_data->attribute_format);
	}
}
void
backend_set_config_free_config(struct backend_shr_set_data *data)
{
	backend_set_config_free_config_contents(data->self);
	free(data);
}
static struct backend_shr_set_data *
backend_copy_set_config(const struct backend_set_data *data)
{
	struct backend_set_data *ret;
	ret = malloc(sizeof(*ret));
	if (ret == NULL) {
		return NULL;
	}
	ret->common.self = ret;
	ret->common.state = data->common.state;
	ret->common.group = data->common.group ? strdup(data->common.group) : NULL;
	ret->common.set = data->common.set ? strdup(data->common.set) : NULL;
	ret->common.bases = backend_shr_dup_strlist(data->common.bases);
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
	ret->common.ref_attr_list = data->common.ref_attr_list ?
				    format_dup_ref_attr_list(data->common.ref_attr_list) :
				    NULL;
	ret->common.inref_attrs = data->common.inref_attrs ?
				  format_dup_inref_attrs(data->common.inref_attrs) :
				  NULL;
	ret->common.inref_attr_list = data->common.inref_attrs ?
				      format_dup_ref_attr_list(data->common.inref_attr_list) :
				      NULL;
	ret->common.entry_filter = data->common.entry_filter ?
				   strdup(data->common.entry_filter) :
				   NULL;
	ret->common.skip_uninteresting_updates =
		data->common.skip_uninteresting_updates;
	ret->container_sdn = slapi_sdn_dup(data->container_sdn);
	ret->rdn_format = data->rdn_format ? strdup(data->rdn_format) : NULL;
	ret->attribute_format = backend_shr_dup_strlist(data->attribute_format);
	ret->check_access = data->check_access;
	ret->check_nsswitch = data->check_nsswitch;
	ret->nsswitch_min_id = data->nsswitch_min_id;

	if ((ret->common.group == NULL) ||
	    (ret->common.set == NULL) ||
	    (ret->common.bases == NULL) ||
	    (ret->common.entry_filter == NULL) ||
	    (ret->container_sdn == NULL) ||
	    (ret->rdn_format == NULL)) {
		backend_set_config_free_config(&ret->common);
		return NULL;
	}
	return &ret->common;
}

/* Given a configuration entry, read the map configuration for the given group
 * and container name from the entry. */
void
backend_set_config_read_config(struct plugin_state *state, Slapi_Entry *e,
			       const char *group, const char *container,
			       bool_t *flag, struct backend_shr_set_data **pret)
{
	char **bases, *entry_filter, **attributes, *rdn_format, *tmp_dn;
	char *nsswitch_min_id, *check_nsswitch, *strp;
	bool_t check_access;
	struct backend_set_data ret;
	Slapi_DN *tmp_sdn;
	const Slapi_DN **restrict_subtrees, **ignore_subtrees;

	/* Read the values from the configuration entry. */
	bases = backend_shr_get_vattr_strlist(state, e,
					      SCH_CONTAINER_CONFIGURATION_BASE_ATTR);
	restrict_subtrees = backend_shr_get_vattr_sdnlist(state, e,
							 SCH_CONTAINER_CONFIGURATION_RESTRICT_SUBTREES_ATTR);
	ignore_subtrees = backend_shr_get_vattr_sdnlist(state, e,
							SCH_CONTAINER_CONFIGURATION_IGNORE_SUBTREES_ATTR);
	if (ignore_subtrees == NULL) {
		backend_shr_add_sdnlist(&ignore_subtrees, DEFAULT_IGNORE_SUBTREE);
	}
	entry_filter = backend_shr_get_vattr_filter(state, e,
						    SCH_CONTAINER_CONFIGURATION_FILTER_ATTR);
	rdn_format = backend_shr_get_vattr_str(state, e,
					       SCH_CONTAINER_CONFIGURATION_RDN_ATTR);
	check_access = backend_shr_get_vattr_boolean(state, e,
						     SCH_CONTAINER_CONFIGURATION_ACCESS_ATTR,
						     TRUE);
	check_nsswitch = backend_shr_get_vattr_str(state, e,
						   SCH_CONTAINER_CONFIGURATION_NSSWITCH_ATTR);
	nsswitch_min_id = backend_shr_get_vattr_str(state, e,
						    SCH_CONTAINER_CONFIGURATION_NSSWITCH_MIN_ID_ATTR);
	attributes = backend_shr_get_vattr_strlist(state, e,
						   SCH_CONTAINER_CONFIGURATION_ATTR_ATTR);
	/* Populate the returned structure. */
	ret.common.state = state;
	tmp_sdn = slapi_sdn_new_dn_byval(group);
	ret.common.group = strdup(slapi_sdn_get_ndn(tmp_sdn));
	ret.common.set = strdup(container);
	ret.common.bases = bases;
	ret.common.restrict_subtrees = restrict_subtrees;
	ret.common.ignore_subtrees = ignore_subtrees;
	ret.common.entry_filter = entry_filter;
	ret.common.rel_attrs = NULL;
	ret.common.rel_attr_list = NULL;
	ret.common.rel_attrs_list = NULL;
	ret.common.ref_attrs = NULL;
	ret.common.inref_attrs = NULL;
	ret.common.ref_attr_list = NULL;
	ret.common.inref_attr_list = NULL;
	if ((getenv(SCHEMA_COMPAT_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV) == NULL) ||
	    (atol(getenv(SCHEMA_COMPAT_PLUGIN_PROCESS_UNINTERESTING_UPDATES_ENV)) == 0)) {
		ret.common.skip_uninteresting_updates = 1;
	} else {
		ret.common.skip_uninteresting_updates = 0;
	}
	if ((ret.common.set != NULL) && (strlen(ret.common.set) > 0)) {
		tmp_dn = slapi_dn_plus_rdn(ret.common.group, ret.common.set);
		slapi_sdn_free(&tmp_sdn);
		tmp_sdn = slapi_sdn_new_dn_passin(tmp_dn);
	}
	ret.container_sdn = slapi_sdn_new_dn_byval(slapi_sdn_get_ndn(tmp_sdn));
	slapi_sdn_free(&tmp_sdn);
	ret.rdn_format = rdn_format;
	ret.attribute_format = attributes;
	ret.check_access = check_access;

	if (check_nsswitch != NULL) {
		if (strcasecmp(check_nsswitch, "group") == 0) {
			ret.check_nsswitch = SCH_NSSWITCH_GROUP;
		} else if ((strcasecmp(check_nsswitch, "user") == 0) ||
		           (strcasecmp(check_nsswitch, "passwd") == 0)) {
			ret.check_nsswitch = SCH_NSSWITCH_USER;
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"unrecognized %s setting in %s: %s\n",
					SCH_CONTAINER_CONFIGURATION_NSSWITCH_ATTR,
					slapi_entry_get_dn(e),
					check_nsswitch);
			ret.check_nsswitch = SCH_NSSWITCH_NONE;
		}
		free(check_nsswitch);
	} else {
		ret.check_nsswitch = SCH_NSSWITCH_NONE;
	}

	/* Make sure we don't return system users/groups by limiting lower
	 * bound on the UIDs and GIDs of entries we'll pull in from the
	 * nsswitch databases.  If the configured value cannot be parsed or
	 * there's none specified, default to 1000. */
	ret.nsswitch_min_id = 1000; /* default in Fedora */
	if (nsswitch_min_id != NULL) {
		errno = 0;
		ret.nsswitch_min_id = strtoul(nsswitch_min_id, &strp, 10);
		if ((errno != 0) || ((strp != NULL) && (*strp != '\0'))) {
			ret.nsswitch_min_id = 1000;
		}
		free(nsswitch_min_id);
	}

	*pret = backend_copy_set_config(&ret);
	if (*pret == NULL) {
		if (strlen(container) > 0) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"out of memory initializing container %s in %s\n",
					container, group);
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"out of memory initializing group %s\n",
					group);
		}
	}
	free(ret.common.group);
	free(ret.common.set);
	backend_shr_free_strlist(ret.common.bases);
	backend_shr_free_sdnlist(ret.common.restrict_subtrees);
	backend_shr_free_sdnlist(ret.common.ignore_subtrees);
	free(ret.common.entry_filter);
	slapi_sdn_free(&ret.container_sdn);
	backend_shr_free_strlist(ret.attribute_format);
	free(ret.rdn_format);
}

/* Create and destroy entry-specific data. */
static struct backend_entry_data *
backend_entry_make_entry_data(enum backend_entry_source source,
			      Slapi_DN *original_entry_dn, Slapi_Entry *e)
{
	struct backend_entry_data *ret;
	ret = malloc(sizeof(*ret));
	if (ret != NULL) {
		ret->original_entry_dn = slapi_sdn_dup(original_entry_dn);
		ret->source = source;
		ret->e = e;
	} else {
		slapi_entry_free(e);
	}
	return ret;
}
static void
backend_entry_free_entry_data(void *p)
{
	struct backend_entry_data *data;
	data = p;
	slapi_entry_free(data->e);
	slapi_sdn_free(&data->original_entry_dn);
	free(data);
}

/* Retrieve the USN of the passed-in entry, or the last-USN value from the root
 * DSE, or NULL.  The result needs to be free()d. */
static char *
backend_entry_get_usn(Slapi_PBlock *pb, Slapi_Entry *e,
		      struct plugin_state *state)
{
	Slapi_Entry *root;
	Slapi_ValueSet *value_set;
	Slapi_Value *value;
	Slapi_DN *sdn;
	char *attr, *attrs[2], *actual_attr, *val;
	const char *cval;
	int count, disposition, buffer_flags;

	root = NULL;
	if (e != NULL) {
		/* We'll read "entryUSN" from the entry. */
		attr = SLAPI_ATTR_ENTRYUSN;
	} else {
		/* We'll read "lastUSN" from the root DSE. */
		attr = "lastUSN";
		attrs[0] = attr;
		attrs[1] = NULL;
		sdn = slapi_sdn_new_dn_byval("");
		if (sdn == NULL) {
			return NULL;
		}
		wrap_search_internal_get_entry(pb, sdn, NULL, attrs,
					       &root, state->plugin_desc);
		slapi_sdn_free(&sdn);
		e = root;
	}
	/* No source entry, and failed to read the root DSE. */
	if (e == NULL) {
		return NULL;
	}
	if (slapi_vattr_values_get(e, attr,
				   &value_set,
				   &disposition,
				   &actual_attr,
				   0, &buffer_flags) != 0) {
		/* Error reading the attribute. Bail. */
		if (root != NULL) {
			slapi_entry_free(root);
		}
		return NULL;
	}
	count = slapi_valueset_count(value_set);
	if (count == 1) {
		if (slapi_valueset_first_value(value_set, &value) != -1) {
			cval = slapi_value_get_string(value);
		} else {
			cval = NULL;
		}
	} else {
		/* Either no results, or too many results.  More likely no
		 * results, if the USN plugin isn't loaded. */
		cval = NULL;
	}
	val = cval ? strdup(cval) : NULL;
	slapi_vattr_values_free(&value_set, &actual_attr, buffer_flags);
	if (root != NULL) {
		slapi_entry_free(root);
	}
	return val;
}

/* Add operational attributes to a synthetic entry. */
static void
backend_set_operational_attributes(Slapi_Entry *e,
				   struct plugin_state *state,
				   time_t timestamp,
				   int n_subordinates,
				   const char *usn)
{
	struct tm timestamp_tm;
	char timestamp_str[4 + 2 + 2 + 2 + 2 + 2 + 2]; /* YYYYMMDDHHMMSSZ\0 */
	/* Set operational attributes.  Do it first so that if users of the
	 * plugin want to override the values using the configuration, they
	 * can. */
	if (gmtime_r(&timestamp, &timestamp_tm) == &timestamp_tm) {
		sprintf(timestamp_str, "%04d%02d%02d%02d%02d%02dZ",
			timestamp_tm.tm_year + 1900,
			timestamp_tm.tm_mon + 1,
			timestamp_tm.tm_mday,
			timestamp_tm.tm_hour,
			timestamp_tm.tm_min,
			timestamp_tm.tm_sec);
		slapi_entry_add_string(e, "createTimestamp", timestamp_str);
		slapi_entry_add_string(e, "modifyTimestamp", timestamp_str);
	}
	slapi_entry_add_string(e, "creatorsName", state->plugin_base);
	slapi_entry_add_string(e, "modifiersName", state->plugin_base);
	slapi_entry_add_string(e, "entryDN", slapi_entry_get_ndn(e));
	if ((usn != NULL) && (strlen(usn) > 0)) {
		slapi_entry_add_string(e, "entryUSN", usn);
	}
	if (n_subordinates > 0) {
		slapi_entry_add_string(e, "hasSubordinates", "TRUE");
		snprintf(timestamp_str, sizeof(timestamp_str), "%ld",
			 (long) n_subordinates);
		slapi_entry_add_string(e, "numSubordinates", timestamp_str);
	}
}

/* Given a map-entry directory entry, determine a key, a value, and extra data
 * to be stored in the map cache, and add them to the map cache. */
static void
backend_set_entry_from(Slapi_PBlock *pb, enum backend_entry_source source,
		       Slapi_Entry *e, struct backend_set_data *data)
{
	const char *hexchars = "0123456789ABCDEF";
	char *rdn, *ndn, *ldif, *plugin_id, *keys[2], *values[2], **ava, *p, *q;
	char *usn, *attr, *val;
	unsigned int rdn_len[2], value_len[2], *ava_lens;
	const char *rdnstr;
	int len, i, j, k, count;
	Slapi_Entry *entry;
	Slapi_DN *e_dn, *sdn;
	Slapi_RDN *srdn;
	Slapi_Value **value;

	plugin_id = data->common.state->plugin_desc->spd_id;
	e_dn = slapi_entry_get_sdn(e);
	ndn = slapi_entry_get_ndn(e);
	if (ndn != NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"examining input entry \"%s\"\n", ndn);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"examining unnamed input entry(?)\n");
	}
	/* Generate the RDN for the entry. */
	rdn = format_get_data(data->common.state, pb, e,
			      data->common.group, data->common.set,
			      data->rdn_format, NULL,
			      data->common.restrict_subtrees,
			      data->common.ignore_subtrees,
			      &data->common.rel_attrs,
			      &data->common.ref_attrs,
			      &data->common.inref_attrs,
			      &data->common.ref_attr_list,
			      &data->common.inref_attr_list,
			      rdn_len);
	if ((rdn == NULL) || (strlen(rdn) == 0) || (strchr(rdn, '=') == NULL)) {
		slapi_log_error(SLAPI_LOG_FATAL, plugin_id,
				"no RDN for %s, unsetting domain/map/id "
				"\"%s\"/\"%s\"/(\"%s\")\n",
				ndn, data->common.group, data->common.set, ndn);
		map_data_unset_entry(data->common.state,
				     data->common.group, data->common.set, ndn);
		return;
	}
	/* Assume attribute=value and hex-escape the whole value to build the
	 * new entry's RDN.  The server functions will un-escape whatever they
	 * can when we build the resulting DN. */
	q = malloc(strlen(rdn) * 3 + 1);
	p = strchr(rdn, '=') + 1;
	i = p - rdn;
	memcpy(q, rdn, i);
	while (*p != '\0') {
		j = ((unsigned int) *p++) & 0xff;
		q[i++] = '\\';
		q[i++] = hexchars[(j & 0xf0) >> 4];
		q[i++] = hexchars[j & 0xf];
	}
	q[i] = '\0';
	srdn = slapi_rdn_new_dn(q);
	free(q);
	/* Now build the SDN.  Check it for validity. */
	sdn = slapi_sdn_add_rdn(slapi_sdn_dup(data->container_sdn), srdn);
	slapi_rdn_free(&srdn);
	if ((sdn == NULL) ||
	    (slapi_sdn_get_dn(sdn) == NULL) ||
	    (slapi_sdn_get_ndn(sdn) == NULL)) {
		slapi_log_error(SLAPI_LOG_FATAL, plugin_id,
				"would generate an invalid DN (1), "
				"unsetting domain/map/id "
				"\"%s\"/\"%s\"/(\"%s\")\n",
				data->common.group, data->common.set, ndn);
		map_data_unset_entry(data->common.state,
				     data->common.group, data->common.set, ndn);
		if (sdn != NULL) {
			slapi_sdn_free(&sdn);
		}
		format_free_data(rdn);
		return;
	}
	/* Now build the entry itself.  Set the DN first, and make sure it took
	 * the value. */
	entry = slapi_entry_alloc();
	slapi_entry_set_sdn(entry, sdn);
	slapi_sdn_free(&sdn);
	if ((slapi_entry_get_dn(entry) == NULL) ||
	    (slapi_entry_get_ndn(entry) == NULL)) {
		slapi_log_error(SLAPI_LOG_FATAL, plugin_id,
				"would generate an invalid DN (2), "
				"unsetting domain/map/id "
				"\"%s\"/\"%s\"/(\"%s\")\n",
				data->common.group, data->common.set, ndn);
		map_data_unset_entry(data->common.state,
				     data->common.group, data->common.set, ndn);
		slapi_entry_free(entry);
		format_free_data(rdn);
		return;
	}
	/* Set operational attributes here so that they can be overridden. */
	usn = backend_entry_get_usn(pb, e, data->common.state);
	backend_set_operational_attributes(entry, data->common.state,
					   time(NULL), 0, usn);
	free(usn);
	/* Iterate through the set of attributes. */
	if (data->attribute_format != NULL) {
		for (i = 0; data->attribute_format[i] != NULL; i++) {
			/* Expand the format specifier into a list. */
			ava_lens = NULL;
			ava = format_get_data_set(data->common.state, pb, e,
						  data->common.group,
						  data->common.set,
						  data->attribute_format[i],
						  NULL,
						  data->common.restrict_subtrees,
						  data->common.ignore_subtrees,
						  &data->common.rel_attrs,
						  &data->common.ref_attrs,
						  &data->common.inref_attrs,
						  &data->common.ref_attr_list,
						  &data->common.inref_attr_list,
						  &ava_lens);
			if ((ava != NULL) && (ava_lens != NULL)) {
				/* Count the values. */
				count = 0;
				for (j = 0; ava[j] != NULL; j++) {
					count++;
				}
				/* Create the value array. */
				value = malloc((count + 1) * sizeof(Slapi_Value *));
				if (value != NULL) {
					attr = NULL;
					len = 0;
					k = 0;
					for (j = 0; ava[j] != NULL; j++) {
						/* Assume attribute=value. */
						val = memchr(ava[j], '=',
							     ava_lens[j]);
						/* Skip over anything that didn't have
						 * a '=' or that produced an empty
						 * value. */
						if ((val != NULL) &&
						    (ava_lens[j] > val + 1 - ava[j])) {
							/* Add a new value. */
							value[k] = slapi_value_new();
							if (value[k] != NULL) {
								/* Set the value. */
								attr = ava[j];
								len = ava_lens[j];
								slapi_value_set(value[k],
										val + 1,
										ava_lens[j] -
										(val + 1 -
										ava[j]));
								k++;
							}
						}
					}
					value[k] = NULL;
					if ((k > 0) && (attr != NULL) && (len > 0)) {
						/* We assumed attribute=value when we
						 * saved this particular value.
						 * Pull the attribute name out
						 * of the last attribute=value
						 * pair that we examined. */
						val = memchr(attr, '=', len);
						if (val != NULL) {
							*val = '\0';
							slapi_entry_merge_values_sv(entry,
										    attr,
										    value);
							*val = '=';
						}
					}
					/* Clean up the values. */
					for (j = 0; j < k; j++) {
						slapi_value_free(&value[j]);
					}
					free(value);
				}
			}
			format_free_data_set(ava, ava_lens);
		}
	}
	/* Try to make the entry look "right". */
	if (!slapi_entry_rdn_values_present(entry)) {
		slapi_entry_add_rdn_values(entry);
	}
	if (slapi_entry_schema_check(NULL, entry) != 0) {
		slapi_entry_add_string(entry,
				       "objectClass", "extensibleObject");
	}
	/* Clean up the entry by doing a round trip through the LDIF parser. */
	ldif = slapi_entry2str(entry, &len);
	slapi_entry_free(entry);
	entry = slapi_str2entry(ldif,
				SLAPI_STR2ENTRY_REMOVEDUPVALS |
				SLAPI_STR2ENTRY_ADDRDNVALS |
				SLAPI_STR2ENTRY_EXPAND_OBJECTCLASSES |
				SLAPI_STR2ENTRY_NOT_WELL_FORMED_LDIF);
	slapi_ch_free((void **) &ldif);
	/* Normalize the RDN, so that we can use it as a key. */
	srdn = slapi_rdn_new_sdn(slapi_entry_get_sdn(entry));
	if (srdn != NULL) {
		rdnstr = slapi_rdn_get_nrdn(srdn);
	} else {
		rdnstr = NULL;
	}
	/* If we actually generated a useful new entry for this entry, then set
	 * it, otherwise clear it in case there was one set before. */
	if ((rdnstr != NULL) && (slapi_entry_get_ndn(entry) != NULL)) {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"setting group/container/key/value "
				"\"%s\"/\"%s\"/\"%s\"(\"%s\")=\"%s\"\n",
				data->common.group, data->common.set,
				rdn, ndn, slapi_entry_get_ndn(entry));
		keys[0] = (char *) rdnstr;
		keys[1] = NULL;
		rdn_len[0] = strlen(rdnstr);
		rdn_len[1] = -1;
		values[0] = (char *) slapi_entry_get_ndn(entry);
		values[1] = NULL;
		value_len[0] = -1;
		value_len[1] = -1;
		map_data_set_entry(data->common.state,
				   data->common.group, data->common.set, ndn,
				   rdn_len, keys,
				   value_len, values,
				   backend_entry_make_entry_data(source, e_dn,
								 entry),
				   backend_entry_free_entry_data);
	} else {
		if (rdnstr == NULL) {
			slapi_log_error(SLAPI_LOG_FATAL, plugin_id,
					"would generate an invalid RDN, "
					"unsetting domain/map/id "
					"\"%s\"/\"%s\"/(\"%s\")\n",
					data->common.group, data->common.set,
					ndn);
		}
		if (slapi_entry_get_ndn(entry) == NULL) {
			slapi_log_error(SLAPI_LOG_FATAL, plugin_id,
					"would generate an invalid entry DN, "
					"unsetting domain/map/id "
					"\"%s\"/\"%s\"/(\"%s\")\n",
					data->common.group, data->common.set,
					ndn);
		}
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"no value for %s, unsetting domain/map/id "
				"\"%s\"/\"%s\"/(\"%s\")\n",
				ndn, data->common.group, data->common.set, ndn);
		map_data_unset_entry(data->common.state,
				     data->common.group, data->common.set, ndn);
		slapi_entry_free(entry);
	}
	slapi_rdn_free(&srdn);
	format_free_data(rdn);
}
void
backend_set_entry(Slapi_PBlock *pb, Slapi_Entry *e, struct backend_set_data *data)
{
	backend_set_entry_from(pb, backend_entry_source_dit, e, data);
}

/* Process a set configuration directory entry.  Pull out the group and
 * container names which are valid for this configuration and configure such a
 * container for each in turn. */
int
backend_set_config_entry_add_cb(Slapi_Entry *e, void *callback_data)
{
	char **groups, **containers;
	int i, j;
	struct backend_set_config_entry_add_cbdata *cbdata;

	cbdata = callback_data;
	groups = backend_shr_get_vattr_strlist(cbdata->state, e,
					       SCH_CONTAINER_CONFIGURATION_GROUP_ATTR);
	containers = backend_shr_get_vattr_strlist(cbdata->state, e,
						   SCH_CONTAINER_CONFIGURATION_CONTAINER_ATTR);
	for (i = 0; (groups != NULL) && (groups[i] != NULL); i++) {
		/* If this is a multiple-container group, walk the list. */
		for (j = 0;
		     (containers != NULL) && (containers[j] != NULL);
		     j++) {
			backend_shr_set_config_entry_add(cbdata->state,
							 cbdata->pb,
							 e,
							 groups[i],
							 containers[j]);
		}
		/* If there are no containers, add one with an empty name. */
		if (containers == NULL) {
			backend_shr_set_config_entry_add(cbdata->state,
							 cbdata->pb,
							 e,
							 groups[i],
							 "");
		}
	}
	backend_shr_free_strlist(containers);
	backend_shr_free_strlist(groups);
	return 0;
}

/* Process a set configuration directory entry.  Pull out the domain and map
 * names which are specified in the entry and delete each in turn. */
int
backend_set_config_entry_delete_cb(Slapi_Entry *e, void *callback_data)
{
	struct plugin_state *state;
	state = callback_data;
	return backend_shr_set_config_entry_delete(state, e,
						   SCH_CONTAINER_CONFIGURATION_GROUP_ATTR,
						   SCH_CONTAINER_CONFIGURATION_CONTAINER_ATTR);
}

/* Functions for passing information about a container's configuration to the
 * formatting functions. */
struct backend_get_set_config_if_matching_cb {
	struct plugin_state *state;
	Slapi_DN *groupdn, *setrdn;
	Slapi_DN *search_groupdn, *search_setrdn;
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
backend_get_set_config_entry_if_matching_cb(Slapi_Entry *e, void *callback_data)
{
	struct backend_get_set_config_if_matching_cb *cbdata;
	char **groups, **sets;
	int i, j;

	cbdata = callback_data;
	groups = backend_shr_get_vattr_strlist(cbdata->state, e, SCH_CONTAINER_CONFIGURATION_GROUP_ATTR);
	sets = backend_shr_get_vattr_strlist(cbdata->state, e, SCH_CONTAINER_CONFIGURATION_CONTAINER_ATTR);
	if (groups == NULL) {
		backend_shr_free_strlist(groups);
		backend_shr_free_strlist(sets);
		return TRUE;
	}
	for (i = 0; (groups[i] != NULL); i++) {
		cbdata->groupdn = slapi_sdn_set_dn_byval(cbdata->groupdn, groups[i]);
		for (j = 0; (sets != NULL) && (sets[j] != NULL); j++) {
			cbdata->setrdn = slapi_sdn_set_dn_byval(cbdata->setrdn, sets[j]);
			if ((slapi_sdn_compare(cbdata->groupdn, cbdata->search_groupdn) == 0) &&
			    (slapi_sdn_compare(cbdata->setrdn, cbdata->search_setrdn) == 0)) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						cbdata->state->plugin_desc->spd_id,
						"reading container configuration from \"%s\"\n",
						slapi_entry_get_ndn(e));
				cbdata->bases = backend_shr_get_vattr_strlist(cbdata->state, e,
									      SCH_CONTAINER_CONFIGURATION_BASE_ATTR);
				cbdata->entry_filter = backend_shr_get_vattr_filter(cbdata->state, e,
										    SCH_CONTAINER_CONFIGURATION_FILTER_ATTR);
			}
		}
		if (sets == NULL) {
			if (slapi_sdn_compare(cbdata->groupdn, cbdata->search_groupdn) == 0) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						cbdata->state->plugin_desc->spd_id,
						"reading container configuration from \"%s\"\n",
						slapi_entry_get_ndn(e));
				cbdata->bases = backend_shr_get_vattr_strlist(cbdata->state, e,
									      SCH_CONTAINER_CONFIGURATION_BASE_ATTR);
				cbdata->entry_filter = backend_shr_get_vattr_filter(cbdata->state, e,
										    SCH_CONTAINER_CONFIGURATION_FILTER_ATTR);
			}
		}
	}
	backend_shr_free_strlist(groups);
	backend_shr_free_strlist(sets);
	return TRUE;
}

void
backend_get_set_config(Slapi_PBlock *parent_pb, struct plugin_state *state,
		       const char *group, const char *container,
		       char ***bases, char **entry_filter)
{
	Slapi_PBlock *pb;
	char *attrs[] = {SCH_CONTAINER_CONFIGURATION_FILTER_ATTR,
			 SCH_CONTAINER_CONFIGURATION_BASE_ATTR,
			 NULL};
	Slapi_DN *groupdn, *setrdn;
	struct backend_get_set_config_if_matching_cb cbdata;

	/* Build the search filter. */
	groupdn = slapi_sdn_new_dn_byval(group);
	if (groupdn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"out of memory reading configuration for "
				"\"%s\"/\"%s\"!\n", group, container);
		return;
	}
	if (strlen(container) > 0) {
		setrdn = slapi_sdn_new_dn_byval(container);
		if (setrdn == NULL) {
			slapi_sdn_free(&groupdn);
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"out of memory reading configuration "
					"for \"%s\"/\"%s\"!\n",
					group, container);
			return;
		}
	} else {
		setrdn = NULL;
	}
	cbdata.groupdn = slapi_sdn_new();
	if (cbdata.groupdn == NULL) {
		if (setrdn != NULL) {
			slapi_sdn_free(&setrdn);
		}
		slapi_sdn_free(&groupdn);
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"out of memory reading configuration for "
				"\"%s\"/\"%s\"!\n", group, container);
		return;
	}
	cbdata.setrdn = slapi_sdn_new();
	if (cbdata.setrdn == NULL) {
		slapi_sdn_free(&cbdata.groupdn);
		if (setrdn != NULL) {
			slapi_sdn_free(&setrdn);
		}
		slapi_sdn_free(&groupdn);
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"out of memory reading configuration for "
				"\"%s\"/\"%s\"!\n", group, container);
		return;
	}

	/* Perform the search. */
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"searching from \"%s\" for \"%s\" for configuration\n",
			state->plugin_base, SCH_CONTAINER_CONFIGURATION_FILTER);
	pb = wrap_pblock_new(parent_pb);
	slapi_search_internal_set_pb(pb,
				     state->plugin_base,
				     LDAP_SCOPE_SUBTREE,
				     SCH_CONTAINER_CONFIGURATION_FILTER,
				     attrs, FALSE,
				     NULL,
				     NULL,
				     state->plugin_identity,
				     0);
	cbdata.bases = NULL;
	cbdata.state = state;
	cbdata.entry_filter = NULL;
	cbdata.search_groupdn = groupdn;
	cbdata.search_setrdn = setrdn;
	slapi_search_internal_callback_pb(pb, &cbdata,
					  NULL,
					  backend_get_set_config_entry_if_matching_cb,
					  NULL);
	slapi_pblock_destroy(pb);

	/* Return the results. */
	*bases = cbdata.bases;
	*entry_filter = cbdata.entry_filter;

	/* Clean up. */
	slapi_sdn_free(&cbdata.setrdn);
	slapi_sdn_free(&cbdata.groupdn);
	if (setrdn != NULL) {
		slapi_sdn_free(&setrdn);
	}
	slapi_sdn_free(&groupdn);
}

/* Given an entry, return the filter which will match a container entry beneath
 * the plugin's configuration entry. */
const char *
backend_entry_get_set_config_entry_filter(void)
{
	return SCH_CONTAINER_CONFIGURATION_FILTER;
}

/* Re-read plugin-wide settings that may have changed.  Nothing to do. */
void
backend_update_params(Slapi_PBlock *pb, struct plugin_state *state)
{
	Slapi_DN *our_dn;
	Slapi_Entry *our_entry;
	int use_be_txns;

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
	/* Pull out the attribute values.  Just the one here. */
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

static bool_t
backend_should_descend(Slapi_DN *this_dn, Slapi_DN *target_dn, int scope)
{
	switch (scope) {
	case LDAP_SCOPE_BASE:
		/* The target DN needs to be a subordinate of this entry, but
		 * not actually be the entry itself. */
		if ((slapi_sdn_issuffix(target_dn, this_dn) != 0) &&
		    (slapi_sdn_compare(target_dn, this_dn) != 0)) {
			return TRUE;
		}
		break;
	case LDAP_SCOPE_ONELEVEL:
		/* The target DN needs to be a subordinate of this entry, or
		 * be the entry itself. */
		if (slapi_sdn_issuffix(target_dn, this_dn) != 0) {
			return TRUE;
		}
		break;
	case LDAP_SCOPE_SUBTREE:
		/* The target DN needs to be a subordinate of this entry, or
		 * this entry needs to be a subordinate of the target. */
		if ((slapi_sdn_issuffix(target_dn, this_dn) != 0) ||
		    (slapi_sdn_issuffix(this_dn, target_dn) != 0)) {
			return TRUE;
		}
		break;
	default:
		break;
	}
	return FALSE;
}

static bool_t
backend_search_entry_cb(const char *domain, const char *map, bool_t secure,
			const char *key, unsigned int key_len,
			const char *value, unsigned int value_len,
			const char *id, int key_index,
			void *backend_data, void *cb_data)
{
	Slapi_DN *sdn;
	Slapi_Entry *entry;
	struct backend_search_cbdata *cbdata;
	struct backend_entry_data *entry_data;
	int result;

	cbdata = cb_data;
	entry_data = backend_data;
	sdn = slapi_entry_get_sdn(entry_data->e);

	/* Check if this entry _is_ the target. */
	if (slapi_sdn_compare(sdn, cbdata->target_dn) == 0) {
		cbdata->matched = TRUE;
	}

	/* Check if this entry belongs. */
	if (slapi_sdn_scope_test(sdn, cbdata->target_dn, cbdata->scope) == 0) {
		/* If the target DN would have been a subordinate of this
		 * entry, store its DN as the closest match. */
		if ((slapi_sdn_issuffix(cbdata->target_dn, sdn) != 0) &&
		    !cbdata->matched) {
			free(cbdata->closest_match);
			cbdata->closest_match = strdup(slapi_sdn_get_ndn(sdn));
		}
		return TRUE;
	}

	/* Now check the entry against the filter. */
	result = slapi_filter_test(cbdata->pb, entry_data->e,
				   cbdata->filter, cbdata->check_access);
	switch (result) {
	default:
		/* Not a match. */
		break;
	case 0:
		/* Match. Return the entry. */
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"search matched %s\n",
				slapi_sdn_get_ndn(sdn));
		entry = entry_data->e;
#ifdef USE_IPA_IDVIEWS
		entry = slapi_entry_dup(entry_data->e);
		if (cbdata->idview != NULL) {
			idview_process_overrides(cbdata, key, map, domain, entry);
		}

		if (slapi_entry_attr_exists(entry, IPA_IDVIEWS_ATTR_ANCHORUUID) == 1) {
			slapi_entry_attr_delete(entry, IPA_IDVIEWS_ATTR_ANCHORUUID);
			slapi_entry_delete_string(entry, "objectClass", "ipaOverrideTarget");
		}
#endif
		slapi_send_ldap_search_entry(cbdata->pb, entry, NULL,
					     cbdata->attrs, cbdata->attrsonly);
		cbdata->n_entries++;

		if (entry != entry_data->e) {
			slapi_entry_free(entry);
		}
		break;
	}

	return TRUE;
}
static bool_t
backend_search_set_cb(const char *group, const char *set, bool_t flag,
		      void *backend_data, void *cb_data)
{
	struct backend_search_cbdata *cbdata;
	struct backend_set_data *set_data;
	Slapi_Entry *set_entry;
	int result, n_entries;
	int n_entries_without_nsswitch;
	const char *ndn;

	cbdata = cb_data;
	set_data = backend_data;
	cbdata->check_access = set_data->check_access;
	cbdata->check_nsswitch = set_data->check_nsswitch;
	cbdata->nsswitch_min_id = set_data->nsswitch_min_id;

	/* Count the number of results that we've found before looking at this
	 * set of entries. */
	n_entries_without_nsswitch = cbdata->n_entries;

	/* Check the set itself, unless it's also the group, in which case we
	 * already evaluated it for this search. */
	if ((strlen(set_data->common.set) != 0) &&
	    (slapi_sdn_scope_test(set_data->container_sdn,
				  cbdata->target_dn, cbdata->scope))) {
		set_entry = slapi_entry_alloc();
		slapi_entry_add_string(set_entry,
				       "objectClass", "extensibleObject");
		slapi_entry_set_sdn(set_entry, set_data->container_sdn);
		n_entries = map_data_get_map_size(cbdata->state,
						  set_data->common.group,
						  set_data->common.set);
		backend_set_operational_attributes(set_entry,
						   cbdata->state, time(NULL),
						   n_entries,
						   NULL);
		if (!slapi_entry_rdn_values_present(set_entry)) {
			slapi_entry_add_rdn_values(set_entry);
		}
		ndn = slapi_sdn_get_ndn(set_data->container_sdn);
		result = slapi_filter_test(cbdata->pb, set_entry,
					   cbdata->filter,
					   cbdata->check_access);
		switch (result) {
		default:
			/* Not a match. */
			break;
		case 0:
			/* Match. Return the entry. */
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata->state->plugin_desc->spd_id,
					"search matched %s\n", ndn);
#ifdef USE_IPA_IDVIEWS
			if (cbdata->idview != NULL) {
				idview_process_overrides(cbdata, NULL,
							 set_data->common.set,
							 set_data->common.group, set_entry);
			}
#endif
			slapi_send_ldap_search_entry(cbdata->pb, set_entry,
						     NULL, cbdata->attrs,
						     cbdata->attrsonly);
			cbdata->n_entries++;
			break;
		}
		slapi_entry_free(set_entry);
	}

	/* Check if this set _is_ the target. */
	if (slapi_sdn_compare(set_data->container_sdn,
			      cbdata->target_dn) == 0) {
		cbdata->matched = TRUE;
	}

	/* Walk the set of entries in this set if they're in scope. */
	if (backend_should_descend(set_data->container_sdn,
				   cbdata->target_dn,
				   cbdata->scope)) {
		map_data_foreach_entry_id(cbdata->state, group, set, NULL,
					  backend_search_entry_cb, cbdata);
#ifdef USE_NSSWITCH
		/* If we didn't find a matching entry in this set, but we're
		 * configured to also consult nsswitch, check if the search
		 * filter is one that should trigger an nsswitch lookup, and
		 * make a note if it would.  We'll come back and actually
		 * perform the lookup later when we're not holding a lock that
		 * can stall other threads. */
		if ((cbdata->n_entries == n_entries_without_nsswitch) &&
		    (cbdata->check_nsswitch != SCH_NSSWITCH_NONE)) {
			backend_search_nsswitch(set_data, cbdata);
		}
#endif
	}

	/* If we didn't find an exact match for the entry, then store this
	 * container's DN as the closest match. */
	if ((!cbdata->matched) &&
	    (cbdata->closest_match == NULL) &&
	    slapi_sdn_issuffix(cbdata->target_dn, set_data->container_sdn)) {
		ndn = slapi_sdn_get_ndn(set_data->container_sdn);
		cbdata->closest_match = strdup(ndn);
	}

	return TRUE;
}

static bool_t
backend_search_find_set_data_in_group_cb(const char *group, const char *set, bool_t flag,
					 void *backend_data, void *cb_data)
{
	struct backend_search_cbdata *cbdata;
	struct backend_set_data *set_data;

	cbdata = cb_data;
	set_data = backend_data;

	if ((0 == strcmp(group, cbdata->cur_staged->map_group)) &&
	    (0 == strcmp(set, cbdata->cur_staged->map_set))) {
		cbdata->cur_staged->set_data = set_data;
	}

	return TRUE;

}

static bool_t
backend_search_find_set_data_cb(const char *group, void *cb_data)
{
	struct backend_search_cbdata *cbdata;

	cbdata = cb_data;
	map_data_foreach_map(cbdata->state, group,
			     backend_search_find_set_data_in_group_cb, cb_data);
	return TRUE;
}

static bool_t
backend_search_group_cb(const char *group, void *cb_data)
{
	struct backend_search_cbdata *cbdata;
	Slapi_DN *group_dn;
	Slapi_Entry *group_entry;
	int result, n_maps;

	cbdata = cb_data;

	/* Check the group itself. */
	group_dn = slapi_sdn_new_dn_byval(group);
	if (slapi_sdn_scope_test(group_dn, cbdata->target_dn, cbdata->scope)) {
		group_entry = slapi_entry_alloc();
		slapi_entry_add_string(group_entry,
				       "objectClass", "extensibleObject");
		slapi_entry_set_sdn(group_entry, group_dn);
		n_maps = map_data_get_domain_size(cbdata->state, group);
		backend_set_operational_attributes(group_entry, cbdata->state,
						   time(NULL), n_maps, NULL);
		if (!slapi_entry_rdn_values_present(group_entry)) {
			slapi_entry_add_rdn_values(group_entry);
		}
		result = slapi_filter_test(cbdata->pb, group_entry,
					   cbdata->filter,
					   cbdata->check_access);
		switch (result) {
		default:
			/* Not a match. */
			break;
		case 0:
			/* Match. Return the entry. */
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata->state->plugin_desc->spd_id,
					"search matched %s\n", group);
#ifdef USE_IPA_IDVIEWS
			if (cbdata->idview != NULL) {
				idview_process_overrides(cbdata, NULL, NULL, group, group_entry);
			}
#endif
			slapi_send_ldap_search_entry(cbdata->pb, group_entry,
						     NULL, cbdata->attrs,
						     cbdata->attrsonly);
			cbdata->n_entries++;
			break;
		}
		slapi_entry_free(group_entry);
	}

	/* Check if this group _is_ the target. */
	if (slapi_sdn_compare(group_dn, cbdata->target_dn) == 0) {
		cbdata->matched = TRUE;
	}

	/* Now check the group's sets and their contents if they're in scope. */
	if (backend_should_descend(group_dn,
				   cbdata->target_dn,
				   cbdata->scope)) {
		map_data_foreach_map(cbdata->state, group,
				     backend_search_set_cb, cbdata);
	}

	/* If we didn't find an exact match for the entry, then store this
	 * group's DN as the closest match. */
	if ((!cbdata->matched) &&
	    (cbdata->closest_match == NULL) &&
	    slapi_sdn_issuffix(cbdata->target_dn, group_dn)) {
		cbdata->closest_match = strdup(slapi_sdn_get_ndn(group_dn));
	}

	/* If the search is confined to this group, we need to send the result
	 * ourselves. */
	if (slapi_sdn_scope_test(cbdata->target_dn,
				 group_dn, LDAP_SCOPE_SUBTREE)) {
		cbdata->answer = TRUE;
	}

	slapi_sdn_free(&group_dn);

	return TRUE;
}

static const char *
backend_sch_scope_as_string(int scope)
{
	switch (scope) {
	case LDAP_SCOPE_SUBTREE:
		return " (sub)";
		break;
	case LDAP_SCOPE_ONELEVEL:
		return " (one)";
		break;
	case LDAP_SCOPE_BASE:
		return " (base)";
		break;
#ifdef LDAP_SCOPE_SUBORDINATE
	case LDAP_SCOPE_SUBORDINATE:
		return " (children)";
		break;
#endif
	}
	return "";
}

static int
backend_search_cb(Slapi_PBlock *pb)
{
	struct backend_search_cbdata cbdata;
	struct backend_staged_search *staged, *next;
	int i;

	if (wrap_get_call_level() > 0) {
		return 0;
	}
	memset(&cbdata, 0, sizeof(cbdata));
	cbdata.pb = pb;
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &cbdata.state);
	if (cbdata.state->plugin_base == NULL) {
		/* The plugin was not actually started. */
		return 0;
	}
	slapi_pblock_get(pb, SLAPI_SEARCH_TARGET, &cbdata.target);
	slapi_pblock_get(pb, SLAPI_SEARCH_SCOPE, &cbdata.scope);
	slapi_pblock_get(pb, SLAPI_SEARCH_SIZELIMIT, &cbdata.sizelimit);
	slapi_pblock_get(pb, SLAPI_SEARCH_TIMELIMIT, &cbdata.timelimit);
	slapi_pblock_get(pb, SLAPI_SEARCH_FILTER, &cbdata.filter);
	slapi_pblock_get(pb, SLAPI_SEARCH_STRFILTER, &cbdata.strfilter);
	slapi_pblock_get(pb, SLAPI_SEARCH_ATTRS, &cbdata.attrs);
	slapi_pblock_get(pb, SLAPI_SEARCH_ATTRSONLY, &cbdata.attrsonly);
	cbdata.answer = FALSE;
	cbdata.result = 0;
	cbdata.matched = FALSE;
	cbdata.closest_match = NULL;
	cbdata.text = NULL;
	cbdata.n_entries = 0;
	cbdata.staged = NULL;
	cbdata.cur_staged = NULL;
	cbdata.idview = NULL;
	cbdata.overrides = NULL;
	/* Okay, we can search. */
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata.state->plugin_desc->spd_id,
			"searching from \"%s\" for \"%s\" with scope %d%s\n",
			cbdata.target, cbdata.strfilter, cbdata.scope,
			backend_sch_scope_as_string(cbdata.scope));
#ifdef USE_IPA_IDVIEWS
	idview_replace_target_dn(&cbdata.target, &cbdata.idview);
#endif
	cbdata.target_dn = slapi_sdn_new_dn_byval(cbdata.target);
	/* Check if there's a backend handling this search. */
	if (!slapi_be_exist(cbdata.target_dn)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"slapi_be_exists(\"%s\") = 0, "
				"ignoring search\n", cbdata.target);
		slapi_sdn_free(&cbdata.target_dn);
		if (cbdata.idview != NULL) {
			slapi_ch_free_string(&cbdata.target);
		}
		slapi_ch_free_string(&cbdata.idview);
#ifdef USE_IPA_IDVIEWS
		idview_free_overrides(&cbdata);
#endif
		return 0;
	}

	/* Walk the list of groups. */
	wrap_inc_call_level();
#ifdef USE_IPA_IDVIEWS
	idview_replace_filter(&cbdata);
#endif
	if (map_rdlock() == 0) {
		map_data_foreach_domain(cbdata.state, backend_search_group_cb,
					&cbdata);
		map_unlock();
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata.state->plugin_desc->spd_id,
				"unable to acquire read lock\n");
	}
	wrap_dec_call_level();
#ifdef USE_NSSWITCH
	/* If during search of some sets we staged additional lookups, perform them. */
	if (cbdata.staged != NULL) {
		/* Allocate buffer to be used for getpwnam_r/getgrnam_r requests */
		cbdata.nsswitch_buffer_len = MAX(sysconf(_SC_GETPW_R_SIZE_MAX), sysconf(_SC_GETGR_R_SIZE_MAX));
		if (cbdata.nsswitch_buffer_len == -1) {
			cbdata.nsswitch_buffer_len = 16384;
		}
		cbdata.nsswitch_buffer = malloc(cbdata.nsswitch_buffer_len);
		/* Go over the list of staged requests and retrieve entries.
		 * It is important to perform the retrieval *without* holding any locks to the map cache */
		staged = cbdata.staged;
		while (staged != NULL) {
			if (staged->entries == NULL) {
				backend_retrieve_from_nsswitch(staged, &cbdata);
			}
			staged = staged->next;
		}
		cbdata.nsswitch_buffer_len = 0;
		free(cbdata.nsswitch_buffer);
		/* Add the entries to the map cache */
		wrap_inc_call_level();
		if (map_wrlock() == 0) {
			staged = cbdata.staged;
			while (staged != NULL) {
				if (staged->entries != NULL) {
					cbdata.cur_staged = staged;
					/* We actually need to find the original set first */
					map_data_foreach_domain(cbdata.state, backend_search_find_set_data_cb, &cbdata);
					for (i = 0; i < staged->count; i++) {
						if (staged->entries[i] != NULL) {
							if ((cbdata.cur_staged->set_data != NULL) &&
							    !map_data_check_entry(cbdata.state,
										  staged->map_group, staged->map_set,
										  slapi_sdn_get_ndn(slapi_entry_get_sdn(staged->entries[i])))) {
								backend_set_entry_from(cbdata.pb, backend_entry_source_nsswitch,
										       staged->entries[i], staged->set_data);
							}
							slapi_entry_free(staged->entries[i]);
							staged->entries[i] = NULL;
						}
					}
					free(staged->entries);
					staged->count = 0;
					staged->entries = NULL;
				}
				slapi_ch_free_string(&staged->map_group);
				slapi_ch_free_string(&staged->map_set);
				slapi_ch_free_string(&staged->name);
				slapi_ch_free_string(&staged->container_sdn);
				next = staged->next;
				free(staged);
				staged = next;
			}
			cbdata.staged = NULL;
			map_unlock();
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata.state->plugin_desc->spd_id,
					"unable to acquire write lock\n");
			staged = cbdata.staged;
			while (staged != NULL) {
				for (i = 0;
				     (i < staged->count) &&
				     (staged->entries != NULL) &&
				     (staged->entries[i] != NULL);
				     i++) {
					slapi_entry_free(staged->entries[i]);
					staged->entries[i] = NULL;
				}
				slapi_ch_free_string(&staged->map_group);
				slapi_ch_free_string(&staged->map_set);
				slapi_ch_free_string(&staged->name);
				slapi_ch_free_string(&staged->container_sdn);
				next = staged->next;
				free(staged);
				staged = next;
			}
			cbdata.staged = NULL;
		}
		/* Perform search again, this time to collect the data added by the NSSWITCH search */
		if (map_rdlock() == 0) {
			map_data_foreach_domain(cbdata.state, backend_search_group_cb, &cbdata);
			map_unlock();
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata.state->plugin_desc->spd_id,
					"unable to acquire read lock, "
					"ignoring search\n");
		}
		wrap_dec_call_level();
	}
#endif
	/* If we "own" the search target DN, then we need to send a response. */
	if (cbdata.answer) {
		if (cbdata.matched || (cbdata.n_entries > 0)) {
			/* Free the closest-match that we've recorded, so that
			 * we don't send it as part of the result. */
			free(cbdata.closest_match);
			cbdata.closest_match = NULL;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata.state->plugin_desc->spd_id,
					"sending error %d\n", cbdata.result);
		} else {
			/* Return a no-such-object error because the target DN
			 * was not found. */
			cbdata.result = LDAP_NO_SUCH_OBJECT;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata.state->plugin_desc->spd_id,
					"sending error %d with closest match = "
					"\"%s\"\n", cbdata.result,
					cbdata.closest_match);
		}
		slapi_pblock_set(cbdata.pb, SLAPI_PLUGIN_OPRETURN,
				 &cbdata.result);
		/* XXX - THIS IS NOT A PUBLIC FUNCTION, but
		 * slapi_send_ldap_result() stores the values we pass in, calls
		 * the backend functions, which then overwrite the matched-dn
		 * with a "real" entry's name before sending back the result.
		 * If we return a -1 here, we prevent backends from being
		 * called, but then no result gets sent if we use
		 * slapi_send_ldap_result(), so we call the internal
		 * send_ldap_result() function directly. */
		send_ldap_result(cbdata.pb, cbdata.result,
				 cbdata.closest_match, cbdata.text,
				 cbdata.n_entries, NULL);
	}
	slapi_sdn_free(&cbdata.target_dn);
	if (cbdata.idview != NULL) {
		slapi_ch_free_string(&cbdata.target);
	}
	slapi_ch_free_string(&cbdata.idview);
#ifdef USE_IPA_IDVIEWS
	idview_free_overrides(&cbdata);
#endif
	free(cbdata.closest_match);
	free(cbdata.text);
	return cbdata.answer ? -1 : 0;
}

/* Locate the entry for a given DN. */
struct backend_locate_cbdata {
	struct plugin_state *state;
	char *target;
	Slapi_DN *target_dn;

	struct backend_entry_data *entry_data;
	const char *entry_group;
	const char *entry_set;
};
/* Check if the target DN is an entry in this container's set of entries.  If
 * it is, pull the entry's data out and save it. */
static bool_t
backend_locate_cb(const char *group, const char *set, bool_t flag,
		  void *backend_set_data, void *cb_data)
{
	struct backend_locate_cbdata *cbdata;
	struct backend_set_data *set_data;
	struct backend_entry_data *entry_data;
	Slapi_RDN *rdn;
	const char *rdnstr, *ndn, *original_dn;
	unsigned int ndnlen;

	cbdata = cb_data;
	set_data = backend_set_data;
	/* Check if the target DN looks like it would be part of this set. */
	if (slapi_sdn_scope_test(cbdata->target_dn, set_data->container_sdn,
				 LDAP_SCOPE_ONELEVEL)) {
		/* Pull out the RDN and check for an entry which is using the
		 * RDN as a key. */
		rdn = slapi_rdn_new_sdn(cbdata->target_dn);
		if (rdn != NULL) {
			rdnstr = slapi_rdn_get_nrdn(rdn);
			if (map_match(cbdata->state, group, set, &flag,
				      strlen(rdnstr), rdnstr,
				      &ndnlen, &ndn,
				      &original_dn, (void **) &entry_data)) {
				if (entry_data != NULL) {
					cbdata->entry_data = entry_data;
					cbdata->entry_group = group;
					cbdata->entry_set = set;
				}
			}
			slapi_rdn_free(&rdn);
		}
	}
	return TRUE;
}
static void
backend_locate(Slapi_PBlock *pb, struct backend_entry_data **data, const char **group, const char**set)
{
	struct backend_locate_cbdata cbdata;
	char *idview = NULL;

	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &cbdata.state);
	if (cbdata.state->plugin_base == NULL) {
		/* The plugin was not actually started. */
		*data = NULL;
		return;
	}
	slapi_pblock_get(pb, SLAPI_TARGET_DN, &cbdata.target);
#ifdef USE_IPA_IDVIEWS
	idview_replace_target_dn(&cbdata.target, &idview);
#endif
	cbdata.target_dn = slapi_sdn_new_dn_byval(cbdata.target);
	cbdata.entry_data = NULL;
	cbdata.entry_group = NULL;
	cbdata.entry_set = NULL;
	map_data_foreach_map(cbdata.state, NULL, backend_locate_cb, &cbdata);
	*data = cbdata.entry_data;
	*group = cbdata.entry_group;
	*set = cbdata.entry_set;
	slapi_sdn_free(&cbdata.target_dn);
	if (idview != NULL) {
		slapi_ch_free_string(&cbdata.target);
	}
	slapi_ch_free_string(&idview);
}

/* Check if the target DN is part of this group's tree.  If it is, return an
 * insufficient-access error. */
struct backend_group_check_scope_cbdata {
	struct plugin_state *state;
	const char *target;
	Slapi_DN *target_dn;
	bool_t ours;
};

static bool_t
backend_group_check_scope_cb(const char *group, void *cb_data)
{
	struct backend_group_check_scope_cbdata *cbdata;
	Slapi_DN *group_dn;

	cbdata = cb_data;
	group_dn = slapi_sdn_new_dn_byref(group);
	if (slapi_sdn_scope_test(cbdata->target_dn, group_dn,
				 LDAP_SCOPE_SUBTREE)) {
		cbdata->ours = TRUE;
	}
	slapi_sdn_free(&group_dn);
	return TRUE;
}

static bool_t
backend_check_scope_pb(Slapi_PBlock *pb)
{
	struct backend_group_check_scope_cbdata cbdata;

	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &cbdata.state);
	if (cbdata.state->plugin_base == NULL) {
		/* The plugin was not actually started. */
		return FALSE;
	}
	slapi_pblock_get(pb, SLAPI_TARGET_DN, &cbdata.target);
	cbdata.target_dn = slapi_sdn_new_dn_byval(cbdata.target);
	cbdata.ours = FALSE;
	map_data_foreach_domain(cbdata.state, backend_group_check_scope_cb,
				&cbdata);
	slapi_sdn_free(&cbdata.target_dn);
	return cbdata.ours;
}

static int
backend_write_cb(Slapi_PBlock *pb, struct plugin_state *state)
{
	int ret;

	if (wrap_get_call_level() > 0) {
		return 0;
	}

	wrap_inc_call_level();
	if (map_rdlock() == 0) {
		if (backend_check_scope_pb(pb)) {
			slapi_send_ldap_result(pb, LDAP_UNWILLING_TO_PERFORM,
					       NULL, NULL, 0, NULL);
			ret = -1;
		} else {
			ret = 0;
		}
		map_unlock();
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"unable to acquire read lock\n");
		ret = -1;
	}
	wrap_dec_call_level();

	return ret;
}

static int
backend_pre_write_cb(Slapi_PBlock *pb)
{
	struct plugin_state *state;
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
	return state->use_be_txns ? 0: backend_write_cb(pb, state);
}

static int
backend_betxn_pre_write_cb(Slapi_PBlock *pb)
{
	struct plugin_state *state;

	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
	return state->use_be_txns ? backend_write_cb(pb, state) : 0;
}

#ifdef USE_PAM
static int
backend_bind_cb_pam(Slapi_PBlock *pb, const char *username, char *ndn)
{
	int ret = 0;
	LDAPControl **reqctrls = NULL;
	struct plugin_state *state;
	char *conn_dn = NULL;
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);

	/* PAM API is thread-unsafe, we need to lock exclusively */
	wrap_rwlock_wrlock(state->pam_lock);
	ret = backend_sch_do_pam_auth(pb, username);
	wrap_rwlock_unlock(state->pam_lock);

	if (ret == LDAP_SUCCESS) {
		/*
		 * If bind succeeded, change authentication information associated
		 * with this connection.
		 */
		conn_dn = slapi_ch_strdup(ndn);
		if (conn_dn == NULL) {
			ret = LDAP_OPERATIONS_ERROR;
		} else {
			if ((slapi_pblock_set(pb, SLAPI_CONN_DN, (void*) conn_dn) != 0) ||
			    (slapi_pblock_set(pb, SLAPI_CONN_AUTHMETHOD, SLAPD_AUTH_SIMPLE) != 0)) {
				ret = LDAP_OPERATIONS_ERROR;
				slapi_ch_free_string(&conn_dn);
			} else {
				slapi_pblock_get(pb, SLAPI_REQCONTROLS, &reqctrls);
				if (slapi_control_present(reqctrls, LDAP_CONTROL_AUTH_REQUEST, NULL, NULL)) {
					slapi_add_auth_response_control(pb, conn_dn);
				}
			}
		}

		/* we are handling the result */
		slapi_send_ldap_result(pb, ret, NULL, NULL, 0, NULL);
	}
	return ret;
}
#else
static int
backend_bind_cb_pam(Slapi_PBlock *pb, const char *username, char *ndn)
{
	slapi_send_ldap_result(pb, LDAP_INVALID_CREDENTIALS, NULL, NULL, 0, NULL);
	return LDAP_INVALID_CREDENTIALS;
}
#endif

static int
backend_bind_cb(Slapi_PBlock *pb)
{
	struct backend_entry_data *data;
	struct plugin_state *state;
	int ret;
	Slapi_DN *sdn = NULL;
	char *ndn;
	char *username = NULL;
	char *group = NULL;
	const char *entry_group = NULL;
	char *set = NULL;
	const char *entry_set = NULL;

	if (wrap_get_call_level() > 0) {
		return 0;
	}

	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
	/* The code below handles three separate facts:
	 * 1. For NSSWITCH-discovered users PAM is responsible for authentication.
	 *    We want to run PAM auth without any slapi-nis lock taken to avoid
	 *    issues when Kerberos KDC is backed by the same LDAP store and
	 *    changes in a Kerberos principal would cause cascading effect on
	 *    some of entries belonging to a slapi-nis map cache.
	 * 2. If bind target DN exists in LDAP store, its map cache entry
	 *    will have orginal entry DN recorded. Enforcing SLAPI_BIND_TARGET_SDN
	 *    to it will force other plugins to handle authentication request against
	 *    the original because slapi-nis' map cache entry doesn't have paswords
	 *    recorded. To make it working, slapi-nis should be registered with higher
	 *    plugin ordering priority than other plugins.
	 * 3. If bind target DN is not found in the map cache, bind request is rejected.
	 * */
	wrap_inc_call_level();
	if (map_rdlock() != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"unable to acquire read lock\n");
		ret = 0;
		goto done_with_lock;
	}
	backend_locate(pb, &data, &entry_group, &entry_set);
	if (data != NULL) {
		ndn = slapi_ch_strdup(slapi_sdn_get_ndn(data->original_entry_dn));
		username = slapi_entry_attr_get_charptr(data->e, "uid");
		group = slapi_ch_strdup(entry_group);
		set = slapi_ch_strdup(entry_set);
		map_unlock();
		wrap_dec_call_level();

		/* If user comes from NSSWITCH, it will get authentication handled by PAM. */
		if (data->source == backend_entry_source_nsswitch) {
			ret = backend_bind_cb_pam(pb, username, ndn);
			if (ret == LDAP_NO_SUCH_OBJECT) {
				/* Evict the entry from the cache */
				if ((group != NULL) && (set != NULL)) {
					map_data_unset_entry(state, group, set, ndn);
				} else {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"Error: unable to locate group and set "
							" when removing cached entry %s\n",
							ndn);
				}
			}
			slapi_ch_free_string(&ndn);
			ret = -1;
		} else {
			/* Otherwise force rewrite of the SLAPI_BIND_TARGET_SDN
			 * and let other plugins to handle it.
			 * slapi-nis should have plugin ordering set below standard 50 to succeed */
			slapi_pblock_get(pb, SLAPI_BIND_TARGET_SDN, &sdn);
			if (sdn != NULL) {
				slapi_sdn_free(&sdn);
			}
			sdn = slapi_sdn_new_dn_byref(ndn);
			slapi_pblock_set(pb, SLAPI_BIND_TARGET_SDN, (void*) sdn);
			ret = 0;
		}
		slapi_ch_free_string(&set);
		slapi_ch_free_string(&group);
		slapi_ch_free_string(&username);
	} else {
		map_unlock();
done_with_lock:
		wrap_dec_call_level();
		if (backend_check_scope_pb(pb)) {
			slapi_send_ldap_result(pb, LDAP_INVALID_CREDENTIALS,
					       NULL, NULL, 0, NULL);
			ret = -1;
		} else {
			ret = 0;
		}
	}
	return ret;
}

static int
backend_compare_cb(Slapi_PBlock *pb)
{
	struct plugin_state *state;
	int ret = -1;

	if (wrap_get_call_level() > 0) {
		return 0;
	}
	wrap_inc_call_level();
	if (map_rdlock() == 0) {
		if (backend_check_scope_pb(pb)) {
			slapi_send_ldap_result(pb, LDAP_UNWILLING_TO_PERFORM,
					       NULL, NULL, 0, NULL);
			ret = -1;
		} else {
			ret = 0;
		}
		map_unlock();
	} else {
		slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"unable to acquire read lock\n");
	}
	wrap_dec_call_level();
	return ret;
}

/* Warn if a set is empty. */
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
				"warning: no entries set up under %s%s%s\n",
				set, strlen(set) ? ", " : "", group);
	}
}

/* Populate our data cache. */
void
backend_startup(Slapi_PBlock *pb, struct plugin_state *state)
{
	backend_shr_startup(state, pb, SCH_CONTAINER_CONFIGURATION_FILTER);
}

int
backend_init_preop(Slapi_PBlock *pb, struct plugin_state *state)
{
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"hooking up preoperation callbacks\n");
	/* Intercept bind requests and return a referral or failure for entries
	 * that we're managing. */
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN,
			     backend_bind_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up pre bind callback\n");
		return -1;
	}
	/* Intercept compare requests and return the right data. */
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_COMPARE_FN,
			     backend_compare_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up pre compare callback\n");
		return -1;
	}
	/* Intercept search requests and return the right data. */
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_SEARCH_FN,
			     backend_search_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up pre search callback\n");
		return -1;
	}
	/* Intercept write requests to our areas. */
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_ADD_FN,
			     backend_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up pre add callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODIFY_FN,
			     backend_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up pre modify callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_MODRDN_FN,
			     backend_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up pre modrdn callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_DELETE_FN,
			     backend_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up pre delete callback\n");
		return -1;
	}
	/* We don't hook abandonment requests. */
	/* We don't hook unbind requests. */
	return 0;
}

#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
int
backend_init_betxn_preop(Slapi_PBlock *pb, struct plugin_state *state)
{
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
	                "hooking up betxn preoperation callbacks\n");
	/* Intercept write requests and return an insufficient-access error for
	 * attempts to write to anything we're managing. */
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_ADD_FN,
			     backend_betxn_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up betxn pre add callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_MODIFY_FN,
			     backend_betxn_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up betxn pre modify callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_MODRDN_FN,
			     backend_betxn_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up betxn pre modrdn callback\n");
		return -1;
	}
	if (slapi_pblock_set(pb, SLAPI_PLUGIN_BE_TXN_PRE_DELETE_FN,
			     backend_betxn_pre_write_cb) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error hooking up betxn pre delete callback\n");
		return -1;
	}
	/* We don't hook abandonment requests. */
	/* We don't hook unbind requests. */
	return 0;
}

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
