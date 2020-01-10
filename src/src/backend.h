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

#ifndef backend_h
#define backend_h
struct backend_set_data;
struct plugin_state;
struct format_inref_attr;

/* Configuration data common to all backends. */
struct backend_shr_set_data {
	struct plugin_state *state;
	char *group, *set, **bases, *entry_filter;
	/* The list of "relevant" attributes, from _any_ entry, which matter
	 * when we're evaluating key or value data.  We skip updating an entry
	 * in this map if a modification request doesn't touch any of these
	 * attributes. */
	char **rel_attrs, *rel_attr_list, **rel_attrs_list;
	/* The list of attributes in source entries for this map which directly
	 * name other entries. */
	char **ref_attrs;
	/* A list of group/set/attributes by which source entries in any other
	 * group/set refer to entries in this set. */
	struct format_inref_attr **inref_attrs;
	/* More general-purpose versions of the above, which allow for
	 * overriding the search bases and filters as well. */
	struct format_ref_attr_list **ref_attr_list, **inref_attr_list;
	/* Configuration flag indicating whether or not we try to skip
	 * recomputing data in this map. */
	int skip_uninteresting_updates:1;
	struct backend_set_data *self;
};

/* Startup/initialization functions called through the map. */
void backend_startup(struct slapi_pblock *pb, struct plugin_state *state);
int backend_init_preop(struct slapi_pblock *pb, struct plugin_state *state);
int backend_init_postop(struct slapi_pblock *pb, struct plugin_state *state);
int backend_init_internal_postop(struct slapi_pblock *pb,
				 struct plugin_state *state);
#ifdef USE_SLAPI_BE_TXNS
int backend_init_be_txn_postop(struct slapi_pblock *pb,
			       struct plugin_state *state);
#endif

/* Read the server's name. */
int backend_read_master_name(struct plugin_state *state,
			     struct slapi_pblock *pb,
			     char **master);
void backend_free_master_name(struct plugin_state *state, char *master);

/* Read enough of the set's configuration for the formatter to be able to
 * resolve references correctly. */
void backend_get_set_config(Slapi_PBlock *pb, struct plugin_state *state,
			    const char *group, const char *set,
			    char ***bases, char **entry_filter);
void backend_free_set_config(char **bases, char *entry_filter);

/* Check if an entry is a set configuration, and add or remove one. */
const char *backend_entry_get_set_config_entry_filter(void);
struct backend_set_config_entry_add_cbdata {
	struct plugin_state *state;
	Slapi_PBlock *pb;
};
int backend_set_config_entry_add_cb(Slapi_Entry *e, void *callback_data);
int backend_set_config_entry_delete_cb(Slapi_Entry *e, void *callback_data);

/* Set an entry in a set. */
void backend_set_entry(Slapi_PBlock *pb, Slapi_Entry *e,
		       struct backend_set_data *set_data);

/* Read and free set configurations. */
void backend_set_config_read_config(struct plugin_state *state,
				    Slapi_Entry *e,
				    const char *group, const char *set,
				    bool_t *flag,
				    struct backend_shr_set_data **set_data);
void backend_set_config_free_config(struct backend_shr_set_data *set_data);

/* Warn if a just-populated set of entries is actually empty. */
void backend_check_empty(struct plugin_state *state,
			 const char *group, const char *set);

/* Re-read any plugin configuration data which can be modified without
 * requiring a restart. */
void backend_update_params(Slapi_PBlock *pb, struct plugin_state *state);

/* Check if the operation which this pblock describes was initiated by the
 * current plugin. */
bool_t backend_shr_is_caller(struct plugin_state *state,
			     struct slapi_pblock *pb);

#endif
