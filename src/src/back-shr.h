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

#ifndef back_shr_h
#define back_shr_h

struct plugin_state;

void backend_shr_free_server_name(struct plugin_state *state, char *master);
int backend_shr_read_server_name(Slapi_PBlock *pb, struct plugin_state *state,
				 char **master);

void backend_shr_free_strlist(char **strlist);
char **backend_shr_dup_strlist_n(char **strlist, int n);
char **backend_shr_dup_strlist(char **strlist);
char **backend_shr_dup_strlist_unless_empty(char **strlist);
void backend_shr_add_strlist(char ***strlist, const char *item);
void backend_shr_add_sdnlist(const Slapi_DN ***sdnlist, const char *dn);
const Slapi_DN **backend_shr_dup_sdnlist(const Slapi_DN **sdnlist);
void backend_shr_free_sdnlist(const Slapi_DN **sdnlist);

void backend_shr_startup(struct plugin_state *state,
			 Slapi_PBlock *pb, const char *set_filter);
void backend_shr_shutdown(struct plugin_state *state);
int backend_shr_betxn_postop_init(Slapi_PBlock *pb,
				  struct plugin_state *state);
int backend_shr_postop_init(Slapi_PBlock *pb, struct plugin_state *state);
int backend_shr_internal_postop_init(Slapi_PBlock *pb,
				     struct plugin_state *state);

int backend_shr_set_config_entry_add(struct plugin_state *state,
				     Slapi_PBlock *pb,
				     Slapi_Entry *e,
				     const char *group_name,
				     const char *set_name);
int backend_shr_set_config_entry_delete(struct plugin_state *state,
					Slapi_Entry *e,
					const char *group_attr,
					const char *set_attr);
char **backend_shr_get_vattr_strlist(struct plugin_state *state,
				     Slapi_Entry *e, const char *attribute);
const Slapi_DN ** backend_shr_get_vattr_sdnlist(struct plugin_state *state,
						Slapi_Entry *e,
						const char *attribute);
char *backend_shr_get_vattr_str(struct plugin_state *state,
				Slapi_Entry *e, const char *attribute);
unsigned int backend_shr_get_vattr_uint(struct plugin_state *state,
					Slapi_Entry *e, const char *attribute,
					unsigned int default_value);
char *backend_shr_get_vattr_filter(struct plugin_state *state,
				   Slapi_Entry *e, const char *attribute);
bool_t backend_shr_get_vattr_boolean(struct plugin_state *state,
				     Slapi_Entry *e, const char *attribute,
				     bool_t default_value);
#endif
