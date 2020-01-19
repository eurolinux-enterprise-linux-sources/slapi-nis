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

#ifndef map_h
#define map_h
struct plugin_state;
struct slapi_pblock;
/* Functions to pull data out of maps. */
int map_startup(struct plugin_state *state);
int map_init(struct slapi_pblock *pb, struct plugin_state *state);
void map_done(struct plugin_state *state);
int map_master_name(struct plugin_state *state, const char **master);
bool_t map_supports_domain(struct plugin_state *state,
			   const char *domain,
			   bool_t *supported);
bool_t map_supports_map(struct plugin_state *state,
			const char *domain,
			const char *map,
			bool_t *supported,
			bool_t *secure);
bool_t map_match(struct plugin_state *state,
		 const char *domain, const char *map, bool_t *secure,
		 unsigned int key_len, const char *key,
		 unsigned int *value_len, const char **value,
		 const char **id, void **backend_data);
bool_t map_match_id(struct plugin_state *state,
		    const char *domain, const char *map, bool_t *secure,
		    const char *id_in, unsigned int id_index,
		    unsigned int *key_len, const char **key,
		    unsigned int *value_len, const char **value,
		    const char **id, void **backend_data);
bool_t map_first(struct plugin_state *state,
		 const char *domain, const char *map, bool_t *secure,
		 unsigned int *first_key_len, char **first_key,
		 unsigned int *first_value_len, char **first_value,
		 const char **first_id, int *first_key_index);
bool_t map_next(struct plugin_state *state,
		const char *domain, const char *map, bool_t *secure,
		unsigned int prev_len, const char *prev,
		unsigned int *next_key_len, char **next_key,
		unsigned int *next_value_len, char **next_value);
bool_t map_next_id(struct plugin_state *state,
		   const char *domain, const char *map, bool_t *secure,
		   const char *prev_id, int prev_index,
		   unsigned int *next_key_len, char **next_key,
		   unsigned int *next_value_len, char **next_value,
		   const char **next_id, int *next_key_index);
bool_t map_order(struct plugin_state *state,
		 const char *domain, const char *map, bool_t *map_secure,
		 unsigned int *order);
/* Functions to push data into maps. */
void map_data_clear_map(struct plugin_state *state,
			const char *domain_name, const char *map_name);
void map_data_unset_map(struct plugin_state *state,
			const char *domain_name, const char *map_name);
void map_data_set_map(struct plugin_state *state,
		      const char *domain_name, const char *map_name,
		      bool_t secure,
		      void *backend_data, void (*free_backend_data)(void *p));
void map_data_unset_entry(struct plugin_state *state,
			  const char *domain_name, const char *map_name,
			  const char *id);
void map_data_set_entry(struct plugin_state *state,
			const char *domain_name, const char *map_name,
			const char *id,
			unsigned int *key_lengths, char **keys,
			unsigned int *value_lengths, char **values,
			void *backend_data, void (*free_backend_data)(void *p));
bool_t map_data_check_entry(struct plugin_state *state,
			    const char *domain_name, const char *map_name,
			    const char *id);
bool_t map_data_foreach_entry_id(struct plugin_state *state,
				 const char *domain, const char *map,
				 const char *id,
				 bool_t (*fn)(const char *domain,
					      const char *map,
					      bool_t secure,
					      const char *key,
					      unsigned int key_len,
					      const char *value,
					      unsigned int value_len,
					      const char *id, int key_index,
					      void *backend_data,
					      void *cbdata),
				 void *cbdata);
bool_t map_data_foreach_domain(struct plugin_state *state,
			       bool_t (*fn)(const char *domain, void *cbdata),
			       void *cbdata);
bool_t map_data_foreach_map(struct plugin_state *state, const char *domain_name,
			    bool_t (*fn)(const char *domain,
			   		 const char *map,
					 bool_t secure,
					 void *backend_data,
					 void *cbdata),
			    void *cbdata);
int map_data_get_domain_size(struct plugin_state *state,
			     const char *domain_name);
int map_data_get_map_size(struct plugin_state *state,
			  const char *domain_name, const char *map_name);
int map_rdlock(void);
int map_wrlock(void);
int map_unlock(void);
#endif
