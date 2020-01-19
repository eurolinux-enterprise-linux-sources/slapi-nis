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

#ifndef format_h
#define format_h
struct slapi_entry;
struct slapi_dn;
struct plugin_state;

struct format_inref_attr {
	char *group, *set, *attribute;
};

struct format_ref_attr_list {
	char *group, *set;
	struct format_ref_attr_list_link {
		char *attribute, *filter_str;
		Slapi_Filter *filter;
		struct slapi_dn **base_sdn_list, **base_sdn_list2;
	} *links;
	int n_links;
};

void format_free_attr_list(char **attr_list);
char **format_dup_attr_list(char **attr_list);

void format_free_inref_attrs(struct format_inref_attr **);
struct format_inref_attr **format_dup_inref_attrs(struct format_inref_attr **);

void format_free_ref_attr_list(struct format_ref_attr_list **);
struct format_ref_attr_list **
format_dup_ref_attr_list(struct format_ref_attr_list **);

void format_free_sdn_list(struct slapi_dn **list, struct slapi_dn **list2);
void format_add_sdn_list(struct slapi_dn ***list, struct slapi_dn ***list2,
			 const char *dn);

void format_free_data(char *data);
char *format_get_data(struct plugin_state *state,
		      struct slapi_pblock *pb, struct slapi_entry *e,
		      const char *domain, const char *map,
		      const char *fmt,
		      const char *disallowed_chars,
		      const struct slapi_dn **restrict_subtrees,
		      const struct slapi_dn **ignore_subtrees,
		      char ***rel_attrs,
		      char ***ref_attrs,
		      struct format_inref_attr ***inref_attrs,
		      struct format_ref_attr_list ***ref_attr_list,
		      struct format_ref_attr_list ***inref_attr_list,
		      unsigned int *data_length);
void format_free_data_set(char **data_set, unsigned int *data_lengths);
char **format_get_data_set(struct plugin_state *state,
			   Slapi_PBlock *pb, Slapi_Entry *e,
			   const char *domain, const char *map,
			   const char *fmt,
			   const char *disallowed,
			   const struct slapi_dn **restrict_subtrees,
			   const struct slapi_dn **ignore_subtrees,
			   char ***rel_attrs,
			   char ***ref_attrs,
			   struct format_inref_attr ***inref_attrs,
			   struct format_ref_attr_list ***ref_attr_list,
			   struct format_ref_attr_list ***inref_attr_list,
			   unsigned int **data_lengths);

char *format_escape_for_filter(const char *unescaped);
#endif
