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
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include "../yp/yp.h"

#include "backend.h"
#include "back-shr.h"
#include "format.h"
#include "plugin.h"

#define DEFAULT_BUFFER_SIZE 0x1000
#define MAX_BUFFER_SIZE     0x100000
struct format_choice {
	char *offset;
	int n_values;
	struct berval **values;
	struct format_choice *next;
};

static int format_expand(struct plugin_state *state,
			 Slapi_PBlock *pb, Slapi_Entry *e,
			 const char *group, const char *set,
			 const char *fmt, const char *disallowed,
			 char *outbuf, int outbuf_len,
			 struct format_choice **outbuf_choices,
			 char ***rel_attrs, char ***ref_attrs,
			 struct format_inref_attr ***inref_attrs,
			 struct format_ref_attr_list ***ref_attr_list,
			 struct format_ref_attr_list ***inref_attr_list);

static char *
xstrndup(const char *start, size_t length)
{
	char *ret, *end;
	end = memchr(start, '\0', length);
	if (end != NULL) {
		length = end - start;
	}
	ret = malloc(length + 1);
	if (ret != NULL) {
		memcpy(ret, start, length);
		ret[length] = '\0';
	}
	return ret;
}

static char *
xstrndupp(const char *start, const char *end)
{
	return xstrndup(start, end - start);
}

static void *
xmemdup(char *region, int size)
{
	char *ret;
	ret = malloc(size + 1);
	if (ret != NULL) {
		if (size > 0) {
			memcpy(ret, region, size);
		}
		ret[size] = '\0';
	}
	return ret;
}

/* Maintain a DN list, which is list of distinguished names, and a sorted copy
 * which we can check for inclusion much faster. */
static int
compare_sdn(const void *a, const void *b)
{
	const struct slapi_dn **sa, **sb;
	sa = (const struct slapi_dn **) a;
	sb = (const struct slapi_dn **) b;
	return strcmp(slapi_sdn_get_ndn(*sa), slapi_sdn_get_ndn(*sb));
}

void
format_free_sdn_list(struct slapi_dn **list, struct slapi_dn **list2)
{
	unsigned int i;
	if (list != NULL) {
		for (i = 0; list[i] != NULL; i++) {
			slapi_sdn_free(&(list[i]));
		}
		free(list);
	}
	free(list2);
}

/* Turn shallow-copy list pointers into deep ones. */
static void
format_dup_sdn_list(struct slapi_dn ***list, struct slapi_dn ***list2)
{
	struct slapi_dn **ret = NULL, **ret2 = NULL;
	unsigned int i;
	for (i = 0;
	     (list != NULL) && (*list != NULL) && ((*list)[i] != NULL);
	     i++) {
		continue;
	}
	if (i > 0) {
		ret = malloc((i + 1) * sizeof(struct slapi_dn*));
		ret2 = malloc((i + 1) * sizeof(struct slapi_dn*));
		if ((ret != NULL) && (ret2 != NULL)) {
			for (i = 0;
			     (list2 != NULL) && (*list2 != NULL) && ((*list2)[i] != NULL);
			     i++) {
				ret[i] = slapi_sdn_dup((*list2)[i]);
				ret2[i] = ret[i];
			}
			ret[i] = NULL;
			ret2[i] = NULL;
			*list = ret;
			*list2 = ret2;
		} else {
			free(ret);
			free(ret2);
		}
	}
}

/* Build a list from string DN values. */
static struct slapi_dn **
format_make_sdn_list(char **list, struct slapi_dn ***ret,
		     struct slapi_dn ***ret2)
{
	unsigned int i;
	for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
		continue;
	}
	*ret = malloc((i + 1) * sizeof(struct slapi_dn*));
	*ret2 = malloc((i + 1) * sizeof(struct slapi_dn*));
	if ((*ret != NULL) && (*ret2 != NULL)) {
		for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
			(*ret)[i] = slapi_sdn_new_dn_byval(list[i]);
			(*ret2)[i] = (*ret)[i];
		}
		(*ret)[i] = NULL;
		(*ret2)[i] = NULL;
		qsort((*ret2), i, sizeof(**ret2), &compare_sdn);
	} else {
		free(*ret);
		*ret = NULL;
		free(*ret2);
		*ret2 = NULL;
	}
	return *ret;
}

/* Find the DN in a sorted list.  Return either where it is, or where it
 * should be inserted. */
static bool_t
format_bsearch_sdn_list(struct slapi_dn **list, struct slapi_dn *sdn,
			int len, unsigned int *point)
{
	int lo, mid, hi, result;
	bool_t found;

	if (len == -1) {
		for (len = 0; (list != NULL) && (list[len] != NULL); len++) {
			continue;
		}
	}
	if (len > 0) {
		lo = 0;
		hi = len - 1;
		for (;;) {
			mid = (lo + hi) / 2;
			result = slapi_sdn_compare(list[mid], sdn);
			if (result == 0) {
				found = TRUE;
				*point = mid;
				break;
			}
			if (lo == hi) {
				found = FALSE;
				if (result < 0) {
					*point = mid + 1;
				} else {
					*point = mid;
				}
				break;
			}
			if (result < 0) {
				lo = MIN(hi, mid + 1);
			} else {
				hi = MAX(lo, mid - 1);
			}
		}
	} else {
		found = FALSE;
		*point = 0;
	}
	return found;
}

void
format_add_sdn_list(struct slapi_dn ***list, struct slapi_dn ***list2,
		    const char *dn)
{
	struct slapi_dn **ret, **ret2, *sdn;
	unsigned int len, point;

	sdn = slapi_sdn_new_dn_byval(dn);
	/* Figure out the size of the list. */
	for (len = 0;
	     (list != NULL) && (*list != NULL) && ((*list)[len] != NULL);
	     len++) {
		continue;
	}
	/* Search the sorted list. */
	if (format_bsearch_sdn_list(*list2, sdn, len, &point)) {
		slapi_sdn_free(&sdn);
		return;
	}
	/* Append the entry to the unsorted list, insert it into the sorted
	 * list. */
	ret = malloc((len + 2) * sizeof(struct slapi_dn*));
	ret2 = malloc((len + 2) * sizeof(struct slapi_dn*));
	if ((ret != NULL) && (ret2 != NULL)) {
		/* Copy pointers to existing entries. */
		memcpy(ret, *list, len * sizeof(sdn));
		/* The new entry. */
		ret[len] = sdn;
		/* The end of the list. */
		ret[len + 1] = NULL;
		free(*list);
		/* Copy pointers to lesser entries. */
		if (point > 0) {
			memcpy(ret2, *list2, point * sizeof(sdn));
		}
		/* The new entry. */
		ret2[point] = sdn;
		/* The rest of the list. */
		if (len > point) {
			memcpy(ret2 + point + 1,
			       (*list2) + point,
			       (len - point) * sizeof(sdn));
		}
		ret2[len + 1] = NULL;
		free(*list2);
	}
	*list = ret;
	*list2 = ret2;
	return;
}

static int
format_check_entry(Slapi_PBlock *pb, const char *dn, char *filter,
		   void *identity)
{
	Slapi_DN *sdn;
	Slapi_Entry *entry;

	sdn = slapi_sdn_new_dn_byval(dn);
	wrap_search_internal_get_entry(pb, sdn, filter, NULL, &entry, identity);
	slapi_sdn_free(&sdn);
	if (entry != NULL) {
		slapi_entry_free(entry);
		return 0;
	} else {
		return ENOENT;
	}
}

static void
format_add_filtered_sdn_list(Slapi_PBlock *pb,
			     struct slapi_dn ***list, struct slapi_dn ***list2,
			     const char *dn, char *filter, void *identity)
{
	if (format_check_entry(pb, dn, filter, identity) == 0) {
		format_add_sdn_list(list, list2, dn);
	}
}

/* Maintain a reference attribute list, which is group of lists of attribute
 * names, filters, and search bases. */
void
format_free_ref_attr_list(struct format_ref_attr_list **list)
{
	struct format_ref_attr_list_link *link;
	unsigned int i;
	int j;
	if (list != NULL) {
		for (i = 0; list[i] != NULL; i++) {
			for (j = 0; j < list[i]->n_links; j++) {
				link = &list[i]->links[j];
				free(link->attribute);
				free(link->filter_str);
				if (link->filter != NULL) {
					slapi_filter_free(link->filter, TRUE);
				}
				format_free_sdn_list(link->base_sdn_list,
						     link->base_sdn_list2);
			}
			free(list[i]->links);
			free(list[i]->set);
			free(list[i]->group);
			free(list[i]);
		}
		free(list);
	}
}

struct format_ref_attr_list **
format_dup_ref_attr_list(struct format_ref_attr_list **list)
{
	struct format_ref_attr_list **ret;
	struct slapi_dn **sdn_list;
	unsigned int i;
	int j;
	for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
		continue;
	}
	ret = malloc((i + 1) * sizeof(struct format_ref_attr_list*));
	if (ret != NULL) {
		memset(ret, 0, (i + 1) * sizeof(struct format_ref_attr_list*));
		for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
			ret[i] = malloc(sizeof(*(list[i])));
			if (ret[i] == NULL) {
				format_free_ref_attr_list(ret);
				return NULL;
			}
			memset(ret[i], 0, sizeof(*(ret[i])));
			ret[i]->links = malloc(sizeof(*(ret[i]->links)) *
					       list[i]->n_links);
			if (ret[i]->links == NULL) {
				format_free_ref_attr_list(ret);
				return NULL;
			}
			memset(ret[i]->links, 0,
			       sizeof(*(ret[i]->links)) * list[i]->n_links);
			for (j = 0; j < list[i]->n_links; j++) {
				ret[i]->links[j].attribute =
					strdup(list[i]->links[j].attribute);
				if (ret[i]->links[j].attribute == NULL) {
					format_free_ref_attr_list(ret);
					return NULL;
				}
				if (list[i]->links[j].filter_str != NULL) {
					ret[i]->links[j].filter_str =
						strdup(list[i]->links[j].filter_str);
					if (ret[i]->links[j].filter_str == NULL) {
						format_free_ref_attr_list(ret);
						return NULL;
					}
				}
				if (list[i]->links[j].filter != NULL) {
					ret[i]->links[j].filter =
						slapi_filter_dup(list[i]->links[j].filter);
					if (ret[i]->links[j].filter == NULL) {
						format_free_ref_attr_list(ret);
						return NULL;
					}
				}
				sdn_list = list[i]->links[j].base_sdn_list;
				ret[i]->links[j].base_sdn_list = sdn_list;
				sdn_list = list[i]->links[j].base_sdn_list2;
				ret[i]->links[j].base_sdn_list2 = sdn_list;
				format_dup_sdn_list(&ret[i]->links[j].base_sdn_list,
						    &ret[i]->links[j].base_sdn_list2);
				ret[i]->n_links++;
			}
			ret[i]->group = strdup(list[i]->group);
			ret[i]->set = strdup(list[i]->set);
		}
		ret[i] = NULL;
	}
	return ret;
}

static struct format_ref_attr_list *
format_find_ref_attr_list(struct format_ref_attr_list **list,
			  const char *group, const char *set,
			  const char **names, const char **filters)
{
	struct format_ref_attr_list *item;
	struct format_ref_attr_list_link *link;
	unsigned int i;
	int j;
	for (i = 0; (list != NULL) && (list[i] != NULL); i++) {
		item = list[i];
		for (j = 0; names[j] != NULL; j++) {
			if (j < item->n_links) {
				link = &item->links[j];
				if (strcmp(names[j], link->attribute) != 0) {
					break;
				}
				if (j < item->n_links - 1) {
					if (((filters == NULL) ||
					     (filters[j] == NULL)) &&
					    (link->filter_str != NULL)) {
						break;
					}
					if ((filters != NULL) &&
					    (filters[j] != NULL) &&
					    (link->filter_str == NULL)) {
						break;
					}
					if ((filters != NULL) &&
					    (filters[j] != NULL) &&
					    (link->filter_str != NULL) &&
					    (strcmp(filters[j],
						    link->filter_str) != 0)) {
						break;
					}
				}
			}
		}
		if ((j == item->n_links) && (names[j] == NULL)) {
			return item;
		}
	}
	return NULL;
}

static struct format_ref_attr_list **
format_add_ref_attr_list(struct format_ref_attr_list ***list,
			 const char *group, const char *set,
			 const char **names, const char **filters)
{
	struct format_ref_attr_list **ret;
	char *ftmp;
	unsigned int i;
	int j;
	if (format_find_ref_attr_list(*list, group, set,
				      names, filters) != NULL) {
		return *list;
	}
	for (i = 0; (*list != NULL) && ((*list)[i] != NULL); i++) {
		continue;
	}
	ret = malloc((i + 2) * sizeof(struct format_ref_attr_list*));
	if (ret != NULL) {
		memcpy(ret, *list, i * sizeof(struct format_ref_attr_list*));
		free(*list);
		*list = NULL;
		ret[i] = malloc(sizeof(*(ret[i])));
		if (ret[i] == NULL) {
			format_free_ref_attr_list(ret);
			return NULL;
		}
		memset(ret[i], 0, sizeof(*(ret[i])));
		for (j = 0; names[j] != NULL; j++) {
			continue;
		}
		ret[i]->links = malloc(sizeof(*(ret[i]->links)) * j);
		if (ret[i]->links == NULL) {
			format_free_ref_attr_list(ret);
			return NULL;
		}
		memset(ret[i]->links, 0, sizeof(*(ret[i]->links)) * j);
		ret[i]->n_links = j;
		for (j = 0; j < ret[i]->n_links; j++) {
			ret[i]->links[j].attribute = strdup(names[j]);
			if (ret[i]->links[j].attribute == NULL) {
				format_free_ref_attr_list(ret);
				return NULL;
			}
			if ((filters != NULL) && (filters[j] != NULL)) {
				ftmp = strdup(filters[j]);
				if (ftmp == NULL) {
					format_free_ref_attr_list(ret);
					return NULL;
				}
				ret[i]->links[j].filter_str = strdup(ftmp);
				if (ret[i]->links[j].filter_str == NULL) {
					format_free_ref_attr_list(ret);
					return NULL;
				}
				ret[i]->links[j].filter = slapi_str2filter(ftmp);
				free(ftmp);
				if (ret[i]->links[j].filter == NULL) {
					format_free_ref_attr_list(ret);
					return NULL;
				}
			}
			ret[i]->links[j].base_sdn_list = NULL;
			ret[i]->links[j].base_sdn_list2 = NULL;
		}
		ret[i]->group = strdup(group);
		ret[i]->set = strdup(set);
		i++;
		ret[i] = NULL;
		*list = ret;
	}
	return ret;
}

/* Maintain an attribute list, which is really just a string list.  Entries
 * named by an attribute in the list carry "interesting" information. */
char **
format_dup_attr_list(char **attr_list)
{
	return backend_shr_dup_strlist(attr_list);
}

void
format_free_attr_list(char **attr_list)
{
	return backend_shr_free_strlist(attr_list);
}

void
format_add_attrlist(char ***attrlist, const char *attribute)
{
	backend_shr_add_strlist(attrlist, attribute);
}

/* Maintain an inref attribute list, which tracks a group and set name and an
 * attribute.  If an entry in the group and set contains this entry's name in
 * the named attribute, then it's "interesting". */
struct format_inref_attr **
format_dup_inref_attrs(struct format_inref_attr **attrs)
{
	int i, j, elements;
	struct format_inref_attr **ret;

	elements = 0;
	ret = NULL;
	if (attrs != NULL) {
		for (i = 0; attrs[i] != NULL; i++) {
			continue;
		}
		elements = i;
		ret = malloc(sizeof(*ret) * (elements + 1));
		if (ret != NULL) {
			for (i = 0, j = 0; i < elements; i++) {
				ret[j] = malloc(sizeof(**attrs));
				if (ret[j] != NULL) {
					ret[j]->group =
						strdup(attrs[i]->group);
					ret[j]->set = strdup(attrs[i]->set);
					ret[j]->attribute =
						strdup(attrs[i]->attribute);
					if ((ret[j]->group != NULL) &&
					    (ret[j]->set != NULL) &&
					    (ret[j]->attribute != NULL)) {
						j++;
					}
				}
			}
			ret[j] = NULL;
		}
	}
	return ret;
}

void
format_add_inref_attrs(struct format_inref_attr ***attrs,
		       const char *group, const char *set,
		       const char *attribute)
{
	struct format_inref_attr **ret;
	int i, elements;
	elements = 0;
	ret = NULL;
	if (*attrs != NULL) {
		for (i = 0; (*attrs)[i] != NULL; i++) {
			if ((strcmp((*attrs)[i]->group, group) == 0) &&
			    (strcmp((*attrs)[i]->set, set) == 0) &&
			    (strcmp((*attrs)[i]->attribute, attribute) == 0)) {
				return;
			}
		}
		elements = i;
	}
	ret = malloc(sizeof(*ret) * (elements + 2));
	if (ret != NULL) {
		if (elements > 0) {
			memcpy(ret, *attrs, elements * sizeof(**attrs));
		}
		ret[elements] = malloc(sizeof(**ret));
		if (ret[elements] != NULL) {
			ret[elements]->group = strdup(group);
			ret[elements]->set = strdup(set);
			ret[elements]->attribute = strdup(attribute);
			ret[elements + 1] = NULL;
		}
		free(*attrs);
		*attrs = ret;
	}
}

void
format_free_inref_attrs(struct format_inref_attr **attrs)
{
	int i;
	if (attrs != NULL) {
		for (i = 0; attrs[i] != NULL; i++) {
			free(attrs[i]->group);
			free(attrs[i]->set);
			free(attrs[i]->attribute);
			free(attrs[i]);
		}
		free(attrs);
	}
}

/* Maintain berval lists. */
static int
format_count_bv_list(struct berval **bvlist)
{
	int i;
	if (bvlist != NULL) {
		for (i = 0; bvlist[i] != NULL; i++) {
			continue;
		}
		return i;
	}
	return 0;
}
static void
format_free_bv_list(struct berval **bvlist)
{
	int i;
	if (bvlist != NULL) {
		for (i = 0; bvlist[i] != NULL; i++) {
			free(bvlist[i]->bv_val);
			free(bvlist[i]);
		}
		free(bvlist);
	}
}
static struct berval **
format_dup_bv_list(struct berval **bvlist)
{
	struct berval **ret, *bv;
	int i;
	ret = NULL;
	if (bvlist != NULL) {
		for (i = 0; bvlist[i] != NULL; i++) {
			continue;
		}
		if (i == 0) {
			return NULL;
		}
		ret = malloc((i + 1) * sizeof(struct berval *));
		if (ret != NULL) {
			for (i = 0; bvlist[i] != NULL; i++) {
				ret[i] = malloc(sizeof(struct berval));
				if (ret[i] != NULL) {
					bv = bvlist[i];
					ret[i]->bv_val = xmemdup(bv->bv_val,
								 bv->bv_len);
					ret[i]->bv_len = bv->bv_len;
				}
			}
			ret[i] = NULL;
		}
	}
	return ret;
}
static void
format_add_bv_list(struct berval ***bvlist, const struct berval *bv)
{
	struct berval **list;
	int i;
	if (bvlist == NULL) {
		return;
	}
	for (i = 0; (*bvlist != NULL) && ((*bvlist)[i] != NULL); i++) {
		continue;
	}
	list = malloc((i + 2) * sizeof(struct berval *));
	if (list != NULL) {
		if (i > 0) {
			memcpy(list, *bvlist, i * sizeof(struct berval *));
		}
		list[i] = malloc(sizeof(struct berval));
		if (list[i] != NULL) {
			list[i]->bv_val = xmemdup(bv->bv_val, bv->bv_len);
			if (list[i]->bv_val != NULL) {
				list[i]->bv_len = bv->bv_len;
				list[i + 1] = NULL;
				free(*bvlist);
				*bvlist = list;
			} else {
				free(list[i]);
				free(list);
				format_free_bv_list(*bvlist);
				*bvlist = NULL;
			}
		} else {
			free(list);
			format_free_bv_list(*bvlist);
			*bvlist = NULL;
		}
	} else {
		format_free_bv_list(*bvlist);
		*bvlist = NULL;
	}
}

/* Maintain "choices" lists. */
static void
format_retarget_choicesp(struct format_choice **choices, char *oldt, char *newt)
{
	struct format_choice *this_choice;
	int offset;
	if (choices != NULL) {
		for (this_choice = *choices;
		     this_choice != NULL;
		     this_choice = this_choice->next) {
			offset = this_choice->offset - oldt;
			this_choice->offset = newt + offset;
		}
	}
}
static void
format_free_choices(struct format_choice *choices)
{
	struct format_choice *next;
	while (choices != NULL) {
		next = choices->next;
		format_free_bv_list(choices->values);
		free(choices);
		choices = next;
	}
}
static void
format_free_choicesp(struct format_choice **choices)
{
	if (choices) {
		format_free_choices(*choices);
		*choices = NULL;
	}
}
static void
format_append_choice(struct format_choice **choices,
		     struct format_choice *choice)
{
	struct format_choice *here;
	if (choices == NULL) {
		return;
	}
	if (*choices == NULL) {
		*choices = choice;
	} else {
		here = *choices;
		while (here->next != NULL) {
			here = here->next;
		}
		choice->next = here->next;
		here->next = choice;
	}
}
static void
format_add_choice(struct format_choice **choices, char *offset,
		  struct berval ***values)
{
	struct format_choice *choice;
	int i;
	if ((values != NULL) && (*values != NULL)) {
		choice = malloc(sizeof(*choice));
		if (choice != NULL) {
			choice->offset = offset;
			choice->next = NULL;
			for (i = 0; (*values)[i] != NULL; i++) {
				continue;
			}
			choice->n_values = i;
			choice->values = *values;
			*values = NULL;
			if (choice->values != NULL) {
				format_append_choice(choices, choice);
			} else {
				free(choice);
			}
		}
	}
}

/* Convert a strlist to a berval list. */
static struct berval **
format_strlist_to_bv_list(char **values)
{
	struct berval **val;
	int i;
	char *p;
	if (values != NULL) {
		for (i = 0; values[i] != NULL; i++) {
			continue;
		}
		val = malloc(sizeof(struct berval *) * (i + 1));
		if (val != NULL) {
			for (i = 0; values[i] != NULL; i++) {
				val[i] = malloc(sizeof(struct berval));
				if (val[i] != NULL) {
					p = values[i];
					val[i]->bv_val = xmemdup(p, strlen(p));
					if (val[i] != NULL) {
						val[i]->bv_len = strlen(p);
					}
				}
			}
			val[i] = NULL;
			return val;
		}
	}
	return NULL;
}
static void
format_add_choice_str(struct format_choice **choices, char *offset,
		      char **values)
{
	struct berval **vals;
	vals = format_strlist_to_bv_list(values);
	format_add_choice(choices, offset, &vals);
}

/* Parse an argument string into an array of arguments. */
static void
format_free_parsed_args(char **argv)
{
	free(argv);
}
static int
format_parse_args(struct plugin_state *state, const char *args,
		  int *pargc, char ***pargv)
{
	int i, dq, argc;
	char *out, **argv;
	*pargc = 0;
	*pargv = NULL;
	argv = malloc((sizeof(char *) + 1) * (strlen(args) + 1));
	if (argv == NULL) {
		return -1;
	}
	memset(argv, 0, (sizeof(char *) + 1) * (strlen(args) + 1));
	out = (char *) argv;
	out += sizeof(char *) * (strlen(args) + 1);
	argc = 0;
	i = 0;
	dq = 0;
	while (args[i] != '\0') {
		switch (args[i]) {
		case '"':
			dq = !dq;
			if (dq) {
				argv[argc++] = out;
			} else {
				*out++ = '\0';
			}
			i++;
			break;
		case '\\':
			i++;
			/* fall through */
		default:
			*out++ = args[i++];
			break;
		}
	}
	argv[argc] = NULL;
	*out = '\0';
	out = malloc((argc * 3) + strlen(args));
	if (out != NULL) {
		*out = '\0';
		for (i = 0; i < argc; i++) {
			if (i > 0) {
				strcat(out, ",");
			}
			strcat(out, "'");
			strcat(out, argv[i]);
			strcat(out, "'");
		}
		free(out);
	}
	*pargc = argc;
	*pargv = argv;
	return 0;
}

/* Choose the first value of the set of results for the first argument, and if
 * we get no results, return the second argument. */
static int
format_first(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	     const char *group, const char *set,
	     const char *args, const char *disallowed,
	     char *outbuf, int outbuf_len,
	     struct format_choice **outbuf_choices,
	     char ***rel_attrs,
	     char ***ref_attrs, struct format_inref_attr ***inref_attrs,
	     struct format_ref_attr_list ***ref_attr_list,
	     struct format_ref_attr_list ***inref_attr_list)
{
	int ret, i, argc, first, common_length;
	char **argv, **values;
	const char *value_format, *default_value;
	unsigned int *lengths;
	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"first: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"first: error parsing arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (argc < 2) {
		value_format = argv[0];
		default_value = NULL;
	} else {
		value_format = argv[0];
		default_value = argv[1];
	}
	ret = -ENOENT;
	values = format_get_data_set(state, pb, e, group, set,
				     value_format, disallowed,
				     rel_attrs, ref_attrs, inref_attrs,
				     ref_attr_list, inref_attr_list,
				     &lengths);
	if (values == NULL) {
		if (default_value == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"first: no values for ->%s<-, "
					"and no default value provided\n",
					value_format);
			ret = -ENOENT;
		} else {
			i = format_expand(state, pb, e,
					  group, set,
					  default_value, NULL,
					  outbuf, outbuf_len,
					  outbuf_choices,
					  rel_attrs, ref_attrs, inref_attrs,
					  ref_attr_list, inref_attr_list);
			ret = i;
		}
	} else {
		first = 0;
		for (i = 1; values[i] != NULL; i++) {
			/* Check if this entry sorts "earlier" than the current
			 * "first" entry.  If it does, note its position as the
			 * "first". */
			common_length = lengths[first] < lengths[i] ?
					lengths[first] : lengths[i];
			ret = memcmp(values[i], values[first], common_length);
			if ((ret < 0) ||
			    ((ret == 0) && (lengths[i] < lengths[first]))) {
				first = i;
			}
		}
		if ((int) lengths[first] > outbuf_len) {
			ret = -ENOBUFS;
		} else {
			memcpy(outbuf, values[first], lengths[first]);
			ret = lengths[first];
		}
		format_free_data_set(values, lengths);
	}
	format_free_parsed_args(argv);
	return ret;
}

/* Look up the entries matching DNs stored in the attribute named by the first
 * argument, pull out the values for the attribute named by the second
 * argument, and return a list of those values. */
static int
format_deref_x(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	       const char *fname, const char *group, const char *set,
	       char *ref_attr, char *target_attr,
	       char *filter, const char *disallowed,
	       char *outbuf, int outbuf_len,
	       struct format_choice **outbuf_choices,
	       char ***rel_attrs,
	       char ***ref_attrs, struct format_inref_attr ***inref_attrs,
	       struct format_ref_attr_list ***ref_attr_list,
	       struct format_ref_attr_list ***inref_attr_list)
{
	int i, j;
	Slapi_Entry *ref;
	Slapi_DN *refdn;
	Slapi_ValueSet *ref_values, *values;
	Slapi_Value *ref_value, *value;
	int disposition, ref_disposition, buffer_flags, ref_buffer_flags;
	char *attrs[2], *actual_attr, *actual_ref_attr;
	const char *cref;
	const struct berval *val;
	struct berval **choices;
	/* Note that this map cares about this attribute. */
	if (rel_attrs != NULL) {
		format_add_attrlist(rel_attrs, ref_attr);
	}
	/* Note that the attribute in this entry refers to other entries. */
	if (ref_attrs != NULL) {
		format_add_attrlist(ref_attrs, ref_attr);
	}
	/* Get the values of the reference attribute from this entry. */
	if (slapi_vattr_values_get(e, ref_attr, &ref_values,
				   &ref_disposition, &actual_ref_attr,
				   0, &ref_buffer_flags) != 0) {
		/* No references means we're done, no answers to give. */
		return -ENOENT;
	}
	/* Retrieve these attributes from the referred-to entries. */
	attrs[0] = target_attr;
	attrs[1] = NULL;
	/* Iterate through the names of the referred-to entries. */
	choices = NULL;
	for (i = slapi_valueset_first_value(ref_values, &ref_value);
	     i != -1;
	     i = slapi_valueset_next_value(ref_values, i, &ref_value)) {
		/* Pull up the referred-to entry. */
		cref = slapi_value_get_string(ref_value);
		if (cref == NULL) {
			continue;
		}
		refdn = slapi_sdn_new_dn_byval(cref);
		if (refdn == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"%s: internal error parsing name "
					"\"%s\"\n", fname, cref);
			continue;
		}
		wrap_search_internal_get_entry(pb, refdn, filter, attrs, &ref,
					       state->plugin_identity);
		if (ref == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"%s: failure reading entry \"%s\"\n",
					fname, slapi_sdn_get_ndn(refdn));
			slapi_sdn_free(&refdn);
			continue;
		}
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"%s: reading \"%s\" from \"%s\"\n",
				fname, target_attr, slapi_sdn_get_ndn(refdn));
		slapi_sdn_free(&refdn);
		/* Note that this map cares about this attribute. */
		if (rel_attrs != NULL) {
			format_add_attrlist(rel_attrs, target_attr);
		}
		/* Pull out the attribute from the referred-to entry. */
		if (slapi_vattr_values_get(ref, target_attr, &values,
					   &disposition, &actual_attr,
					   0, &buffer_flags) != 0) {
			slapi_entry_free(ref);
			continue;
		}
		for (j = slapi_valueset_first_value(values, &value);
		     j != -1;
		     j = slapi_valueset_next_value(values, j, &value)) {
			/* Get the value. */
			val = slapi_value_get_berval(value);
			/* If the value is empty, skip it. */
			if (val->bv_len == 0) {
				continue;
			}
			format_add_bv_list(&choices, val);
		}
		slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
		slapi_entry_free(ref);
	}
	slapi_vattr_values_free(&ref_values,
				&actual_ref_attr,
				ref_buffer_flags);
	/* Return any values we found. */
	if (choices != NULL) {
		format_add_choice(outbuf_choices, outbuf, &choices);
		return 0;
	} else {
		return -ENOENT;
	}
}

static int
format_deref(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	     const char *group, const char *set,
	     const char *args, const char *disallowed,
	     char *outbuf, int outbuf_len,
	     struct format_choice **outbuf_choices,
	     char ***rel_attrs,
	     char ***ref_attrs, struct format_inref_attr ***inref_attrs,
	     struct format_ref_attr_list ***ref_attr_list,
	     struct format_ref_attr_list ***inref_attr_list)
{
	int argc, ret;
	char **argv, *ref_attr, *target_attr;
	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc != 2) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref: requires two arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref: returns a list, but a list "
				"would not be appropriate\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	ref_attr = argv[0];
	target_attr = argv[1];
	ret = format_deref_x(state, pb, e, "deref", group, set,
			     ref_attr, target_attr, NULL, disallowed,
			     outbuf, outbuf_len, outbuf_choices,
			     rel_attrs, ref_attrs, inref_attrs,
			     ref_attr_list, inref_attr_list);
	format_free_parsed_args(argv);
	return ret;
}

static int
format_deref_f(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	       const char *group, const char *set,
	       const char *args, const char *disallowed,
	       char *outbuf, int outbuf_len,
	       struct format_choice **outbuf_choices,
	       char ***rel_attrs, char ***ref_attrs,
	       struct format_inref_attr ***inref_attrs,
	       struct format_ref_attr_list ***ref_attr_list,
	       struct format_ref_attr_list ***inref_attr_list)
{
	int argc, ret;
	char **argv, *ref_attr, *filter, *target_attr;
	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_f: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc != 3) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_f: requires three arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_f: returns a list, but a list "
				"would not be appropriate\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	ref_attr = argv[0];
	filter = argv[1];
	target_attr = argv[2];
	ret = format_deref_x(state, pb, e, "deref_f", group, set,
			     ref_attr, target_attr, filter, disallowed,
			     outbuf, outbuf_len, outbuf_choices,
			     rel_attrs, ref_attrs, inref_attrs,
			     ref_attr_list, inref_attr_list);
	format_free_parsed_args(argv);
	return ret;
}

/* For the first N-1 arguments, look up the entries matching DNs stored in the
 * attribute named by the argument, following the chain of named entries, and
 * at last, pull out the values for the attribute named by the last argument,
 * and return a list of those values. */
static int
format_deref_rx(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
		const char *fname, const char *group, const char *set,
		const char **attributes, const char **filters,
		const char *disallowed,
		char *outbuf, int outbuf_len,
		struct format_choice **outbuf_choices,
		char ***rel_attrs, char ***ref_attrs,
		struct format_inref_attr ***inref_attrs,
		struct format_ref_attr_list ***ref_attr_list,
		struct format_ref_attr_list ***inref_attr_list)
{
	int i, j, k;
	Slapi_Entry *entry;
	Slapi_DN **these, **these2, **next, **next2, *parent;
	Slapi_ValueSet *values;
	Slapi_Value *value;
	int disposition, buffer_flags;
	char *attrs[2], *actual_attr;
	const char *dn, *cvalue;
	const struct berval *bval;
	struct berval **choices;
	struct format_ref_attr_list *list;

	/* Note that this map cares about all of these attributes. */
	if ((rel_attrs != NULL) && (attributes != NULL)) {
		for (i = 0; attributes[i] != NULL; i++) {
			format_add_attrlist(rel_attrs, attributes[i]);
		}
	}

	/* Note that this list of attributes is used for pulling up data. */
	format_add_ref_attr_list(ref_attr_list, group, set,
				 attributes, filters);
	list = format_find_ref_attr_list(*ref_attr_list, group, set,
					 attributes, filters);

	/* Follow the chain: set up the first link. */
	these = NULL;
	these2 = NULL;
	choices = NULL;
	dn = slapi_entry_get_dn(e);
	format_add_sdn_list(&these, &these2, dn);
	parent = slapi_sdn_new();

	/* For the first N-1 links, read the contents of the named attribute
	 * from each entry we're examining at this point, and use the values
	 * to build a list of entries to visit the next time.  For the last
	 * link, pull the values out and prep them to be returned to our
	 * caller. */
	for (i = 0; (these != NULL) && (i < list->n_links); i++) {
		next = NULL;
		next2 = NULL;
		attrs[0] = list->links[i].attribute;
		attrs[1] = NULL;
		/* Walk the set of entries for this iteration. */
		for (j = 0; these[j] != NULL; j++) {
			/* For heuristic use later, note the parent of the
			 * entry from which we're reading this attribute. */
			dn = slapi_sdn_get_ndn(these[j]);
			slapi_sdn_get_parent(these[j], parent);
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"%s: noting parent "
					"\"%s\" for \"%s\"\n",
					fname, slapi_sdn_get_ndn(parent),
					attrs[0]);
			format_add_sdn_list(&list->links[i].base_sdn_list,
					    &list->links[i].base_sdn_list2,
					    slapi_sdn_get_ndn(parent));
			/* Pull up the named entry. */
			wrap_search_internal_get_entry(pb, these[j],
						       NULL,
						       attrs, &entry,
						       state->plugin_identity);
			if (entry == NULL) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"%s: error reading entry "
						"\"%s\"\n", fname,
						slapi_sdn_get_dn(these[j]));
				continue;
			} else {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"%s: reading entry "
						"\"%s\" (%d)\n", fname,
						slapi_sdn_get_dn(these[j]), i);
			}
			/* Pull up the value set. */
			if (slapi_vattr_values_get(entry, attrs[0], &values,
						   &disposition,
						   &actual_attr,
						   0, &buffer_flags) != 0) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"%s: entry \"%s\" has no "
						"values for \"%s\"\n", fname,
						slapi_entry_get_dn(entry),
						attrs[0]);
				slapi_entry_free(entry);
				continue;
			}
			for (k = slapi_valueset_first_value(values, &value);
			     k != -1;
			     k = slapi_valueset_next_value(values, k, &value)){
				if (i < list->n_links - 1) {
					/* Get the text. */
					cvalue = slapi_value_get_string(value);
					/* If the value is empty, skip it. */
					if (cvalue == NULL) {
						continue;
					}
					/* Let's visit the named entry this
					 * time, in case we're nesting. */
					format_add_filtered_sdn_list(pb, &these, &these2,
								     cvalue,
								     list->links[i + 1].filter_str,
								     state->plugin_identity);
					/* We need to visit the named entry
					 * next time. */
					format_add_filtered_sdn_list(pb, &next, &next2,
								     cvalue,
								     list->links[i + 1].filter_str,
								     state->plugin_identity);
				} else {
					/* Get the value. */
					bval = slapi_value_get_berval(value);
					/* If the value is empty, skip it. */
					if (bval->bv_len == 0) {
						continue;
					}
					format_add_bv_list(&choices, bval);
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"%s: found value "
							"\"%.*s\" in \"%s\"\n",
							fname,
							(int) bval->bv_len,
							bval->bv_val,
							dn);
				}
			}
			slapi_vattr_values_free(&values, &actual_attr,
						buffer_flags);
			slapi_entry_free(entry);
		}
		/* Replace the list of entries we're examining now with the
		 * list of entries we need to examine next. */
		format_free_sdn_list(these, these2);
		these = next;
		these2 = next2;
		next = NULL;
		next2 = NULL;
	}

	/* Clean up and return any values we found. */
	slapi_sdn_free(&parent);
	format_free_sdn_list(these, these2);
	if (choices != NULL) {
		format_add_choice(outbuf_choices, outbuf, &choices);
		return 0;
	} else {
		return -ENOENT;
	}
}

static int
format_deref_r(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	       const char *group, const char *set,
	       const char *args, const char *disallowed,
	       char *outbuf, int outbuf_len,
	       struct format_choice **outbuf_choices,
	       char ***rel_attrs,
	       char ***ref_attrs, struct format_inref_attr ***inref_attrs,
	       struct format_ref_attr_list ***ref_attr_list,
	       struct format_ref_attr_list ***inref_attr_list)
{
	int ret, argc;
	char **argv;
	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_r: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 2) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_r: requires at least two arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_r: returns a list, but a list "
				"would not be appropriate\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	ret = format_deref_rx(state, pb, e, "deref_r",
			      group, set,
			      (const char **) argv, NULL,
			      disallowed,
			      outbuf, outbuf_len,
			      outbuf_choices,
			      rel_attrs, ref_attrs, inref_attrs,
			      ref_attr_list, inref_attr_list);
	format_free_parsed_args(argv);
	return ret;
}

static int
format_deref_rf(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
		const char *group, const char *set,
		const char *args, const char *disallowed,
		char *outbuf, int outbuf_len,
		struct format_choice **outbuf_choices,
		char ***rel_attrs,
		char ***ref_attrs, struct format_inref_attr ***inref_attrs,
		struct format_ref_attr_list ***ref_attr_list,
		struct format_ref_attr_list ***inref_attr_list)
{
	int ret, argc, n, i;
	char **argv, **attrs, **filters;
	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_rf: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 3) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_rf: requires at least three "
				"arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_rf: returns a list, but a list "
				"would not be appropriate\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	/* Build the lists of attributes and filters. */
	n = (argc + 1) / 2;
	attrs = malloc(sizeof(char *) * (n + 1));
	if (attrs == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_rf: out of memory\n");
		format_free_parsed_args(argv);
		return -ENOMEM;
	}
	memset(attrs, 0, sizeof(char *) * (n + 1));
	filters = malloc(sizeof(char *) * (n + 1));
	if (filters == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"deref_rf: out of memory\n");
		free(attrs);
		format_free_parsed_args(argv);
		return -ENOMEM;
	}
	memset(filters, 0, sizeof(char *) * (n + 1));
	for (i = 0; i < n; i++) {
		attrs[i] = argv[i * 2];
		if (i < (n - 1)) {
			filters[i + 1] = argv[i * 2 + 1];
		}
	}
	ret = format_deref_rx(state, pb, e, "deref_rf",
			      group, set,
			      (const char **) attrs, (const char **) filters,
			      disallowed,
			      outbuf, outbuf_len,
			      outbuf_choices,
			      rel_attrs, ref_attrs, inref_attrs,
			      ref_attr_list, inref_attr_list);
	free(filters);
	free(attrs);
	format_free_parsed_args(argv);
	return ret;
}

/* Look up entries in the set named by the first argument, which have this
 * entry's DN stored in the attribute named by the second argument, pull out
 * the values for the attribute named by the third argument, and return a list
 * of those values. */
struct format_referred_cbdata {
	struct plugin_state *state;
	char *attr;
	struct berval **choices;
};
static int
format_referred_entry_cb(Slapi_Entry *e, void *callback_data)
{
	Slapi_ValueSet *values;
	Slapi_Value *value;
	int i, disposition, buffer_flags;
	char *actual_attr;
	const struct berval *val;
	struct format_referred_cbdata *cbdata;

	cbdata = callback_data;

	slapi_log_error(SLAPI_LOG_PLUGIN,
			cbdata->state->plugin_desc->spd_id,
			"referred: examining \"%s\" in \%s\"\n",
			cbdata->attr, slapi_entry_get_ndn(e));

	/* Iterate through the values for the specified attribute. */
	if (slapi_vattr_values_get(e, cbdata->attr, &values,
				   &disposition, &actual_attr,
				   0, &buffer_flags) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"referred: no values for \"%s\" in \"%s\"\n",
				cbdata->attr, slapi_entry_get_ndn(e));
		return 0;
	}
	for (i = slapi_valueset_first_value(values, &value);
	     i != -1;
	     i = slapi_valueset_next_value(values, i, &value)) {
		/* Pull up the value. */
		val = slapi_value_get_berval(value);
		if (val->bv_len == 0) {
			continue;
		}
		slapi_log_error(SLAPI_LOG_PLUGIN,
				cbdata->state->plugin_desc->spd_id,
				"referred: got %d-byte value for \"%s\"\n",
				(int) val->bv_len, actual_attr);
		/* Add it to the list of values we've retrieved. */
		format_add_bv_list(&cbdata->choices, val);
	}
	slapi_vattr_values_free(&values, &actual_attr, buffer_flags);
	return 0;
}
static int
format_referred(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
		const char *group, const char *set,
		const char *args, const char *disallowed,
		char *outbuf, int outbuf_len,
		struct format_choice **outbuf_choices,
		char ***rel_attrs, char ***ref_attrs,
		struct format_inref_attr ***inref_attrs,
		struct format_ref_attr_list ***ref_attr_list,
		struct format_ref_attr_list ***inref_attr_list)
{
	int i, ret, argc;
	Slapi_PBlock *local_pb;
	char **argv, *attrs[2], *filter, *tndn, *attr, *other_attr;
	char *other_set, *set_filter, **set_bases, *use_filter;
	struct format_referred_cbdata cbdata;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc != 3) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred: requires 3 arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred: returns a list, but a list would "
				"not be appropriate here\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	other_set = argv[0];
	other_attr = argv[1];
	attr = argv[2];

	/* Set up to search for matches. */
	cbdata.state = state;
	cbdata.attr = attr;
	cbdata.choices = NULL;

	/* Retrieve the set-specific paramaters to determine which entries to
	 * examine. */
	set_filter = NULL;
	set_bases = NULL;
	backend_get_set_config(pb, state, group, other_set,
			       &set_bases, &set_filter);
	if (set_bases == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"no search bases defined for \"%s\"/\"%s\"?\n",
				group, other_set);
		backend_free_set_config(set_bases, set_filter);
		format_free_parsed_args(argv);
		return -ENOENT;
	}

	/* Note that this map cares both attributes. */
	if (rel_attrs != NULL) {
		format_add_attrlist(rel_attrs, other_attr);
		format_add_attrlist(rel_attrs, attr);
	}

	/* Note that the attribute in this map refers to this entry. */
	if (inref_attrs != NULL) {
		format_add_inref_attrs(inref_attrs, group,
				       other_set, other_attr);
	}

	/* Escape the current entry's DN in case it's necessary, and build a
	 * search filter. */
	tndn = format_escape_for_filter(slapi_entry_get_ndn(e));
	if (tndn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"referred: out of memory\n");
		backend_free_set_config(set_bases, set_filter);
		format_free_parsed_args(argv);
		return -ENOMEM;
	}
	use_filter = set_filter ? set_filter : "(objectClass=*)";
	filter = malloc(strlen(use_filter) + strlen(other_attr) +
			strlen(tndn) + 7);
	if (filter == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred: out of memory\n");
		free(tndn);
		backend_free_set_config(set_bases, set_filter);
		format_free_parsed_args(argv);
		return -ENOMEM;
	}
	sprintf(filter, "(&(%s=%s)%s)", other_attr, tndn, use_filter);
	free(tndn);

	/* Search through the entries used for the set. */
	attrs[0] = attr;
	attrs[1] = NULL;
	for (i = 0; (set_bases != NULL) && (set_bases[i] != NULL); i++) {
		/* Set up the search. */
		local_pb = wrap_pblock_new(pb);
		slapi_search_internal_set_pb(local_pb,
					     set_bases[i], LDAP_SCOPE_SUBTREE,
					     filter, attrs, FALSE,
					     NULL, NULL,
					     state->plugin_identity, 0);
		/* Let the callback do the work of saving a value. */
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"searching under \"%s\" for \"%s\"\n",
				set_bases[i], filter);
		slapi_search_internal_callback_pb(local_pb, &cbdata,
						  NULL,
						  format_referred_entry_cb,
						  NULL);
		slapi_pblock_destroy(local_pb);
	}
	free(filter);

	backend_free_set_config(set_bases, set_filter);
	format_free_parsed_args(argv);

	/* Return any values we found. */
	if (cbdata.choices != NULL) {
		format_add_choice(outbuf_choices, outbuf, &cbdata.choices);
		return 0;
	} else {
		return -ENOENT;
	}
}

/* Add the name of this entry to the DN list in the cbdata. */
struct format_referred_r_entry_cbdata {
	struct plugin_state *state;
	char *attribute;
	struct berval ***choices;
	Slapi_DN ***sdn_list, ***sdn_list2;
};

static int
format_referred_r_entry_cb(Slapi_Entry *e, void *cbdata_ptr)
{
	struct format_referred_r_entry_cbdata *cbdata = cbdata_ptr;
	const struct berval *bval;
	Slapi_DN *sdn;
	Slapi_ValueSet *values;
	Slapi_Value *value;
	int i, disposition, buffer_flags;
	char *actual_attr;

	/* Note that we visited this entry. */
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata->state->plugin_desc->spd_id,
			"search matched entry \"%s\"\n", slapi_entry_get_dn(e));
	format_add_sdn_list(cbdata->sdn_list, cbdata->sdn_list2,
			    slapi_entry_get_dn(e));
	sdn = slapi_entry_get_sdn(e);

	/* If we're also being asked to pull values out of the entry... */
	if ((cbdata->attribute != NULL) && (cbdata->choices != NULL)) {
		/* Pull up the value set. */
		if (slapi_vattr_values_get(e, cbdata->attribute, &values,
					   &disposition,
					   &actual_attr,
					   0, &buffer_flags) != 0) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					cbdata->state->plugin_desc->spd_id,
					"referred_r: entry \"%s\" has no "
					"values for \"%s\"\n",
					slapi_sdn_get_dn(sdn),
					cbdata->attribute);
		} else {
			/* Walk the value set. */
			for (i = slapi_valueset_first_value(values, &value);
			     i != -1;
			     i = slapi_valueset_next_value(values, i, &value)){
				/* Get the value. */
				bval = slapi_value_get_berval(value);
				/* If the value is empty, skip it. */
				if (bval->bv_len == 0) {
					continue;
				}
				format_add_bv_list(cbdata->choices, bval);
				slapi_log_error(SLAPI_LOG_PLUGIN,
						cbdata->state->plugin_desc->spd_id,
						"referred_r: found value "
						"\"%.*s\" in \"%s\"\n",
						(int) bval->bv_len,
						bval->bv_val,
						slapi_sdn_get_dn(sdn));
			}
			slapi_vattr_values_free(&values, &actual_attr,
						buffer_flags);
		}
	}
	return 0;
}

/* For the first N-1 arguments, treat them as pairs, looking entries in the
 * map named by the first part of the pair which refer to this entry using the
 * attribute named by the second part in the pair, following links until we
 * get to the last argument, at which point we return the value of the
 * attribute named by the final argument. */
static int
format_referred_r(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
		  const char *group, const char *set,
		  const char *args, const char *disallowed,
		  char *outbuf, int outbuf_len,
		  struct format_choice **outbuf_choices,
		  char ***rel_attrs,
		  char ***ref_attrs, struct format_inref_attr ***inref_attrs,
		  struct format_ref_attr_list ***ref_attr_list,
		  struct format_ref_attr_list ***inref_attr_list)
{
	int i, j, k, ret, argc, attrs_list_length;
	Slapi_PBlock *local_pb;
	Slapi_DN **these_bases, **next_bases, **these_entries, **next_entries;
	Slapi_DN **these_entries2, **next_entries2;
	struct berval **choices;
	struct format_referred_r_entry_cbdata entry_cbdata;
	struct format_ref_attr_list *list;
	char **argv, *attrs[2], *filter, *tndn, *attr;
	char *set_filter, **set_bases;
	const char **attr_links, *ndn;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred_r: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 3) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred_r: requires at least 3 arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if ((argc % 2) != 1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred_r: requires an odd number of "
				"arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred_r: returns a list, but a list would "
				"not be appropriate here\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	attr = argv[argc - 1];

	/* Build the list of attributes which we can use to select the list of
	 * references. */
	attrs_list_length = (argc + 1) / 2;
	attr_links = malloc((attrs_list_length + 1) * sizeof(char *));
	if (attr_links == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"referred_r: out of memory\n");
		format_free_parsed_args(argv);
		return -ENOMEM;
	}
	for (i = 0; i < attrs_list_length; i++) {
		if (i < (attrs_list_length - 1)) {
			attr_links[i] = argv[i * 2 + 1];
		} else {
			attr_links[i] = argv[i * 2];
		}
	}
	attr_links[i] = NULL;

	/* Note that this map cares about these attributes. */
	if (rel_attrs != NULL) {
		format_add_attrlist(rel_attrs, attr);
		for (i = 0; attr_links[i] != NULL; i++) {
			format_add_attrlist(rel_attrs, attr_links[i]);
		}
	}

	/* Note this list of attributes. */
	format_add_ref_attr_list(inref_attr_list, group, set, attr_links, NULL);
	list = format_find_ref_attr_list(*inref_attr_list, group, set,
					 attr_links, NULL);
	free(attr_links);

	/* Get the searching parameters for the set which contains the entry,
	 * and all of the referred-to sets, and save them for use at the last
	 * link in the chain. */
	backend_get_set_config(pb, state, group, set,
			       &set_bases, &set_filter);
	for (i = 0; (set_bases != NULL) && (set_bases[i] != NULL); i++) {
		format_add_sdn_list(&(list->links[0].base_sdn_list),
				    &(list->links[0].base_sdn_list2),
				    set_bases[i]);
	}
	backend_free_set_config(set_bases, set_filter);
	for (i = 0; i < list->n_links - 1; i++) {
		backend_get_set_config(pb, state, group, argv[i * 2],
				       &set_bases, &set_filter);
		for (j = 0;
		     (set_bases != NULL) && (set_bases[j] != NULL);
		     j++) {
			format_add_sdn_list(&(list->links[i + 1].base_sdn_list),
					    &(list->links[i + 1].base_sdn_list2),
					    set_bases[j]);
		}
		backend_free_set_config(set_bases, set_filter);
	}

	/* Walk the chain, searching for entries which refer to entries at
	 * this point in the chain. */
	these_entries = NULL;
	these_entries2 = NULL;
	format_add_sdn_list(&these_entries, &these_entries2,
			    slapi_entry_get_dn(e));
	choices = NULL;
	next_entries = NULL;
	next_entries2 = NULL;
	attrs[0] = attr;
	attrs[1] = NULL;
	for (i = 0; i < list->n_links - 1; i++) {
		these_bases = list->links[i].base_sdn_list;
		if (i < list->n_links - 1) {
			next_bases = list->links[i + 1].base_sdn_list;
		} else {
			next_bases = NULL;
		}
		/* Perform the search for entries which refer to each entry we
		 * see here. */
		for (j = 0;
		     (these_entries != NULL) && (these_entries[j] != NULL);
		     j++) {
			ndn = slapi_sdn_get_ndn(these_entries[j]);
			tndn = format_escape_for_filter(ndn);
			if (tndn == NULL) {
				continue;
			}
			/* Walk the set of search bases for this link. */
			filter = malloc(strlen(list->links[i].attribute) +
					strlen(tndn) + 4);
			if (filter == NULL) {
				free(tndn);
				continue;
			}
			sprintf(filter, "(%s=%s)",
				list->links[i].attribute, tndn);
			for (k = 0;
			     (these_bases != NULL) && (these_bases[k] != NULL);
			     k++) {
				ndn = slapi_sdn_get_dn(these_bases[k]);
				/* Search for referrers under this tree. */
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"referred_r: searching under %s"
						" for \"%s\" (link=1.%d)\n",
						ndn, filter, i);
				local_pb = wrap_pblock_new(pb);
				slapi_search_internal_set_pb(local_pb,
							     ndn,
							     LDAP_SCOPE_SUBTREE,
							     filter, attrs,
							     FALSE,
							     NULL, NULL,
							     state->plugin_identity,
							     0);
				entry_cbdata.state = state;
				entry_cbdata.attribute = attr;
				entry_cbdata.choices = &choices;
				entry_cbdata.sdn_list = &these_entries;
				entry_cbdata.sdn_list2 = &these_entries2;
				slapi_search_internal_callback_pb(local_pb,
								  &entry_cbdata,
								  NULL,
								  format_referred_r_entry_cb,
								  NULL);
				slapi_pblock_destroy(local_pb);
			}
			free(filter);
			/* Walk the set of search bases for the next link. */
			filter = malloc(strlen(list->links[i].attribute) +
					strlen(tndn) + 4);
			if (filter == NULL) {
				free(tndn);
				continue;
			}
			sprintf(filter, "(%s=%s)",
				list->links[i].attribute, tndn);
			for (k = 0;
			     (next_bases != NULL) && (next_bases[k] != NULL);
			     k++) {
				ndn = slapi_sdn_get_dn(next_bases[k]);
				/* Search for referrers under that tree. */
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"referred_r: searching under %s"
						" for \"%s\" (link=2.%d)\n",
						ndn, filter, i);
				local_pb = wrap_pblock_new(pb);
				slapi_search_internal_set_pb(local_pb,
							     ndn,
							     LDAP_SCOPE_SUBTREE,
							     filter, attrs,
							     FALSE,
							     NULL, NULL,
							     state->plugin_identity,
							     0);
				entry_cbdata.state = state;
				entry_cbdata.attribute = attr;
				entry_cbdata.choices = &choices;
				entry_cbdata.sdn_list = &next_entries;
				entry_cbdata.sdn_list2 = &next_entries2;
				slapi_search_internal_callback_pb(local_pb,
								  &entry_cbdata,
								  NULL,
								  format_referred_r_entry_cb,
								  NULL);
				slapi_pblock_destroy(local_pb);
			}
			free(filter);
			free(tndn);
		}
		/* Set up for the next iteration. */
		format_free_sdn_list(these_entries, these_entries2);
		these_entries = next_entries;
		these_entries2 = next_entries2;
		next_entries = NULL;
		next_entries2 = NULL;
	}
	format_free_sdn_list(these_entries, these_entries2);

	format_free_parsed_args(argv);

	/* Return any values we found. */
	if (choices != NULL) {
		format_add_choice(outbuf_choices, outbuf, &choices);
		return 0;
	} else {
		return -ENOENT;
	}
}

/* Evaluate each argument's list of results, after the first, in turn, and
 * merge them, using the first argument as a separator. */
static int
format_merge(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	     const char *group, const char *set,
	     const char *args, const char *disallowed,
	     char *outbuf, int outbuf_len,
	     struct format_choice **outbuf_choices,
	     char ***rel_attrs, char ***ref_attrs,
	     struct format_inref_attr ***inref_attrs,
	     struct format_ref_attr_list ***ref_attr_list,
	     struct format_ref_attr_list ***inref_attr_list)
{
	int ret, i, j, argc, slen, count;
	unsigned int *lengths;
	char **argv, **values;
	const char *sep;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"merge: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"merge: requires at least one argument\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	sep = argv[0];
	slen = strlen(sep);
	for (i = 1, ret = 0, count = 0; i < argc; i++) {
		/* Expand this argument. */
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"merge: expanding ->%s<-\n", argv[i]);
		values = format_get_data_set(state, pb, e, group, set,
					     argv[i], disallowed,
					     rel_attrs, ref_attrs, inref_attrs,
					     ref_attr_list, inref_attr_list,
					     &lengths);
		if (values == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"merge: no values for ->%s<-\n",
					argv[i]);
			continue;
		}
		for (j = 0; values[j] != NULL; j++) {
			/* Check if there's space for this value. */
			if (ret + lengths[j] + (count ? slen : 0) >
			    (unsigned int) outbuf_len) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"merge: out of space\n");
				format_free_data_set(values, lengths);
				format_free_parsed_args(argv);
				return -ENOBUFS;
			}
			/* Log this value. */
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"merge: got %d-byte value for ->%s<\n",
					lengths[j], argv[i]);
			/* If this isn't the first result, fill in the
			 * separator.  Then fill in the value. */
			if (count > 0) {
				memcpy(outbuf + ret, sep, slen);
				ret += slen;
			}
			memcpy(outbuf + ret, values[j], lengths[j]);
			ret += lengths[j];
			count++;
		}
		format_free_data_set(values, lengths);
	}
	format_free_parsed_args(argv);
	return ret;
}

/* Look up the entry's values for the attribute named by the first argument,
 * and use the callback to check if they match the second argument.  If we find
 * exactly one match, store it in the output buffer, otherwise store the text
 * of the default_arg'th argument if given, or return everything if no
 * default_arg'th argument was given. */
static int
format_match_generic(struct plugin_state *state,
		     Slapi_PBlock *pb, Slapi_Entry *e,
		     const char *group, const char *set,
		     const char *args, int min_args, int default_arg,
		     const char *disallowed,
		     char *outbuf, int outbuf_len,
		     struct format_choice **outbuf_choices,
		     char ***rel_attrs,
		     char ***ref_attrs,
		     struct format_inref_attr ***inref_attrs,
		     struct format_ref_attr_list ***ref_attr_list,
		     struct format_ref_attr_list ***inref_attr_list,
		     const char *fnname,
		     char * (*match_fn)(const char *pattern, const char *value,
					char **argv))
{
	char *cvalue, **argv, **matches, **values, *plugin_id, *default_value;
	int i, count, argc, ret, len;
	unsigned int *lengths, default_length;

	plugin_id = state->plugin_desc->spd_id;
	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"%s: error parsing arguments\n", fnname);
		return -EINVAL;
	}
	if (argc < min_args) {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
				"%s: requires at least %d arguments\n",
				fnname, min_args);
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	/* Evaluate the expression as a list, then walk it. */
	matches = NULL;
	count = 0;
	lengths = NULL;
	values = format_get_data_set(state, pb, e, group, set,
				     argv[0], disallowed,
				     rel_attrs, ref_attrs, inref_attrs,
				     ref_attr_list, inref_attr_list,
				     &lengths);
	if (values != NULL) {
		for (i = 0; values[i] != NULL; i++) {
			continue;
		}
		matches = malloc(sizeof(char *) * (i + 1));
		if (matches != NULL) {
			for (i = 0; values[i] != NULL; i++) {
				cvalue = xstrndup(values[i], lengths[i]);
				matches[count] = match_fn(argv[1], cvalue,
							  argv + 2);
				free(cvalue);
				if (matches[count] != NULL) {
					count++;
				}
			}
			matches[count] = NULL;
		}
		format_free_data_set(values, lengths);
	}
	/* Make sure matched is either the single match, the default, or NULL
	 * if we had no default. */
	switch (count) {
	case 1:
		/* Single result. */
		if (outbuf_choices != NULL) {
			/* Return the one match as a list. */
			format_add_choice_str(outbuf_choices, outbuf, matches);
			len = 0;
		} else {
			/* Store the one match directly in the buffer. */
			len = strlen(matches[0]);
			if (len > outbuf_len) {
				slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
						"%s: out of space\n", fnname);
				free(matches[0]);
				free(matches);
				format_free_parsed_args(argv);
				return -ENOBUFS;
			}
			memcpy(outbuf, matches[0], len);
		}
		break;
	case 0:
	default:
		/* Either no matches, or multiple matches, which may be too
		 * many matches to store. */
		default_value = NULL;
		if ((default_arg >= 0) && (argv[default_arg] != NULL)) {
			default_value = format_get_data(state, pb, e,
							group, set,
							argv[default_arg],
							disallowed,
							rel_attrs,
							ref_attrs,
							inref_attrs,
							ref_attr_list,
							inref_attr_list,
							&default_length);
		}
		if (default_arg < 0) {
			/* Return all of the matches as a list. */
			format_add_choice_str(outbuf_choices, outbuf, matches);
			len = 0;
		} else if ((default_arg >= 0) && (default_value != NULL)) {
			if (count == 0) {
				slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
						"%s: no matching value "
						"for \"%s\", using default "
						"value \"%s\"\n",
						fnname, argv[1], default_value);
			} else {
				slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
						"%s: too many matching values "
						"for \"%s\", using default "
						"value \"%s\"\n",
						fnname, argv[1], default_value);
			}
			len = default_length;
			if (len > outbuf_len) {
				slapi_log_error(SLAPI_LOG_PLUGIN, plugin_id,
						"%s: out of space\n", fnname);
				format_free_data(default_value);
				for (i = 0; i < count; i++) {
					free(matches[i]);
				}
				free(matches);
				format_free_parsed_args(argv);
				return -ENOBUFS;
			}
			memcpy(outbuf, default_value, default_length);
			format_free_data(default_value);
		} else {
			if ((default_arg >= 0) && (argv[default_arg] != NULL)) {
				if (count == 0) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							plugin_id,
							"%s: no matching value "
							"for \"%s\", and no "
							"single value for "
							"default \"%s\"\n",
							fnname, argv[1],
							argv[default_arg]);
				} else {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							plugin_id,
							"%s: too many "
							"matching values "
							"for \"%s\", and no "
							"single value for "
							"default \"%s\"\n",
							fnname, argv[1],
							argv[default_arg]);
				}
			} else {
				if (count == 0) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							plugin_id,
							"%s: no matching value "
							"for \"%s\", and no "
							"default value",
							fnname, argv[1]);
				} else {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							plugin_id,
							"%s: too many "
							"matching values "
							"for \"%s\", and no "
							"default value",
							fnname, argv[1]);
				}
			}
			for (i = 0; i < count; i++) {
				free(matches[i]);
			}
			free(matches);
			format_free_parsed_args(argv);
			return -ENOENT;
		}
		break;
	}
	if (matches != NULL) {
		for (i = 0; i < count; i++) {
			free(matches[i]);
		}
		free(matches);
	}
	format_free_parsed_args(argv);
	return len;
}

/* Check for glob-style matched values. */
static char *
format_match_cb(const char *pattern, const char *value, char **argv)
{
	return (fnmatch(pattern, value, 0) == 0) ? strdup(value) : NULL;
}
static int
format_match(struct plugin_state *state,
	     Slapi_PBlock *pb, Slapi_Entry *e,
	     const char *group, const char *set,
	     const char *args, const char *disallowed,
	     char *outbuf, int outbuf_len,
	     struct format_choice **outbuf_choices,
	     char ***rel_attrs, char ***ref_attrs,
	     struct format_inref_attr ***inref_attrs,
	     struct format_ref_attr_list ***ref_attr_list,
	     struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 2, 2,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_match", format_match_cb);
}
static int
format_mmatch(struct plugin_state *state,
	      Slapi_PBlock *pb, Slapi_Entry *e,
	      const char *group, const char *set,
	      const char *args, const char *disallowed,
	      char *outbuf, int outbuf_len,
	      struct format_choice **outbuf_choices,
	      char ***rel_attrs, char ***ref_attrs,
	      struct format_inref_attr ***inref_attrs,
	      struct format_ref_attr_list ***ref_attr_list,
	      struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 2, -1,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_mmatch", format_match_cb);
}

/* Check for a regex match. */
static char *
format_regmatch_base_cb(const char *pattern, int cflags,
			const char *value, char **argv)
{
	regex_t reg;
	regmatch_t matches;
	bool_t matched;
	memset(&reg, 0, sizeof(reg));
	if (regcomp(&reg, pattern, REG_EXTENDED | REG_NOSUB | cflags) != 0) {
		return NULL;
	}
	matched = (regexec(&reg, value, 1, &matches, 0) == 0);
	regfree(&reg);
	return matched ? strdup(value) : NULL;
}
static char *
format_regmatch_cb(const char *pattern, const char *value, char **argv)
{
	return format_regmatch_base_cb(pattern, 0, value, argv);
}
static int
format_regmatch(struct plugin_state *state,
		Slapi_PBlock *pb, Slapi_Entry *e,
		const char *group, const char *set,
		const char *args, const char *disallowed,
		char *outbuf, int outbuf_len,
		struct format_choice **outbuf_choices,
		char ***rel_attrs, char ***ref_attrs,
		struct format_inref_attr ***inref_attrs,
		struct format_ref_attr_list ***ref_attr_list,
		struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 2, 2,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_regmatch", format_regmatch_cb);
}
static int
format_mregmatch(struct plugin_state *state,
		 Slapi_PBlock *pb, Slapi_Entry *e,
		 const char *group, const char *set,
		 const char *args, const char *disallowed,
		 char *outbuf, int outbuf_len,
		 struct format_choice **outbuf_choices,
		 char ***rel_attrs, char ***ref_attrs,
		 struct format_inref_attr ***inref_attrs,
		 struct format_ref_attr_list ***ref_attr_list,
		 struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 2, -1,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_mregmatch", format_regmatch_cb);
}
static char *
format_regmatchi_cb(const char *pattern, const char *value, char **argv)
{
	return format_regmatch_base_cb(pattern, REG_ICASE, value, argv);
}
static int
format_regmatchi(struct plugin_state *state,
		 Slapi_PBlock *pb, Slapi_Entry *e,
		 const char *group, const char *set,
		 const char *args, const char *disallowed,
		 char *outbuf, int outbuf_len,
		 struct format_choice **outbuf_choices,
		 char ***rel_attrs, char ***ref_attrs,
		 struct format_inref_attr ***inref_attrs,
		 struct format_ref_attr_list ***ref_attr_list,
		 struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 2, 2,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_regmatchi", format_regmatchi_cb);
}
static int
format_mregmatchi(struct plugin_state *state,
		  Slapi_PBlock *pb, Slapi_Entry *e,
		  const char *group, const char *set,
		  const char *args, const char *disallowed,
		  char *outbuf, int outbuf_len,
		  struct format_choice **outbuf_choices,
		  char ***rel_attrs, char ***ref_attrs,
		  struct format_inref_attr ***inref_attrs,
		  struct format_ref_attr_list ***ref_attr_list,
		  struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 2, -1,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_mregmatchi", format_regmatchi_cb);
}

/* Check for a regex match and build a custom result from the matching value. */
static char *
format_regsub_base_cb(const char *pattern, int cflags,
		      const char *value, char **argv)
{
	regex_t reg;
	regmatch_t matches[10];
	bool_t matched;
	int i, j, m, len;
	char *template, *ret;
	memset(&reg, 0, sizeof(reg));
	if (regcomp(&reg, pattern, REG_EXTENDED | cflags) != 0) {
		return NULL;
	}
	memset(&matches, 0, sizeof(matches));
	i = regexec(&reg, value,
		    sizeof(matches) / sizeof(matches[0]), &matches[0],
		    0);
	matched = (i == 0);
	regfree(&reg);
	if (!matched) {
		return NULL;
	}
	template = argv[0];
	for (i = 0, len = 0; (template != NULL) && (template[i] != '\0'); i++) {
		switch (template[i]) {
		case '%':
			i++;
			switch (template[i]) {
			case '%':
				len++;
				continue;
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				m = template[i] - '0';
				if (matches[m].rm_so != -1) {
					len += (matches[m].rm_eo -
						matches[m].rm_so);
				}
				continue;
				break;
			default:
				len++;
				break;
			}
			break;
		default:
			len++;
			break;
		}
	}
	ret = malloc(len + 1);
	if (ret == NULL) {
		return NULL;
	}
	for (i = 0, j = 0;
	     (template != NULL) && (template[i] != '\0') && (j < len);
	     i++) {
		switch (template[i]) {
		case '%':
			i++;
			switch (template[i]) {
			case '%':
				ret[j++] = template[i];
				continue;
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				m = template[i] - '0';
				if (matches[m].rm_so != -1) {
					memcpy(ret + j,
					       value + matches[m].rm_so,
					       matches[m].rm_eo -
					       matches[m].rm_so);
					j += (matches[m].rm_eo -
					      matches[m].rm_so);
				}
				continue;
				break;
			default:
				ret[j++] = template[i];
				break;
			}
			break;
		default:
			ret[j++] = template[i];
			break;
		}
	}
	ret[j] = '\0';
	return ret;
}
static char *
format_regsub_cb(const char *pattern, const char *value, char **argv)
{
	return format_regsub_base_cb(pattern, 0, value, argv);
}
static int
format_regsub(struct plugin_state *state,
	      Slapi_PBlock *pb, Slapi_Entry *e,
	      const char *group, const char *set,
	      const char *args, const char *disallowed,
	      char *outbuf, int outbuf_len,
	      struct format_choice **outbuf_choices,
	      char ***rel_attrs, char ***ref_attrs,
	      struct format_inref_attr ***inref_attrs,
	      struct format_ref_attr_list ***ref_attr_list,
	      struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 3, 3,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_regsub", format_regsub_cb);
}
static int
format_mregsub(struct plugin_state *state,
	       Slapi_PBlock *pb, Slapi_Entry *e,
	       const char *group, const char *set,
	       const char *args, const char *disallowed,
	       char *outbuf, int outbuf_len,
	       struct format_choice **outbuf_choices,
	       char ***rel_attrs, char ***ref_attrs,
	       struct format_inref_attr ***inref_attrs,
	       struct format_ref_attr_list ***ref_attr_list,
	       struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 3, -1,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_mregsub", format_regsub_cb);
}
static char *
format_regsubi_cb(const char *pattern, const char *value, char **argv)
{
	return format_regsub_base_cb(pattern, REG_ICASE, value, argv);
}
static int
format_regsubi(struct plugin_state *state,
	       Slapi_PBlock *pb, Slapi_Entry *e,
	       const char *group, const char *set,
	       const char *args, const char *disallowed,
	       char *outbuf, int outbuf_len,
	       struct format_choice **outbuf_choices,
	       char ***rel_attrs, char ***ref_attrs,
	       struct format_inref_attr ***inref_attrs,
	       struct format_ref_attr_list ***ref_attr_list,
	       struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 3, 3,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_regsubi", format_regsubi_cb);
}
static int
format_mregsubi(struct plugin_state *state,
		Slapi_PBlock *pb, Slapi_Entry *e,
		const char *group, const char *set,
		const char *args, const char *disallowed,
		char *outbuf, int outbuf_len,
		struct format_choice **outbuf_choices,
		char ***rel_attrs, char ***ref_attrs,
		struct format_inref_attr ***inref_attrs,
		struct format_ref_attr_list ***ref_attr_list,
		struct format_ref_attr_list ***inref_attr_list)
{
	return format_match_generic(state, pb, e, group, set, args, 3, -1,
				    disallowed,
				    outbuf, outbuf_len, outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list,
				    "format_mregsubi", format_regsubi_cb);
}

/* If the attribute given by the first argument is equal to the value given in
 * the second, return the third, else return the fourth.  We used to allow an
 * expression instead of an attribute name, but then it was never clear how
 * exactly we needed to do the comparison check (specifically,
 * case-sensitivity). */
static int
format_ifeq(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	    const char *group, const char *set,
	    const char *args, const char *disallowed,
	    char *outbuf, int outbuf_len,
	    struct format_choice **outbuf_choices,
	    char ***rel_attrs, char ***ref_attrs,
	    struct format_inref_attr ***inref_attrs,
	    struct format_ref_attr_list ***ref_attr_list,
	    struct format_ref_attr_list ***inref_attr_list)
{
	int ret, argc, i;
	unsigned int *lengths;
	char **argv, **values;
	bool_t matched;
	struct berval bv;
	Slapi_Value *value;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"ifeq: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"ifeq: error parsing arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (argc != 4) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"ifeq: expected four arguments (got %d)\n",
				argc);
		format_free_parsed_args(argv);
		return -EINVAL;
	}

	/* Note that this map cares about the tested attribute. */
	if (rel_attrs != NULL) {
		format_add_attrlist(rel_attrs, argv[0]);
	}

	/* Evaluate the value expression to get a list of candidate values. */
	values = format_get_data_set(state, pb, e, group, set,
				     argv[1], disallowed,
				     rel_attrs, ref_attrs, inref_attrs,
				     ref_attr_list, inref_attr_list,
				     &lengths);
	if (values == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"ifeq: error evaluating \"%s\"\n", argv[1]);
		format_free_parsed_args(argv);
		return -EINVAL;
	}

	/* Check if any of the value expression's values match the entry's
	 * value for the named attribute. */
	matched = FALSE;
	value = slapi_value_new();
	for (i = 0; values[i] != NULL; i++) {
		ret = 0;
		memset(&bv, 0, sizeof(bv));
		bv.bv_val = values[i];
		bv.bv_len = lengths[i];
		slapi_value_set_berval(value, &bv);
		if ((slapi_vattr_value_compare(e, argv[0], value,
					       &ret, 0) == 0) &&
		    (ret == 1)) {
			matched = TRUE;
			break;
		}
	}
	slapi_value_free(&value);
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"ifeq: \"%s\" %s \"%s\"\n",
			argv[0], matched ? "matches" : "doesn't match",
			argv[1]);
	format_free_data_set(values, lengths);

	/* Evaluate the argument which corresponds to the output expression and
	 * return its values. */
	ret = format_expand(state, pb, e, group, set,
			    argv[matched ? 2 : 3], disallowed,
			    outbuf, outbuf_len,
			    outbuf_choices,
			    rel_attrs, ref_attrs, inref_attrs,
			    ref_attr_list, inref_attr_list);
	format_free_parsed_args(argv);
	return ret;
}

/* If the expression given as the first argument returns any values, return
 * them.  Otherwise, return the second expression. */
static int
format_default(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	       const char *group, const char *set,
	       const char *args, const char *disallowed,
	       char *outbuf, int outbuf_len,
	       struct format_choice **outbuf_choices,
	       char ***rel_attrs, char ***ref_attrs,
	       struct format_inref_attr ***inref_attrs,
	       struct format_ref_attr_list ***ref_attr_list,
	       struct format_ref_attr_list ***inref_attr_list)
{
	int ret, argc, i;
	unsigned int *lengths;
	char **argv, **values;
	bool_t first;
	struct berval bv, **choices;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"default: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 2) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"default: expected at least two arguments "
				"(got %d)\n",
				argc);
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	/* Evaluate expressions until we run out of them or succeed. */
	for (i = 0; i < argc; i++) {
		ret = format_expand(state, pb, e, group, set,
				    argv[i], disallowed,
				    outbuf, outbuf_len,
				    outbuf_choices,
				    rel_attrs, ref_attrs, inref_attrs,
				    ref_attr_list, inref_attr_list);
		if (ret >= 0) {
			break;
		}
	}
	format_free_parsed_args(argv);
	return ret;
}

/* Evaluate all of the arguments, and concatentate all of the lists of results
 * to produce one long list. */
static int
format_collect(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	       const char *group, const char *set,
	       const char *args, const char *disallowed,
	       char *outbuf, int outbuf_len,
	       struct format_choice **outbuf_choices,
	       char ***rel_attrs, char ***ref_attrs,
	       struct format_inref_attr ***inref_attrs,
	       struct format_ref_attr_list ***ref_attr_list,
	       struct format_ref_attr_list ***inref_attr_list)
{
	int ret, argc, i, j;
	unsigned int *lengths;
	char **argv, **values;
	struct berval bv, **choices;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"collect: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"collect: error parsing arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"collect: returns a list, but a list "
				"would not be appropriate\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}

	/* Walk the list of the arguments. */
	choices = NULL;
	for (i = 0; i < argc; i++) {
		/* Evaluate this argument. */
		values = format_get_data_set(state, pb, e, group, set,
					     argv[i], disallowed,
					     rel_attrs, ref_attrs, inref_attrs,
					     ref_attr_list, inref_attr_list,
					     &lengths);
		if (values != NULL) {
			/* Walk the list of values. */
			for (j = 0; values[j] != NULL; j++) {
				/* Add it to the list. */
				bv.bv_val = values[j];
				bv.bv_len = lengths[j];
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"collect: \"%.*s\"\n",
						(int) bv.bv_len, bv.bv_val);
				format_add_bv_list(&choices, &bv);
			}
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"collect: expanded \"%s\" to produce "
					"%d values for \"%s\"\n", argv[i], j,
					slapi_entry_get_dn(e));
			format_free_data_set(values, lengths);
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"collect: expanding \"%s\" produced "
					"no values for \"%s\"\n", argv[i],
					slapi_entry_get_dn(e));
		}
	}

	if (choices != NULL) {
		for (i = 0; choices[i] != NULL; i++) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"collect: returning \"%.*s\" as a "
					"value for \"%s\"\n",
					(int) choices[i]->bv_len,
					choices[i]->bv_val,
					slapi_entry_get_dn(e));
			continue;
		}
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"collect: returning %d values for \"%s\"\n", i,
				slapi_entry_get_dn(e));
		format_add_choice(outbuf_choices, outbuf, &choices);
		ret = 0;
	} else {
		ret = -ENOENT;
	}

	format_free_parsed_args(argv);

	return ret;
}

/* Evaluate all of the arguments, and concatentate sets of entries from each
 * list, separating them with an optional separator, padding the lists with a
 * specified value until all of the elements of all lists have been used. */
static int
format_link(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	    const char *group, const char *set,
	    const char *args, const char *disallowed,
	    char *outbuf, int outbuf_len,
	    struct format_choice **outbuf_choices,
	    char ***rel_attrs, char ***ref_attrs,
	    struct format_inref_attr ***inref_attrs,
	    struct format_ref_attr_list ***ref_attr_list,
	    struct format_ref_attr_list ***inref_attr_list)
{
	int ret, argc, i, j, *n_items, l, result_n, n_lists, n_done;
	unsigned int **lengths, length, max_length;
	char **argv, ***values, *buffer, *p;
	struct berval bv, **choices;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"link: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"link: error parsing arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (((argc + 1) % 3) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"link: wrong number of arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"link: returns a list, but a list "
				"would not be appropriate\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}

	/* Allocate space to store the information. */
	values = malloc(sizeof(char **) * (((argc + 1) / 3) * 2));
	lengths = malloc(sizeof(int *) * (((argc + 1) / 3) * 2));
	n_items = malloc(sizeof(int) * (((argc + 1) / 3) * 2));
	if ((values == NULL) || (lengths == NULL) || (n_items == NULL)) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"link: out of memory\n");
		format_free_parsed_args(argv);
		free(values);
		free(lengths);
		free(n_items);
		return -ENOMEM;
	}

	/* Walk the list of the arguments, building a list of lists. */
	choices = NULL;
	n_lists = 0;
	for (i = 0; i < argc; i += 3) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"link: evaluating \"%s\"\n", argv[i]);
		j = (i / 3) * 2;
		values[j] = format_get_data_set(state, pb, e, group, set,
						argv[i], disallowed,
						rel_attrs,
						ref_attrs, inref_attrs,
						ref_attr_list,
						inref_attr_list,
						&lengths[j]);
		if (values[j] != NULL) {
			n_lists++;
		}
		j++;
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"link: evaluating \"%s\"\n", argv[i + 1]);
		values[j] = format_get_data_set(state, pb, e, group, set,
						argv[i + 1], disallowed,
						rel_attrs,
						ref_attrs, inref_attrs,
						ref_attr_list,
						inref_attr_list,
						&lengths[j]);
		if (values[j] != NULL) {
			n_lists++;
		}
	}

	/* If we got _no_ answers for everything, that's a NULL result. */
	if (n_lists == 0) {
		format_free_parsed_args(argv);
		free(values);
		free(lengths);
		free(n_items);
		return -ENOENT;
	}

	/* Walk the lists, building the output data items. */
	n_lists = ((argc + 1) / 3) * 2;
	/* Count the number of items in each list. */
	for (i = 0; i < n_lists; i++) {
		for (j = 0;
		     (values[i] != NULL) && (values[i][j] != NULL);
		     j++) {
			continue;
		}
		n_items[i] = j;
	}
	max_length = 0;
	buffer = NULL;
	length = 0;
	n_done = 0;
	for (result_n = 0; n_done < (n_lists / 2); result_n++) {
		/* Calculate how much space we need for this result. */
		length = 0;
		n_done = 0;
		for (i = 0; i < n_lists; i += 2) {
			if (result_n < n_items[i]) {
				/* This list has an item for this result. */
				length += lengths[i][result_n];
			} else {
				/* This list ran out of items -- use a value
				 * from the pad result list. */
				length += lengths[i + 1][result_n %
							 n_items[i + 1]];
				/* Note that this list has run out. */
				n_done++;
			}
			if (i < (n_lists - 2)) {
				/* And the separator. */
				length += strlen(argv[(i / 2) * 3 + 2]);
			}
		}
		/* If we're out of data, we should stop before adding a result
		 * to the list. */
		if (n_done == n_lists / 2) {
			break;
		}
		/* Make sure the buffer is large enough. */
		if (length > max_length) {
			free(buffer);
			buffer = malloc(length);
			if (buffer == NULL) {
				format_free_bv_list(choices);
				format_free_parsed_args(argv);
				for (i = 0; i < n_lists; i++) {
					format_free_data_set(values[i],
							     lengths[i]);
				}
				free(values);
				free(lengths);
				free(n_items);
				return -ENOMEM;
			}
			max_length = length;
		}
		/* Build the output value. */
		p = buffer;
		for (i = 0; i < n_lists; i += 2) {
			if (result_n < n_items[i]) {
				/* This list has an item for this result. */
				l = lengths[i][result_n];
				memcpy(p, values[i][result_n], l);
				p += l;
			} else {
				/* This list ran out of items -- use padding. */
				l = lengths[i + 1][result_n %
						   n_items[i + 1]];
				memcpy(p, values[i + 1][result_n %
							n_items[i + 1]], l);
				p += l;
			}
			if (i < (n_lists - 2)) {
				/* Separator. */
				l = strlen(argv[(i / 2) * 3 + 2]);
				memcpy(p, argv[(i / 2) * 3 + 2], l);
				p += l;
			}
		}
		/* Add it to the result list. */
		bv.bv_val = buffer;
		bv.bv_len = length;
		if ((p - buffer) != length) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"link: internal error\n");
			break;
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"link: \"%.*s\"\n",
					(int) bv.bv_len, bv.bv_val);
			format_add_bv_list(&choices, &bv);
		}
	}

	if (choices != NULL) {
		format_add_choice(outbuf_choices, outbuf, &choices);
		ret = 0;
	} else {
		ret = -ENOENT;
	}

	format_free_parsed_args(argv);
	for (i = 0; i < n_lists; i++) {
		format_free_data_set(values[i], lengths[i]);
	}
	free(buffer);
	free(values);
	free(lengths);
	free(n_items);

	return ret;
}

/* Eliminate duplicate values from the list. */
static int
format_unique(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	      const char *group, const char *set,
	      const char *args, const char *disallowed,
	      char *outbuf, int outbuf_len,
	      struct format_choice **outbuf_choices,
	      char ***rel_attrs,
	      char ***ref_attrs, struct format_inref_attr ***inref_attrs,
	      struct format_ref_attr_list ***ref_attr_list,
	      struct format_ref_attr_list ***inref_attr_list)
{
	int ret, i, j, argc;
	char **argv, **values;
	const char *value_format, *default_value;
	unsigned int *lengths;
	struct berval **choices, bv;

	ret = format_parse_args(state, args, &argc, &argv);
	if (ret != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"unique: error parsing arguments\n");
		return -EINVAL;
	}
	if (argc < 1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"unique: error parsing arguments\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	if (argc < 2) {
		value_format = argv[0];
		default_value = NULL;
	} else {
		value_format = argv[0];
		default_value = argv[1];
	}
	if (outbuf_choices == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"unique: returns a list, but a list "
				"would not be appropriate\n");
		format_free_parsed_args(argv);
		return -EINVAL;
	}
	ret = -ENOENT;
	values = format_get_data_set(state, pb, e, group, set,
				     value_format, disallowed,
				     rel_attrs, ref_attrs, inref_attrs,
				     ref_attr_list, inref_attr_list,
				     &lengths);
	if (values == NULL) {
		if (default_value == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"unique: no values for ->%s<-, "
					"and no default value provided\n",
					value_format);
			ret = -ENOENT;
		} else {
			i = format_expand(state, pb, e,
					  group, set,
					  default_value, NULL,
					  outbuf, outbuf_len,
					  outbuf_choices,
					  rel_attrs, ref_attrs, inref_attrs,
					  ref_attr_list, inref_attr_list);
			ret = i;
		}
	} else {
		if (values != NULL) {
			choices = NULL;
			for (i = 0; values[i] != NULL; i++) {
				/* XXX this is horribly slow */
				for (j = 0; j < i; j++) {
					if ((lengths[i] == lengths[j]) &&
					    (memcmp(values[i], values[j], lengths[i]) == 0)) {
						break;
					}
				}
				if (j == i) {
					/* Add it to the list. */
					bv.bv_val = values[i];
					bv.bv_len = lengths[i];
					format_add_bv_list(&choices, &bv);
				}
			}
			format_free_data_set(values, lengths);
			if (choices != NULL) {
				for (i = 0; choices[i] != NULL; i++) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"unique: returning \"%.*s\" as a "
							"value for \"%s\"\n",
							(int) choices[i]->bv_len,
							choices[i]->bv_val,
							slapi_entry_get_dn(e));
					continue;
				}
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"unique: returning %d values for \"%s\"\n", i,
						slapi_entry_get_dn(e));
				format_add_choice(outbuf_choices, outbuf, &choices);
				ret = 0;
			} else {
				ret = -ENOENT;
			}
		}
	}
	format_free_parsed_args(argv);
	return ret;
}

/* Produce an internal sequence number. */
static int
format_internal_sequence_number(struct plugin_state *state,
				Slapi_PBlock *pb, Slapi_Entry *e,
				const char *group, const char *set,
				const char *args, const char *disallowed,
				char *outbuf, int outbuf_len,
				struct format_choice **outbuf_choices,
				char ***rel_attrs,
				char ***ref_attrs,
				struct format_inref_attr ***inref_attrs,
				struct format_ref_attr_list ***ref_attr_list,
				struct format_ref_attr_list ***inref_attr_list)
{
	static int sequence;
	char *buf;
	int ret;
	const char *value_format;
	struct berval **choices, bv;

	choices = NULL;
	buf = malloc(3 * sizeof(sequence));
	if (buf != NULL) {
		sprintf(buf, "%d", ++sequence);
		bv.bv_val = buf;
		bv.bv_len = strlen(buf);
		format_add_bv_list(&choices, &bv);
	}
	if (choices != NULL) {
		format_add_choice(outbuf_choices, outbuf, &choices);
		ret = 0;
	} else {
		ret = -ENOENT;
	}
	if (ret == 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"internal_sequence_number: ->%s<-\n", buf);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"internal_sequence_number: error building result\n");
	}
	free(buf);
	return ret;
}

/* Choose a formatting function by name. */
static void *
format_lookup_fn(const char *fnname)
{
	unsigned int i;
	struct {
		const char *name;
		int (*fct_ptr)(struct plugin_state *state,
			       Slapi_PBlock *pb, Slapi_Entry *e,
			       const char *group, const char *set,
			       const char *args, const char *disallowed,
			       char *outbuf, int outbuf_len,
			       struct format_choice **outbuf_choices,
			       char ***rel_attrs,
			       char ***ref_attrs,
			       struct format_inref_attr ***inref_attrs,
			       struct format_ref_attr_list ***ref_attr_list,
			       struct format_ref_attr_list ***inref_attr_list);
	} fns[] = {
		{"first", format_first},
		{"deref", format_deref},
		{"deref_f", format_deref_f},
		{"deref_r", format_deref_r},
		{"deref_rf", format_deref_rf},
		{"deref_fr", format_deref_rf},
		{"referred", format_referred},
		{"referred_r", format_referred_r},
		{"merge", format_merge},
		{"match", format_match},
		{"regmatch", format_regmatch},
		{"regmatchi", format_regmatchi},
		{"regsub", format_regsub},
		{"regsubi", format_regsubi},
		{"mmatch", format_mmatch},
		{"mregmatch", format_mregmatch},
		{"mregmatchi", format_mregmatchi},
		{"mregsub", format_mregsub},
		{"mregsubi", format_mregsubi},
		{"ifeq", format_ifeq},
		{"default", format_default},
		{"collect", format_collect},
		{"link", format_link},
		{"unique", format_unique},
		{"internal_sequence_number", format_internal_sequence_number},
	};
	for (i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
		if ((fns[i].name != NULL) &&
		    (strcmp(fns[i].name, fnname) == 0)) {
			return fns[i].fct_ptr;
		}
	}
	return NULL;
}

/* Check for the presence of any character in the disallowed list in the
 * passed-in value. */
static char *
format_check_disallowed(const struct berval *bv, const char *disallowed)
{
	int i;
	unsigned char c;
	char *p;
	if (disallowed != NULL) {
		for (i = 0; disallowed[i] != '\0'; i++) {
			c = disallowed[i];
			if (c == '\\') {
				switch (disallowed[i + 1]) {
				case '\\':
					c = '\\';
					i++;
					break;
				case 'a':
					c = '\a';
					i++;
					break;
				case 'b':
					c = '\b';
					i++;
					break;
				case 'f':
					c = '\f';
					i++;
					break;
				case 'n':
					c = '\n';
					i++;
					break;
				case 'r':
					c = '\r';
					i++;
					break;
				case 't':
					c = '\t';
					i++;
					break;
				case 'v':
					c = '\v';
					i++;
					break;
				}
			}
			p = memchr(bv->bv_val, c, bv->bv_len);
			if (p != NULL) {
				return p;
			}
		}
	}
	return NULL;
}
/* Retrieve a single value for an attribute.  If there are no values, or more
 * than one, return NULL.  If there's more than one, store the values in the
 * array argument. */
static struct berval
format_single(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	      const char *attr, const char *disallowed,
	      char ***attrlist, struct berval ***values)
{
	Slapi_ValueSet *value_set;
	Slapi_Value *value;
	char *actual_attr;
	const char *d;
	const struct berval *val;
	struct berval bv;
	int count, disposition, buffer_flags, i;
	if (attrlist != NULL) {
		format_add_attrlist(attrlist, attr);
	}
	memset(&bv, 0, sizeof(bv));
	if (slapi_vattr_values_get(e, (char *) attr, &value_set,
				   &disposition, &actual_attr,
				   0, &buffer_flags) != 0) {
		return bv;
	}
	count = slapi_valueset_count(value_set);
	if (count == 1) {
		if (slapi_valueset_first_value(value_set, &value) != -1) {
			val = slapi_value_get_berval(value);
			d = format_check_disallowed(val, disallowed);
			if (d != NULL) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"value for \"%s\" "
						"contains disallowed "
						"character \"%c\", "
						"ignoring\n",
						attr, *d);
			} else {
				bv.bv_val = xmemdup(val->bv_val, val->bv_len);
				if (bv.bv_val != NULL) {
					bv.bv_len = val->bv_len;
				} else {
					bv.bv_len = 0;
				}
			}
		}
	} else {
		if ((count == 0) || (values == NULL)) {
			/* Either no results, or too many results with no place
			 * to put them. */
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"%d values for \"%s\"\n", count, attr);
		} else {
			/* Return the list of values. */
			for (i = slapi_valueset_first_value(value_set,
							    &value);
			     i != -1;
			     i = slapi_valueset_next_value(value_set, i,
							   &value)) {
				val = slapi_value_get_berval(value);
				if (val->bv_len == 0) {
					continue;
				}
				d = format_check_disallowed(val, disallowed);
				if (d == NULL) {
					format_add_bv_list(values, val);
				}
			}
		}
	}
	slapi_vattr_values_free(&value_set, &actual_attr, buffer_flags);
	return bv;
}

/* Find the matching closing marker -- assumes that the first character in
 * pattern is the opener. */
static const char *
format_find_closer(const char *pair, const char *pattern)
{
	int i, dq, level = 0;
	for (i = 0, dq = 0; pattern[i] != '\0'; i++) {
		if (pattern[i] == '\\') {
			i++;
			continue;
		}
		if (pattern[i] == '"') {
			dq = !dq;
			continue;
		}
		if (!dq) {
			if (pattern[i] == pair[0]) {
				level++;
			} else {
				if (pattern[i] == pair[1]) {
					level--;
				}
			}
			if (level == 0) {
				return &pattern[i];
			}
		}
	}
	return NULL;
}

/* Trim off prefixes or suffixes which match the given patterns, free the
 * original, and return the result. */
static struct berval
format_trim_value(struct plugin_state *state, struct berval input,
		  const char *shortstart, const char *longstart,
		  const char *shortend, const char *longend,
		  const char *replace, const char *replaceall,
		  const char *replaceval)
{
	struct berval ret;
	char *buf;
	unsigned int i, len;
	buf = xmemdup(input.bv_val, input.bv_len);
	len = input.bv_len;
	if (buf != NULL) {
		if (shortstart) {
			/* The shortest initial subsection which matches gets
			 * trimmed off. */
			for (i = 0; i <= input.bv_len; i++) {
				memcpy(buf, input.bv_val, i);
				buf[i] = '\0';
				if (fnmatch(shortstart, buf, 0) == 0) {
					memcpy(buf, input.bv_val + i,
					       input.bv_len - i);
					buf[input.bv_len - i] = '\0';
					ret.bv_val = buf;
					ret.bv_len = input.bv_len - i;
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"trim-ss: ->%.*s<- => "
							"->%.*s<-\n",
							(int) input.bv_len,
							input.bv_val,
							(int) ret.bv_len,
							ret.bv_val);
					free(input.bv_val);
					return ret;
				}
			}
		}
		if (shortend) {
			/* The shortest ending substring which matches gets
			 * snipped. */
			for (i = 0; i <= input.bv_len; i++) {
				memcpy(buf,
				       input.bv_val + input.bv_len - i,
				       i);
				buf[i] = '\0';
				if (fnmatch(shortend, buf, 0) == 0) {
					memcpy(buf, input.bv_val,
					       input.bv_len - i);
					buf[input.bv_len - i] = '\0';
					ret.bv_val = buf;
					ret.bv_len = input.bv_len - i;
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"trim-se: ->%.*s<- => "
							"->%.*s<-\n",
							(int) input.bv_len,
							input.bv_val,
							(int) ret.bv_len,
							ret.bv_val);
					free(input.bv_val);
					return ret;
				}
			}
		}
		if (longstart) {
			/* The longest initial substring which matches gets
			 * skipped. */
			for (i = 0; i <= len; i++) {
				memcpy(buf, input.bv_val, (input.bv_len - i));
				buf[input.bv_len - i] = '\0';
				if (fnmatch(longstart, buf, 0) == 0) {
					memcpy(buf, input.bv_val + i,
					       input.bv_len - i);
					buf[input.bv_len - i] = '\0';
					ret.bv_val = buf;
					ret.bv_len = input.bv_len - i;
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"trim-ls: ->%.*s<- => "
							"->%.*s<-\n",
							(int) input.bv_len,
							input.bv_val,
							(int) ret.bv_len,
							ret.bv_val);
					free(input.bv_val);
					return ret;
				}
			}
		}
		if (longend) {
			/* The longest ending substring which matches gets
			 * snipped. */
			for (i = 0; i <= len; i++) {
				memcpy(buf, input.bv_val + i, input.bv_len - i);
				buf[input.bv_len - i] = '\0';
				if (fnmatch(longend, buf, 0) == 0) {
					memcpy(buf, input.bv_val,
					       input.bv_len - i);
					buf[i] = '\0';
					ret.bv_val = buf;
					ret.bv_len = input.bv_len - i;
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"trim-le: ->%.*s<- => "
							"->%.*s<-\n",
							(int) input.bv_len,
							input.bv_val,
							(int) ret.bv_len,
							ret.bv_val);
					free(input.bv_val);
					return ret;
				}
			}
		}
		if (replaceval == NULL) {
			replaceval = "";
		}
		if (replace) {
			/* FIXME */
		}
		if (replaceall) {
			/* FIXME */
		}
		free(buf);
	}
	return input;
}

/* Expand the simple expression into the output buffer. This is limited to one
 * attribute value, perhaps with a default or alternate value, perhaps with a
 * prefix or suffix stripped, perhaps with internal replacements made. */
static int
format_expand_simple(struct plugin_state *state,
		     Slapi_PBlock *pb, Slapi_Entry *e,
		     const char *group, const char *set,
		     const char *fmt, const char *disallowed,
		     char *outbuf, int outbuf_len,
		     struct format_choice **outbuf_choices,
		     char ***rel_attrs,
		     char ***ref_attrs,
		     struct format_inref_attr ***inref_attrs,
		     struct format_ref_attr_list ***ref_attr_list,
		     struct format_ref_attr_list ***inref_attr_list)
{
	char *shortstart, *longstart, *shortend, *longend;
	struct berval tmp, **values;
	char *replace, *replaceall, *replaceval, *expr, *p;
	const char *attribute, *default_value, *alternate_value;
	size_t spn;
	int i;
	shortstart = NULL;
	longstart = NULL;
	shortend = NULL;
	longend = NULL;
	replace = NULL;
	replaceall = NULL;
	replaceval = NULL;
	expr = strdup(fmt);
	/* It's a simple expression, so evaluate it.  Check for substitutions
	 * and text to be stripped if the magic character occurs before the
	 * default/alternate signals. */
	if (strcspn(expr, "#%/!") < strcspn(expr, ":")) {
		spn = strcspn(expr, "#%/!");
		p = expr + spn;
		if (strncmp(p, "##", 2) == 0) {
			longstart = p + 2;
		}
		else if (strncmp(p, "%%", 2) == 0) {
			longend = p + 2;
		}
		else if (strncmp(p, "//", 2) == 0) {
			replaceall = p + 2;
		}
		else if (strncmp(p, "#", 1) == 0) {
			shortstart = p + 1;
		}
		else if (strncmp(p, "%", 1) == 0) {
			shortend = p + 1;
		}
		else if (strncmp(p, "/", 1) == 0) {
			replace = p + 1;
		}
		expr[spn] = '\0';
		if ((replace != NULL) || (replaceall != NULL)) {
			replaceval = NULL;
			if (replace != NULL) {
				spn = strcspn(replace, "/");
				replaceval = replace + spn;
			}
			if (replaceall != NULL) {
				spn = strcspn(replaceall, "/");
				replaceval = replaceall + spn;
			}
			if ((replaceval != NULL) &&
			    (*replaceval != '\0')) {
				*replaceval = '\0';
				replaceval++;
			}
		}
		attribute = expr;
		alternate_value = NULL;
		default_value = NULL;
	} else {
		/* Check if it uses a default/alternate value. */
		spn = strcspn(expr, ":");
		if (spn == strlen(expr)) {
			/* Plain old variable, no alternate or default value.
			 * */
			attribute = expr;
			alternate_value = NULL;
			default_value = NULL;
		} else {
			/* Make a copy of the attribute name. */
			expr[spn] = '\0';
			attribute = expr;
			alternate_value = NULL;
			default_value = NULL;
			/* Figure out if there's an alternate or default value
			 * given. */
			switch (expr[spn + 1]) {
			case '+':
				alternate_value = expr + spn + 2;
				break;
			case '-':
				default_value = expr + spn + 2;
				break;
			default:
				default_value = expr + spn + 1;
				break;
			}
		}
	}
	/* Retrieve the value. */
	values = NULL;
	tmp = format_single(state, pb, e, attribute, disallowed,
			    rel_attrs, outbuf_choices ? &values : NULL);
	if (tmp.bv_val == NULL) {
		/* The attribute is undefined, or we're treating it as if it
		 * is. */
		if (values == NULL) {
			if (default_value != NULL) {
				/* Supply the default value, expanding it if
				 * needed. */
				i = format_expand(state, pb, e,
						  group, set,
						  default_value, NULL,
						  outbuf, outbuf_len,
						  outbuf_choices,
						  rel_attrs,
						  ref_attrs, inref_attrs,
						  ref_attr_list,
						  inref_attr_list);
				free(expr);
				return i;
			} else {
				/* No value, and no default: FAIL. */
				free(expr);
				return -ENOENT;
			}
		} else {
			if (alternate_value != NULL) {
				/* Supply the alternate value. */
				i = format_expand(state, pb, e,
						  group, set,
						  alternate_value, NULL,
						  outbuf, outbuf_len,
						  outbuf_choices,
						  rel_attrs,
						  ref_attrs, inref_attrs,
						  ref_attr_list,
						  inref_attr_list);
				free(expr);
				format_free_bv_list(values);
				return i;
			} else {
				/* Store nothing in the immediate position, but
				 * return a note that any of these values would
				 * be fine at this point in the output string.
				 * */
				format_add_choice(outbuf_choices,
						  outbuf, &values);
				free(expr);
				return 0;
			}
		}
	} else {
		if (values != NULL) {
			format_free_bv_list(values);
		}
		/* There's a suitable single value available. */
		if (alternate_value != NULL) {
			/* Supply the alternate value. */
			i = format_expand(state, pb, e,
					  group, set, alternate_value, NULL,
					  outbuf, outbuf_len, outbuf_choices,
					  rel_attrs, ref_attrs, inref_attrs,
					  ref_attr_list, inref_attr_list);
			free(tmp.bv_val);
			free(expr);
			return i;
		} else {
			/* Munge up the looked-up value. */
			tmp = format_trim_value(state, tmp,
						shortstart, longstart,
						shortend, longend,
						replace, replaceall,
						replaceval);
			/* Supply the looked-up value. */
			if (tmp.bv_val != NULL) {
				if (tmp.bv_len <= (unsigned int) outbuf_len) {
					memcpy(outbuf, tmp.bv_val, tmp.bv_len);
				}
				free(tmp.bv_val);
				free(expr);
				return tmp.bv_len;
			} else {
				/* No useful value: FAIL. */
				free(expr);
				return -ENOENT;
			}
		}
	}
	/* not reached */
}

/* Recursively expand the expression into the output buffer.  If the result
 * will also be an expression, treat the entire result as an attribute
 * specifier and evaluate it, otherwise return it. */
static int
format_expand(struct plugin_state *state, Slapi_PBlock *pb, Slapi_Entry *e,
	      const char *group, const char *set,
	      const char *fmt, const char *disallowed,
	      char *outbuf, int outbuf_len,
	      struct format_choice **outbuf_choices,
	      char ***rel_attrs, char ***ref_attrs,
	      struct format_inref_attr ***inref_attrs,
	      struct format_ref_attr_list ***ref_attr_list,
	      struct format_ref_attr_list ***inref_attr_list)
{
	int i, j, used;
	const char *fmtstart, *fmtend, *match, *pair;
	char *subexp, *fnname, *params, *spd_id;
	const char *paramstart, *paramend;
	int (*formatfn)(struct plugin_state *state,
			Slapi_PBlock *pb, Slapi_Entry *e,
			const char *group, const char *set,
			const char *args, const char *disallowed,
			char *outbuf, int outbuf_len,
			struct format_choice **outbuf_choices,
			char ***rel_attrs,
			char ***ref_attrs,
			struct format_inref_attr ***inref_attrs,
			struct format_ref_attr_list ***ref_attr_list,
			struct format_ref_attr_list ***inref_attr_list);

	spd_id = state->plugin_desc->spd_id;

	/* Expand any subexpressions and call any "functions". */
	i = 0;
	j = 0;
	while ((fmt[i] != '\0') && (j < outbuf_len)) {
		switch (fmt[i]) {
		case '%':
			/* This might be a subexpression, a "function" call, or
			 * an escaped character. */
			switch (fmt[i + 1]) {
			case '%':
				/* It's just an escaped "%". */
				outbuf[j++] = '%';
				i += 2;
				continue;
				break;
			case '{':
				/* Find the beginning of the simple expression.
				 */
				fmtstart = fmt + i;
				/* Find the end of the simple expression. */
				match = format_find_closer("{}", fmtstart + 1);
				if (match == NULL) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion failed: "
							"no closing brace\n");
					return -EINVAL;
				} else {
					/* Track the first character after the
					 * simple expression. */
					fmtend = match + 1;
					/* Make a copy of the simple
					 * expression. */
					subexp = xstrndupp(fmtstart + 2,
							   fmtend - 1);
					if (subexp == NULL) {
						slapi_log_error(SLAPI_LOG_PLUGIN,
								spd_id,
								"expansion "
								"failed: out "
								"of memory\n");
						return -ENOMEM;
					}
					/* Expand the simple expression. */
					used = format_expand_simple(state,
								    pb, e,
								    group,
								    set,
								    subexp,
								    disallowed,
								    outbuf + j,
								    outbuf_len - j,
								    outbuf_choices,
								    rel_attrs,
								    ref_attrs,
								    inref_attrs,
								    ref_attr_list,
								    inref_attr_list);
					if (used < 0) {
						/* Some failure, FAIL. */
						slapi_log_error(SLAPI_LOG_PLUGIN,
								spd_id,
								"error "
								"expanding "
								"expression "
								"->%s<-: %s\n",
								subexp,
								strerror(-used));
						free(subexp);
						return used;
					}
					free(subexp);
					subexp = NULL;
					if (used + j >= outbuf_len) {
						/* Out of space, or would be,
						 * so return a failure. */
						slapi_log_error(SLAPI_LOG_PLUGIN,
								spd_id,
								"expansion "
								"failed: result"
								" would be too "
								"big\n");
						return -ENOBUFS;
					} else {
						/* It fit, so keep going. */
						i = (match + 1) - fmt;
						j += used;
					}
				}
				continue;
				break;
			default:
				/* Assume it's a "function" call.  Pick out the
				 * name of the function. */
				paramstart = strpbrk(fmt + i + 1, "{(");
				if (paramstart == NULL) {
					/* No start? Bad format. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion failed: "
							"bad function "
							"invocation\n");
					return -EINVAL;
				}
				if (*paramstart == '{') {
					pair = "{}";
				} else {
					pair = "()";
				}
				paramend = format_find_closer(pair, paramstart);
				if (paramend == NULL) {
					/* No matching end? Bad format. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion failed: "
							"bad function "
							"invocation\n");
					return -EINVAL;
				}
				fnname = xstrndupp(fmt + i + 1, paramstart);
				if (fnname == NULL) {
					/* Out of memory, FAIL. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion failed: "
							"out of memory\n");
					return -ENOMEM;
				}
				/* Pick out the parameter list. */
				params = xstrndupp(paramstart + 1, paramend);
				if (params == NULL) {
					/* Out of memory, FAIL. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion failed: "
							"out of memory\n");
					free(fnname);
					return -ENOMEM;
				}
				/* Find the "function". */
				formatfn = format_lookup_fn(fnname);
				if (formatfn == NULL) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion "
							"failed: no function "
							"named \"%s\" is "
							"defined\n", fnname);
					free(fnname);
					free(params);
					return -ENOSYS;
				}
				/* Call the "function". */
				used = (*formatfn)(state, pb, e,
						   group, set,
						   params, disallowed,
						   outbuf + j, outbuf_len - j,
						   outbuf_choices,
						   rel_attrs,
						   ref_attrs, inref_attrs,
						   ref_attr_list,
						   inref_attr_list);
				if (used < 0) {
					/* Error in function, FAIL. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion "
							"failed: function "
							"'%s'(%s) failed: %s\n",
							fnname, params,
							strerror(-used));
					free(fnname);
					free(params);
					params = NULL;
					return used;
				}
				free(params);
				params = NULL;
				free(fnname);
				fnname = NULL;
				if (used + j >= outbuf_len) {
					/* We'd be out of space, fail. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion "
							"failed: result"
							" would be too "
							"big\n");
					return -ENOBUFS;
				}
				i = (paramend - fmt) + 1;
				j += used;
				continue;
				break;
			}
			break;
		default:
			/* Default is just a literal character. */
			outbuf[j++] = fmt[i++];
			break;
		}
	}
	outbuf[j] = '\0';

	if (j > outbuf_len) {
		return -ENOBUFS;
	} else {
		return j;
	}
}

static char *
format_format(struct plugin_state *state,
	      Slapi_PBlock *parent_pb, Slapi_Entry *e,
	      const char *group, const char *set,
	      const char *fmt, const char *disallowed,
	      struct format_choice **choices,
	      char ***rel_attrs, char ***ref_attrs,
	      struct format_inref_attr ***inref_attrs,
	      struct format_ref_attr_list ***ref_attr_list,
	      struct format_ref_attr_list ***inref_attr_list,
	      unsigned int *data_length)
{
	Slapi_PBlock *pb;
	char *buf, *ret, *spd_id;
	int i, buflen;

	spd_id = state->plugin_desc->spd_id;
	buflen = DEFAULT_BUFFER_SIZE;
	do {
		buf = malloc(buflen);
		if (buf == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					spd_id,
					"expansion of \"%s\" "
					"for \"%s\" failing: out of memory\n",
					fmt,
					slapi_entry_get_ndn(e));
			return NULL;
		}

		pb = wrap_pblock_new(parent_pb);
		i = format_expand(state, pb, e, group, set,
				  fmt, disallowed,
				  buf, buflen, choices,
				  rel_attrs, ref_attrs, inref_attrs,
				  ref_attr_list, inref_attr_list);
		slapi_pblock_destroy(pb);
		if ((i >= 0) && (i < buflen)) {
			buf[i] = '\0';
			ret = xmemdup(buf, i);
			*data_length = i;
			format_retarget_choicesp(choices, buf, ret);
		} else {
			if (i == -ENOBUFS) {
				if (buflen < MAX_BUFFER_SIZE) {
					buflen *= 2;
#if 0
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion of \"%s\" "
							"for \"%s\" failed: %s "
							"(will try again)\n",
							fmt,
							slapi_entry_get_ndn(e),
							strerror(-i));
#endif
				} else {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							spd_id,
							"expansion of \"%s\" "
							"for \"%s\" failed: %s "
							"(giving up)\n",
							fmt,
							slapi_entry_get_ndn(e),
							strerror(-i));
				}
			} else {
				slapi_log_error(SLAPI_LOG_PLUGIN, spd_id,
						"expansion of \"%s\" "
						"for \"%s\" failed: %s\n",
						fmt, slapi_entry_get_ndn(e),
						strerror(-i));
			}
			format_free_choicesp(choices);
			ret = NULL;
		}
		free(buf);
	} while (i == -ENOBUFS);

	return ret;
}

void
format_free_data(char *data)
{
	if (data != NULL) {
		free(data);
	}
}
char *
format_get_data(struct plugin_state *state,
		Slapi_PBlock *pb, Slapi_Entry *e,
		const char *group, const char *set,
		const char *fmt, const char *disallowed,
		char ***rel_attrs,
		char ***ref_attrs,
		struct format_inref_attr ***inref_attrs,
		struct format_ref_attr_list ***ref_attr_list,
		struct format_ref_attr_list ***inref_attr_list,
		unsigned int *data_length)
{
	unsigned int ignored;
	return format_format(state, pb, e, group, set, fmt,
			     disallowed, NULL,
			     rel_attrs,
			     ref_attrs, inref_attrs,
			     ref_attr_list, inref_attr_list,
			     data_length ? data_length : &ignored);
}

void
format_free_data_set(char **data, unsigned int *data_lengths)
{
	int i;
	if (data != NULL) {
		for (i = 0; data[i] != NULL; i++) {
			free(data[i]);
		}
		free(data);
	}
	free(data_lengths);
}
char **
format_get_data_set(struct plugin_state *state,
		    Slapi_PBlock *pb, Slapi_Entry *e,
		    const char *group, const char *set,
		    const char *fmt, const char *disallowed,
		    char ***rel_attrs,
		    char ***ref_attrs,
		    struct format_inref_attr ***inref_attrs,
		    struct format_ref_attr_list ***ref_attr_list,
		    struct format_ref_attr_list ***inref_attr_list,
		    unsigned int **data_lengths)
{
	struct format_choice *choices, *this_choice;
	struct berval *val;
	char **ret, *template;
	int combinations, groupsize, i, j, k, offset, length, prev_offset;
	unsigned int template_len;
	choices = NULL;
	template = format_format(state, pb, e, group, set, fmt, disallowed,
				 &choices,
				 rel_attrs, ref_attrs, inref_attrs,
				 ref_attr_list, inref_attr_list,
				 &template_len);
	if (template == NULL) {
		format_free_choices(choices);
		*data_lengths = NULL;
		return NULL;
	}
	/* Figure out how many results we're going to have. */
	combinations = 1;
	for (this_choice = choices, prev_offset = 0;
	     this_choice != NULL;
	     this_choice = this_choice->next) {
		if ((this_choice->offset - template) > prev_offset) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"choice: fixed \"%.*s\" at %d\n",
					(int) (this_choice->offset - template) -
					prev_offset,
					template + prev_offset,
					prev_offset);
			prev_offset = this_choice->offset - template;
		}
		for (i = 0; i < this_choice->n_values; i++) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"choice: option \"%.*s\" at %ld\n",
					(int) this_choice->values[i]->bv_len,
					(char *) this_choice->values[i]->bv_val,
					(long) (this_choice->offset -
						template));
		}
		combinations *= this_choice->n_values;
	}
	if (template[prev_offset] != '\0') {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"choice: fixed \"%s\" at %d\n",
				template + prev_offset,
				prev_offset);
	}
	if (combinations == 0) {
		format_free_choices(choices);
		*data_lengths = NULL;
		return NULL;
	}
	ret = malloc((combinations + 1) * sizeof(char *));
	*data_lengths = malloc(sizeof(**data_lengths) * combinations);
	if ((ret != NULL) && (*data_lengths != NULL)) {
		/* Work out all of the results. */
		for (i = 0, j = 0; i < combinations; i++) {
			/* First figure out how long this result will be. */
			groupsize = combinations;
			length = template_len;
			for (this_choice = choices;
			     this_choice != NULL;
			     this_choice = this_choice->next) {
				/* Add the length of the value used here. */
				groupsize /= this_choice->n_values;
				val = this_choice->values[(i / groupsize) %
							  this_choice->n_values];
				length += val->bv_len;
			}
			/* Allocate memory for this result. */
			ret[j] = malloc(length + 1);
			if (ret[j] == NULL) {
				continue;
			}
			/* Build the result's value. */
			offset = 0;
			k = 0;
			groupsize = combinations;
			for (this_choice = choices;
			     this_choice != NULL;
			     this_choice = this_choice->next) {
				/* Copy any part of the template that should be
				 * in the result by now. */
				length = (this_choice->offset - template) -
					 offset;
				memcpy(ret[j] + k, template + offset, length);
				k += length;
				offset += length;
				groupsize /= this_choice->n_values;
				val = this_choice->values[(i / groupsize) %
							  this_choice->n_values];
				memcpy(ret[j] + k, val->bv_val, val->bv_len);
				k += val->bv_len;
			}
			/* Copy any part of the template which trails the
			 * choices. */
			length = template_len - offset;
			memcpy(ret[j] + k, template + offset, length);
			ret[j][k + length] = '\0';
			(*data_lengths)[j] = k + length;
			j++;
		}
		ret[j] = NULL;
	} else {
		free(ret);
		free(*data_lengths);
		ret = NULL;
		*data_lengths = NULL;
	}
	format_free_choices(choices);
	free(template);
	return ret;
}

char *
format_escape_for_filter(const char *unescaped)
{
	int i, j, count;
	char *ret;
	for (i = 0, count = 0; unescaped[i] != 0; i++) {
		switch (unescaped[i]) {
		case '*':
		case '(':
		case ')':
		case '\\':
			count++;
			break;
		default:
			break;
		}
	}
	ret = malloc(i + (2 * count) + 1);
	if (ret != NULL) {
		for (i = 0, j = 0; unescaped[i] != 0; i++) {
			switch (unescaped[i]) {
			case '*':
				ret[j++] = '\\';
				ret[j++] = '2';
				ret[j++] = 'a';
				break;
			case '(':
				ret[j++] = '\\';
				ret[j++] = '2';
				ret[j++] = '8';
				break;
			case ')':
				ret[j++] = '\\';
				ret[j++] = '2';
				ret[j++] = '9';
				break;
			case '\\':
				ret[j++] = '\\';
				ret[j++] = '5';
				ret[j++] = 'c';
				break;
			default:
				ret[j++] = unescaped[i];
				break;
			}
		}
		ret[j] = '\0';
	}
	return ret;
}
