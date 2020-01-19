/*
 * Copyright 2013 Red Hat, Inc.
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

#ifndef back_sch_h
#define back_sch_h

enum sch_search_nsswitch_t {
	SCH_NSSWITCH_NONE = 0,
	SCH_NSSWITCH_USER,
	SCH_NSSWITCH_GROUP
};

/* The data we ask the map cache to keep, for us, for each set. */
struct backend_set_data {
	struct backend_shr_set_data common;
	/* Schema compatibility-specific data. */
	Slapi_DN *container_sdn;
	char *rdn_format;
	char **attribute_format;
	bool_t check_access;
	enum sch_search_nsswitch_t check_nsswitch;
	unsigned long nsswitch_min_id;
};

struct backend_entry_data {
	Slapi_DN *original_entry_dn;
	enum backend_entry_source {
		backend_entry_source_dit,
		backend_entry_source_nsswitch
	} source;
	Slapi_Entry *e;
};

struct backend_staged_search {
	struct backend_staged_search *next;
	char *map_group, *map_set;
	struct backend_set_data *set_data;
	enum sch_search_nsswitch_t type;
	bool_t is_id;
	bool_t is_sid; /* if search is by ipaAnchorUUID beginning with :SID:S-... */
	bool_t search_members;
	char *name;
	char *container_sdn;
	int count;
	Slapi_Entry **entries;
};

/* Entry to be send to clients is cached to allow multiple threads to re-use results.
 */
struct cached_entry {
	Slapi_Entry *entry;
	PRInt32 refcount;
	bool_t not_cached;
};

/* list of entries to actually send, sorted as a linked list
 * Entries are references to the ones stored in a cache
 * Before sending them out one needs to refcount the entry
 */
struct entries_to_send {
	struct entries_to_send *next;
	struct entries_to_send *prev;
	struct cached_entry *entry;
};

/* Intercept a search request, and if it belongs to one of our compatibility
 * trees, answer from our cache before letting the default database have a
 * crack at it. */
struct backend_search_cbdata {
	Slapi_PBlock *pb;
	struct plugin_state *state;
	char *target, *strfilter, **attrs;
	char *idview;
	Slapi_Entry **overrides;
	int scope, sizelimit, timelimit, attrsonly;
	bool_t check_access;
	enum sch_search_nsswitch_t check_nsswitch;
	Slapi_DN *target_dn;
	Slapi_Filter *filter;
	unsigned long nsswitch_min_id;
	char *nsswitch_buffer;
	ssize_t nsswitch_buffer_len;

	bool_t answer;
	int result;
	bool_t matched;
	char *closest_match, *text;
	int n_entries;
	struct backend_staged_search *staged;
	struct backend_staged_search *cur_staged;
	struct entries_to_send *entries_head;
	struct entries_to_send *entries_tail;
};

struct backend_search_filter_config {
	bool_t search_user;
	bool_t search_group;
	bool_t search_uid;
	bool_t search_gid;
	bool_t search_sid;
	bool_t search_members;
	bool_t name_set;
	bool_t wrong_search;
	bool_t override_found;
	char *name;
	/* If callback is defined, it is called on each filter after analyzing it.
	 * Return code of the callback is directly returned to slapi_filter_apply() */
	int (*callback)(Slapi_Filter *filter, const char *filter_type, struct berval *bval, struct backend_search_filter_config *config);
	void *callback_data;
};

/* OIDs of the supported extended operation */
#define EXTOP_PASSWD_OID	"1.3.6.1.4.1.4203.1.11.1"

/* ber tags for the PasswdModifyRequestValue sequence */
#define LDAP_EXTOP_PASSMOD_TAG_USERID	0x80U
#define LDAP_EXTOP_PASSMOD_TAG_OLDPWD	0x81U
#define LDAP_EXTOP_PASSMOD_TAG_NEWPWD	0x82U

typedef int (*IFP)();
static int backend_passwdmod_extop(Slapi_PBlock *pb);
typedef struct backend_extop_handlers {
    char *oid;
    IFP extop_fct;
} backend_extop_handlers_t;


/* Analyzes the filter to decide what kind of NSS search is it
 * Returns 0 on success, 1 on failure
 * struct backend_search_filter_config is populated with information about the filter
 * config.name should be freed with slapi_ch_free_string()
 */

int backend_analyze_search_filter(Slapi_Filter *filter, struct backend_search_filter_config *config);

/* Operations against nsswitch API */
struct nss_ops_ctx;
void backend_nss_init_context(struct nss_ops_ctx **nss_context);
void backend_nss_free_context(struct nss_ops_ctx **nss_context);

void backend_search_nsswitch(struct backend_set_data *set_data,
			     struct backend_search_cbdata *cbdata);

bool_t backend_retrieve_from_nsswitch(struct backend_staged_search *staged,
				      struct backend_search_cbdata *cbdata);

int backend_sch_do_pam_auth(Slapi_PBlock *pb, const char *username);

#ifdef USE_IPA_IDVIEWS
void idview_get_overrides(struct backend_search_cbdata *cbdata);
void idview_free_overrides(struct backend_search_cbdata *cbdata);
void idview_process_overrides(struct backend_search_cbdata *cbdata,
			      const char *key, const char *map, const char *domain,
			      Slapi_Entry *entry);
void idview_replace_target_dn(char **target, char **idview);
void idview_replace_filter(struct backend_search_cbdata *cbdata);
/* Takes struct berval value of an attribute attr_name and replaces it with an override
 * Returns 0 if no override was found, 1 for 'uid' replacement, 2 for ipaAnchorUUID replacement */
int  idview_replace_bval_by_override(const char *bval_usage, const char *attr_name,
				     struct berval *bval, struct backend_search_cbdata *cbdata);
#endif

#endif
