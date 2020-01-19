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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include <rpc/xdr.h>
#ifdef HAVE_SSS_NSS_IDMAP
#include <sss_nss_idmap.h>
#endif

#include "backend.h"
#include "back-shr.h"
#include "plugin.h"
#include "map.h"
#include "back-sch.h"
#include "format.h"

static int
bvstrprefix(const struct berval *bval, const char *s)
{
	size_t len;
	int c;

	len = strlen(s);
	if (len < bval->bv_len) {
		return slapi_utf8ncasecmp((unsigned char *) bval->bv_val, (unsigned char *) s, len) != 0;
	}

	return 1;

}

static int
bvstrcasecmp(const struct berval *bval, const char *s)
{
	size_t len;
	int c;

	len = strlen(s);
	if (len == bval->bv_len) {
		return slapi_utf8ncasecmp((unsigned char *) bval->bv_val, (unsigned char *) s, len);
	}
	c = slapi_utf8ncasecmp((unsigned char *) bval->bv_val, (unsigned char *) s, MIN(bval->bv_len, len));
	if (c != 0) {
		return c;
	}
	return bval->bv_len - strlen(s);
}

/* Check simple filter to see if it has
 * (cn|uid|uidNumber|gidNumber|memberUid=<value>) or
 * (objectClass=posixGroup|shadowAccount)
 * Called by slapi_filter_apply(). */
static int
backend_search_filter_has_cn_uid(Slapi_Filter *filter, void *arg)
{
	struct backend_search_filter_config *config = arg;
	struct berval *bval;
	char *filter_type;
	int f_choice, rc;

	f_choice = slapi_filter_get_choice(filter);
	rc = slapi_filter_get_ava(filter, &filter_type, &bval);
	if ((LDAP_FILTER_EQUALITY == f_choice) && (0 == rc)) {
		if (0 == strcasecmp(filter_type, "uidNumber")) {
			config->search_uid = TRUE;
			config->name_set = TRUE;
		} else if (0 == strcasecmp(filter_type, "gidNumber")) {
			config->search_gid = TRUE;
			config->name_set = TRUE;
		} else if (0 == strcasecmp(filter_type, "uid")) {
			config->search_user = TRUE;
			config->name_set = TRUE;
		} else if (0 == strcasecmp(filter_type, "cn")) {
			config->name_set = TRUE;
		} else if (0 == strcasecmp(filter_type, "memberUid")) {
			/* memberUid is case-sensitive in RFC 2307 but uid is case-insensitive
			 * When memberUid is generated for SSSD-provided entries, it is low-cased,
			 * we need to low case the filter value to actually match it.
			 * However, we will do it only for fully qualified names as they are coming from SSSD. */
			char *memberUid = NULL;
			char *lwMemberUid = NULL;
			unsigned int i = 0;

			for (i=0; i < bval->bv_len ; i++) {
				if (bval->bv_val[i] == '@')
					break;
			}

			if (i < bval->bv_len) {
				memberUid = slapi_ch_malloc(bval->bv_len + 1);
				if (memberUid != NULL) {
					memcpy(memberUid, bval->bv_val, bval->bv_len);
					memberUid[bval->bv_len] = '\0';
					lwMemberUid = (char *) slapi_utf8StrToLower((unsigned char*) memberUid);
					if (lwMemberUid != NULL) {
						struct berval bval_lw = {0, NULL};
						bval_lw.bv_len = strlen((const char *) lwMemberUid);
						bval_lw.bv_val = lwMemberUid;
						slapi_ber_bvdone(bval);
						slapi_ber_bvcpy(bval, &bval_lw);
					}
					slapi_ch_free_string(&memberUid);
				}
				config->name_set = TRUE;
				config->search_members = TRUE;
			} else {
				/* there is no '@' in the memberUid name, it is not a trusted AD forest's user */
				config->wrong_search = TRUE;
			}
		} else if ((0 == strcasecmp(filter_type, "objectClass")) &&
			   (0 == bvstrcasecmp(bval, "posixGroup"))) {
			config->search_group = TRUE;
		} else if ((0 == strcasecmp(filter_type, "objectClass")) &&
			   (0 == bvstrcasecmp(bval, "shadowAccount"))) {
			config->wrong_search = TRUE;
#ifdef HAVE_SSS_NSS_IDMAP
#ifdef USE_IPA_IDVIEWS
		} else if ((0 == strcasecmp(filter_type, "ipaAnchorUUID")) &&
			   (0 == bvstrprefix(bval, ":SID:S-"))) {
			config->search_sid = TRUE;
			config->name_set = TRUE;
#endif
#endif
		}

		if ((NULL == config->name) && config->name_set) {
			config->name = slapi_ch_malloc(bval->bv_len + 1);
			if (config->name != NULL) {
				memcpy(config->name, bval->bv_val,
				       bval->bv_len);
				config->name[bval->bv_len] = '\0';
			}
		}
	}

	if (config->callback != NULL) {
		return config->callback(filter, filter_type, bval, config);
	}

	if ((config->search_uid ||
	     config->search_gid ||
	     config->search_user ||
	     config->search_group ||
	     config->search_sid) && (config->name != NULL)) {
		return SLAPI_FILTER_SCAN_STOP;
	}
	return SLAPI_FILTER_SCAN_CONTINUE;
}

static char *
backend_build_dn(const char *attribute, const char *value,
		 const char *container_sdn)
{
	Slapi_RDN *rdn;
	Slapi_DN *sdn;
	char *val, *dn = NULL;
	const char *ndn, *hexchars = "0123456789ABCDEF";
	int i;

	val = malloc(strlen(value) * 3 + 1);
	if (val == NULL) {
		return NULL;
	}
	rdn = slapi_rdn_new();
	if (rdn == NULL) {
		free(val);
		return NULL;
	}
        for (i = 0; value[i] != '\0'; i++) {
		val[i * 3] = '\\';
		val[i * 3 + 1] = hexchars[(value[i] & 0xf0) >> 4];
		val[i * 3 + 2] = hexchars[value[i] & 0xf];
	}
	val[i * 3] = '\0';
	if (slapi_rdn_add(rdn, attribute, val) == 1) {
		sdn = slapi_sdn_new_dn_byval(container_sdn);
		if (sdn != NULL) {
			sdn = slapi_sdn_add_rdn(sdn, rdn);
			ndn = slapi_sdn_get_ndn(sdn);
			if (ndn != NULL) {
				dn = slapi_ch_strdup(ndn);
			}
			slapi_sdn_free(&sdn);
		}
	}
	free(val);
	slapi_rdn_free(&rdn);
	return dn;
}

static Slapi_Entry *
backend_make_user_entry_from_nsswitch_passwd(struct passwd *pwd,
					     char *container_sdn,
					     struct backend_search_cbdata *cbdata)
{
	Slapi_Entry *entry;
	int rc;
	char *name;
	char *dn = NULL;
#ifdef HAVE_SSS_NSS_IDMAP
	enum sss_id_type id_type;
	char *sid_str;
#endif

	entry = slapi_entry_alloc();
	if (entry == NULL) {
		return NULL;
	}

	name = (char *) slapi_utf8StrToLower((unsigned char *) pwd->pw_name);
	if (name == NULL) {
		slapi_log_error(SLAPI_LOG_FATAL,
				cbdata->state->plugin_desc->spd_id,
				"error building DN for uid=%s,%s skipping\n",
				pwd->pw_name, container_sdn);
		slapi_entry_free(entry);
		return NULL;
	}

	dn = backend_build_dn("uid", name, container_sdn);
	if (dn == NULL) {
		slapi_log_error(SLAPI_LOG_FATAL,
				cbdata->state->plugin_desc->spd_id,
				"error building DN for uid=%s,%s skipping\n",
				name, container_sdn);
		slapi_entry_free(entry);
		return NULL;
	}

	slapi_entry_add_string(entry,
			       "objectClass", "top");
	slapi_entry_add_string(entry,
			       "objectClass", "posixAccount");
	slapi_entry_add_string(entry,
			       "uid", name);
	slapi_entry_attr_set_uint(entry,
				 "uidNumber", pwd->pw_uid);
	slapi_entry_attr_set_uint(entry,
				 "gidNumber", pwd->pw_gid);
	if (strlen(pwd->pw_gecos) > 0) {
		slapi_entry_add_string(entry,
				       "cn", pwd->pw_gecos);
		slapi_entry_add_string(entry,
				       "gecos", pwd->pw_gecos);
	} else {
		slapi_entry_add_string(entry,
				       "cn", pwd->pw_name);
		slapi_entry_add_string(entry,
				       "gecos", pwd->pw_name);
	}

	slapi_entry_add_string(entry,
			       "homeDirectory", pwd->pw_dir);
	if ((pwd->pw_shell != NULL) && (strlen(pwd->pw_shell) > 0)) {
		slapi_entry_add_string(entry,
				       "loginShell", pwd->pw_shell);
	}

	slapi_entry_set_dn(entry, dn);
	slapi_ch_free_string(&name);

#ifdef HAVE_SSS_NSS_IDMAP
	rc = sss_nss_getsidbyid(pwd->pw_uid, &sid_str, &id_type);
	if ((rc == 0) && (sid_str != NULL)) {
#ifdef USE_IPA_IDVIEWS
		char *anchor = NULL;
		/* For overrides of AD users to work correctly, we need to generate
		 * ipaAnchorUUID value so that idviews can be properly searched for the override */
		anchor = slapi_ch_smprintf(":SID:%s", sid_str);
		if (anchor != NULL) {
			slapi_entry_add_string(entry, "objectClass", "ipaOverrideTarget");
			slapi_entry_add_string(entry, "ipaAnchorUUID", anchor);
			slapi_ch_free_string(&anchor);
		}
#else
		slapi_entry_add_string(entry, "objectClass", "extensibleObject");
		slapi_entry_add_string(entry, "ipaNTSecurityIdentifier", sid_str);
#endif
		free(sid_str);
	}
#endif

	return entry;
}

/* Possible results of lookup using a nss_* function.
 * Note: don't include nss.h as its path gets overriden by NSS library */
enum nss_status
{
  NSS_STATUS_TRYAGAIN = -2,
  NSS_STATUS_UNAVAIL,
  NSS_STATUS_NOTFOUND,
  NSS_STATUS_SUCCESS,
  NSS_STATUS_RETURN
};

struct nss_ops_ctx {
	void *dl_handle;

	enum nss_status (*getpwnam_r)(const char *name, struct passwd *result,
			  char *buffer, size_t buflen, int *errnop);
	enum nss_status (*getpwuid_r)(uid_t uid, struct passwd *result,
			  char *buffer, size_t buflen, int *errnop);
	enum nss_status (*setpwent)(void);
	enum nss_status (*getpwent_r)(struct passwd *result,
			  char *buffer, size_t buflen, int *errnop);
	enum nss_status (*endpwent)(void);

	enum nss_status (*getgrnam_r)(const char *name, struct group *result,
			  char *buffer, size_t buflen, int *errnop);
	enum nss_status (*getgrgid_r)(gid_t gid, struct group *result,
			  char *buffer, size_t buflen, int *errnop);
	enum nss_status (*setgrent)(void);
	enum nss_status (*getgrent_r)(struct group *result,
			  char *buffer, size_t buflen, int *errnop);
	enum nss_status (*endgrent)(void);

	enum nss_status (*initgroups_dyn)(const char *user, gid_t group,
			      long int *start, long int *size,
			      gid_t **groups, long int limit,
			      int *errnop);
};

void backend_nss_init_context(struct nss_ops_ctx **nss_context)
{
	struct nss_ops_ctx *ctx = NULL;

	if (nss_context == NULL) {
		return;
	}

	ctx = calloc(1, sizeof(struct nss_ops_ctx));

	*nss_context = ctx;
	if (ctx == NULL) {
		return;
	}

	ctx->dl_handle = dlopen("libnss_sss.so.2", RTLD_NOW);
	if (ctx->dl_handle == NULL) {
		goto fail;
	}

	ctx->getpwnam_r = dlsym(ctx->dl_handle, "_nss_sss_getpwnam_r");
	if (ctx->getpwnam_r == NULL) {
		goto fail;
	}

	ctx->getpwuid_r = dlsym(ctx->dl_handle, "_nss_sss_getpwuid_r");
	if (ctx->getpwuid_r == NULL) {
		goto fail;
	}

	ctx->setpwent = dlsym(ctx->dl_handle, "_nss_sss_setpwent");
	if (ctx->setpwent == NULL) {
		goto fail;
	}

	ctx->getpwent_r = dlsym(ctx->dl_handle, "_nss_sss_getpwent_r");
	if (ctx->getpwent_r == NULL) {
		goto fail;
	}

	ctx->endpwent = dlsym(ctx->dl_handle, "_nss_sss_endpwent");
	if (ctx->endpwent == NULL) {
		goto fail;
	}

	ctx->getgrnam_r = dlsym(ctx->dl_handle, "_nss_sss_getgrnam_r");
	if (ctx->getgrnam_r == NULL) {
		goto fail;
	}

	ctx->getgrgid_r = dlsym(ctx->dl_handle, "_nss_sss_getgrgid_r");
	if (ctx->getgrgid_r == NULL) {
		goto fail;
	}

	ctx->setgrent = dlsym(ctx->dl_handle, "_nss_sss_setgrent");
	if (ctx->setgrent == NULL) {
		goto fail;
	}

	ctx->getgrent_r = dlsym(ctx->dl_handle, "_nss_sss_getgrent_r");
	if (ctx->getgrent_r == NULL) {
		goto fail;
	}

	ctx->endgrent = dlsym(ctx->dl_handle, "_nss_sss_endgrent");
	if (ctx->endgrent == NULL) {
		goto fail;
	}

	ctx->initgroups_dyn = dlsym(ctx->dl_handle, "_nss_sss_initgroups_dyn");
	if (ctx->initgroups_dyn == NULL) {
		goto fail;
	}

	return;

fail:
	backend_nss_free_context(nss_context);

	return;
}

void
backend_nss_free_context(struct nss_ops_ctx **nss_context)
{
	if (nss_context == NULL) {
		return;
	}

	if ((*nss_context)->dl_handle != NULL) {
		dlclose((*nss_context)->dl_handle);
	}

	free((*nss_context));
	*nss_context = NULL;
}



static Slapi_Entry **
backend_retrieve_user_entry_from_nsswitch(char *user_name, bool_t is_uid,
					  char *container_sdn,
					  struct backend_search_cbdata *cbdata,
					  int *count)
{
	struct passwd pwd, *result;
	Slapi_Entry *entry, **entries;
	enum nss_status rc;
	char *buf = NULL;
	struct nss_ops_ctx *ctx = NULL;
	int lerrno;

	ctx = cbdata->state->nss_context;

	if (ctx == NULL) {
		return NULL;
	}
repeat:
	if (cbdata->nsswitch_buffer == NULL) {
		return NULL;
	}

	if (is_uid) {
		rc = ctx->getpwuid_r((uid_t) atoll(user_name), &pwd,
				     cbdata->nsswitch_buffer,
				     cbdata->nsswitch_buffer_len, &lerrno);
	} else {
		rc = ctx->getpwnam_r(user_name, &pwd,
				     cbdata->nsswitch_buffer,
				     cbdata->nsswitch_buffer_len, &lerrno);
	}

	if ((rc != NSS_STATUS_SUCCESS)) {
		if (lerrno == ERANGE) {
			buf = realloc(cbdata->nsswitch_buffer, cbdata->nsswitch_buffer_len * 2);
			if (buf != NULL) {
				cbdata->nsswitch_buffer = buf;
				cbdata->nsswitch_buffer_len *= 2;
				goto repeat;
			}
		}
		return NULL;
	}

	if (pwd.pw_uid < cbdata->nsswitch_min_id) {
		return NULL;
	}

	entry = backend_make_user_entry_from_nsswitch_passwd(&pwd, container_sdn,
							     cbdata);
	entries = malloc(sizeof(entries[0]) * 2);
	if (entries != NULL) {
		entries[0] = entry;
		entries[1] = NULL;
		*count = 1;
	} else {
		slapi_entry_free(entry);
	}

	return entries;
}

static Slapi_Entry *
backend_make_group_entry_from_nsswitch_group(struct group *grp,
					     char *container_sdn,
					     struct backend_search_cbdata *cbdata)
{
	Slapi_Entry *entry;
	int rc, i;
	char *dn = NULL;
	char *name = NULL;
#ifdef HAVE_SSS_NSS_IDMAP
	enum sss_id_type id_type;
	char *sid_str;
#endif

	entry = slapi_entry_alloc();
	if (entry == NULL) {
		return NULL;
	}

	dn = backend_build_dn("cn", grp->gr_name, container_sdn);
	if (dn == NULL) {
		slapi_log_error(SLAPI_LOG_FATAL,
				cbdata->state->plugin_desc->spd_id,
				"error building DN for cn=%s,%s skipping\n",
				grp->gr_name, container_sdn);
		slapi_entry_free(entry);
		return NULL;
	}

	slapi_entry_add_string(entry,
			       "objectClass", "top");
	slapi_entry_add_string(entry,
			       "objectClass", "posixGroup");
	slapi_entry_add_string(entry,
			       "cn", grp->gr_name);
	slapi_entry_attr_set_uint(entry,
				 "gidNumber", grp->gr_gid);

	if (grp->gr_mem) {
		for (i=0; grp->gr_mem[i]; i++) {
			name = (char *) slapi_utf8StrToLower((unsigned char*) grp->gr_mem[i]);
			slapi_entry_add_string(entry, "memberUid", name);
			slapi_ch_free_string(&name);
		}
	}

	slapi_entry_set_dn(entry, dn);

#ifdef HAVE_SSS_NSS_IDMAP
	rc = sss_nss_getsidbyid(grp->gr_gid, &sid_str, &id_type);
	if ((rc == 0) && (sid_str != NULL)) {
#ifdef USE_IPA_IDVIEWS
		char *anchor = NULL;
		/* For overrides of AD users to work correctly, we need to generate
		 * ipaAnchorUUID value so that idviews can be properly searched for the override */
		anchor = slapi_ch_smprintf(":SID:%s", sid_str);
		if (anchor != NULL) {
			slapi_entry_add_string(entry, "objectClass", "ipaOverrideTarget");
			slapi_entry_add_string(entry, "ipaAnchorUUID", anchor);
			slapi_ch_free_string(&anchor);
		}
#else
		slapi_entry_add_string(entry, "objectClass", "extensibleObject");
		slapi_entry_add_string(entry, "ipaNTSecurityIdentifier", sid_str);
#endif
		free(sid_str);
	}
#endif
	return entry;
}

static Slapi_Entry **
backend_retrieve_group_entry_from_nsswitch(char *group_name, bool_t is_gid,
					   char *container_sdn,
					   struct backend_search_cbdata *cbdata,
					   int *count)
{
	struct group grp, *result;
	Slapi_Entry *entry, **entries;
	enum nss_status rc;
	char *buf = NULL;
	struct nss_ops_ctx *ctx = NULL;
	int lerrno = 0;

	ctx = cbdata->state->nss_context;

	if (ctx == NULL) {
		return NULL;
	}
repeat:
	if (cbdata->nsswitch_buffer == NULL) {
		return NULL;
	}

	if (is_gid) {
		rc = ctx->getgrgid_r((gid_t) atoll(group_name), &grp,
				     cbdata->nsswitch_buffer,
				     cbdata->nsswitch_buffer_len, &lerrno);
	} else {
		rc = ctx->getgrnam_r(group_name, &grp,
				     cbdata->nsswitch_buffer,
				     cbdata->nsswitch_buffer_len, &lerrno);
	}
	if ((rc != NSS_STATUS_SUCCESS)) {
		if (lerrno == ERANGE) {
			buf = realloc(cbdata->nsswitch_buffer, cbdata->nsswitch_buffer_len * 2);
			if (buf != NULL) {
				cbdata->nsswitch_buffer = buf;
				cbdata->nsswitch_buffer_len *= 2;
				goto repeat;
			}
		}
		return NULL;
	}

	if (grp.gr_gid < cbdata->nsswitch_min_id) {
		return NULL;
	}

	entry = backend_make_group_entry_from_nsswitch_group(&grp, container_sdn,
							     cbdata);
	entries = malloc(sizeof(entries[0]) * 2);
	if (entries != NULL) {
		entries[0] = entry;
		entries[1] = NULL;
		*count = 1;
	} else {
		slapi_entry_free(entry);
	}

	return entries;
}

static Slapi_Entry *
backend_retrieve_group_entry_from_nsswitch_by_gid(gid_t gid,
						  char *container_sdn,
						  struct backend_search_cbdata *cbdata)
{
	struct group grp, *result;
	Slapi_Entry *entry;
	enum nss_status rc;
	char *buf = NULL;
	struct nss_ops_ctx *ctx = NULL;
	int lerrno = 0;

	ctx = cbdata->state->nss_context;

	if (ctx == NULL) {
		return NULL;
	}
repeat:
	if (cbdata->nsswitch_buffer == NULL) {
		return NULL;
	}

	rc = ctx->getgrgid_r(gid, &grp,
			     cbdata->nsswitch_buffer,
			     cbdata->nsswitch_buffer_len, &lerrno);

	if ((rc != NSS_STATUS_SUCCESS)) {
		if (lerrno == ERANGE) {
			buf = realloc(cbdata->nsswitch_buffer, cbdata->nsswitch_buffer_len * 2);
			if (buf != NULL) {
				cbdata->nsswitch_buffer = buf;
				cbdata->nsswitch_buffer_len *= 2;
				goto repeat;
			}
		}
		return NULL;
	}

	if (grp.gr_gid < cbdata->nsswitch_min_id) {
		return NULL;
	}

	entry = backend_make_group_entry_from_nsswitch_group(&grp, container_sdn,
							     cbdata);

	return entry;
}

static Slapi_Entry **
backend_retrieve_group_list_from_nsswitch(char *user_name, char *container_sdn,
					  struct backend_search_cbdata *cbdata,
					  int *count)
{
	struct passwd pwd, *pwd_result;
	gid_t *grouplist, *tmp_list;
	Slapi_Entry **entries, *entry, **tmp;
	char *buf = NULL;
	int i, idx;
	struct nss_ops_ctx *ctx = NULL;
	int lerrno = 0;
	long int ngroups = 0;
	long int start = 0;
	enum nss_status rc;

	ctx = cbdata->state->nss_context;
	if (ctx == NULL) {
		return NULL;
	}
repeat:
	if (cbdata->nsswitch_buffer == NULL) {
		return NULL;
	}

	rc = ctx->getpwnam_r(user_name, &pwd,
			     cbdata->nsswitch_buffer,
			     cbdata->nsswitch_buffer_len, &lerrno);

	if ((rc != NSS_STATUS_SUCCESS)) {
		if (lerrno == ERANGE) {
			buf = realloc(cbdata->nsswitch_buffer, cbdata->nsswitch_buffer_len * 2);
			if (buf != NULL) {
				cbdata->nsswitch_buffer = buf;
				cbdata->nsswitch_buffer_len *= 2;
				goto repeat;
			}
		}
		return NULL;
	}

	if (pwd.pw_uid < cbdata->nsswitch_min_id) {
		return NULL;
	}

	ngroups = 32;
	start = 0;
	grouplist = malloc(sizeof(gid_t) * ngroups);
	if (grouplist == NULL) {
		return NULL;
	}

	grouplist[0] = pwd.pw_gid;
	start++;

	do {
		rc = ctx->initgroups_dyn(user_name, pwd.pw_gid,
					 &start, &ngroups, &grouplist,
					 -1, &lerrno);
		if ((rc != NSS_STATUS_SUCCESS)) {
			tmp_list = realloc(grouplist, ngroups * sizeof(gid_t));
			if (tmp_list == NULL) {
				free(grouplist);
				return NULL;
			}
			grouplist = tmp_list;
		}
	} while (rc != NSS_STATUS_SUCCESS);

	entries = calloc(ngroups + 1, sizeof(entries[0]));
	if (entries == NULL) {
		free(grouplist);
		return NULL;
	}

	idx = 0;
	/* At this point we are not interested in the buffer used in pwd anymore
	 * so the next function can take it over for getgrid_r()  */
	for (i = 0; i < ngroups; i++) {
		entry = backend_retrieve_group_entry_from_nsswitch_by_gid(grouplist[i], container_sdn, cbdata);
		if (entry != NULL) {
			entries[idx] = entry;
			idx++;
			entries[idx] = NULL;
		}
	}

	if (idx != ngroups) {
		tmp = realloc(entries, (idx + 1) * sizeof(entries[0]));
		if (tmp != NULL) {
			entries = tmp;
		}
	}

	*count = 0;
	if (entries != NULL) {
		*count = idx;
	}

	free(grouplist);

	return entries;
}

const char *
nsswitch_type_to_name(enum sch_search_nsswitch_t type)
{
	switch (type) {
	case SCH_NSSWITCH_USER:
		return "user";
		break;
	case SCH_NSSWITCH_GROUP:
		return "group";
		break;
	case SCH_NSSWITCH_NONE:
		return "none(?)";
		break;
	}
	return "(unknown)";
}

int
backend_analyze_search_filter(Slapi_Filter *filter, struct backend_search_filter_config *config)
{
	int result, rc;
	result = slapi_filter_apply(filter,
				    backend_search_filter_has_cn_uid,
				    config, &rc);
	return (result != SLAPI_FILTER_SCAN_STOP) ? 1 : 0;
}

/* Check if the filter is one (like uid=<value>) that should trigger an
 * nsswitch lookup, and if it is, make a note that we should perform such a
 * lookup. */
void
backend_search_nsswitch(struct backend_set_data *set_data,
			struct backend_search_cbdata *cbdata)
{
	int result, rc;
	struct backend_search_filter_config config =
		{FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, NULL, NULL, NULL};
	struct backend_staged_search *staged = NULL;
	char *idptr = NULL;
	unsigned long id;

	/* First, we search the filter to see if it includes a cn|uid=<value> test. */
	result = backend_analyze_search_filter(cbdata->filter, &config);
	if (result != 0) {
		return;
	}

	if (NULL == config.name) {
		return;
	}

	if (config.wrong_search) {
		goto fail;
	}

	/* Drop irrelevant requests. Each set only works with a single type */
	if ((cbdata->check_nsswitch == SCH_NSSWITCH_GROUP) &&
	    (config.search_uid || config.search_user)) {
		goto fail;
	}

	if ((cbdata->check_nsswitch == SCH_NSSWITCH_USER) &&
	    (config.search_gid || config.search_group)) {
		goto fail;
	}

	if ((config.search_gid || config.search_uid)) {
		errno = 0;
		id = strtoul(config.name, &idptr, 10);
		if ((errno != 0) || ((idptr != NULL) && (*idptr != '\0'))) {
			goto fail;
		}
		if (id < cbdata->nsswitch_min_id) {
			goto fail;
		}
	}

	staged = malloc(sizeof(*staged));
	if (staged == NULL) {
		goto fail;
	}

	staged->map_group = slapi_ch_strdup(set_data->common.group);
	staged->map_set = slapi_ch_strdup(set_data->common.set);
	staged->set_data = NULL;
	staged->count = 0;
	staged->entries = NULL;

	staged->container_sdn = slapi_ch_strdup(slapi_sdn_get_dn(set_data->container_sdn));

	staged->type = cbdata->check_nsswitch;
	staged->name = config.name; /* takes ownership */
	staged->is_id = config.search_gid || config.search_uid;
	staged->is_sid = config.search_sid;
	staged->search_members = config.search_members;

	staged->next = cbdata->staged;
	cbdata->staged = staged;

	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata->state->plugin_desc->spd_id,
			"staged nsswitch %s search for %s/%s/%s\n",
			nsswitch_type_to_name(staged->type),
			staged->map_group, staged->map_set,
			staged->name);
	return;

fail:
	slapi_ch_free_string(&config.name);
	return;
}

 /* Actually look up the information that we previously noted that we should,
  * then convert whatever we find into one or more Slapi_Entry pointers. */
bool_t
backend_retrieve_from_nsswitch(struct backend_staged_search *staged,
			       struct backend_search_cbdata *cbdata)
{
	Slapi_Entry **entries;

#ifdef HAVE_SSS_NSS_IDMAP
	if (staged->is_sid) {
		char *name = NULL;
		enum sss_id_type id_type;
		/* we expect name to be a SID prefixed with :SID: */
		int result = sss_nss_getnamebysid(staged->name+5, &name, &id_type);
		if  (result == 0) {
			staged->is_sid = FALSE;
			staged->is_id = FALSE;

			slapi_ch_free_string(&staged->name);
			staged->name = slapi_ch_strdup(name);
			free(name);
		}
	}
#endif

	if (((staged->type == SCH_NSSWITCH_GROUP) && staged->search_members) &&
	    (NULL != staged->name)) {
		entries = backend_retrieve_group_list_from_nsswitch(staged->name, staged->container_sdn,
								    cbdata, &staged->count);
		if (entries != NULL) {
			staged->entries = entries;
			return TRUE;
		}
		return FALSE;
	}

	if ((staged->type == SCH_NSSWITCH_GROUP) && (NULL != staged->name)) {
		entries = backend_retrieve_group_entry_from_nsswitch(staged->name, staged->is_id,
							             staged->container_sdn,
							             cbdata, &staged->count);
		if (entries != NULL) {
			staged->entries = entries;
			return TRUE;
		}
		return FALSE;
	}

	if ((staged->type == SCH_NSSWITCH_USER) && (NULL != staged->name)) {
		entries = backend_retrieve_user_entry_from_nsswitch(staged->name, staged->is_id,
							            staged->container_sdn,
							            cbdata, &staged->count);
		if (entries != NULL) {
			staged->entries = entries;
			return TRUE;
		}
		return FALSE;
	}

	return FALSE;
}
