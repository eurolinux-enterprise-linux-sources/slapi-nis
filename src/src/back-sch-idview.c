/*
 * Copyright 2014 Red Hat, Inc.
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
#include "back-shr.h"
#include "format.h"
#include "plugin.h"
#include "map.h"
#include "back-sch.h"

void
idview_get_overrides(struct backend_search_cbdata *cbdata)
{
	char *dn = NULL;
	int ret = 0, result = 0;
	const Slapi_DN *suffix = NULL;
	Slapi_PBlock *pb;

	if (cbdata->idview == NULL)
		return;

	pb = wrap_pblock_new(cbdata->pb);
	if (pb == NULL)
		return;

	wrap_inc_call_level();

	suffix = slapi_get_suffix_by_dn(cbdata->target_dn);
	dn = slapi_ch_smprintf("cn=%s,cn=views,cn=accounts,%s", cbdata->idview, slapi_sdn_get_dn(suffix));
	/* Fetch all attributes; there is a bug in 389-ds: it gives out all attributes for the entry anyway
	 * when search returns Slapi_Entry* objects. Instead, we'll do removal later */
	slapi_search_internal_set_pb(pb, dn, LDAP_SCOPE_SUBTREE,
				     "(objectclass=ipaOverrideAnchor)", NULL, 0,
				     NULL, NULL, cbdata->state->plugin_identity, 0);
	ret = slapi_search_internal_pb(pb);
	slapi_ch_free_string(&dn);
	slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_RESULT, &result);

	if (result == 0) {
		/* Steal search result entries to avoid re-allocating them */
		slapi_pblock_get(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, &(cbdata->overrides));
		slapi_pblock_set(pb, SLAPI_PLUGIN_INTOP_SEARCH_ENTRIES, NULL);
	}

	wrap_dec_call_level();
	slapi_pblock_destroy(pb);
}

void
idview_free_overrides(struct backend_search_cbdata *cbdata)
{
	int i = 0;
	if (cbdata->overrides != NULL) {
		for(i=0; cbdata->overrides[i] != NULL; i++) {
			slapi_entry_free(cbdata->overrides[i]);
		}
		slapi_ch_free((void**)&(cbdata->overrides));
	}
}

void
idview_process_overrides(struct backend_search_cbdata *cbdata,
		       const char *key, const char *map, const char *domain,
		       Slapi_Entry *entry)
{
#define VIEW_TEMPLATE_KEY_MAP_DOMAIN 0
#define VIEW_TEMPLATE_KEY_MAP_DOMAIN_NEWKEY 3
#define VIEW_TEMPLATE_MAP_DOMAIN 1
#define VIEW_TEMPLATE_DOMAIN 2
	/* After view was applied, entry's DN needs to reflect the view */
	const char *dn_template[] = {"%s,%s,cn=%s,cn=views,%s",    /* an entry for user or group */
				     "%s,cn=%s,cn=views,%s",       /* an entry for a map (container for users or groups) */
				     "cn=%s,cn=views,%s",          /* an entry is a base of the compat tree */
				     "%s=%s,%s,cn=%s,cn=views,%s", /* an entry for user or group which RDN was overridden with new value */
                                    };
	const char *filterout_attrs[] = {"objectclass", "creatorsname", "modifiersname",
					 "createtimestamp", "modifytimestamp", "parentid",
					 "entryusn", "entryid", "entrydn", "ipaoriginaluid",
					 "ipaanchoruuid", "nsuniqueid", "ipasshpubkey", NULL };
	char *new_dn = NULL, *new_key = NULL, *sep = NULL, *new_val = NULL;
	char *override_type = NULL;
	Slapi_Entry *override_entry = NULL;
	Slapi_Attr *anchor = NULL, *id_attr = NULL;
	Slapi_Value *anchor_value = NULL, *id_value = NULL;
	int i, result, dn_template_id;

	if (cbdata->overrides == NULL) {
		/* Only retrieve overrides for the view first time when neccessary */
		idview_get_overrides(cbdata);
		if (cbdata->overrides == NULL)
			return;
	}

	/* 1. See if the entry has ipaAnchorUUID and selected idview has an override for it */
	/* The code below intentionally uses Slapi_Value instead of comparing string values to
	 * avoid allocating additional memory */
	result = slapi_entry_attr_find(entry, IPA_IDVIEWS_ATTR_ANCHORUUID, &anchor);
	if ((result == 0) && (anchor != NULL) && (cbdata->overrides != NULL)) {
		result = slapi_attr_first_value(anchor, &anchor_value);
		for(i = 0; cbdata->overrides[i] != NULL; i++) {
			result = slapi_entry_attr_find(cbdata->overrides[i], IPA_IDVIEWS_ATTR_ANCHORUUID, &id_attr);
			if ((result == 0) && (id_attr != NULL)) {
				result = slapi_attr_first_value(id_attr, &id_value);
				result = slapi_value_compare(id_attr, anchor_value, id_value);
				if (result == 0) {
					override_entry = cbdata->overrides[i];
					break;
				}
			}
		}
	}

	/* 2. If there is indeed an override, replace attribute values except for the ones that should be ignored */
	if (override_entry != NULL) {
		Slapi_Attr  *override_attr = NULL;
		Slapi_Attr  *sattr = NULL;

		result = slapi_entry_first_attr(override_entry, &override_attr);
		while (result == 0) {
			Slapi_ValueSet *override_valueset = NULL;

			/* Filter out override attributes that we don't care about */
			result = slapi_attr_get_type(override_attr, &override_type);
			for (i = 0; filterout_attrs[i] != NULL; i++) {
				if (strcasecmp(override_type, filterout_attrs[i]) == 0) {
					break;
				}
			}

			if (filterout_attrs[i] == NULL) {
				/* Replace the attribute's value with the override or
				 * add an override value if the attribute didn't exist */
				result = slapi_entry_attr_find(entry, override_type, &sattr);
				if (result == 0) {
					result = slapi_entry_attr_delete(entry, override_type);
				}
				result = slapi_attr_get_valueset(override_attr, &override_valueset);
				result = slapi_entry_add_valueset(entry, override_type, override_valueset);
			}
			result = slapi_entry_next_attr(override_entry, override_attr, &override_attr);
		}
	}

	/* 3. If entry has memberUid, we need to replace memberUid values too, if they were overridden */
	override_type = "memberUid";
	result = slapi_entry_attr_find(entry, override_type, &anchor);
	if ((result == 0) && (anchor != NULL) && (cbdata->overrides != NULL)) {
		int value_idx = 0;
		Slapi_ValueSet *new_valueset = slapi_valueset_new();

		if (new_valueset != NULL) {
			/* For each memberUid value, find an override with ipaOriginalUid attribute of the same value */
			value_idx = slapi_attr_first_value(anchor, &anchor_value);
			while (value_idx != -1) {
				bool_t value_found = FALSE;
				for(i = 0; cbdata->overrides[i] != NULL; i++) {
					result = slapi_entry_attr_find(cbdata->overrides[i], IPA_IDVIEWS_ATTR_ORIGINALUID, &id_attr);
					if ((result == 0) && (id_attr != NULL)) {
						result = slapi_attr_first_value(id_attr, &id_value);
						result = slapi_value_compare(id_attr, anchor_value, id_value);
						if (result == 0) {
							/* If there is an override with ipaOriginalUid: <memberUid value>, use its 'uid' value to override */
							result = slapi_entry_attr_find(cbdata->overrides[i], "uid", &id_attr);
							if ((result == 0) && (id_attr != NULL)) {
								result = slapi_attr_first_value(id_attr, &id_value);
								if (result == 0) {
									/* finally: we have an override with ipaOriginalUid: <memberUid value> _and_
									 * this override is changing the 'uid' attribute so we have something to replace */
									slapi_valueset_add_value(new_valueset, id_value);
									value_found = TRUE;
									break;
								}
							}
						}
					}
				}

				if (value_found == FALSE) {
					slapi_valueset_add_value(new_valueset, anchor_value);
				}
				value_idx = slapi_attr_next_value(anchor, value_idx, &anchor_value);
			}

			result = slapi_entry_attr_delete(entry, override_type);
			result = slapi_entry_add_valueset(entry, override_type, new_valueset);
			slapi_valueset_free(new_valueset);
		}
	}

	/* 4. Even if there were no overrides, since we are serving throught the view, replace DN value */
	dn_template_id = (key == NULL ? 1 : 0) + (map == NULL ? 1 : 0);
	switch (dn_template_id) {
		case VIEW_TEMPLATE_KEY_MAP_DOMAIN:
			/* update RDN with proper value from the entry after overrides were applied */
			sep = strchr(key, '=');
			if (sep != NULL) {
				sep[0] = '\0';
				new_val = slapi_entry_attr_get_charptr(entry, key);
				new_dn = slapi_ch_smprintf(dn_template[VIEW_TEMPLATE_KEY_MAP_DOMAIN_NEWKEY], key, new_val, map, cbdata->idview, domain);
				slapi_ch_free_string(&new_val);
				sep[0] = '=';
			} else {
				new_dn = slapi_ch_smprintf(dn_template[dn_template_id], key, map, cbdata->idview, domain);
			}
			break;
		case VIEW_TEMPLATE_MAP_DOMAIN:
			new_dn = slapi_ch_smprintf(dn_template[dn_template_id], map, cbdata->idview, domain);
			break;
		case VIEW_TEMPLATE_DOMAIN:
			new_dn = slapi_ch_smprintf(dn_template[dn_template_id], cbdata->idview, domain);
			break;
	};
	slapi_entry_set_dn(entry, new_dn);
}

void
idview_replace_target_dn(char **target, char **idview)
{
	char *idview_p = NULL;
	char *cnviews = NULL;
	char *new_target = NULL;

	cnviews = strstr(*target, ",cn=views,");
	if (cnviews != NULL && cnviews != *target) {
		cnviews[0] = '\0';
		idview_p = strrchr(*target, ',');
		if (idview_p == NULL) {
			idview_p = *target;
		} else {
			idview_p++;
		}
		if (strstr(idview_p, "cn=") != idview_p) {
			cnviews[0] = ',';
			return;
		}
		*idview = slapi_ch_strdup(&idview_p[3]);
		if (idview_p !=  *target) {
			idview_p[0] = '\0';
			new_target = slapi_ch_smprintf("%s%s", *target, cnviews+10);
			idview_p--;
			idview_p[0] = ',';
		} else {
			new_target = slapi_ch_smprintf("%s", cnviews+10);
		}
		cnviews[0] = ',';
		*target = new_target;
	}
}

int
idview_replace_bval_by_override(const char *bval_usage, const char *attr_name,
				struct berval *bval, struct backend_search_cbdata *cbdata)
{
	int res, i;
	Slapi_Value *attr_val, *value, *anchor_val;
	Slapi_Attr *anchor, *attr = NULL;
	bool_t uid_override_found = FALSE;
	bool_t anchor_override_found = FALSE;

	if (cbdata->overrides == NULL) {
		/* Only retrieve overrides for the view first time when neccessary */
		idview_get_overrides(cbdata);
	}

	if (cbdata->overrides == NULL) {
		return 0;
	}

	attr_val = slapi_value_new_berval(bval);
	slapi_log_error(SLAPI_LOG_PLUGIN, cbdata->state->plugin_desc->spd_id,
			"Searching for an override of the %s %s with %s=%*s from the overrides\n.",
			bval_usage, attr_name, attr_name, (int) bval->bv_len, bval->bv_val);

	/* If filter contains an attribute name which is overridden in the view and filter value
	 * corresponds to the override, replace the filter by (ipaAnchorUUID=...) from the override
	 * to point to the original because otherwise an entry will not be found in the slapi-nis map */
	for(i=0; cbdata->overrides[i] != NULL; i++) {
		res = slapi_entry_attr_find(cbdata->overrides[i], attr_name, &attr);
		if ((res == 0) && (attr != NULL)) {
			res = slapi_attr_first_value(attr, &value);
			res = slapi_value_compare(attr, value, attr_val);
			if (res == 0) {
				/* For uid overrides we should have ipaOriginalUID in the override */
				if (strcasecmp(attr_name, "uid") == 0) {
					res = slapi_entry_attr_find(cbdata->overrides[i], IPA_IDVIEWS_ATTR_ORIGINALUID, &anchor);
					if (res == 0) {
						res = slapi_attr_first_value(anchor, &anchor_val);
						slapi_ber_bvdone(bval);
						slapi_ber_bvcpy(bval, slapi_value_get_berval(anchor_val));
						uid_override_found = TRUE;
						slapi_log_error(SLAPI_LOG_FATAL, cbdata->state->plugin_desc->spd_id,
								"Overriding the %s %s with %s=%*s from the override %s\n.",
								bval_usage, attr_name, attr_name, (int) bval->bv_len, bval->bv_val,
								slapi_entry_get_dn_const(cbdata->overrides[i]));
						break;
					}
				}

				/* otherwise, use ipaAnchorUUID value */
				res = slapi_entry_attr_find(cbdata->overrides[i], IPA_IDVIEWS_ATTR_ANCHORUUID, &anchor);
				if (res == 0) {
					res = slapi_attr_first_value(anchor, &anchor_val);
					slapi_ber_bvdone(bval);
					slapi_ber_bvcpy(bval, slapi_value_get_berval(anchor_val));
					anchor_override_found = TRUE;
					slapi_log_error(SLAPI_LOG_PLUGIN, cbdata->state->plugin_desc->spd_id,
							"Overriding the %s %s with %s=%*s from the override %s\n.",
							bval_usage, attr_name, IPA_IDVIEWS_ATTR_ANCHORUUID,
							(int) bval->bv_len, bval->bv_val,
							slapi_entry_get_dn_const(cbdata->overrides[i]));
					break;
				}

			}
		}
	}

	slapi_value_free(&attr_val);

	if (uid_override_found) {
		return 1;
	}

	if (anchor_override_found) {
		return 2;
	}

	return 0;
}

static int
idview_process_filter_cb(Slapi_Filter *filter, const char *filter_type,
			 struct berval *bval, struct backend_search_filter_config *config)
{
	int res;
	struct backend_search_cbdata *cbdata = (struct backend_search_cbdata *) config->callback_data;

	if (cbdata == NULL || cbdata->idview == NULL) {
		return SLAPI_FILTER_SCAN_CONTINUE;
	}

	if (filter_type == NULL || config->name == NULL) {
		return SLAPI_FILTER_SCAN_CONTINUE;
	}

	res = idview_replace_bval_by_override("filter", filter_type, bval, cbdata);

	if (res == 2) {
		slapi_filter_changetype(filter, IPA_IDVIEWS_ATTR_ANCHORUUID);
	}

	config->override_found = (res != 0);

	return SLAPI_FILTER_SCAN_CONTINUE;

}

/* Traverse through the filter and replace overridden attribute/value pairs with references to the original
 * entries. This allows to properly handle overrides of uid and cn attributes where searches look like
 * (&(objectclass=posixAccount)(uid=foobar)) -- if uid=foobar is part of an override for uid=admin, we need
 * to point back to uid=admin to be able to find original entry in the slapi-nis cache.
 *
 * Note that in reality we don't use original value of the uid/cn attribue. Instead, we use ipaAnchorUUID
 * to refer to the original entry. */
void
idview_replace_filter(struct backend_search_cbdata *cbdata)
{
	struct backend_search_filter_config config =
		{FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, FALSE, NULL, NULL, NULL};
	int res = 0;

	if (cbdata->idview == NULL) {
		return;
	}

	config.callback = idview_process_filter_cb;
	config.callback_data = cbdata;

	/* Ignore the return code as it will always be SLAPI_FILTER_SCAN_NO_MORE */
	res = backend_analyze_search_filter(cbdata->filter, &config);

	if (config.name != NULL) {
		slapi_ch_free_string(&config.name);
	}

}
