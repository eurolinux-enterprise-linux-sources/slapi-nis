/*
 * Copyright 2008,2011,2012 Red Hat, Inc.
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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rpc/rpc.h>
#include "../yp/yp.h"

#ifdef HAVE_TCPD_H
#include <tcpd.h>
#endif

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <plhash.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include "backend.h"
#include "back-shr.h"
#include "back-sch.h"
#include "map.h"
#include "plugin.h"
#include "portmap.h"
#include "wrap.h"

#define PLUGIN_ID "schema-compat-plugin"
#define PLUGIN_PREOP_ID PLUGIN_ID "-preop"
#define PLUGIN_BETXN_PREOP_ID PLUGIN_ID "-betxn_preop"
#define PLUGIN_BETXN_POSTOP_ID PLUGIN_ID "-betxn_postop"
#define PLUGIN_POSTOP_ID PLUGIN_ID "-postop"
#define PLUGIN_INTERNAL_POSTOP_ID PLUGIN_ID "-internal-postop"
#define PLUGIN_PRE_EXTOP_ID PLUGIN_ID "-extop-preop"

/* the module initialization function */
static Slapi_PluginDesc
plugin_description = {
	.spd_id = PLUGIN_ID,
	.spd_vendor = "redhat.com",
	.spd_version = PACKAGE_VERSION PACKAGE_VERSION_TXNS,
	.spd_description = "Schema Compatibility Plugin",
};
static struct plugin_state *global_plugin_state;

/* Handle the part of startup that needs to be done before we drop privileges,
 * which for this plugin isn't much at all. */
static int
plugin_state_init(Slapi_PBlock *pb, struct plugin_state **lstate)
{
	struct plugin_state *state = NULL;

	state = malloc(sizeof(*state));
	if (state == NULL) {
		return -1;
	}
	memset(state, 0, sizeof(*state));
	state->plugin_base = NULL;
	state->plugin_desc = &plugin_description;
	slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &state->plugin_identity);
	state->plugin_base = NULL;
	*lstate = state;
	return 0;
}

static int
plugin_startup(Slapi_PBlock *pb)
{
	/* Populate the maps and data. */
	struct plugin_state *state;
	Slapi_Entry *plugin_entry = NULL;
	Slapi_DN *pluginsdn = NULL;

	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
	slapi_pblock_get(pb, SLAPI_TARGET_SDN, &pluginsdn);
	/* plugin base need to be duplicated because it will be destroyed
	 * when pblock is destroyed but we need to use it in a separate thread */
	if (NULL == pluginsdn || 0 == slapi_sdn_get_ndn_len(pluginsdn)) {
        slapi_log_error(SLAPI_LOG_FATAL, state->plugin_desc->spd_id,
                        "scheman compat plugin_startup: unable to retrieve plugin DN\n");
		return -1;

    } else {
        state->plugin_base = slapi_ch_strdup(slapi_sdn_get_dn(pluginsdn));
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"configuration entry is %s%s%s\n",
				state->plugin_base ? "\"" : "",
				state->plugin_base ? state->plugin_base : "NULL",
				state->plugin_base ? "\"" : "");
    }

	state->pam_lock = wrap_new_rwlock();
	backend_nss_init_context((struct nss_ops_ctx**) &state->nss_context);
	if ((slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY, &plugin_entry) == 0) &&
	    (plugin_entry != NULL)) {
		state->use_entry_cache = backend_shr_get_vattr_boolean(state, plugin_entry,
									"slapi-entry-cache",
									1);
	}
	state->cached_entries_lock = wrap_new_rwlock();
	wrap_rwlock_wrlock(state->cached_entries_lock);
	state->cached_entries = PL_NewHashTable(0, PL_HashString, PL_CompareStrings, PL_CompareValues, 0, 0);
	wrap_rwlock_unlock(state->cached_entries_lock);
	/* Populate the tree of fake entries. */
        if (state->priming_mutex == NULL) {
            state->priming_mutex = wrap_new_mutex();
            state->start_priming_thread = 1;
        }
	backend_startup(pb, state);
	/* Note that the plugin is ready to go. */
	slapi_log_error(SLAPI_LOG_PLUGIN, plugin_description.spd_id,
			"plugin startup completed\n");
	return 0;
}

static PRIntn
remove_cached_entries_cb(PLHashEntry *he, PRIntn i, void *arg)
{
	struct cached_entry *e = (struct cached_entry*) he->value;
	if (e != NULL) {
		if (e->entry != NULL) {
			slapi_entry_free(e->entry);
		}
		slapi_ch_free((void **) &e);
	}
	return HT_ENUMERATE_REMOVE;
}

static int
plugin_shutdown(Slapi_PBlock *pb)
{
	struct plugin_state *state;
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
        backend_shutdown(state);
	map_done(state);
	wrap_free_rwlock(state->pam_lock);
	state->pam_lock = NULL;
	backend_nss_free_context((struct nss_ops_ctx**) &state->nss_context);
	if (state->cached_entries != NULL) {
		wrap_rwlock_wrlock(state->cached_entries_lock);
		PL_HashTableEnumerateEntries(state->cached_entries, remove_cached_entries_cb, NULL);
		PL_HashTableDestroy(state->cached_entries);
		state->cached_entries = NULL;
		wrap_rwlock_unlock(state->cached_entries_lock);
		wrap_free_rwlock(state->cached_entries_lock);
		state->cached_entries_lock = NULL;
	}
	if (state->plugin_base != NULL) {
		slapi_ch_free((void **)&state->plugin_base);
	}
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"plugin shutdown completed\n");
	return 0;
}
static int
schema_compat_plugin_init_extop(Slapi_PBlock *pb)
{
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, global_plugin_state);
	if (backend_init_extop(pb, global_plugin_state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				global_plugin_state->plugin_desc->spd_id,
				"error registering extop hooks\n");
		return -1;
	}
	return 0;
}

static int
schema_compat_plugin_init_preop(Slapi_PBlock *pb)
{
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, global_plugin_state);
	if (backend_init_preop(pb, global_plugin_state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				global_plugin_state->plugin_desc->spd_id,
				"error registering preoperation hooks\n");
		return -1;
	}
	return 0;
}
#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
static int
schema_compat_plugin_init_betxnpreop(Slapi_PBlock *pb)
{
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, global_plugin_state);
	if (backend_init_betxn_preop(pb, global_plugin_state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				global_plugin_state->plugin_desc->spd_id,
				"error registering preoperation hooks\n");
		return -1;
	}
	return 0;
}
static int
schema_compat_plugin_init_betxn_postop(Slapi_PBlock *pb)
{
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, global_plugin_state);
	if (backend_init_betxn_postop(pb, global_plugin_state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				global_plugin_state->plugin_desc->spd_id,
				"error registering betxn postoperation "
				"hooks\n");
		return -1;
	}
	return 0;
}
#endif
static int
schema_compat_plugin_init_postop(Slapi_PBlock *pb)
{
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, global_plugin_state);
	if (backend_init_postop(pb, global_plugin_state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				global_plugin_state->plugin_desc->spd_id,
				"error registering postoperation hooks\n");
		return -1;
	}
	return 0;
}
static int
schema_compat_plugin_init_internal_postop(Slapi_PBlock *pb)
{
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, global_plugin_state);
	if (backend_init_internal_postop(pb, global_plugin_state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				global_plugin_state->plugin_desc->spd_id,
				"error registering internal postop hooks\n");
		return -1;
	}
	return 0;
}
int
schema_compat_plugin_init(Slapi_PBlock *pb)
{
	struct plugin_state *state = NULL;
	Slapi_Entry *plugin_entry = NULL;
	int is_betxn = 0;

	/* Allocate a memory pool. */
	if (plugin_state_init(pb, &state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, plugin_description.spd_id,
				"error setting up plugin\n");
		return -1;
	}
	/* Read global configuration. */
	if ((slapi_pblock_get(pb, SLAPI_PLUGIN_CONFIG_ENTRY,
			      &plugin_entry) == 0) &&
	    (plugin_entry != NULL)) {
		is_betxn = backend_shr_get_vattr_boolean(state, plugin_entry,
							 "nsslapd-pluginbetxn",
							 DEFAULT_PLUGIN_USE_BETXNS);
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"starting with betxn support %s\n",
				is_betxn ? "enabled" : "disabled");
		state->use_be_txns = is_betxn;
	}
	/* Minimally set up our cache. */
	map_init(pb, state);
	/* Register the plugin with the server. */
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_START_FN, &plugin_startup);
	slapi_pblock_set(pb, SLAPI_PLUGIN_CLOSE_FN, &plugin_shutdown);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, state);
	/* Register the sub-plugins. */
	global_plugin_state = state;
	if (slapi_register_plugin("preoperation", TRUE,
				  "schema_compat_plugin_init_preop",
				  schema_compat_plugin_init_preop,
				  PLUGIN_PREOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering preoperation plugin\n");
		return -1;
	}
#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
	if (slapi_register_plugin("betxnpreoperation", TRUE,
				  "schema_compat_plugin_init_betxnpreop",
				  schema_compat_plugin_init_betxnpreop,
				  PLUGIN_BETXN_PREOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering betxn preoperation plugin\n");
		return -1;
	}
#endif
	if (slapi_register_plugin("postoperation", TRUE,
				  "schema_compat_plugin_init_postop",
				  schema_compat_plugin_init_postop,
				  PLUGIN_POSTOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering postoperation plugin\n");
		return -1;
	}
	if (slapi_register_plugin("internalpostoperation", TRUE,
				  "schema_compat_plugin_init_internal_postop",
				  schema_compat_plugin_init_internal_postop,
				  PLUGIN_INTERNAL_POSTOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering internal postoperation plugin\n");
		return -1;
	}
#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
	if (slapi_register_plugin("betxnpostoperation", TRUE,
				  "schema_compat_plugin_init_betxn_postop",
				  schema_compat_plugin_init_betxn_postop,
				  PLUGIN_BETXN_POSTOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering betxn postoperation plugin\n");
		return -1;
	}
#endif
	if (slapi_register_plugin("preextendedop", TRUE,
				  "schema_compat_plugin_init_extop",
				  schema_compat_plugin_init_extop,
				  PLUGIN_PRE_EXTOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering extop plugin\n");
		return -1;
	}
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"registered plugin hooks\n");
	global_plugin_state = NULL;
	/* Note that the plugin was successfully loaded. */
	slapi_log_error(SLAPI_LOG_PLUGIN, plugin_description.spd_id,
			"plugin initialized\n");
	return 0;
}
