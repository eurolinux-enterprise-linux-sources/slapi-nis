/*
 * Copyright 2008,2011,2013 Red Hat, Inc.
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
#include <sys/uio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include <rpc/rpc.h>
#include "../yp/yp.h"

#include "disp-nis.h"
#include "map.h"
#include "nis.h"
#include "plugin.h"

/* Indicate whether or not we serve the specified domain.  We handle both the
 * normal and nonack case by letting the caller tell us which of the two types
 * of requests is being handled. */
static void
nis_domain(struct plugin_state *state,
	   dispatch_reply_fragment *reply_fragment_fn,
	   dispatch_reply *reply_fn,
	   struct dispatch_client_data *cdata,
	   XDR *request_xdrs, bool_t reply_on_failure,
	   struct rpc_msg *reply, XDR *reply_xdrs,
	   bool_t *reply_bool)
{
	char *domain = NULL;
	*reply_bool = FALSE;
	if (xdr_string(request_xdrs, &domain, YPMAXDOMAIN)) {
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"domain(%s) -> lock error (no reply)\n",
					domain);
			goto done_with_lock;
		}
		map_supports_domain(state, domain, reply_bool);
		if (*reply_bool || reply_on_failure) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"domain(%s) -> %s\n",
					domain, *reply_bool ? "TRUE" : "FALSE");
			(*reply_fn)(state, cdata, reply, reply_xdrs);
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"domain(%s) -> %s (no reply)\n",
					domain, *reply_bool ? "TRUE" : "FALSE");
		}
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_string, (char *) &domain);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"argument parsing error\n");
		/* XXX */
	}
}

/* Search for a single entry in a NIS map. */
static void
nis_match(struct plugin_state *state,
	  dispatch_reply_fragment *reply_fragment_fn,
	  dispatch_reply *reply_fn,
	  struct dispatch_client_data *cdata,
	  XDR *request_xdrs, bool_t client_secure,
	  struct rpc_msg *reply, XDR *reply_xdrs,
	  struct ypresp_val *reply_val)
{
	struct ypreq_key req_key;
	bool_t map_supported, map_secure;
	const char *entry_id;

	memset(&req_key, 0, sizeof(req_key));
	memset(reply_val, 0, sizeof(*reply_val));
	if (xdr_ypreq_key(request_xdrs, &req_key)) {
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"match(%s/%s/%.*s) -> "
					"lock error (no reply)\n",
					req_key.domain, req_key.map,
					(int) req_key.key.keydat_len,
					req_key.key.keydat_val);
			goto done_with_lock;
		}
		if (map_match(state, req_key.domain, req_key.map, &map_secure,
			      req_key.key.keydat_len,
			      req_key.key.keydat_val,
			      &reply_val->val.valdat_len,
			      (const char **) &reply_val->val.valdat_val,
			      &entry_id, NULL) &&
		    (client_secure || !map_secure)) {
			/* Success! */
			reply_val->stat = YP_TRUE;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"match(%s/%s/%.*s) -> %d\n",
					req_key.domain,
					req_key.map,
					(int) req_key.key.keydat_len,
					req_key.key.keydat_val,
					reply_val->stat);
		} else {
			/* Distinguish between no-such-key and no-such-map for
			 * reporting the error.  We're making maps which the
			 * client isn't allowed to read appear to be empty. */
			map_supported = FALSE;
			map_supports_map(state, req_key.domain, req_key.map,
					 &map_supported, NULL);
			reply_val->stat = map_supported ? YP_NOKEY : YP_NOMAP;
		}
		(*reply_fn)(state, cdata, reply, reply_xdrs);
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_ypreq_key, (char *) &req_key);
	} else {
		/* XXX */
	}
}

/* Read the first entry in a given map. */
static void
nis_first(struct plugin_state *state,
	  dispatch_reply_fragment *reply_fragment_fn,
	  dispatch_reply *reply_fn,
	  struct dispatch_client_data *cdata,
	  XDR *request_xdrs, bool_t client_secure,
	  struct rpc_msg *reply, XDR *reply_xdrs,
	  struct ypresp_key_val *reply_key_val)
{
	struct ypreq_nokey req_nokey;
	bool_t map_supported, map_secure;
	const char *entry_id;
	int entry_key_index;

	memset(&req_nokey, 0, sizeof(req_nokey));
	memset(reply_key_val, 0, sizeof(*reply_key_val));
	if (xdr_ypreq_nokey(request_xdrs, &req_nokey)) {
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"first(%s/%s) -> "
					"lock error (no reply)\n",
					req_nokey.domain, req_nokey.map);
			goto done_with_lock;
		}
		if (map_first(state, req_nokey.domain, req_nokey.map,
			      &map_secure,
			      &reply_key_val->key.keydat_len,
			      &reply_key_val->key.keydat_val,
			      &reply_key_val->val.valdat_len,
			      &reply_key_val->val.valdat_val,
			      &entry_id, &entry_key_index) &&
		    (client_secure || !map_secure)) {
			/* Success! */
			reply_key_val->stat = YP_TRUE;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"first(%s/%s) -> %d\n",
					req_nokey.domain,
					req_nokey.map,
					reply_key_val->stat);
		} else {
			/* Distinguish between no-such-key and no-such-map for
			 * reporting the error.  We're making maps which the
			 * client isn't allowed to read appear to be empty. */
			map_supported = FALSE;
			map_supports_map(state, req_nokey.domain, req_nokey.map,
					 &map_supported, NULL);
			reply_key_val->stat = map_supported ? YP_NOKEY :
							      YP_NOMAP;
		}
		(*reply_fn)(state, cdata, reply, reply_xdrs);
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_ypreq_nokey, (char *) &req_nokey);
	} else {
		/* XXX */
	}
}

/* Find the key and value which follow the passed-in key. */
static void
nis_next(struct plugin_state *state,
	 dispatch_reply_fragment *reply_fragment_fn,
	 dispatch_reply *reply_fn,
	 struct dispatch_client_data *cdata,
	 XDR *request_xdrs, bool_t client_secure,
	 struct rpc_msg *reply, XDR *reply_xdrs,
	 struct ypresp_key_val *reply_key_val)
{
	struct ypreq_key req_key;
	const char *entry_id;
	bool_t map_secure, map_supported;
	memset(&req_key, 0, sizeof(req_key));
	memset(reply_key_val, 0, sizeof(*reply_key_val));
	if (xdr_ypreq_key(request_xdrs, &req_key)) {
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"next(%s/%s/%.*s) -> "
					"lock error (no reply)\n",
					req_key.domain, req_key.map,
					req_key.key.keydat_len,
					req_key.key.keydat_val);
			goto done_with_lock;
		}
		if (map_next(state, req_key.domain, req_key.map, &map_secure,
			     req_key.key.keydat_len,
			     req_key.key.keydat_val,
			     &reply_key_val->key.keydat_len,
			     &reply_key_val->key.keydat_val,
			     &reply_key_val->val.valdat_len,
			     &reply_key_val->val.valdat_val) &&
		    (client_secure || !map_secure)) {
			/* Success! */
			reply_key_val->stat = YP_TRUE;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"next(%s/%s/%.*s) -> %d\n",
					req_key.domain,
					req_key.map,
					req_key.key.keydat_len,
					req_key.key.keydat_val,
					reply_key_val->stat);
		} else {
			/* Distinguish between no-next-key and no-this-key for
			 * reporting the error so that the client can know when
			 * to stop.  We're making maps which the client isn't
			 * allowed to read appear to be empty. */
			if (map_match(state, req_key.domain, req_key.map,
				      &map_secure,
				      req_key.key.keydat_len,
				      req_key.key.keydat_val,
				      &reply_key_val->val.valdat_len,
				      (const char **) &reply_key_val->val.valdat_val,
				      &entry_id, NULL) &&
			    (client_secure || !map_secure)) {
				/* Have data for this key, but not the next. */
				reply_key_val->stat = YP_NOMORE;
				map_supported = TRUE;
			} else {
				/* No data for this key. Check if we even have
				 * a map by that name, just to be sure. */
				map_supported = FALSE;
				map_supports_map(state,
						 req_key.domain,
						 req_key.map,
						 &map_supported, NULL);
				reply_key_val->stat = map_supported ?
						      YP_NOKEY : YP_NOMAP;
			}
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"next(%s/%s/%.*s) -> no %s!\n",
					req_key.domain,
					req_key.map,
					req_key.key.keydat_len,
					req_key.key.keydat_val,
					map_supported ? "more" : "map");
		}
		(*reply_fn)(state, cdata, reply, reply_xdrs);
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_ypreq_key, (char *) &req_key);
	} else {
		/* XXX */
	}
}

/* Return information about where we think this map is maintained: here, of
 * course. */
static void
nis_master(struct plugin_state *state,
	   dispatch_reply_fragment *reply_fragment_fn,
	   dispatch_reply *reply_fn,
	   struct dispatch_client_data *cdata,
	   XDR *request_xdrs,
	   struct rpc_msg *reply, XDR *reply_xdrs,
	   struct ypresp_master *reply_master)
{
	struct ypreq_nokey req_nokey;
	bool_t supported;
	const char *master;
	memset(&req_nokey, 0, sizeof(req_nokey));
	memset(reply_master, 0, sizeof(*reply_master));
	if (xdr_ypreq_nokey(request_xdrs, &req_nokey)) {
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"master(%s/%s) -> "
					"lock error (no reply)\n",
					req_nokey.domain, req_nokey.map);
			goto done_with_lock;
		}
		if (map_supports_domain(state, req_nokey.domain, &supported) &&
		    supported) {
			if (map_supports_map(state,
					     req_nokey.domain, req_nokey.map,
					     &supported, NULL) &&
			    supported) {
				reply_master->stat = YP_TRUE;
				if (map_master_name(state, &master) != 0) {
					master = "localhost";
				}
				reply_master->peer = (char *) master;
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"master(%s/%s) -> %s\n",
						req_nokey.domain,
						req_nokey.map,
						reply_master->peer);
			} else {
				reply_master->stat = YP_NOMAP;
				reply_master->peer = NULL;
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"master(%s/%s) -> no-map\n",
						req_nokey.domain,
						req_nokey.map);
			}
		} else {
			reply_master->stat = YP_NODOM;
			reply_master->peer = NULL;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"master(%s/%s) -> no-domain\n",
					req_nokey.domain,
					req_nokey.map);
		}
		(*reply_fn)(state, cdata, reply, reply_xdrs);
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_ypreq_nokey, (char *) &req_nokey);
	} else {
		/* XXX */
	}
}

/* Return the time the map was last changed. */
static void
nis_order(struct plugin_state *state,
	  dispatch_reply_fragment *reply_fragment_fn,
	  dispatch_reply *reply_fn,
	  struct dispatch_client_data *cdata,
	  XDR *request_xdrs, bool_t client_secure,
	  struct rpc_msg *reply, XDR *reply_xdrs,
	  struct ypresp_order *reply_order)
{
	struct ypreq_nokey req_nokey;
	bool_t map_secure;
	memset(&req_nokey, 0, sizeof(req_nokey));
	memset(reply_order, 0, sizeof(*reply_order));
	if (xdr_ypreq_nokey(request_xdrs, &req_nokey)) {
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"order(%s/%s) -> "
					"lock error (no reply)\n",
					req_nokey.domain, req_nokey.map);
			goto done_with_lock;
		}
		reply_order->stat = YP_TRUE;
		if (map_order(state, req_nokey.domain, req_nokey.map,
			      &map_secure, &reply_order->ordernum) &&
			      (client_secure || !map_secure)) {
			reply_order->stat = YP_TRUE;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"order(%s/%s) -> %d\n",
					req_nokey.domain,
					req_nokey.map,
					reply_order->ordernum);
		} else {
			reply_order->stat = YP_FALSE;
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"order(%s/%s) -> ?\n",
					req_nokey.domain,
					req_nokey.map);
		}
		(*reply_fn)(state, cdata, reply, reply_xdrs);
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_ypreq_nokey, (char *) &req_nokey);
	} else {
		/* XXX */
	}
}

/* Return the list of maps. */
struct nis_maplist_cbdata {
	struct ypmaplist *list;
	bool_t client_secure;
};
static bool_t
nis_maplist_cb(const char *domain, const char *mapname, bool_t secure,
	       void *backend_data, void *cb_data)
{
	struct ypmaplist *next;
	struct nis_maplist_cbdata *cbdata;
	cbdata = cb_data;
	if (cbdata->client_secure || !secure) {
		next = malloc(sizeof(*next));
		if (next != NULL) {
			memset(next, 0, sizeof(*next));
			next->map = strdup(mapname);
			if (next->map == NULL) {
				free(next);
				return TRUE;
			}
			next->next = cbdata->list;
			cbdata->list = next;
		}
	}
	return TRUE;
}
static void
nis_free_maplist_cb_result(struct nis_maplist_cbdata *cbdata)
{
	struct ypmaplist *node, *next;
	node = cbdata->list;
	while (node != NULL) {
		next = node->next;
		free(node->map);
		free(node);
		node = next;
	}
	cbdata->list = NULL;
}
static void
nis_maplist(struct plugin_state *state,
	    dispatch_reply_fragment *reply_fragment_fn,
	    dispatch_reply *reply_fn,
	    struct dispatch_client_data *cdata,
	    XDR *request_xdrs, bool_t client_secure,
	    struct rpc_msg *reply, XDR *reply_xdrs,
	    struct ypresp_maplist *reply_maplist)
{
	char *domain = NULL;
	struct ypmaplist *list;
	struct nis_maplist_cbdata cbdata;
	memset(reply_maplist, 0, sizeof(*reply_maplist));
	if (xdr_string(request_xdrs, &domain, YPMAXDOMAIN)) {
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"maplist(%s) -> "
					"lock error (no reply)\n",
					domain);
			goto done_with_lock;
		}
		cbdata.list = NULL;
		cbdata.client_secure = client_secure;
		map_data_foreach_map(state, domain, nis_maplist_cb, &cbdata);
		reply_maplist->stat = YP_TRUE;
		reply_maplist->maps = cbdata.list;
		if (reply_maplist->maps == NULL) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"maplist(%s) -> (none)\n",
					domain);
		} else {
			for (list = reply_maplist->maps;
			     list != NULL;
			     list = list->next) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"maplist(%s) -> %s\n",
						domain, list->map);
			}
		}
		(*reply_fn)(state, cdata, reply, reply_xdrs);
		nis_free_maplist_cb_result(&cbdata);
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_string, (char *) &domain);
	} else {
		/* XXX */
	}
}

/* Enumeration, if we want to break it down into chunks, happens in a few
 * phases (given the protocol):
 * 1. we're sending the first entry in a map
 * 2. we're sending a not-the-first entry in a map
 * 3. we're sending an end-of-map
 */
struct nis_all_cookie {
	enum nis_all_cookie_state {
		cookie_bad,
		cookie_first,
		cookie_next,
		cookie_this,
		cookie_end0,
		cookie_end1,
		cookie_end2,
	} state;
	unsigned int id_length;
	int key_index;
	char id[1];
};
static void
nis_all_free_cookie(struct nis_all_cookie *cookie)
{
	free(cookie);
}
static struct nis_all_cookie *
nis_all_make_cookie(enum nis_all_cookie_state state,
		    const char *id, int key_index)
{
	struct nis_all_cookie *cookie;
	int length;
	length = id ? strlen(id) : 0;
	cookie = malloc(sizeof(*cookie) + length + 1);
	if (cookie != NULL) {
		cookie->state = state;
		memset(cookie->id, '\0', sizeof(cookie->id));
		cookie->id_length = 0;
		cookie->key_index = 0;
		switch (cookie->state) {
		case cookie_bad:
		case cookie_first:
		case cookie_end0:
		case cookie_end1:
		case cookie_end2:
			break;
		case cookie_this:
		case cookie_next:
			cookie->id_length = length;
			cookie->key_index = key_index;
			if (length > 0) {
				memcpy(&cookie->id, id, cookie->id_length);
				cookie->id[length] = '\0';
			} else {
				cookie->id[0] = '\0';
			}
			break;
		}
	}
	return cookie;
}

static void
nis_all(struct plugin_state *state,
	dispatch_reply_fragment *reply_fragment_fn,
	dispatch_reply *reply_fn,
	struct dispatch_client_data *cdata,
	XDR *request_xdrs, bool_t client_secure,
	struct rpc_msg *reply, XDR *reply_xdrs,
	struct ypresp_all *reply_all, void **continuation_cookie)
{
	struct ypreq_nokey req_nokey;
	keydat *reply_key;
	valdat *reply_val;
	struct nis_all_cookie *cookie;
	enum nis_all_cookie_state next_state;
	bool_t map_supported, map_secure, stop;
	const char *entry_id;
	int entry_key_index;

	memset(&req_nokey, 0, sizeof(req_nokey));
	reply_key = &reply_all->ypresp_all_u.val.key;
	reply_val = &reply_all->ypresp_all_u.val.val;
	if (xdr_ypreq_nokey(request_xdrs, &req_nokey)) {
		/* Take ownership of the cookie data. */
		if (continuation_cookie) {
			if (*continuation_cookie != NULL) {
				cookie = *continuation_cookie;
			} else {
				cookie = nis_all_make_cookie(cookie_bad,
							     NULL, 0);
			}
			*continuation_cookie = NULL;
		} else {
			cookie = nis_all_make_cookie(cookie_bad, NULL, 0);
		}
		/* Check if we even support the map. */
		if (map_rdlock() != 0) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"all(%s/%s) -> "
					"lock error (no reply)\n",
					req_nokey.domain, req_nokey.map);
			goto done_with_lock;
		}
		map_supported = FALSE;
		if (!map_supports_map(state, req_nokey.domain, req_nokey.map,
				      &map_supported, NULL) ||
		    !map_supported) {
			/* No entries? No-such-map final status. */
			reply_all->more = TRUE;
			reply_all->ypresp_all_u.val.stat = YP_NOMAP;
			reply_key->keydat_len = 0;
			reply_val->valdat_len = 0;
			/* Encode the reply header so that we can queue the
			 * entire reply as one block. */
	                xdr_replymsg(reply_xdrs, reply);
			/* End of data. */
			reply_all->more = FALSE;
			if (xdr_ypresp_all(reply_xdrs, reply_all)) {
				/* Queue the entire response. */
				if (!(*reply_fragment_fn)(state, cdata,
							  reply, reply_xdrs,
							  FALSE, TRUE)) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"all(%s/%s) - "
							"error queueing "
							"error response\n",
							req_nokey.domain,
							req_nokey.map);
				}
			} else {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"all(%s/%s) - "
						"error building "
						"error response\n",
						req_nokey.domain,
						req_nokey.map);
			}
			/* Don't return a cookie, if one was passed to us. */
			nis_all_free_cookie(cookie);
			cookie = NULL;
		} else
		for (stop = FALSE; stop == FALSE;) {
			bool_t found, skip;
			xdr_setpos(reply_xdrs, 0);
			memset(reply_all, 0, sizeof(*reply_all));
			/* Follow any instructions we left for this iteration.
			 */
			switch (cookie->state) {
			case cookie_bad:
				/* fall through */
			case cookie_first:
				/* Read the first key in the map, and make the
				 * next state either be queuing the first item
				 * or queueing the end-of-map reply. */
				found = map_first(state,
						  req_nokey.domain,
						  req_nokey.map, &map_secure,
						  &reply_key->keydat_len,
						  &reply_key->keydat_val,
						  &reply_val->valdat_len,
						  &reply_val->valdat_val,
						  &entry_id,
						  &entry_key_index) &&
				        (client_secure || !map_secure);
				if (found) {
					/* Next time grab the entry after this
					 * one. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"all(%s/%s) \"%.*s\"\n",
							req_nokey.domain,
							req_nokey.map,
							reply_key->keydat_len,
							reply_key->keydat_val);
					skip = FALSE;
					reply_all->more = TRUE;
					reply_all->ypresp_all_u.val.stat = YP_TRUE;
					next_state = cookie_next;
				} else {
					/* Don't reply, just move to end-of-map
					 * state. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"all(%s/%s) no-first\n",
							req_nokey.domain,
							req_nokey.map);
					skip = TRUE;
					next_state = cookie_end0;
				}
				/* Try to queue the packet. */
				nis_all_free_cookie(cookie);
				if (skip ||
				    (*reply_fragment_fn)(state, cdata,
							 reply,
							 reply_xdrs,
							 TRUE, FALSE)) {
					/* Leave a note to choose the next
					 * entry or send end0 or end1,
					 * whichever is appropriate. */
					cookie = nis_all_make_cookie(next_state,
								     entry_id,
								     entry_key_index);
				} else {
					/* Leave a note to try sending the
					 * first entry again. */
					cookie = nis_all_make_cookie(cookie_first,
								     NULL, 0);
					stop = TRUE;
				}
				break;
			case cookie_next:
				/* Read the next key in the map, and set up the
				 * cookie to note that we're queuing a not-
				 * first item. */
				found = map_next_id(state,
						    req_nokey.domain,
						    req_nokey.map,
						    &map_secure,
						    cookie->id,
						    cookie->key_index,
						    &reply_key->keydat_len,
						    &reply_key->keydat_val,
						    &reply_val->valdat_len,
						    &reply_val->valdat_val,
						    &entry_id,
						    &entry_key_index) &&
				        (client_secure || !map_secure);
				if (found) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"all(%s/%s) \"%.*s\"\n",
							req_nokey.domain,
							req_nokey.map,
							reply_key->keydat_len,
							reply_key->keydat_val);
					/* Next time grab the entry after this
					 * one. */
					skip = FALSE;
					reply_all->more = TRUE;
					reply_all->ypresp_all_u.val.stat = YP_TRUE;
					next_state = cookie_next;
				} else {
					/* Don't reply, just move to end-of-map
					 * state. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"all(%s/%s) no-next\n",
							req_nokey.domain,
							req_nokey.map);
					skip = TRUE;
					next_state = cookie_end1;
				}
				/* Try to queue the packet. */
				if (skip ||
				    (xdr_ypresp_all(reply_xdrs, reply_all) &&
				     (*reply_fragment_fn)(state, cdata,
							  reply,
							  reply_xdrs,
							  FALSE, FALSE))) {
					/* Leave a note to choose the next
					 * entry or send end1, whichever is
					 * appropriate. */
					nis_all_free_cookie(cookie);
					cookie = nis_all_make_cookie(next_state,
								     entry_id,
								     entry_key_index);
				} else {
					/* Leave a note to retry sending this
					 * entry the next time. */
					nis_all_free_cookie(cookie);
					cookie = nis_all_make_cookie(cookie_this,
								     entry_id,
								     entry_key_index);
					stop = TRUE;
				}
				break;
			case cookie_this:
				/* Read the matching key in the map, and set up
				 * the cookie to note that we're queuing a not-
				 * first item. */
				found = map_match_id(state,
						     req_nokey.domain,
						     req_nokey.map,
						     &map_secure,
						     cookie->id,
						     cookie->key_index,
						     &reply_key->keydat_len,
						     (const char **) &reply_key->keydat_val,
						     &reply_val->valdat_len,
						     (const char **) &reply_val->valdat_val,
						     &entry_id, NULL) &&
				        (client_secure || !map_secure);
				entry_key_index = cookie->key_index;
				if (found) {
					/* Next time grab the entry after this
					 * one. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"all(%s/%s) \"%s\":%d "
							"(retry)\n",
							req_nokey.domain,
							req_nokey.map,
							cookie->id,
							cookie->key_index);
					skip = FALSE;
					reply_all->more = TRUE;
					reply_all->ypresp_all_u.val.stat = YP_TRUE;
					next_state = cookie_next;
				} else {
					/* Don't reply, just move to end-of-map
					 * state. */
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"all(%s/%s) \"%s\":%d "
							"(disappeared?)\n",
							req_nokey.domain,
							req_nokey.map,
							cookie->id,
							cookie->key_index);
					skip = TRUE;
					next_state = cookie_end1;
				}
				/* Try to queue the packet. */
				if (!skip) {
					if (xdr_ypresp_all(reply_xdrs,
							   reply_all)) {
					     (*reply_fragment_fn)(state, cdata,
								  reply,
								  reply_xdrs,
								  FALSE, FALSE);
					}
				}
				/* Leave a note to choose the next entry, even
				 * if we failed here, otherwise we can get
				 * stuck. */
				nis_all_free_cookie(cookie);
				cookie = nis_all_make_cookie(next_state,
							     entry_id,
							     entry_key_index);
				break;
			case cookie_end0:
				/* Send the end-of-map message as the first
				 * result. */
				memset(reply_key, 0, sizeof(*reply_key));
				memset(reply_val, 0, sizeof(*reply_key));
				reply_all->more = TRUE;
				reply_all->ypresp_all_u.val.stat = YP_NOMORE;
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"all(%s/%s) no entries\n",
						req_nokey.domain,
						req_nokey.map);
				if ((*reply_fragment_fn)(state, cdata,
							 reply,
							 reply_xdrs,
							 TRUE, FALSE)) {
					/* Leave a note to finish the reply. */
					nis_all_free_cookie(cookie);
					cookie = nis_all_make_cookie(cookie_end2,
								     NULL, 0);
				} else {
					/* Leave the note alone, so that we'll
					 * have to try again. */
					stop = TRUE;
				}
				break;
			case cookie_end1:
				/* Send the end-of-map message after having
				 * sent one or more results. */
				memset(reply_key, 0, sizeof(*reply_key));
				memset(reply_val, 0, sizeof(*reply_key));
				reply_all->more = TRUE;
				reply_all->ypresp_all_u.val.stat = YP_NOMORE;
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"all(%s/%s) end-of-map\n",
						req_nokey.domain,
						req_nokey.map);
				if (xdr_ypresp_all(reply_xdrs, reply_all) &&
				    (*reply_fragment_fn)(state, cdata,
							 reply,
							 reply_xdrs,
							 FALSE, FALSE)) {
					/* Leave a note to finish the reply. */
					nis_all_free_cookie(cookie);
					cookie = nis_all_make_cookie(cookie_end2,
								     NULL, 0);
				} else {
					/* Leave the note alone, so that we'll
					 * have to try again. */
					stop = TRUE;
				}
				break;
			case cookie_end2:
				/* Send the final message. */
				reply_all->more = FALSE;
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"all(%s/%s) done\n",
						req_nokey.domain,
						req_nokey.map);
				if (xdr_ypresp_all(reply_xdrs, reply_all) &&
				    (*reply_fragment_fn)(state, cdata,
							 reply,
							 reply_xdrs,
							 FALSE, TRUE)) {
					/* We're done. */
					nis_all_free_cookie(cookie);
					cookie = NULL;
				} else {
					/* Leave the note alone, so that we'll
					 * have to try again. */
				}
				stop = TRUE;
				break;
			}
		}
		map_unlock();
done_with_lock:
		xdr_free((xdrproc_t)xdr_ypreq_nokey, (char *) &req_nokey);
		/* Return the cookie if we can, else destroy it. */
		if (continuation_cookie) {
			*continuation_cookie = cookie;
		} else {
			nis_all_free_cookie(cookie);
		}
	} else {
		/* XXX */
	}
}

/* Process a NIS request in the buffer and use a passed-in callback function to
 * send the response back to the client. */
void
nis_process_request(struct plugin_state *state,
		    char *request_buf, size_t request_buflen,
		    dispatch_reply_fragment *reply_fragment_fn,
		    dispatch_reply *reply_fn,
		    struct dispatch_client_data *cdata, bool_t client_secure,
		    char *reply_buf, size_t reply_buf_size,
		    void **continuation_cookie)
{
	XDR request_xdrs, reply_xdrs, auth_xdrs;
	AUTH *request_auth, *reply_auth;
	char auth_buf[MAX_AUTH_BYTES];
	struct rpc_msg request, reply;
	int auth_flavor, auth_len;
	struct ypresp_val reply_val;
	struct ypresp_key_val reply_key_val;
	struct ypresp_all reply_all;
	struct ypresp_master reply_master;
	struct ypresp_order reply_order;
	struct ypresp_maplist reply_maplist;
	struct accepted_reply *accepted;
	bool_t reply_bool;

	memset(&request_xdrs, 0, sizeof(request_xdrs));
	memset(&reply_xdrs, 0, sizeof(reply_xdrs));
	memset(&request, 0, sizeof(request));
	memset(&reply, 0, sizeof(reply));
	memset(&auth_buf, 0, sizeof(auth_buf));
	memset(reply_buf, 0, reply_buf_size);

	/* Parse the client request and make sure it looks like an RPC. */
	xdrmem_create(&request_xdrs, request_buf, request_buflen, XDR_DECODE);
	if (!xdr_callmsg(&request_xdrs, &request)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"error parsing client RPC request!\n");
		return;
	}
	if (request.rm_direction != CALL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"client didn't send us an actual request\n");
		goto done;
	}

	/* Now we know we've got a request to respond to. */
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"client request prog=%ld,ver=%ld,proc=%ld\n",
			(long) request.rm_call.cb_prog,
			(long) request.rm_call.cb_vers,
			(long) request.rm_call.cb_proc);
	xdrmem_create(&reply_xdrs, reply_buf, reply_buf_size, XDR_ENCODE);

	/* Validate the client's credentials. */
	auth_flavor = request.rm_call.cb_cred.oa_flavor;
	switch (auth_flavor) {
	case AUTH_SYS:
		request_auth = authunix_create_default();
		break;
	case AUTH_NONE:
	default:
		request_auth = authnone_create();
		break;
	}
	if (auth_validate(request_auth, &request.rm_call.cb_cred)) {
		switch (auth_flavor) {
		case AUTH_SYS:
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"validated auth_sys creds\n");
			break;
		case AUTH_NONE:
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"validated \"none\" creds\n");
			break;
		default:
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"validated other creds\n");
			break;
		}
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"failed to validate client creds\n");
	}
	auth_destroy(request_auth);

	/* Build the authenticator for our response. */
	xdrmem_create(&auth_xdrs, auth_buf, sizeof(auth_buf), XDR_ENCODE);
	switch (auth_flavor) {
	case AUTH_SYS:
		reply_auth = authunix_create_default();
		break;
	case AUTH_NONE:
	default:
		reply_auth = authnone_create();
		break;
	}
	auth_marshall(reply_auth, &auth_xdrs);
	auth_destroy(reply_auth);
	auth_len = xdr_getpos(&auth_xdrs);
	xdr_destroy(&auth_xdrs);
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"built reply authenticator\n");

	/* Fill out the common RPC reply fields. */
	reply.rm_xid = request.rm_xid;
	reply.rm_direction = REPLY;

	/* If the request isn't meant for us, return an error. */
	if ((request.rm_direction != CALL) ||
	    (request.rm_call.cb_rpcvers != 2) ||
	    (request.rm_call.cb_prog != YPPROG) ||
	    (request.rm_call.cb_vers != YPVERS)) {
		reply.rm_reply.rp_stat = MSG_DENIED;
		reply.rm_reply.rp_rjct.rj_stat = RPC_MISMATCH;
		xdr_replymsg(&reply_xdrs, &reply);
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"program request mismatch\n");
		goto send_reply;
	}

	/* Fill in the default reply - success, no data returned. */
	reply.rm_reply.rp_stat = MSG_ACCEPTED;
	accepted = &reply.rm_reply.rp_acpt;
	accepted->ar_stat = SUCCESS;
	accepted->ar_results.where = (caddr_t) NULL;
	accepted->ar_results.proc = (xdrproc_t) xdr_void;

	/* Now figure out what we were asked to do. */
	switch (request.rm_call.cb_proc) {
	default:
		/* If we don't know the specific request, we'll return a
		 * mismatch error. */
		reply.rm_reply.rp_stat = MSG_DENIED;
		reply.rm_reply.rp_rjct.rj_stat = RPC_MISMATCH;
		break;
	case YPPROC_NULL:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_null()\n");
		/* Do nothing. The default successful reply is fine. */
		break;
	case YPPROC_DOMAIN:
	case YPPROC_DOMAIN_NONACK:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				request.rm_call.cb_proc == YPPROC_DOMAIN ?
				"yp_domain()\n" : "yp_domainnonack()\n");
		/* Change the reply data to be a boolean. */
		memset(&reply_bool, 0, sizeof(reply_bool));
		accepted->ar_results.where = (caddr_t) &reply_bool;
		accepted->ar_results.proc = (xdrproc_t) xdr_bool;
		/* Call the real function. */
		nis_domain(state, reply_fragment_fn, reply_fn,
			   cdata, &request_xdrs,
			   request.rm_call.cb_proc == YPPROC_DOMAIN,
			   &reply, &reply_xdrs, &reply_bool);
		goto sent_reply;
		break;
	case YPPROC_MATCH:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_match()\n");
		/* Change the reply data to be a resp_val. */
		memset(&reply_val, 0, sizeof(reply_val));
		accepted->ar_results.where = (caddr_t) &reply_val;
		accepted->ar_results.proc = (xdrproc_t) xdr_ypresp_val;
		/* Call the real function. */
		nis_match(state, reply_fragment_fn, reply_fn,
			  cdata, &request_xdrs, client_secure,
			  &reply, &reply_xdrs, &reply_val);
		goto sent_reply;
		break;
	case YPPROC_FIRST:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_first()\n");
		/* Change the reply data to be a resp_key_val. */
		memset(&reply_key_val, 0, sizeof(reply_key_val));
		accepted->ar_results.where = (caddr_t) &reply_key_val;
		accepted->ar_results.proc = (xdrproc_t) xdr_ypresp_key_val;
		/* Call the real function. */
		nis_first(state, reply_fragment_fn, reply_fn,
			  cdata, &request_xdrs, client_secure,
			  &reply, &reply_xdrs, &reply_key_val);
		goto sent_reply;
		break;
	case YPPROC_NEXT:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_next()\n");
		/* Change the reply data to be a resp_key_val. */
		memset(&reply_key_val, 0, sizeof(reply_key_val));
		accepted->ar_results.where = (caddr_t) &reply_key_val;
		accepted->ar_results.proc = (xdrproc_t) xdr_ypresp_key_val;
		/* Call the real function. */
		nis_next(state, reply_fragment_fn, reply_fn,
			 cdata, &request_xdrs, client_secure,
			 &reply, &reply_xdrs, &reply_key_val);
		goto sent_reply;
		break;
	case YPPROC_XFR:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_xfr()\n");
		/* Do nothing. The default successful reply is fine. */
		break;
	case YPPROC_CLEAR:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_clear()\n");
		/* Do nothing. The default successful reply is fine. */
		break;
	case YPPROC_ALL:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_all()\n");
		/* Set the result type to a boolean. */
		memset(&reply_all, 0, sizeof(reply_all));
		accepted->ar_results.where = (caddr_t) &reply_all;
		accepted->ar_results.proc = (xdrproc_t) &xdr_ypresp_all;
		/* Call the real function. */
		nis_all(state, reply_fragment_fn, reply_fn,
			cdata, &request_xdrs, client_secure,
			&reply, &reply_xdrs, &reply_all,
			continuation_cookie);
		goto sent_reply;
		break;
	case YPPROC_MASTER:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_master()\n");
		/* Change reply type to be a resp_master. */
		memset(&reply_master, 0, sizeof(reply_master));
		accepted->ar_results.where = (caddr_t) &reply_master;
		accepted->ar_results.proc = (xdrproc_t) xdr_ypresp_master;
		/* Call the real function. */
		nis_master(state, reply_fragment_fn, reply_fn,
			   cdata, &request_xdrs,
			   &reply, &reply_xdrs, &reply_master);
		goto sent_reply;
		break;
	case YPPROC_ORDER:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_order()\n");
		/* Change reply type to be a resp_order. */
		memset(&reply_order, 0, sizeof(reply_order));
		accepted->ar_results.where = (caddr_t) &reply_order;
		accepted->ar_results.proc = (xdrproc_t) xdr_ypresp_order;
		/* Call the real function. */
		nis_order(state, reply_fragment_fn, reply_fn, cdata,
			  &request_xdrs, client_secure,
			  &reply, &reply_xdrs, &reply_order);
		goto sent_reply;
		break;
	case YPPROC_MAPLIST:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_maplist()\n");
		/* Change reply type to be a resp_maplist. */
		memset(&reply_maplist, 0, sizeof(reply_maplist));
		accepted->ar_results.where = (caddr_t) &reply_maplist;
		accepted->ar_results.proc = (xdrproc_t) xdr_ypresp_maplist;
		/* Call the real function. */
		nis_maplist(state, reply_fragment_fn, reply_fn,
			    cdata, &request_xdrs, client_secure,
			    &reply, &reply_xdrs, &reply_maplist);
		goto sent_reply;
		break;
#ifdef YPPROC_NEWXFR
	case YPPROC_NEWXFR:
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"yp_newxfr()\n");
		reply.rm_reply.rp_stat = MSG_DENIED;
		reply.rm_reply.rp_rjct.rj_stat = RPC_MISMATCH;
		break;
#endif
	}

send_reply:
	(*reply_fn)(state, cdata, &reply, &reply_xdrs);

sent_reply:
	xdr_destroy(&reply_xdrs);

done:
	xdr_free((xdrproc_t)xdr_callmsg, (char *) &request);
	xdr_destroy(&request_xdrs);
	return;
}
