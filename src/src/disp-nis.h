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

#ifndef disp_nis_h
#define disp_nis_h
struct plugin_state;
struct wrapped_thread;
struct dispatch_client_data;
void *dispatch_thread(struct wrapped_thread *t);
typedef bool_t (dispatch_reply_fragment)(struct plugin_state *state,
					 struct dispatch_client_data *cdata,
					 struct rpc_msg *reply, XDR *reply_xdrs,
					 bool_t first_fragment,
					 bool_t last_fragment);
typedef void (dispatch_reply)(struct plugin_state *state,
			      struct dispatch_client_data *cdata,
			      struct rpc_msg *reply, XDR *reply_xdrs);
void dispatch_securenets_clear(struct plugin_state *state);
void dispatch_securenets_add(struct plugin_state *state, const char *value);
#endif
