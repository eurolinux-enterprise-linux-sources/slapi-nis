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

#ifndef nis_h
#define nis_h

#include "disp-nis.h"
struct plugin_state;

struct dispatch_client_data;
void nis_process_request(struct plugin_state *state,
			 char *request_buf, size_t request_buflen,
			 dispatch_reply_fragment *reply_fragment,
			 dispatch_reply *reply,
			 struct dispatch_client_data *cdata,
			 bool_t client_secure,
			 char *reply_buf, size_t reply_buf_size,
			 void **continuation_cookie);

#endif
