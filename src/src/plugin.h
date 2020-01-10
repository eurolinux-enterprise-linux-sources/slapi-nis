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

#ifndef plug_nis_h
#define plug_nis_h

#include "wrap.h"

struct request_info;
struct securenet_info;

struct plugin_state {
	/* Common information. */
	char *plugin_base;
	Slapi_ComponentId *plugin_identity;
	Slapi_PluginDesc *plugin_desc;

	/* NIS-specific data. */
	struct wrapped_thread *tid;
	int pmap_client_socket;
	int max_dgram_size, max_value_size;
	struct request_info *request_info;
	struct securenet_info *securenet_info;
	int n_listeners;
	struct {
		int fd, port, pf, type;
	} listener[4];
};

#endif
