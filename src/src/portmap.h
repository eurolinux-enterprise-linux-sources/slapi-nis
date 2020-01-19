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

#ifndef portmap_h
#define portmap_h

bool_t portmap_register(const char *log_id, int *resv_sock, int but_not,
			int program, int version,
			int family, int protocol, int port);
bool_t portmap_unregister(const char *log_id, int *resv_sock, int but_not,
			  int program, int version,
			  int family, int protocol, int port);
int portmap_create_client_socket(char *module, int but_not);
int portmap_bind_resvport(int fd, int family, int but_not);

#endif
