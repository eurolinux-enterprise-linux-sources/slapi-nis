/*
 * Copyright 2008,2009,2011,2012 Red Hat, Inc.
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
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include "backend.h"
#include "back-shr.h"
#include "disp-nis.h"
#include "map.h"
#include "nis.h"
#include "plugin.h"
#include "portmap.h"
#include "wrap.h"

#define PLUGIN_ID "nis-server-plugin"
#define PLUGIN_BETXN_POSTOP_ID PLUGIN_ID "-betxn_postop"
#define PLUGIN_POSTOP_ID PLUGIN_ID "-postop"
#define PLUGIN_INTERNAL_POSTOP_ID PLUGIN_ID "-internal-postop"

/* the module initialization function */
static Slapi_PluginDesc
plugin_description = {
	.spd_id = "nis-plugin",
	.spd_vendor = "redhat.com",
	.spd_version = PACKAGE_VERSION PACKAGE_VERSION_TXNS,
	.spd_description = "NIS Server Plugin",
};
static struct plugin_state *global_plugin_state;

/* Populate the map cache, register with the local portmapper, and then start
 * the plugin's work thread to answer requests using the cache. */
static int
plugin_startup(Slapi_PBlock *pb)
{
	struct plugin_state *state;
	const char *pname;
	int i, protocol;
	Slapi_DN *pluginsdn = NULL;

	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
	slapi_pblock_get(pb, SLAPI_TARGET_SDN, &pluginsdn);
	/* plugin base need to be duplicated because it will be destroyed
	 * when pblock is destroyed but we need to use it in a separate thread */
	if (NULL == pluginsdn || 0 == slapi_sdn_get_ndn_len(pluginsdn)) {
        slapi_log_error(SLAPI_LOG_FATAL, state->plugin_desc->spd_id,
                        "nis plugin_startup: unable to retrieve plugin DN\n");
		return -1;

    } else {
        state->plugin_base = slapi_ch_strdup(slapi_sdn_get_dn(pluginsdn));
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"configuration entry is %s%s%s\n",
				state->plugin_base ? "\"" : "",
				state->plugin_base ? state->plugin_base : "NULL",
				state->plugin_base ? "\"" : "");
    }

	/* Populate the maps and data. */
        if (state->priming_mutex == NULL) {
            state->priming_mutex = wrap_new_mutex();
	    state->start_priming_thread = 1;
        }
	backend_startup(pb, state);
	/* Start a new listening thread to handle incoming traffic. */
	state->tid = wrap_start_thread(&dispatch_thread, state);
	if (state->tid == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				plugin_description.spd_id,
				"error starting listener thread\n");
		return -1;
	}
	/* Register the listener sockets with the portmapper. */
	if (state->pmap_client_socket != -1) {
		/* Try to kick off any other NIS servers on the local box. */
		portmap_unregister(plugin_description.spd_id,
				   &state->pmap_client_socket, 0,
				   YPPROG, YPVERS,
				   AF_INET6, IPPROTO_TCP, 0);
		portmap_unregister(plugin_description.spd_id,
				   &state->pmap_client_socket, 0,
				   YPPROG, YPVERS,
				   AF_INET6, IPPROTO_UDP, 0);
		portmap_unregister(plugin_description.spd_id,
				   &state->pmap_client_socket, 0,
				   YPPROG, YPVERS,
				   AF_INET, IPPROTO_TCP, 0);
		portmap_unregister(plugin_description.spd_id,
				   &state->pmap_client_socket, 0,
				   YPPROG, YPVERS,
				   AF_INET, IPPROTO_UDP, 0);
		/* Register our listening ports. */
		for (i = 0; i < state->n_listeners; i++) {
			switch (state->listener[i].type) {
			case SOCK_DGRAM:
				protocol = IPPROTO_UDP;
				pname = "UDP";
				break;
			case SOCK_STREAM:
				protocol = IPPROTO_TCP;
				pname = "TCP";
				break;
			default:
				/* never reached */
				assert(0);
				break;
			}
			if (!portmap_register(plugin_description.spd_id,
					      &state->pmap_client_socket,
					      state->listener[i].port,
					      YPPROG, YPVERS,
					      state->listener[i].pf,
					      protocol,
					      state->listener[i].port)) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						plugin_description.spd_id,
						"error registering %s service "
						"with portmap\n", pname);
			} else {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						plugin_description.spd_id,
						"registered %s service "
						"with portmap\n", pname);
				/* If it's an IPv6 service, then it can also
				 * accept connections from IPv4 clients, so
				 * register for them, too. */
				if (state->listener[i].pf == AF_INET6) {
					portmap_register(plugin_description.spd_id,
							 &state->pmap_client_socket,
							 state->listener[i].port,
							 YPPROG, YPVERS,
							 AF_INET,
							 protocol,
							 state->listener[i].port);
				}
			}
		}
	}
	/* Note that the plugin is ready to go. */
	slapi_log_error(SLAPI_LOG_PLUGIN, plugin_description.spd_id,
			"plugin startup completed\n");
	return 0;
}

/* Unregister with the local portmapper and stop the plugin's work thread. */
static int
plugin_shutdown(Slapi_PBlock *pb)
{
	struct plugin_state *state;
	int i, protocol;
	slapi_pblock_get(pb, SLAPI_PLUGIN_PRIVATE, &state);
        backend_shutdown(state);
	for (i = 0; i < state->n_listeners; i++) {
		if (state->pmap_client_socket != -1) {
			switch (state->listener[i].type) {
			case SOCK_DGRAM:
				protocol = IPPROTO_UDP;
				break;
			case SOCK_STREAM:
				protocol = IPPROTO_TCP;
				break;
			default:
				/* never reached */
				assert(0);
				break;
			}
			portmap_unregister(plugin_description.spd_id,
					   &state->pmap_client_socket,
					   state->listener[i].port,
					   YPPROG, YPVERS,
					   state->listener[i].pf,
					   protocol,
					   state->listener[i].port);
			if (state->listener[i].pf == AF_INET6) {
				portmap_unregister(plugin_description.spd_id,
						   &state->pmap_client_socket,
						   state->listener[i].port,
						   YPPROG, YPVERS,
						   AF_INET,
						   protocol,
						   state->listener[i].port);
			}
		}
		close(state->listener[i].fd);
		state->listener[i].fd = -1;
	}
	state->n_listeners = 0;
	wrap_stop_thread(state->tid);
	map_done(state);
#ifdef HAVE_TCPD_H
	free(state->request_info);
#endif
        if (state->plugin_base != NULL) {
		slapi_ch_free((void **)&state->plugin_base);
	}
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"plugin shutdown completed\n");
	return 0;
}

/* Read the plugin configuration parameters which we need to know at plugin
 * initialization time, before the server drops privileges. */
static void
plugin_read_config(Slapi_PBlock *plugin_pb, int *port)
{
	Slapi_ComponentId *id;
	const char **argv = NULL;
	int argc = 0, i;

	*port = 0;

	slapi_pblock_get(plugin_pb, SLAPI_PLUGIN_IDENTITY, &id);
	slapi_pblock_get(plugin_pb, SLAPI_PLUGIN_ARGC, &argc);
	slapi_pblock_get(plugin_pb, SLAPI_PLUGIN_ARGV, &argv);
	for (i = 0; (i < argc) && (argv != NULL) && (argv[i] != NULL); i++) {
		switch (i) {
		case 0:
			*port = atoi(argv[i]);
			slapi_log_error(SLAPI_LOG_PLUGIN,
					plugin_description.spd_id,
					"argument 0 (port) = %d\n", *port);
			break;
		}
	}
}

/* Handle the part of startup that needs to be done before we drop privileges:
 * bind to listening ports and one more for talking to the local portmapper. */
static int
plugin_state_init(Slapi_PBlock *pb, struct plugin_state **lstate)
{
	int port, sockfd = -1, err, i, flags;
	struct plugin_state *state = NULL;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	state = malloc(sizeof(*state));
	if (state == NULL) {
		goto failed;
	}
	memset(state, 0, sizeof(*state));
	state->plugin_base = NULL;
	slapi_pblock_get(pb, SLAPI_PLUGIN_IDENTITY, &state->plugin_identity);
	state->plugin_desc = &plugin_description;
	state->max_value_size = DEFAULT_MAX_VALUE_SIZE;
	state->max_dgram_size = DEFAULT_MAX_DGRAM_SIZE;
	state->pmap_client_socket = -1;
	plugin_read_config(pb, &port);

#ifdef HAVE_TCPD_H
	state->request_info = malloc(sizeof(*(state->request_info)));
	if ((state->request_info == NULL) ||
	    (request_init(state->request_info, 0) != state->request_info) ||
	    (request_set(state->request_info,
			 RQ_DAEMON, DEFAULT_TCPWRAP_NAME,
			 0) != state->request_info)) {
		slapi_log_error(SLAPI_LOG_FATAL, state->plugin_desc->spd_id,
				"error initializing tcp_wrappers for \"%s\"\n",
				plugin_description.spd_id);
		goto failed;
	}
#else
	state->request_info = NULL;
#endif

	/* Create a socket for use in communicating with the portmapper. */
	sockfd = portmap_create_client_socket(state->plugin_desc->spd_id,
					      port);
	if (sockfd == -1) {
		if ((getenv(NIS_PLUGIN_CONTINUE_WITHOUT_PORTMAP_ENV) == NULL) ||
		    !atol(getenv(NIS_PLUGIN_CONTINUE_WITHOUT_PORTMAP_ENV))) {
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"error creating portmap/rpcbind client "
					"socket\n");
			goto failed;
		}
	}
	state->pmap_client_socket = sockfd;

	/* We need to bind on privileged ports for both datagram and connected
	 * listeners, over both IPv4 and IPv6.  We should be using
	 * getaddrinfo()'s AI_PASSIVE flag, and binding to every address it
	 * returns, but getaddrinfo() requires that we specify the port if we
	 * don't specify the host, and we don't always know either. */
	state->n_listeners = 0;
	for (i = 0; i < 4; i++) {
		int pf, type, one, ret;
		const char *sock_desc;
		/* Figure out what kind of socket we need, and a textual
		 * term to use in log messages. */
		pf = (i & 2) ? PF_INET : PF_INET6;
		type = (i & 1) ? SOCK_STREAM: SOCK_DGRAM;
		sock_desc = (pf == PF_INET6) ?
			    ((type == SOCK_DGRAM) ? "udp6" : "tcp6") :
			    ((type == SOCK_DGRAM) ? "udp" : "tcp");
		/* Allocate the socket. */
		sockfd = socket(pf, type, 0);
		if (sockfd == -1) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					plugin_description.spd_id,
					"error creating a %s socket\n",
					sock_desc);
			continue;
		}
		/* Mark the socket as reusable and non-blocking. */
		one = 1;
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
			       &one, sizeof(one)) != 0) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					plugin_description.spd_id,
					"error marking %s socket for reuse, "
					"continuing\n", sock_desc);
			close(sockfd);
			continue;
		}
		/* Mark the v6 sockets as v6-only so that we don't get an
		 * EADDRINUSE error when we try to bind to the same IPv4 port
		 * later. */
		if (pf == PF_INET6) {
			if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
				       &one, sizeof(one)) != 0) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						plugin_description.spd_id,
						"error marking %s socket as "
						"IPv6-only, continuing\n",
						sock_desc);
			}
		}
		/* Bind to the server port, if one was specified, otherwise try
		 * to find an unused one. */
		memset(&sin, 0, sizeof(sin));
		memset(&sin6, 0, sizeof(sin6));
		sin.sin_family = AF_INET;
		sin6.sin6_family = AF_INET6;
		if (port == 0) {
			port = (pf == PF_INET6) ? portmap_bind_resvport(sockfd,
								        AF_INET6,
								        0) :
						  portmap_bind_resvport(sockfd,
								        AF_INET,
								        0);
			ret = (port > 0) ? 0 : -1;
		} else {
			sin.sin_port = htons(port);
			sin6.sin6_port = htons(port);
			ret = (pf == PF_INET6) ? bind(sockfd,
						      (struct sockaddr*) &sin6,
						      sizeof(sin6)) :
						 bind(sockfd,
						      (struct sockaddr*) &sin,
						      sizeof(sin));
		}
		if (ret != 0) {
			char port_desc[16];
			if (port) {
				sprintf(port_desc, "port %d", port);
			} else {
				strcpy(port_desc, "privileged port");
			}
			close(sockfd);
			if (i < 2) {
				slapi_log_error(SLAPI_LOG_FATAL,
						plugin_description.spd_id,
						"error binding %s socket to "
						"%s for incoming NIS "
						"requests: %s\n",
						sock_desc, port_desc,
						strerror(errno));
				goto failed;
			} else {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						plugin_description.spd_id,
						"error binding %s socket to "
						"%s for incoming NIS "
						"requests: %s\n",
						sock_desc, port_desc,
						strerror(errno));
				continue;
			}
		}
		flags = fcntl(sockfd, F_GETFL);
		if ((flags & O_NONBLOCK) == 0) {
			if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
				slapi_log_error(SLAPI_LOG_FATAL,
						plugin_description.spd_id,
						"error marking %s socket as "
						"non-blocking: %s\n", sock_desc,
						strerror(errno));
				close(sockfd);
				goto failed;
			}
		}
		/* If it's a stream socket, let the kernel know that we're
		 * ready to accept client connections. */
		if (type == SOCK_STREAM) {
			if (listen(sockfd, 128) == -1) {
				slapi_log_error(SLAPI_LOG_FATAL,
						plugin_description.spd_id,
						"error marking %s socket for "
						"listening: %s\n", sock_desc,
						strerror(errno));
				close(sockfd);
				goto failed;
			}
		}
		/* Save the other info. */
		state->listener[state->n_listeners].fd = sockfd;
		state->listener[state->n_listeners].port = port;
		state->listener[state->n_listeners].pf = pf;
		state->listener[state->n_listeners].type = type;
		slapi_log_error(SLAPI_LOG_PLUGIN,
				plugin_description.spd_id,
				"listening on port %d for %s clients\n",
				state->listener[state->n_listeners].port,
				sock_desc);
		state->n_listeners++;
	}
	slapi_log_error(SLAPI_LOG_PLUGIN,
			plugin_description.spd_id,
			"set up %d listening sockets\n", state->n_listeners);
	*lstate = state;
	return 0;
failed:
	if (state != NULL) {
		err = errno;
		for (i = 0; i < state->n_listeners; i++) {
			close(state->listener[i].fd);
			state->listener[i].fd = -1;
		}
		if (state->pmap_client_socket != -1) {
			close(state->pmap_client_socket);
			state->pmap_client_socket = -1;
		}
		free(state);
		errno = err;
	}
	return -1;
}

static int
nis_plugin_init_postop(Slapi_PBlock *pb)
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
nis_plugin_init_internal_postop(Slapi_PBlock *pb)
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
#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
static int
nis_plugin_init_betxn_postop(Slapi_PBlock *pb)
{
	slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION, SLAPI_PLUGIN_VERSION_03);
	slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION, &plugin_description);
	slapi_pblock_set(pb, SLAPI_PLUGIN_PRIVATE, global_plugin_state);
	if (backend_init_betxn_postop(pb, global_plugin_state) == -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				global_plugin_state->plugin_desc->spd_id,
				"error registering betxn postop hooks\n");
		return -1;
	}
	return 0;
}
#endif
int
nis_plugin_init(Slapi_PBlock *pb)
{
	struct plugin_state *state = NULL;
	Slapi_Entry *plugin_entry = NULL;
	int is_betxn = 0;

	/* Allocate the module-global data and set up listening sockets. */
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
	if (slapi_register_plugin("postoperation", TRUE,
				  "nis_plugin_init_postop",
				  nis_plugin_init_postop,
				  PLUGIN_POSTOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering postoperation plugin\n");
		return -1;
	}
	if (slapi_register_plugin("internalpostoperation", TRUE,
				  "nis_plugin_init_internal_postop",
				  nis_plugin_init_internal_postop,
				  PLUGIN_INTERNAL_POSTOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering internal postoperation "
				"plugin\n");
		return -1;
	}
#ifdef SLAPI_NIS_SUPPORT_BE_TXNS
	if (slapi_register_plugin("betxnpostoperation", TRUE,
				  "nis_plugin_init_betxn_postop",
				  nis_plugin_init_betxn_postop,
				  PLUGIN_BETXN_POSTOP_ID, NULL,
				  state->plugin_identity) != 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error registering betxn postoperation "
				"plugin\n");
		return -1;
	}
#endif
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"registered plugin hooks\n");
	global_plugin_state = NULL;
	/* Note that the plugin was successfully loaded. */
	slapi_log_error(SLAPI_LOG_PLUGIN, plugin_description.spd_id,
			"plugin initialized\n");
	return 0;
}
