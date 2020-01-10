/*
 * Copyright 2008,2011 Red Hat, Inc.
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
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#include <rpc/rpc.h>
#include "../yp/yp.h"

#include "plugin.h"
#include "disp-nis.h"
#include "nis.h"
#include "portmap.h"

#ifndef TCPD_H
struct request_info;
#endif

union dispatch_client_addr {
	struct sockaddr_storage ss;
	struct sockaddr s;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
};

/* Handle all incoming data. */
struct dispatch_client {
	/* The client socket and address. */
	int client_fd;
	union dispatch_client_addr client_addr;
	socklen_t client_addrlen;
	bool_t client_secure;
	/* The client state. */
	enum {
		client_invalid,
		client_closing,
		client_reading,
		client_replying_with_more,
		client_replying_final,
	} client_state;
	/* The client's request while we're reading it. */
	char client_inbuf[4096];
	ssize_t client_inbuf_used;
	char *client_query;
	ssize_t client_query_size;
	void *client_query_cookie;
	/* The outgoing replies to the client, when we're sending one. */
	char *client_outbuf;
	ssize_t client_outbuf_size, client_outbuf_used;
	/* Working space for a client reply. */
	char *client_workbuf;
	ssize_t client_workbuf_size;
	/* The next client in the linked list of clients. */
	struct dispatch_client *client_next;
};

/* Callback data used by the NIS module when asking us to transmit a response
 * to the client. */
struct dispatch_client_data {
	/* Data for connected clients. */
	struct dispatch_client *connected;
	/* Data for disconnected clients. */
	struct {
		int client_fd;
		union dispatch_client_addr client_addr;
		socklen_t client_addrlen;
		bool_t client_secure;
		char *reply_buf;
		size_t reply_buf_size;
	} dgram;
};

/* A chunk of "securenets" configuration -- if there's a list, then we only
 * respond to clients whose network addresses match the list. */
struct securenet_info {
	int sn_family;
	union {
		struct {
			struct in_addr address, netmask;
		} sin;
		struct {
			struct in6_addr address, netmask;
		} sin6;
	} sn_addr;
	struct securenet_info *sn_next;
};

/* Perform securenets access control. */
void
dispatch_securenets_clear(struct plugin_state *state)
{
	struct securenet_info *sn, *next;
	next = state->securenet_info;
	while (next != NULL) {
		sn = next;
		next = sn->sn_next;
		free(sn);
	}
	state->securenet_info = NULL;
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"cleared securenets access list\n");
}
void
dispatch_securenets_add(struct plugin_state *state, const char *value)
{
	struct securenet_info *sn;
	const char *p, *q;
	char *tmp;
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"adding securenets access entry \"%s\"\n", value);
	sn = malloc(sizeof(*sn));
	if (sn == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"out of memory parsing securenets entry "
				"\"%s\"\n", value);
		return;
	}
	tmp = strdup(value);
	if (tmp == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"out of memory parsing securenets entry "
				"\"%s\"\n", value);
		free(sn);
		return;
	}

	/* Pull out the first token. */
	p = value + strspn(value, " \t");
	q = p + strcspn(p, " \t");
	strncpy(tmp, p, q - p);
	tmp[q - p] = '\0';

	/* Try to parse it. */
	sn->sn_family = AF_UNSPEC;
	if (inet_pton(AF_INET, tmp, &sn->sn_addr.sin.netmask) > 0) {
		sn->sn_family = AF_INET;
	} else {
		if (inet_pton(AF_INET6, tmp, &sn->sn_addr.sin6.netmask) > 0) {
			sn->sn_family = AF_INET6;
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"error parsing \"%s\" as an address, "
					"ignoring\n", tmp);
		}
	}
	if (sn->sn_family == AF_UNSPEC) {
		free(tmp);
		free(sn);
		return;
	}
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"parsed netmask(?) \"%s\" family=%d\n", tmp,
			sn->sn_family);

	/* Pull out the second token. */
	p = q + strspn(q, " \t");
	q = p + strcspn(p, " \t#");
	strncpy(tmp, p, q - p);
	tmp[q - p] = '\0';
	switch (sn->sn_family) {
	case AF_INET:
		if (inet_pton(AF_INET, tmp, &sn->sn_addr.sin.address) <= 0) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"error parsing %s as an IPv4 address, "
					"ignoring\n", tmp);
			sn->sn_family = AF_UNSPEC;
		}
		break;
	case AF_INET6:
		if (inet_pton(AF_INET6, tmp, &sn->sn_addr.sin6.address) <= 0) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"error parsing %s as an IPv6 address, "
					"ignoring\n", tmp);
			sn->sn_family = AF_UNSPEC;
		}
		break;
	default:
		break;
	}

	if (sn->sn_family == AF_UNSPEC) {
		free(sn);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"parsed address \"%s\" family=%d\n", tmp,
				sn->sn_family);
		sn->sn_next = state->securenet_info;
		state->securenet_info = sn;
	}

	free(tmp);
}
static bool_t
dispatch_securenets_check(struct plugin_state *state,
			  union dispatch_client_addr *client_addr)
{
	struct securenet_info *sn;
	struct in_addr addr;
	struct in6_addr addr6, mask6, masked6;
	int i;
	for (sn = state->securenet_info; sn != NULL; sn = sn->sn_next) {
		switch (client_addr->ss.ss_family) {
		case AF_INET:
			if (sn->sn_family != AF_INET) {
				continue;
			}
			addr = client_addr->sin.sin_addr;
			if ((addr.s_addr &
			     sn->sn_addr.sin.netmask.s_addr) ==
			    (sn->sn_addr.sin.address.s_addr &
			     sn->sn_addr.sin.netmask.s_addr)) {
				return TRUE;
			}
			break;
		case AF_INET6:
			addr6 = client_addr->sin6.sin6_addr;
			if ((sn->sn_family == AF_INET) &&
			    IN6_IS_ADDR_V4MAPPED(&addr6)) {
				memcpy(&addr.s_addr,
				       ((uint32_t*)addr6.s6_addr) + 3,
				       sizeof(addr.s_addr));
				if ((addr.s_addr &
				     sn->sn_addr.sin.netmask.s_addr) ==
				    (sn->sn_addr.sin.address.s_addr &
				     sn->sn_addr.sin.netmask.s_addr)) {
					return TRUE;
				}
			}
			if (sn->sn_family == AF_INET6) {
				mask6 = sn->sn_addr.sin6.netmask;
				for (i = 0; i < 16; i++) {
					addr6.s6_addr[i] &= mask6.s6_addr[i];
					masked6.s6_addr[i] &= mask6.s6_addr[i];
					if (addr6.s6_addr[i] !=
					    masked6.s6_addr[i]) {
						break;
					}
				}
				if (i == 16) {
					return TRUE;
				}
			}
			break;
		default:
			break;
		}
	}
	return state->securenet_info ? FALSE : TRUE;
}

/* Send a reply, unbuffered datagram version. */
static bool_t
dispatch_reply_fragment_dgram(struct plugin_state *state,
			      struct dispatch_client_data *cdata,
			      struct rpc_msg *reply,
			      XDR *reply_xdrs,
			      bool_t first_fragment, bool_t last_fragment)
{
	/* Marshal the response. */
	if (xdr_replymsg(reply_xdrs, reply)) {
		/* If this isn't both the first and last fragment in the reply,
		 * log a warning. */
		if (!first_fragment || !last_fragment) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"trying to sending datagram reply (%d "
					"bytes), even though the reply is not "
					"suitable for transmission as a "
					"datagram\n", xdr_getpos(reply_xdrs));
		} else {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"sending datagram reply (%d bytes)\n",
					xdr_getpos(reply_xdrs));
		}
		/* Send the packet. */
		sendto(cdata->dgram.client_fd,
		       cdata->dgram.reply_buf, xdr_getpos(reply_xdrs),
		       0,
		       (struct sockaddr *) &cdata->dgram.client_addr,
		       cdata->dgram.client_addrlen);
	} else {
		/* We weren't able to marshal the response? Try to send a
		 * system-error reply. */
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"error encoding datagram reply -- too big?\n");
		xdr_setpos(reply_xdrs, 0);
		reply->rm_reply.rp_acpt.ar_stat = SYSTEM_ERR;
		reply->rm_reply.rp_acpt.ar_results.proc = (xdrproc_t) &xdr_void;
		reply->rm_reply.rp_acpt.ar_results.where = NULL;
		if (xdr_replymsg(reply_xdrs, reply)) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"sending system-error response\n");
			sendto(cdata->dgram.client_fd,
			       cdata->dgram.reply_buf, xdr_getpos(reply_xdrs),
			       0,
			       (struct sockaddr *) &cdata->dgram.client_addr,
			       cdata->dgram.client_addrlen);
		} else {
			/* XXX */
		}
	}
	return TRUE;
}
static void
dispatch_reply_dgram(struct plugin_state *state,
		     struct dispatch_client_data *cdata,
		     struct rpc_msg *reply, XDR *reply_xdrs)
{
	dispatch_reply_fragment_dgram(state, cdata,
				      reply, reply_xdrs,
				      TRUE, TRUE);
}

static bool_t
dispatch_reply_fragment_connected(struct plugin_state *state,
				  struct dispatch_client_data *cdata,
				  struct rpc_msg *reply,
				  XDR *reply_xdrs,
				  bool_t first_fragment, bool_t last_fragment)
{
	uint32_t len;
	ssize_t next_size;
	/* Record reply - first fragment. */
	if (first_fragment) {
		xdr_replymsg(reply_xdrs, reply);
	}
	/* If we don't have space for the data, stop now. */
	next_size = cdata->connected->client_outbuf_used + 4 +
		    xdr_getpos(reply_xdrs);
	if (next_size > cdata->connected->client_outbuf_size) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"failed to queue stream reply (4+%d bytes)!\n",
				xdr_getpos(reply_xdrs));
		return FALSE;
	}
	/* If we already have data in the buffer, and if this would put us over
	 * the target size, then punt it until next time. */
	if ((cdata->connected->client_outbuf_used > 4) &&
	    (next_size > DEFAULT_TARGET_REPLY_SIZE)) {
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"saving stream reply (4+%d bytes) for later\n",
				xdr_getpos(reply_xdrs));
		return FALSE;
	}
	/* Calculate the fragment length bytes. */
	len = htonl(xdr_getpos(reply_xdrs) | (last_fragment ? 0x80000000 : 0));
	/* Queue the data. */
	memcpy(cdata->connected->client_outbuf +
	       cdata->connected->client_outbuf_used,
	       &len, 4);
	memcpy(cdata->connected->client_outbuf +
	       cdata->connected->client_outbuf_used + 4,
	       cdata->connected->client_workbuf,
	       xdr_getpos(reply_xdrs));
	cdata->connected->client_outbuf_used += (4 + xdr_getpos(reply_xdrs));
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"queued stream reply (4+%d bytes), "
			"%ld total in queue\n",
			xdr_getpos(reply_xdrs),
			(long) cdata->connected->client_outbuf_used);
	return TRUE;
}
/* Send an entire reply record at once. */
static void
dispatch_reply_connected(struct plugin_state *state,
			 struct dispatch_client_data *cdata,
			 struct rpc_msg *reply,
			 XDR *reply_xdrs)
{
	dispatch_reply_fragment_connected(state, cdata,
					  reply, reply_xdrs,
					  TRUE, TRUE);
}

/* Handle a datagram client -- read the request and handle it immediately. */
static void
dispatch_dgram(struct plugin_state *state, int fd)
{
	struct dispatch_client_data cdata;
	char dgram[65536];
	int reqsize;

	/* Read the request. */
	cdata.dgram.client_fd = fd;
	cdata.dgram.client_addrlen = sizeof(cdata.dgram.client_addr);
	cdata.dgram.reply_buf = malloc(state->max_dgram_size);
	cdata.dgram.reply_buf_size = state->max_dgram_size;
	if (cdata.dgram.reply_buf == NULL) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error reading datagram request: "
				"out of memory\n");
		return;
	}
	reqsize = recvfrom(cdata.dgram.client_fd, dgram, sizeof(dgram), 0,
			   (struct sockaddr *) &cdata.dgram.client_addr,
			   &cdata.dgram.client_addrlen);
	if (reqsize != -1) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"datagram request (%d bytes)\n", reqsize);
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"error reading datagram request: %s\n",
				strerror(errno));
		free(cdata.dgram.reply_buf);
		return;
	}
#ifdef HAVE_TCPD
	/* Check tcp_wrappers access control. */
	if ((request_set(state->request_info,
			 RQ_FILE, -1,
			 RQ_CLIENT_SIN, &cdata.dgram.client_addr,
			 0) == NULL) ||
	    (fromhost(state->request_info),
	     hosts_access(state->request_info) == 0)) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"datagram request denied by tcp_wrappers\n");
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"datagram request permitted by tcp_wrappers\n");
	}
#endif
	/* Check securenets access control. */
	if (!dispatch_securenets_check(state, &cdata.dgram.client_addr)) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"datagram request denied by securenets\n");
		free(cdata.dgram.reply_buf);
		return;
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"datagram request permitted by securenets\n");
	}

	switch (cdata.dgram.client_addr.ss.ss_family) {
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	case AF_INET:
		sin = (struct sockaddr_in *) &cdata.dgram.client_addr.sin;
		cdata.dgram.client_secure = ntohs(sin->sin_port) < 1024;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *) &cdata.dgram.client_addr.sin6;
		cdata.dgram.client_secure = ntohs(sin6->sin6_port) < 1024;
		break;
	default:
		cdata.dgram.client_secure = FALSE;
		break;
	}

	/* Handle the request. */
	nis_process_request(state, dgram, reqsize,
			    &dispatch_reply_fragment_dgram,
			    &dispatch_reply_dgram,
			    &cdata, cdata.dgram.client_secure,
			    cdata.dgram.reply_buf,
			    cdata.dgram.reply_buf_size,
			    NULL);
	free(cdata.dgram.reply_buf);
}

/* Set the client's record up to start reading a new query. */
static void
client_set_reading(struct plugin_state *state, struct dispatch_client *client)
{
	client->client_inbuf_used = 0;
	free(client->client_query);
	client->client_query = NULL;
	client->client_query_size = 0;
	client->client_outbuf_used = 0;
	client->client_state = client_reading;
}

/* Set the client's record up to be cleaned up. */
static void
client_set_closing(struct plugin_state *state, struct dispatch_client *client)
{
	client->client_inbuf_used = 0;
	free(client->client_query);
	client->client_query = NULL;
	client->client_query_size = 0;
	free(client->client_outbuf);
	client->client_outbuf = NULL;
	client->client_outbuf_size = 0;
	client->client_outbuf_used = 0;
	free(client->client_workbuf);
	client->client_workbuf = NULL;
	client->client_workbuf_size = 0;
	client->client_state = client_closing;
}

/* Accept a new client connection and set up the client's record. */
static struct dispatch_client *
dispatch_accept_client(struct plugin_state *state, int fd)
{
	struct dispatch_client *client;
	struct linger linger;
	int flags;
	char *outbuf, *workbuf;
	client = malloc(sizeof(*client));
	if (client == NULL) {
		return NULL;
	}
	memset(client, 0, sizeof(*client));
	outbuf = malloc(state->max_dgram_size + state->max_value_size);
	if (outbuf == NULL) {
		free(client);
		return NULL;
	}
	workbuf = malloc(state->max_dgram_size + state->max_value_size);
	if (workbuf == NULL) {
		free(outbuf);
		free(client);
		return NULL;
	}
	client->client_addrlen = sizeof(client->client_addr);
	fd = accept(fd, (struct sockaddr *)&client->client_addr,
		    &client->client_addrlen);
	if (fd == -1) {
		free(workbuf);
		free(outbuf);
		free(client);
		return NULL;
	}
	linger.l_onoff = 1;
	linger.l_linger = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
	switch (client->client_addr.ss.ss_family) {
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	case AF_INET:
		sin = (struct sockaddr_in *) &client->client_addr;
		client->client_secure = ntohs(sin->sin_port) < 1024;
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *) &client->client_addr;
		client->client_secure = ntohs(sin6->sin6_port) < 1024;
		break;
	default:
		client->client_secure = FALSE;
		break;
	}
#ifdef HAVE_TCPD_H
	/* Check tcp_wrappers access control. */
	if ((request_set(state->request_info,
			 RQ_FILE, fd,
			 RQ_CLIENT_SIN, &client->client_addr,
			 0) == NULL) ||
	    (fromhost(state->request_info),
	     hosts_access(state->request_info) == 0)) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"tcp_wrappers rejected client on %d\n", fd);
		close(fd);
		free(workbuf);
		free(outbuf);
		free(client);
		return NULL;
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"tcp_wrappers allows client on %d\n", fd);
	}
#endif
	/* Check securenets access control. */
	if (!dispatch_securenets_check(state, &client->client_addr)) {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"securenets rejected client on %d\n", fd);
		close(fd);
		free(workbuf);
		free(outbuf);
		free(client);
		return NULL;
	} else {
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"securenets allows client on %d\n", fd);
	}
	flags = fcntl(fd, F_GETFL);
	if ((flags & O_NONBLOCK) == 0) {
		fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	}
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"new connected client on %d\n", fd);
	memset(client, 0, sizeof(*client));
	client->client_fd = fd;
	client->client_outbuf = outbuf;
	client->client_outbuf_size = state->max_dgram_size +
				     state->max_value_size;
	client->client_workbuf = workbuf;
	client->client_workbuf_size = state->max_dgram_size +
				      state->max_value_size;
	client_set_reading(state, client);
	return client;
}

/* Decide what to do next. */
static void
client_interpret_nis_result(struct plugin_state *state,
			    struct dispatch_client *client)
{
	if (client->client_query_cookie != NULL) {
		/* The NIS module's expecting us to call again to get more
		 * data. */
		client->client_state = client_replying_with_more;
	} else {
		/* There's no more data to be found for this request. */
		if (client->client_outbuf_used > 0) {
			/* We still have data to send. */
			client->client_state = client_replying_final;
		} else {
			/* Wait to see what the client does next. */
			client_set_reading(state, client);
		}
	}
}

/* Handle reading state. */
static void
client_read(struct plugin_state *state, struct dispatch_client *client)
{
	ssize_t count;
	int32_t len, nlen;
	int last;
	char *query;
	struct dispatch_client_data client_data;
	/* Try to read some data. */
	count = read(client->client_fd,
		     client->client_inbuf + client->client_inbuf_used,
		     sizeof(client->client_inbuf) - client->client_inbuf_used);
	if (count <= 0) {
		if ((count != -1) || (errno != EAGAIN)) {
			/* Disconnect the client. */
			if (count == 0) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"no more data from %d, "
						"marking for closing\n",
						client->client_fd);
			} else {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"error reading from %d, "
						"marking for closing\n",
						client->client_fd);
			}
			client_set_closing(state, client);
		}
	} else {
		/* Record the data as added to the fragment buffer. */
		client->client_inbuf_used += count;
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"have %ld bytes from %d\n",
				(long) client->client_inbuf_used,
				client->client_fd);
		/* Check if we've got a complete fragment. */
		if (client->client_inbuf_used < 4) {
			/* We don't even have a length, so continue reading. */
			return;
		}
		/* Read the length of the first fragment in the buffer. */
		memcpy(&nlen, client->client_inbuf, 4);
		len = ntohl(nlen);
		last = ((len & 0x80000000) != 0);
		len &= 0x7fffffff;
		if (len > 0x10000) {
			/* Disconnect, because that's just ridiculous. */
			slapi_log_error(SLAPI_LOG_FATAL,
					state->plugin_desc->spd_id,
					"client fragment claims to be %d bytes "
					"long, assuming it's an error\n", len);
			client_set_closing(state, client);
			return;
		}
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"fragment is %d bytes long%s, "
				"have %ld bytes pending, on %d\n",
				len, last ? " (last one)" : "",
				(long) client->client_inbuf_used,
				client->client_fd);
		if ((len + 4) <= client->client_inbuf_used) {
			/* Got at least one fragment! */
			nlen = len + client->client_query_size;
			query = malloc(nlen);
			if (query == NULL) {
				/* Out of memory, we'll have to try again
				 * later. */
				return;
			}
			/* Copy any previously-received fragments and append
			 * this one. */
			if (client->client_query_size > 0) {
				memcpy(query,
				       client->client_query,
				       client->client_query_size);
			}
			memcpy(query + client->client_query_size,
			       client->client_inbuf + 4,
			       len);
			/* Save the new query-in-progress. */
			free(client->client_query);
			client->client_query = query;
			client->client_query_size = nlen;
			/* Drop the fragment from the incoming
			 * buffer. */
			memmove(client->client_inbuf,
				client->client_inbuf + (len + 4),
				client->client_inbuf_used - (len + 4));
			client->client_inbuf_used -= (len + 4);
		}
		if (last) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"query is %ld bytes long on %d\n",
					(long) client->client_query_size,
					client->client_fd);
			/* We have a complete query.  Pass it on down. */
			memset(&client_data, 0, sizeof(client_data));
			client_data.connected = client;
			nis_process_request(state,
					    client->client_query,
					    client->client_query_size,
					    &dispatch_reply_fragment_connected,
					    &dispatch_reply_connected,
					    &client_data, client->client_secure,
					    client->client_workbuf,
					    client->client_workbuf_size,
					    &client->client_query_cookie);
			/* Decide what to do next. */
			client_interpret_nis_result(state, client);
		}
	}
}

/* Handle replying states. */
static void
client_write(struct plugin_state *state, struct dispatch_client *client)
{
	ssize_t count;
	int32_t len;
	struct dispatch_client_data client_data;

	/* Try to send some of the pending data. */
	len = client->client_outbuf_used;
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"attempting to send %d bytes to %d\n",
			len, client->client_fd);
	count = write(client->client_fd, client->client_outbuf, len);
	if (count <= 0) {
		if ((count != -1) || (errno != EAGAIN)) {
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"error sending %ld bytes to %d\n",
					(long) client->client_outbuf_used,
					client->client_fd);
			/* Fail, disconnect because we're out of sync. */
			client_set_closing(state, client);
		}
		return;
	}
	slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
			"sent %ld bytes to %d\n", (long) count,
			client->client_fd);
	if (count == client->client_outbuf_used) {
		/* There's no more data to send. */
		if (client->client_state == client_replying_final) {
			/* Done. Go back to reading next time. */
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"waiting for next query on %d\n",
					client->client_fd);
			client_set_reading(state, client);
		} else {
			/* More to send, so ask for more reply data. */
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"fetching more data for %d\n",
					client->client_fd);
			client->client_outbuf_used = 0;
			memset(&client_data, 0, sizeof(client_data));
			client_data.connected = client;
			nis_process_request(state,
					    client->client_query,
					    client->client_query_size,
					    &dispatch_reply_fragment_connected,
					    &dispatch_reply_connected,
					    &client_data, client->client_secure,
					    client->client_workbuf,
					    client->client_workbuf_size,
					    &client->client_query_cookie);
			client_interpret_nis_result(state, client);
		}
	} else {
		/* Partial write, adjust outgoing buffer for next time. */
		memmove(client->client_outbuf,
			client->client_outbuf + count,
			client->client_outbuf_used - count);
		client->client_outbuf_used -= count;
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"%ld bytes to go for %d\n",
				(long) client->client_outbuf_used,
				client->client_fd);
	}
}

/* For a given client that has data for us to read or which is ready for
 * writing, try to service it. */
static void
dispatch_service_client(struct plugin_state *state,
			struct dispatch_client *client,
			struct pollfd *fd)
{
	switch (client->client_state) {
	case client_reading:
		if (fd->revents & POLLIN) {
			client_read(state, client);
		} else {
			client_set_closing(state, client);
		}
		break;
	case client_replying_with_more:
	case client_replying_final:
		if (fd->revents & POLLOUT) {
			client_write(state, client);
		} else {
			client_set_closing(state, client);
		}
		break;
	case client_closing:
	case client_invalid:
		/* never reached */
		assert(0);
		break;
	}
}

void *
dispatch_thread(struct wrapped_thread *t)
{
	struct dispatch_client *clients, *client, *next, **list;
	struct plugin_state *state = wrap_thread_arg(t);
	struct pollfd *fds;
	int i, n_fds, client_count;

	clients = NULL;
	client_count = 0;
	fds = NULL;

	while (state->n_listeners > 0) {
		/* Prune out recently-disconnected clients. */
		list = &clients;
		while (*list != NULL) {
			client = *list;
			next = client->client_next;
			if (client->client_state == client_closing) {
				slapi_log_error(SLAPI_LOG_PLUGIN,
						state->plugin_desc->spd_id,
						"pruning client %d\n",
						client->client_fd);
				if (client->client_fd != -1) {
					close(client->client_fd);
				}
				free(client);
				*list = next;
			} else {
				list = &(client->client_next);
			}
		}
		/* Count the number of connected clients we have. */
		client = clients;
		i = 0;
		while (client != NULL) {
			next = client->client_next;
			client = next;
			i++;
		}
		/* If the "fds" block isn't big enough (or doesn't exist yet),
		 * reallocate it. */
		if (i > client_count) {
			free(fds);
			fds = NULL;
			client_count = i;
		}
		if (fds == NULL) {
			fds = malloc((state->n_listeners + client_count + 1) *
				     sizeof(fds[0]));
			if (fds == NULL) {
				/* Wait a bit, then try again? */
				poll(NULL, 0, 10000);
				continue;
			}
		}
		slapi_log_error(SLAPI_LOG_PLUGIN,
				state->plugin_desc->spd_id,
				"%d connected clients\n", i);

		/* Fill in the set of polling descriptors. */
		memset(fds, 0,
		       ((state->n_listeners + client_count + 1) *
		        sizeof(fds[0])));

		/* Add the shutdown pipe reader. */
		fds[0].fd = wrap_thread_stopfd(t);
		fds[0].events = POLLIN;

		/* Add the listeners. */
		for (i = 0; i < state->n_listeners; i++) {
			fds[i + 1].fd = state->listener[i].fd;
			fds[i + 1].events = POLLIN;
		}
		i++;

		/* Add the client list. */
		client = clients;
		while (client != NULL) {
			fds[i].fd = client->client_fd;
			switch (client->client_state) {
			case client_reading:
				fds[i].events = POLLIN;
				break;
			case client_replying_with_more:
			case client_replying_final:
				fds[i].events = POLLOUT;
				break;
			case client_closing:
			case client_invalid:
				/* shouldn't happen */
				assert(0);
				break;
			}
			client = client->client_next;
			i++;
		}

		/* Check for status updates. */
		slapi_log_error(SLAPI_LOG_PLUGIN, state->plugin_desc->spd_id,
				"listening\n");
		n_fds = i;
		switch (poll(fds, n_fds, -1)) {
		case -1:
			switch (errno) {
			case EINTR:
				continue;
				break;
			default:
				break;
			}
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"done waiting\n");
			free(fds);
			return NULL;
			break;
		case 0:
			slapi_log_error(SLAPI_LOG_PLUGIN,
					state->plugin_desc->spd_id,
					"no request(timeout?)\n");
			continue;
		default:
			break;
		}

		/* Save the head of the existing clients list. */
		client = clients;

		/* Check the shutdown pipe reader. */
		if (fds[0].revents & POLLIN) {
			break;
		}

		/* Iterate over listening sockets which have work for us. */
		for (i = 0; i < state->n_listeners; i++) {
			if ((fds[i + 1].revents & POLLIN) == 0) {
				continue;
			}
			switch (state->listener[i].type) {
			case SOCK_DGRAM:
				/* Datagram requests we handle right
				 * here, right now. */
				dispatch_dgram(state, fds[i + 1].fd);
				break;
			case SOCK_STREAM:
				/* Try to accept a new client. New clients get
				 * inserted at the head of the list. */
				next = dispatch_accept_client(state,
							      fds[i + 1].fd);
				if (next != NULL) {
					slapi_log_error(SLAPI_LOG_PLUGIN,
							state->plugin_desc->spd_id,
							"new client on %d\n",
							next->client_fd);
					next->client_next = clients;
					clients = next;
				}
				break;
			default:
				/* never reached */
				assert(0);
				break;
			}
		}
		i++;

		/* Service the already-connected clients. */
		for (; i < n_fds; i++, client = client->client_next) {
			assert(client != NULL);
			assert(client->client_fd == fds[i].fd);
			dispatch_service_client(state, client, &fds[i]);
		}
	}
	free(fds);
	slapi_log_error(SLAPI_LOG_PLUGIN,
			state->plugin_desc->spd_id,
			"listening thread stopping\n");
	return state;
}
