/*
 * Copyright 2008,2009,2011 Red Hat, Inc.
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
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

#ifdef HAVE_DIRSRV_SLAPI_PLUGIN_H
#include <nspr.h>
#include <nss.h>
#include <dirsrv/slapi-plugin.h>
#else
#include <slapi-plugin.h>
#endif

#include <rpc/xdr.h>
#include "../yp/yp.h"
#include <rpc/pmap_prot.h>

#include "portmap.h"

#ifndef RPCBPROG
#define RPCBPROG PMAPPROG
#endif
#ifndef RPCBVERS
#define RPCBVERS 3
#endif
#ifndef RPCBPROC_SET
#define RPCBPROC_SET 1
#endif
#ifndef RPCBPROC_UNSET
#define RPCBPROC_UNSET 2
#endif
#ifndef _PATH_RPCBINDSOCK
#define _PATH_RPCBINDSOCK "/var/run/rpcbind.sock"
#endif

#ifdef PORTMAP_MAIN
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
int
slapi_log_error(int i, char *f, char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	fprintf(stderr, "%s[%#x]:", f, i);
	vfprintf(stderr, fmt, va);
	va_end(va);
	return 0;
}
int
main(int argc, char **argv)
{
	int s, ret, port;
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		printf("error allocating socket\n");
		return 1;
	}
	if ((port = portmap_bind_resvport(s, AF_INET, 0)) < 0) {
		printf("error binding to reserved port, using 541\n");
		port = 541; /* arbitrary */
	} else {
		printf("bound to reserved port %d\n", port);
	}
	s = portmap_create_client_socket("portmap", port);
	if (s == -1) {
		printf("error creating portmap/rpcbind client socket\n");
		return 1;
	}
	setregid(2516, 2516);
	setreuid(2510, 2510);
	sleep(60);
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET, IPPROTO_TCP, 0);
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET, IPPROTO_UDP, 0);
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET6, IPPROTO_TCP, 0);
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET6, IPPROTO_UDP, 0);
	portmap_register("portmap", &s, port, YPPROG, YPVERS,
			 AF_INET, IPPROTO_TCP, port);
	portmap_register("portmap", &s, port, YPPROG, YPVERS,
			 AF_INET, IPPROTO_UDP, port);
	portmap_register("portmap", &s, port, YPPROG, YPVERS,
			 AF_INET6, IPPROTO_TCP, port);
	portmap_register("portmap", &s, port, YPPROG, YPVERS,
			 AF_INET6, IPPROTO_UDP, port);
	ret = system("rpcinfo | grep ypserv");
	ret = system("rpcinfo -p | grep ypserv");
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET, IPPROTO_TCP, port);
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET, IPPROTO_UDP, port);
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET6, IPPROTO_TCP, port);
	portmap_unregister("portmap", &s, port, YPPROG, YPVERS,
			   AF_INET6, IPPROTO_UDP, port);
	return 0;
}
#endif

static bool_t
portmap_register_work(const char *module, int *client_sock, int but_not,
		      bool_t stream,
		      struct sockaddr *dgram_address, socklen_t addrlen,
		      int prog, int vers, int proc,
		      void *args, xdrproc_t args_xdr)
{
	char portmap_buf[4000], auth_buf[4000], reply_buf[8000], *log_id;
	int portmap_length, reply_length;
	AUTH *auth;
	XDR portmap_xdrs, auth_xdrs;
	struct rpc_msg msg;
	int fragment_length;
	bool_t ret = FALSE;
	struct sockaddr addr;
	struct pollfd pollfd;
	int i, err, sock2 = -1;
	static u_long xid;

	log_id = (char *) module;

	/* Build the RPC header. */
	memset(&msg, 0, sizeof(msg));
	msg.rm_xid = xid = (time(NULL) ^ prog ^ vers ^ proc ^ getpid());
	msg.rm_direction = CALL;
	msg.rm_call.cb_rpcvers = 2;
	msg.rm_call.cb_prog = prog;
	msg.rm_call.cb_vers = vers;
	msg.rm_call.cb_proc = proc;

	/* Build an authenticator. */
	memset(&auth_buf, 0, sizeof(auth_buf));
	xdrmem_create(&auth_xdrs, auth_buf, sizeof(auth_buf), XDR_ENCODE);
	auth = authnone_create();
	auth_marshall(auth, &auth_xdrs);
	msg.rm_call.cb_cred = auth->ah_cred;
	msg.rm_call.cb_verf = auth->ah_verf;

	/* Encode the header and the arguments, then clean up temporaries. */
	memset(&portmap_buf, 0, sizeof(portmap_buf));
	if (stream) {
		/* Leave room for the message length on a stream connection. */
		xdrmem_create(&portmap_xdrs,
			      portmap_buf + 4, sizeof(portmap_buf) - 4,
			      XDR_ENCODE);
	} else {
		/* Straight-up datagram. */
		xdrmem_create(&portmap_xdrs, portmap_buf, sizeof(portmap_buf),
			      XDR_ENCODE);
	}

	/* Encode the message header and the call itself. */
	xdr_callmsg(&portmap_xdrs, &msg);
	(*args_xdr)(&portmap_xdrs, args);
	portmap_length = xdr_getpos(&portmap_xdrs);
	auth_destroy(auth);
	xdr_destroy(&auth_xdrs);
	xdr_destroy(&portmap_xdrs);
	memset(&portmap_xdrs, 0, sizeof(portmap_xdrs));

	if (stream) {
		/* Compute the request message length and prepend it. */
		fragment_length = portmap_length;
		fragment_length |= 0x80000000;
		portmap_buf[0] = (fragment_length >> 24) & 0xff;
		portmap_buf[1] = (fragment_length >> 16) & 0xff;
		portmap_buf[2] = (fragment_length >>  8) & 0xff;
		portmap_buf[3] = (fragment_length >>  0) & 0xff;
		portmap_length += 4;
	} else {
		/* Point the datagram socket at the remote. */
		if (connect(*client_sock, dgram_address, addrlen) != 0) {
			slapi_log_error(SLAPI_LOG_FATAL, log_id,
					"error targeting portmap: %s\n",
					strerror(errno));
			return FALSE;
		}
	}

	/* Transmit our request.  Be ready to retry a few times if it doesn't
	 * go through for datagram connections. */
	for (i = 1; i < 32; i *= 2) {
		/* Try to send our request.  If there's any problem,
		 * immediately retry. */
		if (send(*client_sock, &portmap_buf, portmap_length,
			 MSG_NOSIGNAL) != portmap_length) {
			err = errno;
			slapi_log_error(SLAPI_LOG_FATAL, log_id,
					"error sending request to portmap or "
					"rpcbind on %d: %s\n", *client_sock,
					strerror(err));
			if (stream) {
				if (err == EPIPE) {
					/* Try again with a new client
					 * connection -- some RPC
					 * implementations will cause rpcbind
					 * to drop idle clients. */
					snprintf(reply_buf, sizeof(reply_buf),
						 "%s", module);
					sock2 = portmap_create_client_socket(reply_buf,
									     but_not);
					if (sock2 != -1) {
						if (send(sock2, &portmap_buf, portmap_length,
							 MSG_NOSIGNAL) == portmap_length) {
							slapi_log_error(SLAPI_LOG_FATAL, log_id,
									"retried sending request "
									"to portmap or rpcbind "
									"on %d, and succeeded\n",
									sock2);
							close(*client_sock);
							*client_sock = sock2;
						} else {
							/* Still got an error -- bail. */
							close(sock2);
							break;
						}
					} else {
						break;
					}
				} else {
					break;
				}
			} else {
				continue;
			}
		}

		/* Wait for a response. */
		pollfd.fd = *client_sock;
		pollfd.events = POLLIN | POLLERR;
		if ((poll(&pollfd, 1, stream ? -1 : i * 1000) > 0) &&
		    (pollfd.revents & POLLIN)) {
			/* Read the response. */
			reply_length = recv(*client_sock,
					    reply_buf, sizeof(reply_buf), 0);
			/* Decode the response. */
			if (reply_length > 0) {
				/* Decode an RPC header and the returned
				 * boolean from the buffer. */
				memset(&msg, 0, sizeof(msg));
				if (stream) {
					/* Strip off the fragment length. */
					fragment_length = (reply_buf[0] << 24) |
							  (reply_buf[1] << 16) |
							  (reply_buf[2] <<  8) |
							  (reply_buf[3] <<  0);
					if ((fragment_length & 0x80000000) == 0) {
						/* XXX - if it's not the whole
						 * message, then we're screwed.
						 * */;
					}
					fragment_length &= 0x7fffffff;
					xdrmem_create(&portmap_xdrs,
						      reply_buf + 4,
						      reply_length - 4,
						      XDR_DECODE);
				} else {
					/* Straight-up datagram. */
					xdrmem_create(&portmap_xdrs,
						      reply_buf, reply_length,
						      XDR_DECODE);
				}
				msg.rm_reply.rp_acpt.ar_results.where =
					(caddr_t) &ret;
				msg.rm_reply.rp_acpt.ar_results.proc =
					(xdrproc_t) xdr_bool;
				if (xdr_replymsg(&portmap_xdrs, &msg)) {
					if ((msg.rm_direction == REPLY) &&
					    (msg.rm_xid == xid)) {
						xdr_destroy(&portmap_xdrs);
						memset(&portmap_xdrs, 0,
						       sizeof(portmap_xdrs));
						break;
					}
				}
				xdr_destroy(&portmap_xdrs);
				memset(&portmap_xdrs, 0, sizeof(portmap_xdrs));
			}
		}
	}

	if (!stream) {
		/* "Disconnect" from a datagram service,  but keep our client
		 * socket around. */
		memset(&addr, 0, sizeof(addr));
		addr.sa_family = AF_UNSPEC;
		connect(*client_sock, &addr, sizeof(addr));
		/* Check for a timeout. */
		if (i == 32) {
			slapi_log_error(SLAPI_LOG_FATAL, log_id,
					"timeout registering with portmap "
					"service\n");
			return FALSE;
		}
	}

	/* Check that the portmapper didn't just reject the request out of
	 * hand. */
	if (msg.rm_reply.rp_stat != MSG_ACCEPTED) {
		slapi_log_error(SLAPI_LOG_FATAL, log_id,
				"portmap request not accepted\n");
		switch (msg.rm_reply.rp_rjct.rj_stat) {
		const char *auth_status;
		case AUTH_ERROR:
			switch (msg.rm_reply.rp_rjct.rj_why) {
			case AUTH_OK:
				auth_status = "ok";
				break;
			case AUTH_BADCRED:
				auth_status = "bad credentials";
				break;
			case AUTH_REJECTEDCRED:
				auth_status = "rejected credentials";
				break;
			case AUTH_BADVERF:
				auth_status = "bad verifier";
				break;
			case AUTH_REJECTEDVERF:
				auth_status = "rejected verifier";
				break;
			case AUTH_TOOWEAK:
				auth_status = "too weak";
				break;
			case AUTH_INVALIDRESP:
				auth_status = "invalid response";
				break;
			case AUTH_FAILED:
			default:
				auth_status = "unknown error";
				break;
			}
			slapi_log_error(SLAPI_LOG_FATAL, log_id,
					"portmap request rejected: "
					"authentication failed: %s\n",
					auth_status);
			break;
		case RPC_MISMATCH:
			slapi_log_error(SLAPI_LOG_FATAL, log_id,
					"portmap request rejected: "
					"RPC mismatch\n");
			break;
		}
		return FALSE;
	}

	/* Validate the portmapper's credentials. */
	auth = authunix_create_default();
	if (auth_validate(auth, &msg.rm_reply.rp_acpt.ar_verf)) {
		slapi_log_error(SLAPI_LOG_PLUGIN, log_id,
				"portmap reply authenticated\n");
	} else {
		slapi_log_error(SLAPI_LOG_FATAL, log_id,
				"portmap reply failed authentication\n");
	}
	auth_destroy(auth);

	/* Check if we the portmapper gave us a reply argument. */
	if (msg.rm_reply.rp_acpt.ar_stat != SUCCESS) {
		slapi_log_error(SLAPI_LOG_FATAL, log_id,
				"portmap request not processed\n");
		return FALSE;
	}

	/* Check what happened. */
	if (ret) {
		slapi_log_error(SLAPI_LOG_PLUGIN, log_id,
				"portmap request succeeded\n");
	} else {
		slapi_log_error(SLAPI_LOG_FATAL, log_id,
				"portmap request failed\n");
	}

	return ret;
}

struct rpcbind_req {
	int program;
	int version;
	char *network;
	char *address;
	char *owner;
};

static bool_t
portmap_xdr_rpcbind_req(XDR *xdrs, struct rpcbind_req *req)
{
	return xdr_int(xdrs, &req->program) &&
	       xdr_int(xdrs, &req->version) &&
	       xdr_wrapstring(xdrs, &req->network) &&
	       xdr_wrapstring(xdrs, &req->address) &&
	       xdr_wrapstring(xdrs, &req->owner);
}

static bool_t
portmap_register_rpcbind(const char *module, int *client_sock, int but_not,
			 bool_t create,
		         int family, int protocol, int port,
			 int program, int version)
{
	char address_buf[64];
	struct rpcbind_req req;
	req.program = program;
	req.version = version;
	req.owner = "superuser";
	switch (family) {
	case AF_INET:
		snprintf(address_buf, sizeof(address_buf), "0.0.0.0.%d.%d",
			 (port >> 8) & 0xff, port & 0xff);
		switch (protocol) {
		case IPPROTO_TCP:
			req.network = "tcp";
			req.address = address_buf;
			break;
		case IPPROTO_UDP:
			req.network = "udp";
			req.address = address_buf;
			break;
		default:
			req.network = NULL;
			req.address = NULL;
			break;
		}
		break;
	case AF_INET6:
		snprintf(address_buf, sizeof(address_buf), "::.%d.%d",
			 (port >> 8) & 0xff, port & 0xff);
		switch (protocol) {
		case IPPROTO_TCP:
			req.network = "tcp6";
			req.address = address_buf;
			break;
		case IPPROTO_UDP:
			req.network = "udp6";
			req.address = address_buf;
			break;
		default:
			req.network = NULL;
			req.address = NULL;
			break;
		}
		break;
	default:
		req.network = NULL;
		req.address = NULL;
		break;
	}
	return portmap_register_work(module, client_sock, but_not,
				     TRUE, NULL, 0,
				     RPCBPROG, RPCBVERS,
				     create ? RPCBPROC_SET : RPCBPROC_UNSET,
				     &req,
				     (xdrproc_t) &portmap_xdr_rpcbind_req);
}

static bool_t
portmap_register_portmap(const char *module, int *client_sock, int but_not,
			 bool_t create,
		         int protocol, int port, int program, int version)
{
	struct pmap map;
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port = htons(PMAPPORT);
	map.pm_prog = program;
	map.pm_vers = version;
	map.pm_prot = protocol;
	map.pm_port = port;
	return portmap_register_work(module, client_sock, but_not,
				     FALSE,
				     (struct sockaddr *) &sin, sizeof(sin),
				     PMAPPROG, PMAPVERS,
				     create ? PMAPPROC_SET : PMAPPROC_UNSET,
				     &map, (xdrproc_t) &xdr_pmap);
}

static bool_t
portmap_is_stream(int sd)
{
	int socktype;
	socklen_t socklen = sizeof(socktype);
	if (getsockopt(sd, SOL_SOCKET, SO_TYPE, &socktype, &socklen) == 0) {
		return (socklen == sizeof(int)) && (socktype == SOCK_STREAM);
	}
	return FALSE;
}

bool_t
portmap_register(const char *log_id, int *resv_sock, int but_not,
		 int program, int version,
		 int family, int protocol, int port)
{
	return portmap_is_stream(*resv_sock) ?
	       portmap_register_rpcbind(log_id, resv_sock, but_not,
					TRUE,
					family, protocol, port,
					program, version) :
	       portmap_register_portmap(log_id, resv_sock, but_not,
					TRUE,
					protocol, port,
					program, version);
}

bool_t
portmap_unregister(const char *log_id, int *resv_sock, int but_not,
		   int program, int version,
		   int family, int protocol, int port)
{
	return portmap_is_stream(*resv_sock) ?
	       portmap_register_rpcbind(log_id, resv_sock, but_not,
					FALSE,
					family, protocol, port,
					program, version) :
	       portmap_register_portmap(log_id, resv_sock, but_not,
					FALSE,
					protocol, port,
					program, version);
}

int
portmap_bind_resvport(int fd, int family, int but_not)
{
	int i, offset, port;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	switch (family) {
	case AF_INET:
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		break;
	case AF_INET6:
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		break;
	default:
		return -1;
	}
	offset = getpid() % 512;
	for (i = 512; i < 1024; i++) {
		port = ((offset + i) % 512) + 512;
		if (port == but_not) {
			continue;
		}
		switch (family) {
		case AF_INET:
			sin.sin_port = htons(port);
			if (bind(fd, (struct sockaddr*) &sin,
				 sizeof(sin)) == 0) {
				return port;
			}
			break;
		case AF_INET6:
			sin6.sin6_port = htons(port);
			if (bind(fd, (struct sockaddr*) &sin6,
				 sizeof(sin6)) == 0) {
				return port;
			}
			break;
		}
	}
	return -1;
}

static int
portmap_create_rpcbind_client_socket(char *module)
{
	int sockfd;
	struct sockaddr_un sockun;

	sockfd = socket(PF_LOCAL, SOCK_STREAM, 0);
	if (sockfd == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, module,
				"error allocating portmap client socket\n");
		return -1;
	}
	memset(&sockun, 0, sizeof(sockun));
	sockun.sun_family = AF_LOCAL;
	strcpy(sockun.sun_path, _PATH_RPCBINDSOCK);
	if (connect(sockfd, (struct sockaddr *) &sockun, sizeof(sockun)) != 0) {
		slapi_log_error(SLAPI_LOG_FATAL, module,
				"error connecting rpcbind client "
				"socket to the service\n");
		close(sockfd);
		return -1;
	}
	return sockfd;
}

static int
portmap_create_portmap_client_socket(char *module, int but_not)
{
	int sockfd;
	sockfd = socket(PF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		slapi_log_error(SLAPI_LOG_FATAL, module,
				"error allocating portmap client socket\n");
		return -1;
	}
	if (portmap_bind_resvport(sockfd, AF_INET, but_not) <= 0) {
		slapi_log_error(SLAPI_LOG_PLUGIN, module,
				"unable to bind portmap client socket to a "
				"privileged port\n");
		close(sockfd);
		return -1;
	}
	return sockfd;
}

int
portmap_create_client_socket(char *module, int but_not)
{
	int sock;
	sock = portmap_create_rpcbind_client_socket(module);
	if (sock == -1) {
		sock = portmap_create_portmap_client_socket(module, but_not);
	}
	slapi_log_error(SLAPI_LOG_PLUGIN, module,
			"created client socket %d for portmap client\n",
			sock);
	return sock;
}
