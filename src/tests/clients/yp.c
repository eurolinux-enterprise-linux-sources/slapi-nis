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

#include "../../src/config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <rpc/rpc.h>
#include "../../yp/yp.h"

static struct sockaddr_in server;
static int connected;

static int
master(CLIENT *client, FILE *output, int argc, char **argv)
{
	ypresp_master *ret;
	ypreq_nokey nokey;
	if (argc != 2) {
		fprintf(stderr, "\"master\" requires 2 arguments\n");
		return 1;
	}
	memset(&nokey, 0, sizeof(nokey));
	nokey.domain = argv[0];
	nokey.map = argv[1];
	ret = ypproc_master_2(&nokey, client);
	if ((ret != NULL) && (ret->stat == YP_TRUE)) {
		fprintf(output, "%s\n", ret->peer);
		return 0;
	}
	return 1;
}

static int
order(CLIENT *client, FILE *output, int argc, char **argv)
{
	ypresp_order *ret;
	ypreq_nokey nokey;
	if (argc != 2) {
		fprintf(stderr, "\"order\" requires 2 arguments\n");
		return 1;
	}
	memset(&nokey, 0, sizeof(nokey));
	nokey.domain = argv[0];
	nokey.map = argv[1];
	ret = ypproc_order_2(&nokey, client);
	if ((ret != NULL) && (ret->stat == YP_TRUE)) {
		fprintf(output, "%lu\n", (unsigned long) ret->ordernum);
		return 0;
	}
	return 1;
}

static int
match(CLIENT *client, FILE *output, int argc, char **argv)
{
	ypresp_val *resp;
	ypreq_key req;
	if (argc != 3) {
		fprintf(stderr, "\"match\" requires 3 arguments\n");
		return 1;
	}
	req.domain = argv[0];
	req.map = argv[1];
	req.key.keydat_val = argv[2];
	req.key.keydat_len = strlen(argv[2]);
	memset(&resp, 0, sizeof(resp));
	resp = ypproc_match_2(&req, client);
	if (resp != NULL) {
		fprintf(output, "%s\t%.*s\n",
			argv[2], resp->val.valdat_len, resp->val.valdat_val);
		return 0;
	}
	return 1;
}

static int
domain(CLIENT *client, FILE *output, int argc, char **argv)
{
	bool_t *ret;
	if (argc != 1) {
		fprintf(stderr, "\"domain\" requires 1 argument\n");
		return 1;
	}
	ret = ypproc_domain_2(&argv[0], client);
	if (ret != NULL) {
		fprintf(output, *ret ? "TRUE\n" : "FALSE\n");
		return 0;
	}
	return 1;
}

static int
cat(CLIENT *client, FILE *output, int argc, char **argv)
{
	ypresp_key_val *ret;
	ypreq_key key;
	if (argc != 2) {
		fprintf(stderr, "\"cat\" requires 2 arguments\n");
		return 1;
	}
	memset(&key, 0, sizeof(key));
	key.domain = argv[0];
	key.map = argv[1];
	ret = ypproc_first_2(&key, client);
	if ((ret != NULL) && (ret->stat == YP_TRUE)) {
		while ((ret != NULL) && (ret->stat == YP_TRUE)) {
			fprintf(output, "%.*s\t%.*s\n",
				ret->key.keydat_len,
				ret->key.keydat_val,
				ret->val.valdat_len,
				ret->val.valdat_val);
			key.key = ret->key;
			ret = ypproc_next_2(&key, client);
		}
		return 0;
	}
	return 1;
}
static int
readjunk(char *fd, char *data, int size)
{
	int ret;
	ret = read(* (int *) fd, data, size);
	if (ret == 0) {
		close(* (int *) fd);
		return -1;
	}
	return ret;
}
static int
writejunk(char *fd, char *data, int size)
{
	return write(* (int *) fd, data, size);
}
static int
all(CLIENT *client, FILE *output, int argc, char **argv)
{
	ypresp_all *ret;
	int i, sock;
	ypreq_nokey nokey;
	struct rpc_msg req, rep;
	struct ypresp_all resp;
	XDR s;
	if (argc != 2) {
		fprintf(stderr, "\"all\" requires 2 arguments\n");
		return 1;
	}
	if (!connected) {
		fprintf(stderr, "\"all\" can only be used with -c\n");
		return 1;
	}

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "error setting up RPC client\n");
		return 1;
	}
	if (connect(sock, (struct sockaddr *) &server, sizeof(server)) != 0) {
		fprintf(stderr, "error setting up RPC client\n");
		return 1;
	}

	memset(&s, 0, sizeof(s));
	xdrrec_create(&s, 0, 0, (char *) &sock, &readjunk, &writejunk);
	s.x_op = XDR_ENCODE;

	memset(&req, 0, sizeof(req));
	req.rm_xid = time(NULL) % 0x1000;
	req.rm_direction = CALL;
	req.rm_call.cb_rpcvers = 2;
	req.rm_call.cb_prog = YPPROG;
	req.rm_call.cb_vers = YPVERS;
	req.rm_call.cb_proc = YPPROC_ALL;

	memset(&nokey, 0, sizeof(nokey));
	nokey.domain = argv[0];
	nokey.map = argv[1];

	if (!xdr_callmsg(&s, &req)) {
		fprintf(stderr, "error setting up RPC client\n");
		return 1;
	}
	if (!xdr_ypreq_nokey(&s, &nokey)) {
		fprintf(stderr, "error setting up RPC client\n");
		return 1;
	}
	xdrrec_endofrecord(&s, TRUE);
	xdr_destroy(&s);

	memset(&s, 0, sizeof(s));
	xdrrec_create(&s, 0, 0, (char *) &sock, &readjunk, &writejunk);
	s.x_op = XDR_DECODE;
	xdrrec_skiprecord(&s);

	do {
		memset(&rep, 0, sizeof(rep));
		rep.rm_reply.rp_acpt.ar_results.where = (char*) &resp;
		rep.rm_reply.rp_acpt.ar_results.proc = (xdrproc_t) &xdr_ypresp_all;
		memset(&resp, 0, sizeof(resp));
		if (!xdr_replymsg(&s, &rep)) {
			break;
		}
	} while ((rep.rm_direction != REPLY) || (rep.rm_xid != req.rm_xid));
	if ((rep.rm_reply.rp_stat == MSG_ACCEPTED) &&
	    (rep.rm_reply.rp_acpt.ar_stat == SUCCESS)) {
		while (resp.ypresp_all_u.val.stat == YP_TRUE) {
			fprintf(output, "%.*s\t%.*s\n",
				resp.ypresp_all_u.val.key.keydat_len,
				resp.ypresp_all_u.val.key.keydat_val,
				resp.ypresp_all_u.val.val.valdat_len,
				resp.ypresp_all_u.val.val.valdat_val);
			if (!resp.more) {
				break;
			}
			memset(&resp, 0, sizeof(resp));
			if (!xdr_ypresp_all(&s, &resp)) {
				break;
			}
		}
		xdr_destroy(&s);
		return 0;
	} else {
		xdr_destroy(&s);
		return 1;
	}
}

static int
maplist(CLIENT *client, FILE *output, int argc, char **argv)
{
	ypresp_maplist *list;
	ypmaplist *i;
	if (argc != 1) {
		fprintf(stderr, "\"maplist\" requires 1 argument\n");
		return 1;
	}
	list = ypproc_maplist_2(&argv[0], client);
	if (list != NULL) {
		for (i = list->maps; i != NULL; i = i->next) {
			fprintf(output, "%s\n", i->map);
		}
		return 0;
	}
	return 1;
}

static int
dispatch(CLIENT *client, FILE *output, int argc, char **argv)
{
	if (strcmp(argv[0], "all") == 0) {
		return all(client, output, argc - 1, argv + 1);
	}
	if (strcmp(argv[0], "cat") == 0) {
		return cat(client, output, argc - 1, argv + 1);
	}
	if (strcmp(argv[0], "match") == 0) {
		return match(client, output, argc - 1, argv + 1);
	}
	if (strcmp(argv[0], "domain") == 0) {
		return domain(client, output, argc - 1, argv + 1);
	}
	if (strcmp(argv[0], "order") == 0) {
		return order(client, output, argc - 1, argv + 1);
	}
	if (strcmp(argv[0], "master") == 0) {
		return master(client, output, argc - 1, argv + 1);
	}
	if (strcmp(argv[0], "maplist") == 0) {
		return maplist(client, output, argc - 1, argv + 1);
	}
	return 1;
}

static void
usage(const char *argv0)
{
	if (strchr(argv0, '/') != NULL) {
		argv0 = strrchr(argv0, '/') + 1;
	}
	printf("Usage: %s [-c] [-h host] [-p port] "
	       "[-t udp-timeout] command [args ...]\n", argv0);
	printf("Recognized commands:\n");
	printf("    domain DOMAIN\n\t"
	       "Check if server serves DOMAIN.\n");
	printf("    maplist DOMAIN\n\t"
	       "Retrieve list of maps in DOMAIN.\n");
	printf("    master DOMAIN MAP\n\t"
	       "Retrieve name of master server for MAP in DOMAIN.\n");
	printf("    order DOMAIN MAP\n\t"
	       "Retrieve time of last change to MAP in DOMAIN.\n");
	printf("    match DOMAIN MAP KEY\n\t"
	       "Use yp_match to search for KEY in MAP in DOMAIN.\n");
	printf("    cat DOMAIN MAP\n\t"
	       "Use yp_first/yp_next to walk contents of MAP in DOMAIN.\n");
	printf("    all DOMAIN MAP\n\t"
	       "Use yp_all to list contents of MAP in DOMAIN.\n");
}
int
main(int argc, char **argv)
{
	int c, sock, port = 0, timeout = 60, ret, six;
	FILE *output;
	CLIENT *client;
	struct timeval tv;
	struct addrinfo *hostaddr, hints;
	const char *host = NULL;
	six = 0;
	while ((c = getopt(argc, argv, "6ch:p:t:")) != -1) {
		switch (c) {
#ifdef HAVE_CLNTTCP6_CREATE
		case '6':
			six = 1;
			break;
#else
		case '6':
			fprintf(stderr, "IPv6 not supported\n");
			return 1;
			break;
#endif
		case 'c':
			connected = 1;
			break;
		case 'h':
			host = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			return 1;
			break;
		}
	}
	if (argc == optind) {
		usage(argv[0]);
		return 1;
	}
	output = popen("env LANG=C sort", "w");
	if (output == NULL) {
		perror("popen");
		return 1;
	}
	if (host != NULL) {
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = six ? AF_INET6 : AF_INET;
		hints.ai_socktype = connected ? SOCK_STREAM : SOCK_DGRAM;
		if (getaddrinfo(host, NULL, &hints, &hostaddr) != 0) {
			perror("getaddrinfo");
			return 1;
		}
		memcpy(&server, hostaddr->ai_addr, sizeof(server));
	} else {
		get_myaddress(&server);
	}
	server.sin_port = htons(port);
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = timeout;
	sock = RPC_ANYSOCK;
	client =
#ifdef HAVE_CLNTTCP6_CREATE
	six ?  (connected ? clnttcp6_create(&server, YPPROG, YPVERS, &sock,
					    0, 0) :
			    clntudp6_create(&server, YPPROG, YPVERS, tv,
			     		    &sock)) :
#endif
	       (connected ? clnttcp_create(&server, YPPROG, YPVERS, &sock,
					   0, 0) :
			    clntudp_create(&server, YPPROG, YPVERS, tv,
			     		   &sock));
	if (client == NULL) {
		fprintf(stderr, "error setting up RPC client\n");
		return -1;
	}
	if (argc == optind) {
		fprintf(stderr, "%s: no command specified\n", argv[0]);
		return 1;
	}
	ret = dispatch(client, output, argc - optind, argv + optind);
	fclose(output);
	return ret;
}
