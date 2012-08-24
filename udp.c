/*
 * UDP functions
 * Copyright (C) 2011 Unix Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License (COPYING file) for more details.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "util.h"
#include "udp.h"

#ifndef IPV6_ADD_MEMBERSHIP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif

static int is_multicast(struct sockaddr_storage *addr) {
	int ret = 0;
	switch (addr->ss_family) {
	case AF_INET: {
		struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
		ret = IN_MULTICAST(ntohl(addr4->sin_addr.s_addr));
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
		ret = IN6_IS_ADDR_MULTICAST(&addr6->sin6_addr);
		break;
	} }
	return ret;
}

extern int ai_family;

static int bind_addr(const char *hostname, const char *service, int socktype, struct sockaddr_storage *addr, int *addrlen, int *sock) {
	struct addrinfo hints, *res, *ressave;
	int n, ret = -1;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = ai_family;
	hints.ai_socktype = socktype;

	n = getaddrinfo(hostname, service, &hints, &res);
	if (n < 0) {
		ts_LOGf("ERROR: getaddrinfo(%s): %s\n", hostname, gai_strerror(n));
		return ret;
	}

	ressave = res;
	while (res) {
		*sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (*sock > -1) {
			if (bind(*sock, res->ai_addr, res->ai_addrlen) == 0) {
				memcpy(addr, res->ai_addr, sizeof(*addr));
				*addrlen = res->ai_addrlen;
				ret = 0;
				goto OUT;
			} else {
				char str_addr[INET6_ADDRSTRLEN];
				my_inet_ntop(res->ai_family, res->ai_addr, str_addr, sizeof(str_addr));
				ts_LOGf("ERROR: bind: %s:%s (%s): %s\n",
					hostname, service, str_addr, strerror(errno));
			}
			close(*sock);
			*sock = -1;
		}
		res = res->ai_next;
	}
OUT:
	freeaddrinfo(ressave);

	if (*sock > -1) {
		int on = 1;
		setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		set_sock_nonblock(*sock);
	}

	return ret;
}

static int join_multicast_group(int sock, int ttl, struct sockaddr_storage *addr) {
	switch (addr->ss_family) {
	case AF_INET: {
		struct ip_mreq mreq;
		mreq.imr_multiaddr.s_addr = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
		mreq.imr_interface.s_addr = INADDR_ANY;

		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const void *)&mreq, sizeof(mreq)) < 0) {
			ts_LOGf("ERROR: setsockopt(IP_ADD_MEMBERSHIP): %s\n", strerror(errno));
			return -1;
		}
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
			ts_LOGf("ERROR: setsockopt(IP_MULTICAST_TTL %d): %s\n", ttl, strerror(errno));
		}
		break;
	}

	case AF_INET6: {
		struct ipv6_mreq mreq6;
		memcpy(&mreq6.ipv6mr_multiaddr, &(((struct sockaddr_in6 *)addr)->sin6_addr), sizeof(struct in6_addr));
		mreq6.ipv6mr_interface = 0; // interface index, will be set later

		if (setsockopt(sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq6, sizeof(mreq6)) < 0) {
			ts_LOGf("ERROR: setsockopt(IPV6_ADD_MEMBERSHIP): %s\n", strerror(errno));
			return -1;
		}
		if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &ttl, sizeof(ttl)) < 0) {
			ts_LOGf("ERROR: setsockopt(IPV6_MULTICAST_HOPS %d): %s\n", ttl, strerror(errno));
		}
		break;
	}
	}

	return 0;
}

int udp_connect_input(struct io *io) {
	struct sockaddr_storage addr;
	int addrlen = sizeof(addr);
	int sock = -1;

	memset(&addr, 0, sizeof(addr));

	ts_LOGf("Connecting input to %s port %s\n", io->hostname, io->service);
	if (bind_addr(io->hostname, io->service, SOCK_DGRAM, &addr, &addrlen, &sock) < 0)
		return -1;

	/* Set receive buffer size to ~2.0MB */
	int bufsize = (2000000 / 1316) * 1316;
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (void *)&bufsize, sizeof(bufsize));

	if (is_multicast(&addr)) {
		if (join_multicast_group(sock, io->ttl, &addr) < 0) {
			close(sock);
			return -1;
		}
	}

	io->fd = sock;
	ts_LOGf("Input connected to fd:%d\n", io->fd);

	return 1;
}

int udp_connect_output(struct io *io) {
	struct sockaddr_storage addr;
	int addrlen = sizeof(addr);
	int sock = -1;

	memset(&addr, 0, sizeof(addr));

	ts_LOGf("Connecting output to %s port %s ttl: %d\n",
		io->hostname, io->service, io->ttl);
	if (bind_addr(io->hostname, io->service, SOCK_DGRAM, &addr, &addrlen, &sock) < 0)
		return -1;

	/* Set send buffer size to ~2.0MB */
	int bufsize = (2000000 / 1316) * 1316;
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (void *)&bufsize, sizeof(bufsize));

	if (is_multicast(&addr)) {
		if (join_multicast_group(sock, io->ttl, &addr) < 0) {
			close(sock);
			return -1;
		} else {
			if (addr.ss_family == AF_INET) {
				if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &io->intf, sizeof(io->intf)) < 0) {
					ts_LOGf("ERROR: setsockopt(IP_MUTICAST_IF %s): %s\n", inet_ntoa(io->intf), strerror(errno));
					close(sock);
					return -1;
				}
			}
			if (addr.ss_family == AF_INET6 && io->v6_if_index > -1) {
				if (setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_IF, (void *)&io->v6_if_index, sizeof(io->v6_if_index)) < 0) {
					ts_LOGf("ERROR: setsockopt(IPV6_MUTICAST_IF %d): %s\n", io->v6_if_index, strerror(errno));
					close(sock);
					return -1;
				}
			}
		}
	}

	if (addr.ss_family == AF_INET && io->tos > -1) {
		if (setsockopt(sock, IPPROTO_IP, IP_TOS, &io->tos, sizeof(io->tos)) < 0) {
			ts_LOGf("ERROR: setsockopt(IP_TOS 0x%02x): %s\n", io->tos, strerror(errno));
		}
	}

	if (connect(sock, (struct sockaddr *)&addr, addrlen) < 0) {
		ts_LOGf("ERROR: udp_connect(): %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	io->fd = sock;
	ts_LOGf("Output connected to fd:%d\n", io->fd);

	return 1;
}
