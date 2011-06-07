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

#include "udp.h"

int udp_connect_input(struct io *io) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		ts_LOGf("socket(SOCK_DGRAM): %s", strerror(errno));
		return -1;
	}

	ts_LOGf("Connecting input to udp://%s:%d/\n", inet_ntoa(io->addr), io->port);
	int on = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	// subscribe to multicast group
	if (IN_MULTICAST(ntohl(io->addr.s_addr))) {
		struct ip_mreq mreq;
		memcpy(&mreq.imr_multiaddr, &io->addr, sizeof(struct in_addr));
		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
			ts_LOGf("setsockopt(IP_ADD_MEMBERSHIP %s): %s", inet_ntoa(io->addr), strerror(errno));
			return -1;
		}
	}
	// bind to the socket so data can be read
	struct sockaddr_in receiving_from;
	memset(&receiving_from, 0, sizeof(receiving_from));
	receiving_from.sin_family = AF_INET;
	receiving_from.sin_addr   = io->addr;
	receiving_from.sin_port   = htons(io->port);
	if (bind(sock, (struct sockaddr *) &receiving_from, sizeof(receiving_from)) < 0) {
		ts_LOGf("bind(): %s", strerror(errno));
		return -1;
	}

	io->fd = sock;
	ts_LOGf("Input connected to fd:%d\n", io->fd);

	return 1;
}

int udp_connect_output(struct io *io) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		ts_LOGf("socket(SOCK_DGRAM): %s\n", strerror(errno));
		return -1;
	}

	ts_LOGf("Connecting output to udp://%s:%d ttl:%d\n",
		inet_ntoa(io->addr), io->port, io->ttl);

	int on = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	set_sock_nonblock(sock);

	// subscribe to multicast group
	if (IN_MULTICAST(ntohl(io->addr.s_addr))) {
		int ttl = io->ttl;
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
			ts_LOGf("setsockopt(IP_MUTICAST_TTL): %s\n", strerror(errno));
			close(sock);
			return -1;
		}
		if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, &io->intf, sizeof(io->intf)) < 0) {
			ts_LOGf("setsockopt(IP_MUTICAST_IF %s): %s\n", inet_ntoa(io->intf), strerror(errno));
			close(sock);
			return -1;
		}
	}

	struct sockaddr_in sockaddr;
	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family			= AF_INET;
	sockaddr.sin_addr.s_addr	= io->addr.s_addr;
	sockaddr.sin_port			= htons(io->port);
	if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
		ts_LOGf("udp_connect() error: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	io->fd = sock;
	ts_LOGf("Output connected to fd:%d\n", io->fd);

	return 1;
}
