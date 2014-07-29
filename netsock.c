/*
 * Copyright (C) 2012-2014 B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "alfred.h"
#include "batadv_query.h"
#include "packet.h"

const struct in6_addr in6addr_localmcast = {{{ 0xff, 0x02, 0x00, 0x00,
					       0x00, 0x00, 0x00, 0x00,
					       0x00, 0x00, 0x00, 0x00,
					       0x00, 0x00, 0x00, 0x01 } } };

int netsock_close(int sock)
{
	return close(sock);
}

int netsock_open(struct globals *globals)
{
	int sock;
	struct sockaddr_in6 sin6;
	struct ifreq ifr;
	int ret;

	globals->netsock = -1;

	sock = socket(PF_INET6, SOCK_DGRAM, 0);
	if (sock  < 0) {
		perror("can't open socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, globals->interface, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		perror("can't get interface");
		goto err;
	}

	globals->scope_id = ifr.ifr_ifindex;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_port = htons(ALFRED_PORT);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = in6addr_any;
	sin6.sin6_scope_id = ifr.ifr_ifindex;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("can't get MAC address");
		goto err;
	}

	memcpy(&globals->hwaddr, &ifr.ifr_hwaddr.sa_data, 6);
	mac_to_ipv6(&globals->hwaddr, &globals->address);

	if (bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		perror("can't bind");
		goto err;
	}

	ret = fcntl(sock, F_GETFL, 0);
	if (ret < 0) {
		perror("failed to get file status flags");
		goto err;
	}

	ret = fcntl(sock, F_SETFL, ret | O_NONBLOCK);
	if (ret < 0) {
		perror("failed to set file status flags");
		goto err;
	}

	globals->netsock = sock;

	return 0;
err:
	close(sock);
	return -1;
}
