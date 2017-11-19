// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2012-2017  B.A.T.M.A.N. contributors:
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
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <netinet/ether.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <time.h>
#include "alfred.h"

int time_diff(struct timespec *tv1, struct timespec *tv2,
	      struct timespec *tvdiff) {
	tvdiff->tv_sec = tv1->tv_sec - tv2->tv_sec;
	if (tv1->tv_nsec < tv2->tv_nsec) {
		tvdiff->tv_nsec = 1000000000 + tv1->tv_nsec - tv2->tv_nsec;
		tvdiff->tv_sec -= 1;
	} else {
		tvdiff->tv_nsec = tv1->tv_nsec - tv2->tv_nsec;
	}

	return (tvdiff->tv_sec >= 0);
}

void time_random_seed(void)
{
	struct timespec now;
	uint8_t *c = (uint8_t *)&now;
	size_t i;
	unsigned int s = 0;

	clock_gettime(CLOCK_REALTIME, &now);

	for (i = 0; i < sizeof(now); i++) {
		s *= 127u;
		s += c[i];
	}

	srand(s);
}

uint16_t get_random_id(void)
{
	return random();
}

bool is_valid_ether_addr(uint8_t addr[ETH_ALEN])
{
	/* multicast address */
	if (addr[0] & 0x01)
		return false;

	/* 00:00:00:00:00:00 */
	if ((addr[0] | addr[1] | addr[2] | addr[3] | addr[4] | addr[5]) == 0)
		return false;

	return true;
}

int ipv4_arp_request(struct interface *interface, const alfred_addr *addr,
		     struct ether_addr *mac)
{
	struct arpreq arpreq;
	struct sockaddr_in *sin;

	memset(&arpreq, 0, sizeof(arpreq));
	memset(mac, 0, ETH_ALEN);

	sin = (struct sockaddr_in *)&arpreq.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr->ipv4.s_addr;

	strncpy(arpreq.arp_dev, interface->interface, sizeof(arpreq.arp_dev));
	arpreq.arp_dev[sizeof(arpreq.arp_dev) - 1] = '\0';

	if (ioctl(interface->netsock, SIOCGARP, &arpreq) < 0)
		return -1;

	if (arpreq.arp_flags & ATF_COM) {
		memcpy(mac, arpreq.arp_ha.sa_data, sizeof(*mac));
	} else {
		perror("arp: incomplete");
		return -1;
	}

	return 0;
}
