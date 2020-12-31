// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2012-2021  B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
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
#include <unistd.h>
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

static void ipv4_request_mac_resolve(const alfred_addr *addr)
{
	const struct sockaddr *sockaddr;
	struct sockaddr_in inet4;
	size_t sockaddr_len;
	int sock;
	char t = 0;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return;

	memset(&inet4, 0, sizeof(inet4));
	inet4.sin_family = AF_INET;
	inet4.sin_port = htons(9);
	inet4.sin_addr.s_addr = addr->ipv4.s_addr;
	sockaddr = (const struct sockaddr *)&inet4;
	sockaddr_len = sizeof(inet4);

	sendto(sock, &t, sizeof(t), 0, sockaddr, sockaddr_len);
	close(sock);
}

int ipv4_arp_request(struct interface *interface, const alfred_addr *addr,
		     struct ether_addr *mac)
{
	struct arpreq arpreq;
	struct sockaddr_in *sin;
	int retries = 1;

	memset(&arpreq, 0, sizeof(arpreq));
	memset(mac, 0, ETH_ALEN);

	sin = (struct sockaddr_in *)&arpreq.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr->ipv4.s_addr;

	strncpy(arpreq.arp_dev, interface->interface, sizeof(arpreq.arp_dev));
	arpreq.arp_dev[sizeof(arpreq.arp_dev) - 1] = '\0';

	while ((ioctl(interface->netsock, SIOCGARP, &arpreq) < 0) || !(arpreq.arp_flags & ATF_COM)) {
		ipv4_request_mac_resolve(addr);
		usleep(200000);

		if (retries-- == 0)
			break;
	}

	if (arpreq.arp_flags & ATF_COM) {
		memcpy(mac, arpreq.arp_ha.sa_data, sizeof(*mac));
	} else {
		perror("arp: incomplete");
		return -1;
	}

	return 0;
}
