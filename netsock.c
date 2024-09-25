// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#ifdef CONFIG_ALFRED_CAPABILITIES
#include <sys/capability.h>
#endif
#include "alfred.h"
#include "batadv_query.h"
#include "packet.h"
#include "list.h"
#include "hash.h"

alfred_addr alfred_mcast = {
		.ipv6 = {{{ 0xff, 0x02, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x01 } } }
};

static int server_compare(void *d1, void *d2)
{
	struct server *s1 = d1, *s2 = d2;
	/* compare source and type */
	if (memcmp(&s1->hwaddr, &s2->hwaddr, sizeof(s1->hwaddr)) == 0)
		return 1;
	else
		return 0;
}

static int server_choose(void *d1, int size)
{
	struct server *s1 = d1;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < sizeof(s1->hwaddr); i++) {
		hash += s1->hwaddr.ether_addr_octet[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

void netsock_close_all(struct globals *globals)
{
	struct interface *interface, *is;

	list_for_each_entry_safe(interface, is, &globals->interfaces, list) {
		if (interface->netsock >= 0)
			close(interface->netsock);
		if (interface->netsock_mcast >= 0)
			close(interface->netsock_mcast);
		list_del(&interface->list);
		hash_delete(interface->server_hash, free);
		free(interface->interface);
		free(interface);
	}

	globals->best_server = NULL;
}

struct interface *netsock_first_interface(struct globals *globals)
{
	struct interface *interface;

	list_for_each_entry(interface, &globals->interfaces, list) {
		if (interface->netsock >= 0)
			return interface;
	}

	return NULL;
}

static struct interface *netsock_find_interface(struct globals *globals,
						const char *name)
{
	struct interface *interface;

	list_for_each_entry(interface, &globals->interfaces, list) {
		if (strcmp(name, interface->interface) == 0)
			return interface;
	}

	return NULL;
}

int netsock_set_interfaces(struct globals *globals, char *interfaces)
{
	char *input, *saveptr, *token;
	struct interface *interface;

	netsock_close_all(globals);

	/* interface 'none' disables all interface operations */
	if (is_iface_disabled(interfaces))
		return 0;

	input = interfaces;
	while ((token = strtok_r(input, ",", &saveptr))) {
		input = NULL;

		interface = netsock_find_interface(globals, token);
		if (interface)
			continue;

		interface = malloc(sizeof(*interface));
		if (!interface) {
			netsock_close_all(globals);
			return -ENOMEM;
		}

		memset(&interface->hwaddr, 0, sizeof(interface->hwaddr));
		memset(&interface->address, 0, sizeof(interface->address));
		interface->scope_id = 0;
		interface->interface = NULL;
		interface->netsock = -1;
		interface->netsock_mcast = -1;
		interface->server_hash = NULL;

		interface->interface = strdup(token);
		if (!interface->interface) {
			free(interface);
			netsock_close_all(globals);
			return -ENOMEM;
		}

		interface->server_hash = hash_new(64, server_compare,
						  server_choose);
		if (!interface->server_hash) {
			free(interface->interface);
			free(interface);
			netsock_close_all(globals);
			return -ENOMEM;
		}

		list_add_tail(&interface->list, &globals->interfaces);
	}

	return 0;
}

static int enable_raw_bind_capability(int enable)
{
	int ret = 0;

#ifdef CONFIG_ALFRED_CAPABILITIES
	cap_t cap_cur;
	cap_flag_value_t cap_flag;
	cap_value_t cap_net_raw = CAP_NET_RAW;

	if (enable)
		cap_flag = CAP_SET;
	else
		cap_flag = CAP_CLEAR;

	cap_cur = cap_get_proc();
	if (!cap_cur) {
		perror("cap_get_proc");
		return -1;
	}

	ret = cap_set_flag(cap_cur, CAP_EFFECTIVE, 1, &cap_net_raw, cap_flag);
	if (ret < 0) {
		perror("cap_set_flag");
		goto out;
	}

	ret = cap_set_proc(cap_cur);
	if (ret < 0) {
		perror("cap_set_proc");
		goto out;
	}

out:
	cap_free(cap_cur);
#endif

	return ret;
}

static void netsock_close_error(struct interface *interface)
{
	fprintf(stderr, "Error on netsock detected\n");

	if (interface->netsock >= 0)
		close(interface->netsock);

	if (interface->netsock_mcast >= 0)
		close(interface->netsock_mcast);

	interface->netsock = -1;
	interface->netsock_mcast = -1;
}

static void netsock_handle_event(struct globals *globals,
				 struct epoll_handle *handle,
				 struct epoll_event *ev)
{
	struct interface *interface;

	interface = container_of(handle, struct interface, netsock_epoll);

	if (ev->events & EPOLLERR) {
		netsock_close_error(interface);
		return;
	}

	recv_alfred_packet(globals, interface, interface->netsock);
}

static void netsock_mcast_handle_event(struct globals *globals,
				       struct epoll_handle *handle,
				       struct epoll_event *ev)
{
	struct interface *interface;

	interface = container_of(handle, struct interface, netsock_mcast_epoll);

	if (ev->events & EPOLLERR) {
		netsock_close_error(interface);
		return;
	}

	recv_alfred_packet(globals, interface, interface->netsock_mcast);
}

static int netsock_open(struct globals *globals, struct interface *interface)
{
	int sock;
	int sock_mc;
	struct sockaddr_in6 sin6, sin6_mc;
	struct ipv6_mreq mreq;
	struct epoll_event ev;
	struct ifreq ifr;
	int ret;

	interface->netsock = -1;
	interface->netsock_mcast = -1;

	sock = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock  < 0) {
		perror("can't open socket");
		return -1;
	}

	sock_mc = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_mc  < 0) {
		close(sock);
		perror("can't open socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface->interface, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		perror("can't get interface");
		goto err;
	}

	interface->scope_id = ifr.ifr_ifindex;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("can't get MAC address");
		goto err;
	}

	memcpy(&interface->hwaddr, &ifr.ifr_hwaddr.sa_data, 6);
	mac_to_ipv6(&interface->hwaddr, &interface->address);

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_port = htons(ALFRED_PORT);
	sin6.sin6_family = AF_INET6;
	memcpy(&sin6.sin6_addr, &interface->address, sizeof(sin6.sin6_addr));
	sin6.sin6_scope_id = interface->scope_id;

	memset(&sin6_mc, 0, sizeof(sin6_mc));
	sin6_mc.sin6_port = htons(ALFRED_PORT);
	sin6_mc.sin6_family = AF_INET6;
	memcpy(&sin6_mc.sin6_addr, &alfred_mcast,
	       sizeof(sin6_mc.sin6_addr));
	sin6_mc.sin6_scope_id = interface->scope_id;

	enable_raw_bind_capability(1);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface->interface,
		       strlen(interface->interface) + 1)) {
		perror("can't bind to device");
		goto err;
	}

	if (setsockopt(sock_mc, SOL_SOCKET, SO_BINDTODEVICE,
		       interface->interface,
		       strlen(interface->interface) + 1)) {
		perror("can't bind to device");
		goto err;
	}
	enable_raw_bind_capability(0);

	if (bind(sock, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		char ipstr_buf[INET6_ADDRSTRLEN];
		const char *ipstr;

		ipstr = inet_ntop(AF_INET6, &interface->address.ipv6.s6_addr,
				  ipstr_buf, INET6_ADDRSTRLEN);

		if (errno == EADDRNOTAVAIL)
			fprintf(stderr, "can't bind to interface %s; "
				"expected ipv6 address not found: %s\n",
				interface->interface,
				ipstr);
		else
			perror("can't bind");
		goto err;
	}

	if (bind(sock_mc, (struct sockaddr *)&sin6_mc, sizeof(sin6_mc)) < 0) {
		perror("can't bind");
		goto err;
	}

	memcpy(&mreq.ipv6mr_multiaddr, &alfred_mcast,
	       sizeof(mreq.ipv6mr_multiaddr));
	mreq.ipv6mr_interface = interface->scope_id;

	if (setsockopt(sock_mc, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP,
		       &mreq, sizeof(mreq))) {
		perror("can't add multicast membership");
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

	ret = fcntl(sock_mc, F_GETFL, 0);
	if (ret < 0) {
		perror("failed to get file status flags");
		goto err;
	}

	ret = fcntl(sock_mc, F_SETFL, ret | O_NONBLOCK);
	if (ret < 0) {
		perror("failed to set file status flags");
		goto err;
	}

	ev.events = EPOLLIN;
	ev.data.ptr = &interface->netsock_epoll;
	interface->netsock_epoll.handler = netsock_handle_event;

	if (epoll_ctl(globals->epollfd, EPOLL_CTL_ADD, sock,
		      &ev) == -1) {
		perror("Failed to add epoll for netsock");
		goto err;
	}

	ev.events = EPOLLIN;
	ev.data.ptr = &interface->netsock_mcast_epoll;
	interface->netsock_mcast_epoll.handler = netsock_mcast_handle_event;

	if (epoll_ctl(globals->epollfd, EPOLL_CTL_ADD, sock_mc,
		      &ev) == -1) {
		perror("Failed to add epoll for netsock_mcast");
		goto err;
	}

	interface->netsock = sock;
	interface->netsock_mcast = sock_mc;

	return 0;
err:
	close(sock);
	close(sock_mc);
	return -1;
}

static int netsock_open4(struct globals *globals, struct interface *interface)
{
	int sock;
	int sock_mc;
	struct sockaddr_in sin4, sin_mc;
	struct epoll_event ev;
	struct ip_mreq mreq;
	struct ifreq ifr;
	int ret;

	interface->netsock = -1;
	interface->netsock_mcast = -1;

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock  < 0) {
		perror("ipv4: can't open socket");
		return -1;
	}

	sock_mc = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock_mc  < 0) {
		close(sock);
		perror("ipv4: can't open mc socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface->interface, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl(sock_mc, SIOCGIFHWADDR, &ifr) == -1) {
		perror("ipv4: can't get MAC address");
		goto err;
	}
	memcpy(&interface->hwaddr, &ifr.ifr_hwaddr.sa_data, 6);

	memset(&sin4, 0, sizeof(sin4));
	sin4.sin_port = htons(ALFRED_PORT);
	sin4.sin_family = AF_INET;
	sin4.sin_addr.s_addr = INADDR_ANY;

	memset(&sin_mc, 0, sizeof(sin_mc));
	sin_mc.sin_port = htons(ALFRED_PORT);
	sin_mc.sin_family = AF_INET;
	memcpy(&sin_mc.sin_addr, &alfred_mcast, sizeof(sin_mc.sin_addr));

	enable_raw_bind_capability(1);
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface->interface,
		       strlen(interface->interface) + 1)) {
		perror("ipv4: can't bind to device");
		goto err;
	}

	if (setsockopt(sock_mc, SOL_SOCKET, SO_BINDTODEVICE,
		       interface->interface, strlen(interface->interface) + 1)) {
		perror("ipv4: can't bind to device");
		goto err;
	}
	enable_raw_bind_capability(0);

	ret = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret)) < 0) {
		perror("ipv4: can't set reuse flag");
		goto err;
	}
	if (setsockopt(sock_mc, SOL_SOCKET, SO_REUSEADDR, &ret, sizeof(ret)) < 0) {
		perror("ipv4: can't set mc reuse flag");
		goto err;
	}

	if (bind(sock, (struct sockaddr *)&sin4, sizeof(sin4)) < 0) {
		perror("ipv4: can't bind");
		goto err;
	}

	if (bind(sock_mc, (struct sockaddr *)&sin_mc, sizeof(sin_mc)) < 0) {
		perror("ipv4: can't bind mc");
		goto err;
	}

	memcpy(&mreq.imr_multiaddr, &alfred_mcast.ipv4, sizeof(mreq.imr_multiaddr));

	if (ioctl(sock_mc, SIOCGIFADDR, &ifr) < 0) {
		perror("ipv4: can't get IP address");
		goto err;
	}
	mreq.imr_interface = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
	memcpy(&interface->address.ipv4,
	       &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr,
	       sizeof(struct in_addr));

	if (setsockopt(sock_mc, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		perror("ipv4: can't add multicast membership");
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

	ret = fcntl(sock_mc, F_GETFL, 0);
	if (ret < 0) {
		perror("ipv4: failed to get file status flags");
		goto err;
	}

	ret = fcntl(sock_mc, F_SETFL, ret | O_NONBLOCK);
	if (ret < 0) {
		perror("ipv4: failed to set file status flags");
		goto err;
	}

	ev.events = EPOLLIN;
	ev.data.ptr = &interface->netsock_epoll;
	interface->netsock_epoll.handler = netsock_handle_event;

	if (epoll_ctl(globals->epollfd, EPOLL_CTL_ADD, sock,
		      &ev) == -1) {
		perror("Failed to add epoll for netsock");
		goto err;
	}

	ev.events = EPOLLIN;
	ev.data.ptr = &interface->netsock_mcast_epoll;
	interface->netsock_mcast_epoll.handler = netsock_mcast_handle_event;

	if (epoll_ctl(globals->epollfd, EPOLL_CTL_ADD, sock_mc,
		      &ev) == -1) {
		perror("Failed to add epoll for netsock_mcast");
		goto err;
	}

	interface->netsock = sock;
	interface->netsock_mcast = sock_mc;

	return 0;
err:
	close(sock);
	close(sock_mc);
	return -1;
}

int netsock_open_all(struct globals *globals)
{
	int num_socks = 0;
	int ret;
	struct interface *interface;

	list_for_each_entry(interface, &globals->interfaces, list) {
		if (globals->ipv4mode)
			ret = netsock_open4(globals, interface);
		else
			ret = netsock_open(globals, interface);

		if (ret >= 0)
			num_socks++;
	}

	return num_socks;
}

size_t netsocket_count_interfaces(struct globals *globals)
{
	struct interface *interface;
	size_t count = 0;

	list_for_each_entry(interface, &globals->interfaces, list)
		count++;

	return count;
}

void netsock_reopen(struct globals *globals)
{
	struct interface *interface;

	list_for_each_entry(interface, &globals->interfaces, list) {
		if (interface->netsock < 0) {
			if (globals->ipv4mode)
				netsock_open4(globals, interface);
			else
				netsock_open(globals, interface);
		}
	}
}

int netsock_own_address(const struct globals *globals,
			const alfred_addr *address)
{
	struct interface *interface;

	list_for_each_entry(interface, &globals->interfaces, list) {
		if (0 == memcmp(address, &interface->address,
				sizeof(*address)))
			return 1;
	}

	return 0;
}
