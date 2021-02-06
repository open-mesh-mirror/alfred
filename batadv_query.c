// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "alfred.h"
#include "batadv_query.h"
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef CONFIG_ALFRED_CAPABILITIES
#include <sys/capability.h>
#endif
#include <sys/types.h>

#include "batadv_querynl.h"

static int enable_net_admin_capability(int enable)
{
	int ret = 0;

#ifdef CONFIG_ALFRED_CAPABILITIES
	cap_t cap_cur;
	cap_flag_value_t cap_flag;
	cap_value_t cap_net_admin = CAP_NET_ADMIN;

	if (enable)
		cap_flag = CAP_SET;
	else
		cap_flag = CAP_CLEAR;

	cap_cur = cap_get_proc();
	if (!cap_cur) {
		perror("cap_get_proc");
		return -1;
	}

	ret = cap_set_flag(cap_cur, CAP_EFFECTIVE, 1, &cap_net_admin, cap_flag);
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

int mac_to_ipv6(const struct ether_addr *mac, alfred_addr *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->ipv6.s6_addr[0] = 0xfe;
	addr->ipv6.s6_addr[1] = 0x80;

	addr->ipv6.s6_addr[8] = mac->ether_addr_octet[0] ^ 0x02;
	addr->ipv6.s6_addr[9] = mac->ether_addr_octet[1];
	addr->ipv6.s6_addr[10] = mac->ether_addr_octet[2];

	addr->ipv6.s6_addr[11] = 0xff;
	addr->ipv6.s6_addr[12] = 0xfe;

	addr->ipv6.s6_addr[13] = mac->ether_addr_octet[3];
	addr->ipv6.s6_addr[14] = mac->ether_addr_octet[4];
	addr->ipv6.s6_addr[15] = mac->ether_addr_octet[5];

	return 0;
}

int is_ipv6_eui64(const struct in6_addr *addr)
{
	size_t i;

	for (i = 2; i < 8; i++) {
		if (addr->s6_addr[i] != 0x0)
			return 0;
	}

	if (addr->s6_addr[0] != 0xfe ||
	    addr->s6_addr[1] != 0x80 ||
	    addr->s6_addr[11] != 0xff ||
	    addr->s6_addr[12] != 0xfe)
		return 0;

	return 1;
}

int ipv6_to_mac(const alfred_addr *addr, struct ether_addr *mac)
{
	if (!is_ipv6_eui64(&addr->ipv6))
		return -EINVAL;

	mac->ether_addr_octet[0] = addr->ipv6.s6_addr[8] ^ 0x02;
	mac->ether_addr_octet[1] = addr->ipv6.s6_addr[9];
	mac->ether_addr_octet[2] = addr->ipv6.s6_addr[10];
	mac->ether_addr_octet[3] = addr->ipv6.s6_addr[13];
	mac->ether_addr_octet[4] = addr->ipv6.s6_addr[14];
	mac->ether_addr_octet[5] = addr->ipv6.s6_addr[15];

	if (!is_valid_ether_addr(mac->ether_addr_octet))
		return -EINVAL;

	return 0;
}

int ipv4_to_mac(struct interface *interface,
		const alfred_addr *addr, struct ether_addr *mac)
{
	if (ipv4_arp_request(interface, addr, mac) < 0)
		return -EINVAL;

	if (!is_valid_ether_addr(mac->ether_addr_octet))
		return -EINVAL;

	return 0;
}

int batadv_interface_check(const char *mesh_iface)
{
	int ret;

	enable_net_admin_capability(1);
	ret = batadv_interface_check_netlink(mesh_iface);
	enable_net_admin_capability(0);

	return ret;
}

static int tg_compare(void *d1, void *d2)
{
	struct tg_entry *s1 = d1, *s2 = d2;

	if (memcmp(&s1->mac, &s2->mac, sizeof(s1->mac)) == 0)
		return 1;
	else
		return 0;
}

static int tg_choose(void *d1, int size)
{
	struct tg_entry *s1 = d1;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < sizeof(s1->mac); i++) {
		hash += s1->mac.ether_addr_octet[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

struct hashtable_t *tg_hash_new(const char *mesh_iface)
{
	struct hashtable_t *tg_hash;

	tg_hash = hash_new(64, tg_compare, tg_choose);
	if (!tg_hash)
		return NULL;

	enable_net_admin_capability(1);
	translate_mac_netlink(mesh_iface, tg_hash);
	enable_net_admin_capability(0);

	return tg_hash;
}

void tg_hash_free(struct hashtable_t *tg_hash)
{
	hash_delete(tg_hash, free);
}

int tg_hash_add(struct hashtable_t *tg_hash, struct ether_addr *mac,
		struct ether_addr *originator)
{
	struct tg_entry *n;

	n = malloc(sizeof(*n));
	if (!n)
		return -ENOMEM;

	n->mac = *mac;
	n->originator = *originator;

	if (hash_add(tg_hash, n)) {
		free(n);
		return -EEXIST;
	}

	return 0;
}

struct ether_addr *translate_mac(struct hashtable_t *tg_hash,
				 const struct ether_addr *mac)
{
	struct tg_entry search = {
		.mac = *mac,
	};
	struct tg_entry *found;

	found = hash_find(tg_hash, &search);
	if (!found)
		return 0;

	return &found->originator;
}

static int orig_compare(void *d1, void *d2)
{
	struct orig_entry *s1 = d1, *s2 = d2;

	if (memcmp(&s1->mac, &s2->mac, sizeof(s1->mac)) == 0)
		return 1;
	else
		return 0;
}

static int orig_choose(void *d1, int size)
{
	struct orig_entry *s1 = d1;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < sizeof(s1->mac); i++) {
		hash += s1->mac.ether_addr_octet[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

struct hashtable_t *orig_hash_new(const char *mesh_iface)
{
	struct hashtable_t *orig_hash;

	orig_hash = hash_new(64, orig_compare, orig_choose);
	if (!orig_hash)
		return NULL;

	enable_net_admin_capability(1);
	get_tq_netlink(mesh_iface, orig_hash);
	enable_net_admin_capability(0);

	return orig_hash;
}

void orig_hash_free(struct hashtable_t *orig_hash)
{
	hash_delete(orig_hash, free);
}

int orig_hash_add(struct hashtable_t *orig_hash, struct ether_addr *mac,
		  uint8_t tq)
{
	struct orig_entry *n;

	n = malloc(sizeof(*n));
	if (!n)
		return -ENOMEM;

	n->mac = *mac;
	n->tq = tq;

	if (hash_add(orig_hash, n)) {
		free(n);
		return -EEXIST;
	}

	return 0;
}

uint8_t get_tq(struct hashtable_t *orig_hash, struct ether_addr *mac)
{
	struct orig_entry search = {
		.mac = *mac,
		.tq = 0,
	};
	struct orig_entry *found;

	found = hash_find(orig_hash, &search);
	if (!found)
		return 0;

	return found->tq;
}
