/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2006-2019  B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich, Marek Lindner
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */
#ifndef _BATADV_QUERY_H
#define _BATADV_QUERY_H

#include <stdint.h>
#include <netinet/in.h>

#include "hash.h"

struct orig_entry {
	struct ether_addr mac;
	uint8_t tq;
};

struct tg_entry {
	struct ether_addr mac;
	struct ether_addr originator;
};

struct hashtable_t *tg_hash_new(const char *mesh_iface);
void tg_hash_free(struct hashtable_t *tg_hash);
int tg_hash_add(struct hashtable_t *tg_hash, struct ether_addr *mac,
		struct ether_addr *originator);
struct ether_addr *translate_mac(struct hashtable_t *tg_hash,
				 const struct ether_addr *mac);

struct hashtable_t *orig_hash_new(const char *mesh_iface);
void orig_hash_free(struct hashtable_t *orig_hash);
int orig_hash_add(struct hashtable_t *orig_hash, struct ether_addr *mac,
		  uint8_t tq);
uint8_t get_tq(struct hashtable_t *orig_hash, struct ether_addr *mac);
int batadv_interface_check(const char *mesh_iface);
int mac_to_ipv6(const struct ether_addr *mac, alfred_addr *addr);
int ipv6_to_mac(const alfred_addr *addr, struct ether_addr *mac);
int ipv4_to_mac(struct interface *interface,
		const alfred_addr *addr, struct ether_addr *mac);
int is_ipv6_eui64(const struct in6_addr *addr);

#endif
