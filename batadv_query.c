/*
 * Copyright (C) 2012-2017  B.A.T.M.A.N. contributors:
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
#include "debugfs.h"

#define DEBUG_BATIF_PATH_FMT "%s/batman_adv/%s"
#define DEBUG_TRANSTABLE_GLOBAL "transtable_global"
#define DEBUG_ORIGINATORS "originators"

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

static int batadv_interface_check_debugfs(const char *mesh_iface)
{
	char full_path[MAX_PATH + 1];
	FILE *f;

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_TRANSTABLE_GLOBAL,
			  mesh_iface, full_path, sizeof(full_path));
	f = fopen(full_path, "r");
	if (!f) {
		fprintf(stderr,
			"Could not find %s for interface %s. Make sure it is a valid batman-adv soft-interface\n",
			DEBUG_TRANSTABLE_GLOBAL, mesh_iface);
		return -1;
	}
	fclose(f);

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_ORIGINATORS,
			  mesh_iface, full_path, sizeof(full_path));
	f = fopen(full_path, "r");
	if (!f) {
		fprintf(stderr,
			"Could not find %s for interface %s. Make sure it is a valid batman-adv soft-interface\n",
			DEBUG_ORIGINATORS, mesh_iface);
		return -1;
	}
	fclose(f);

	return 0;
}

int batadv_interface_check(const char *mesh_iface)
{
	int ret;

	enable_net_admin_capability(1);
	ret = batadv_interface_check_netlink(mesh_iface);
	enable_net_admin_capability(0);

	if (ret == -EOPNOTSUPP)
		ret = batadv_interface_check_debugfs(mesh_iface);

	return ret;
}

static int translate_mac_debugfs(const char *mesh_iface,
				 const struct ether_addr *mac,
				 struct ether_addr *mac_out)
{
	enum {
		tg_start,
		tg_mac,
		tg_via,
		tg_originator,
	} pos;
	char full_path[MAX_PATH+1];
	struct ether_addr *mac_tmp;
	FILE *f = NULL;
	size_t len = 0;
	char *line = NULL;
	char *input, *saveptr, *token;
	int line_invalid;
	bool found = false;

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_TRANSTABLE_GLOBAL,
			  mesh_iface, full_path, sizeof(full_path));

	f = fopen(full_path, "r");
	if (!f)
		return -EOPNOTSUPP;

	while (getline(&line, &len, f) != -1) {
		line_invalid = 0;
		pos = tg_start;
		input = line;

		while ((token = strtok_r(input, " \t", &saveptr))) {
			input = NULL;

			switch (pos) {
			case tg_start:
				if (strcmp(token, "*") != 0)
					line_invalid = 1;
				else
					pos = tg_mac;
				break;
			case tg_mac:
				mac_tmp = ether_aton(token);
				if (!mac_tmp || memcmp(mac_tmp, mac,
						       ETH_ALEN) != 0)
					line_invalid = 1;
				else
					pos = tg_via;
				break;
			case tg_via:
				if (strcmp(token, "via") == 0)
					pos = tg_originator;
				break;
			case tg_originator:
				mac_tmp = ether_aton(token);
				if (!mac_tmp) {
					line_invalid = 1;
				} else {
					memcpy(mac_out, mac_tmp, ETH_ALEN);
					found = true;
					goto out;
				}
				break;
			}

			if (line_invalid)
				break;
		}
	}

out:
	if (f)
		fclose(f);
	free(line);

	if (found)
		return 0;
	else
		return -ENOENT;
}

struct ether_addr *translate_mac(const char *mesh_iface,
				 const struct ether_addr *mac)
{
	struct ether_addr in_mac;
	static struct ether_addr out_mac;
	struct ether_addr *mac_result;
	int ret;

	/* input mac has to be copied because it could be in the shared
	 * ether_aton buffer
	 */
	memcpy(&in_mac, mac, sizeof(in_mac));
	memcpy(&out_mac, mac, sizeof(out_mac));
	mac_result = &out_mac;

	enable_net_admin_capability(1);
	ret = translate_mac_netlink(mesh_iface, &in_mac, mac_result);
	enable_net_admin_capability(0);

	if (ret == -EOPNOTSUPP)
		translate_mac_debugfs(mesh_iface, &in_mac, mac_result);

	return mac_result;
}

static int get_tq_debugfs(const char *mesh_iface, struct hashtable_t *orig_hash)
{
	enum {
		orig_mac,
		orig_lastseen,
		orig_tqstart,
		orig_tqvalue,
	} pos;
	char full_path[MAX_PATH + 1];
	struct ether_addr *mac_tmp;
	FILE *f = NULL;
	size_t len = 0;
	char *line = NULL;
	char *input, *saveptr, *token;
	int line_invalid;
	uint8_t tq;

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_ORIGINATORS,
			  mesh_iface, full_path, sizeof(full_path));

	f = fopen(full_path, "r");
	if (!f)
		return -EOPNOTSUPP;

	while (getline(&line, &len, f) != -1) {
		line_invalid = 0;
		pos = orig_mac;
		input = line;

		while ((token = strtok_r(input, " \t", &saveptr))) {
			input = NULL;

			switch (pos) {
			case orig_mac:
				mac_tmp = ether_aton(token);
				if (!mac_tmp)
					line_invalid = 1;
				else
					pos = orig_lastseen;
				break;
			case orig_lastseen:
				pos = orig_tqstart;
				break;
			case orig_tqstart:
				if (strlen(token) == 0) {
					line_invalid = 1;
					break;
				} else if (token[0] != '(') {
					line_invalid = 1;
					break;
				} else if (strlen(token) == 1) {
					pos = orig_tqvalue;
					break;
				}

				token++;
				/* fall through */
			case orig_tqvalue:
				if (token[strlen(token) - 1] != ')') {
					line_invalid = 1;
				} else {
					token[strlen(token) - 1] = '\0';
					tq = strtol(token, NULL, 10);
					orig_hash_add(orig_hash, mac_tmp, tq);
				}
				break;
			}

			if (line_invalid)
				break;
		}
	}

	if (f)
		fclose(f);
	free(line);

	return 0;
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
	int ret;

	orig_hash = hash_new(64, orig_compare, orig_choose);
	if (!orig_hash)
		return NULL;

	enable_net_admin_capability(1);
	ret = get_tq_netlink(mesh_iface, orig_hash);
	enable_net_admin_capability(0);

	ret = -EOPNOTSUPP;
	if (ret == -EOPNOTSUPP)
		get_tq_debugfs(mesh_iface, orig_hash);

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
