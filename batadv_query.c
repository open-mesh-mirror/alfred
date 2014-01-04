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

#include "batadv_query.h"
#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include "debugfs.h"

#define DEBUG_BATIF_PATH_FMT "%s/batman_adv/%s"
#define DEBUG_TRANSTABLE_GLOBAL "transtable_global"
#define DEBUG_ORIGINATORS "originators"

int mac_to_ipv6(const struct ether_addr *mac, struct in6_addr *addr)
{
	memset(addr, 0, sizeof(*addr));
	addr->s6_addr[0] = 0xfe;
	addr->s6_addr[1] = 0x80;

	addr->s6_addr[8] = mac->ether_addr_octet[0] ^ 0x02;
	addr->s6_addr[9] = mac->ether_addr_octet[1];
	addr->s6_addr[10] = mac->ether_addr_octet[2];

	addr->s6_addr[11] = 0xff;
	addr->s6_addr[12] = 0xfe;

	addr->s6_addr[13] = mac->ether_addr_octet[3];
	addr->s6_addr[14] = mac->ether_addr_octet[4];
	addr->s6_addr[15] = mac->ether_addr_octet[5];

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

int ipv6_to_mac(const struct in6_addr *addr, struct ether_addr *mac)
{
	if (!is_ipv6_eui64(addr))
		return -EINVAL;

	mac->ether_addr_octet[0] = addr->s6_addr[8] ^ 0x02;
	mac->ether_addr_octet[1] = addr->s6_addr[9];
	mac->ether_addr_octet[2] = addr->s6_addr[10];
	mac->ether_addr_octet[3] = addr->s6_addr[13];
	mac->ether_addr_octet[4] = addr->s6_addr[14];
	mac->ether_addr_octet[5] = addr->s6_addr[15];

	return 0;
}

int batadv_interface_check(const char *mesh_iface)
{
	char *debugfs_mnt;
	char full_path[MAX_PATH+1];
	FILE *f;

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt) {
		fprintf(stderr, "Could not find debugfs path\n");
		return -1;
	}

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

struct ether_addr *translate_mac(const char *mesh_iface, struct ether_addr *mac)
{
	enum {
		tg_start,
		tg_mac,
		tg_via,
		tg_originator,
	} pos;
	char full_path[MAX_PATH+1];
	char *debugfs_mnt;
	static struct ether_addr in_mac;
	struct ether_addr *mac_result, *mac_tmp;
	FILE *f = NULL;
	size_t len = 0;
	char *line = NULL;
	char *input, *saveptr, *token;
	int line_invalid;

	memcpy(&in_mac, mac, sizeof(in_mac));
	mac_result = &in_mac;

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt)
		goto out;

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_TRANSTABLE_GLOBAL,
			  mesh_iface, full_path, sizeof(full_path));

	f = fopen(full_path, "r");
	if (!f)
		goto out;

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
				if (!mac_tmp || memcmp(mac_tmp, &in_mac,
						       sizeof(in_mac)) != 0)
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
					mac_result = mac_tmp;
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
	return mac_result;
}

uint8_t get_tq(const char *mesh_iface, struct ether_addr *mac)
{
	enum {
		orig_mac,
		orig_lastseen,
		orig_tqstart,
		orig_tqvalue,
	} pos;
	char full_path[MAX_PATH+1];
	char *debugfs_mnt;
	static struct ether_addr in_mac;
	struct ether_addr *mac_tmp;
	FILE *f = NULL;
	size_t len = 0;
	char *line = NULL;
	char *input, *saveptr, *token;
	int line_invalid;
	uint8_t tq = 0;

	memcpy(&in_mac, mac, sizeof(in_mac));

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt)
		goto out;

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" DEBUG_ORIGINATORS,
			  mesh_iface, full_path, sizeof(full_path));

	f = fopen(full_path, "r");
	if (!f)
		goto out;

	while (getline(&line, &len, f) != -1) {
		line_invalid = 0;
		pos = orig_mac;
		input = line;

		while ((token = strtok_r(input, " \t", &saveptr))) {
			input = NULL;

			switch (pos) {
			case orig_mac:
				mac_tmp = ether_aton(token);
				if (!mac_tmp || memcmp(mac_tmp, &in_mac,
						       sizeof(in_mac)) != 0)
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
				} else {
					/* fall through */
					token++;
				}
			case orig_tqvalue:
				if (token[strlen(token) - 1] != ')') {
					line_invalid = 1;
				} else {
					token[strlen(token) - 1] = '\0';
					tq = strtol(token, NULL, 10);
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
	return tq;
}
