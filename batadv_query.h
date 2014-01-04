/*
 * Copyright (C) 2006-2014 B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich, Marek Lindner
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
#ifndef _BATADV_QUERY_H
#define _BATADV_QUERY_H

#include <stdint.h>
#include <netinet/in.h>

struct ether_addr *translate_mac(const char *mesh_iface, struct ether_addr *mac);
uint8_t get_tq(const char *mesh_iface, struct ether_addr *mac);
int batadv_interface_check(const char *mesh_iface);
int mac_to_ipv6(const struct ether_addr *mac, struct in6_addr *addr);
int ipv6_to_mac(const struct in6_addr *addr, struct ether_addr *mac);
int is_ipv6_eui64(const struct in6_addr *addr);

#endif
