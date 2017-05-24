/*
 * Copyright (C) 2009-2017  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>, Andrew Lunn <andrew@lunn.ch>
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

#ifndef _BATADV_QUERYNL_H
#define _BATADV_QUERYNL_H

#include <stdint.h>

struct ether_addr;

int translate_mac_netlink(const char *mesh_iface, const struct ether_addr *mac,
			  struct ether_addr *mac_out);
int get_tq_netlink(const char *mesh_iface, const struct ether_addr *mac,
		   uint8_t *tq);
int batadv_interface_check_netlink(const char *mesh_iface);

#endif /* _BATADV_QUERYNL_H */
