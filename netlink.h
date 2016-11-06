/*
 * Copyright (C) 2009-2016  B.A.T.M.A.N. contributors:
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

#ifndef _ALFRED_NETLINK_H
#define _ALFRED_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stddef.h>

struct ether_addr;

struct nlquery_opts {
	int err;
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#ifndef container_of
#define container_of(ptr, type, member) __extension__ ({ \
	const __typeof__(((type *)0)->member) *__pmember = (ptr); \
	(type *)((char *)__pmember - offsetof(type, member)); })
#endif

int netlink_query_common(const char *mesh_iface, uint8_t nl_cmd,
			 nl_recvmsg_msg_cb_t callback,
			 struct nlquery_opts *query_opts);
int missing_mandatory_attrs(struct nlattr *attrs[],  const int mandatory[],
			    size_t num);
int translate_mac_netlink(const char *mesh_iface, const struct ether_addr *mac,
			  struct ether_addr *mac_out);
int get_tq_netlink(const char *mesh_iface, const struct ether_addr *mac,
		   uint8_t *tq);
int batadv_interface_check_netlink(const char *mesh_iface);

extern struct nla_policy batadv_netlink_policy[];

#endif /* _ALFRED_NETLINK_H */
