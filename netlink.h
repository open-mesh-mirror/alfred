/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2009-2020  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>, Andrew Lunn <andrew@lunn.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef _ALFRED_NETLINK_H
#define _ALFRED_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <stddef.h>

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

extern struct nla_policy batadv_netlink_policy[];

#endif /* _ALFRED_NETLINK_H */
