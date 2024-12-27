/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <marek.lindner@mailbox.org>, Andrew Lunn <andrew@lunn.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef _BATADV_QUERYNL_H
#define _BATADV_QUERYNL_H

#include <stdint.h>

struct ether_addr;
struct hashtable_t;

int translate_mac_netlink(const char *mesh_iface, struct hashtable_t *tg_hash);
int get_tq_netlink(const char *mesh_iface, struct hashtable_t *orig_hash);
int batadv_interface_check_netlink(const char *mesh_iface);

#endif /* _BATADV_QUERYNL_H */
