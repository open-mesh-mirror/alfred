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

#include "netlink.h"

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <net/ethernet.h>

#include "batman_adv.h"

struct nla_policy batadv_netlink_policy[NUM_BATADV_ATTR] = {
	[BATADV_ATTR_VERSION]		= { .type = NLA_STRING },
	[BATADV_ATTR_ALGO_NAME]		= { .type = NLA_STRING },
	[BATADV_ATTR_MESH_IFINDEX]	= { .type = NLA_U32 },
	[BATADV_ATTR_MESH_IFNAME]	= { .type = NLA_STRING,
					    .maxlen = IFNAMSIZ },
	[BATADV_ATTR_MESH_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_HARD_IFINDEX]	= { .type = NLA_U32 },
	[BATADV_ATTR_HARD_IFNAME]	= { .type = NLA_STRING,
					    .maxlen = IFNAMSIZ },
	[BATADV_ATTR_HARD_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_ORIG_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TPMETER_RESULT]	= { .type = NLA_U8 },
	[BATADV_ATTR_TPMETER_TEST_TIME]	= { .type = NLA_U32 },
	[BATADV_ATTR_TPMETER_BYTES]	= { .type = NLA_U64 },
	[BATADV_ATTR_TPMETER_COOKIE]	= { .type = NLA_U32 },
	[BATADV_ATTR_PAD]		= { .type = NLA_UNSPEC },
	[BATADV_ATTR_ACTIVE]		= { .type = NLA_FLAG },
	[BATADV_ATTR_TT_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TT_TTVN]		= { .type = NLA_U8 },
	[BATADV_ATTR_TT_LAST_TTVN]	= { .type = NLA_U8 },
	[BATADV_ATTR_TT_CRC32]		= { .type = NLA_U32 },
	[BATADV_ATTR_TT_VID]		= { .type = NLA_U16 },
	[BATADV_ATTR_TT_FLAGS]		= { .type = NLA_U32 },
	[BATADV_ATTR_FLAG_BEST]		= { .type = NLA_FLAG },
	[BATADV_ATTR_LAST_SEEN_MSECS]	= { .type = NLA_U32 },
	[BATADV_ATTR_NEIGH_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TQ]		= { .type = NLA_U8 },
	[BATADV_ATTR_THROUGHPUT]	= { .type = NLA_U32 },
	[BATADV_ATTR_BANDWIDTH_UP]	= { .type = NLA_U32 },
	[BATADV_ATTR_BANDWIDTH_DOWN]	= { .type = NLA_U32 },
	[BATADV_ATTR_ROUTER]		= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_OWN]		= { .type = NLA_FLAG },
	[BATADV_ATTR_BLA_ADDRESS]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_VID]		= { .type = NLA_U16 },
	[BATADV_ATTR_BLA_BACKBONE]	= { .type = NLA_UNSPEC,
					    .minlen = ETH_ALEN,
					    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_CRC]		= { .type = NLA_U16 },
};
