// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <marek.lindner@mailbox.org>, Andrew Lunn <andrew@lunn.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "netlink.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/if.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <net/ethernet.h>

#include "batman_adv.h"

#ifndef __unused
#define __unused __attribute__((unused))
#endif

struct nla_policy batadv_netlink_policy[NUM_BATADV_ATTR] = {
	[BATADV_ATTR_VERSION]			= { .type = NLA_STRING },
	[BATADV_ATTR_ALGO_NAME]			= { .type = NLA_STRING },
	[BATADV_ATTR_MESH_IFINDEX]		= { .type = NLA_U32 },
	[BATADV_ATTR_MESH_IFNAME]		= { .type = NLA_STRING,
						    .maxlen = IFNAMSIZ },
	[BATADV_ATTR_MESH_ADDRESS]		= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_HARD_IFINDEX]		= { .type = NLA_U32 },
	[BATADV_ATTR_HARD_IFNAME]		= { .type = NLA_STRING,
						    .maxlen = IFNAMSIZ },
	[BATADV_ATTR_HARD_ADDRESS]		= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_ORIG_ADDRESS]		= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TPMETER_RESULT]		= { .type = NLA_U8 },
	[BATADV_ATTR_TPMETER_TEST_TIME]		= { .type = NLA_U32 },
	[BATADV_ATTR_TPMETER_BYTES]		= { .type = NLA_U64 },
	[BATADV_ATTR_TPMETER_COOKIE]		= { .type = NLA_U32 },
	[BATADV_ATTR_PAD]			= { .type = NLA_UNSPEC },
	[BATADV_ATTR_ACTIVE]			= { .type = NLA_FLAG },
	[BATADV_ATTR_TT_ADDRESS]		= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TT_TTVN]			= { .type = NLA_U8 },
	[BATADV_ATTR_TT_LAST_TTVN]		= { .type = NLA_U8 },
	[BATADV_ATTR_TT_CRC32]			= { .type = NLA_U32 },
	[BATADV_ATTR_TT_VID]			= { .type = NLA_U16 },
	[BATADV_ATTR_TT_FLAGS]			= { .type = NLA_U32 },
	[BATADV_ATTR_FLAG_BEST]			= { .type = NLA_FLAG },
	[BATADV_ATTR_LAST_SEEN_MSECS]		= { .type = NLA_U32 },
	[BATADV_ATTR_NEIGH_ADDRESS]		= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_TQ]			= { .type = NLA_U8 },
	[BATADV_ATTR_THROUGHPUT]		= { .type = NLA_U32 },
	[BATADV_ATTR_BANDWIDTH_UP]		= { .type = NLA_U32 },
	[BATADV_ATTR_BANDWIDTH_DOWN]		= { .type = NLA_U32 },
	[BATADV_ATTR_ROUTER]			= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_OWN]			= { .type = NLA_FLAG },
	[BATADV_ATTR_BLA_ADDRESS]		= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_VID]			= { .type = NLA_U16 },
	[BATADV_ATTR_BLA_BACKBONE]		= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_BLA_CRC]			= { .type = NLA_U16 },
	[BATADV_ATTR_DAT_CACHE_IP4ADDRESS]	= { .type = NLA_U32 },
	[BATADV_ATTR_DAT_CACHE_HWADDRESS]	= { .type = NLA_UNSPEC,
						    .minlen = ETH_ALEN,
						    .maxlen = ETH_ALEN },
	[BATADV_ATTR_DAT_CACHE_VID]		= { .type = NLA_U16 },
	[BATADV_ATTR_MCAST_FLAGS]		= { .type = NLA_U32 },
	[BATADV_ATTR_MCAST_FLAGS_PRIV]		= { .type = NLA_U32 },
	[BATADV_ATTR_VLANID]			= { .type = NLA_U16 },
	[BATADV_ATTR_AGGREGATED_OGMS_ENABLED]	= { .type = NLA_U8 },
	[BATADV_ATTR_AP_ISOLATION_ENABLED]	= { .type = NLA_U8 },
	[BATADV_ATTR_ISOLATION_MARK]		= { .type = NLA_U32 },
	[BATADV_ATTR_ISOLATION_MASK]		= { .type = NLA_U32 },
	[BATADV_ATTR_BONDING_ENABLED]		= { .type = NLA_U8 },
	[BATADV_ATTR_BRIDGE_LOOP_AVOIDANCE_ENABLED]	= { .type = NLA_U8 },
	[BATADV_ATTR_DISTRIBUTED_ARP_TABLE_ENABLED]	= { .type = NLA_U8 },
	[BATADV_ATTR_FRAGMENTATION_ENABLED]	= { .type = NLA_U8 },
	[BATADV_ATTR_GW_BANDWIDTH_DOWN]		= { .type = NLA_U32 },
	[BATADV_ATTR_GW_BANDWIDTH_UP]		= { .type = NLA_U32 },
	[BATADV_ATTR_GW_MODE]			= { .type = NLA_U8 },
	[BATADV_ATTR_GW_SEL_CLASS]		= { .type = NLA_U32 },
	[BATADV_ATTR_HOP_PENALTY]		= { .type = NLA_U8 },
	[BATADV_ATTR_LOG_LEVEL]			= { .type = NLA_U32 },
	[BATADV_ATTR_MULTICAST_FORCEFLOOD_ENABLED]	= { .type = NLA_U8 },
	[BATADV_ATTR_MULTICAST_FANOUT]		= { .type = NLA_U32 },
	[BATADV_ATTR_NETWORK_CODING_ENABLED]	= { .type = NLA_U8 },
	[BATADV_ATTR_ORIG_INTERVAL]		= { .type = NLA_U32 },
	[BATADV_ATTR_ELP_INTERVAL]		= { .type = NLA_U32 },
	[BATADV_ATTR_THROUGHPUT_OVERRIDE]	= { .type = NLA_U32 },
};

int missing_mandatory_attrs(struct nlattr *attrs[],  const int mandatory[],
			    size_t num)
{
	size_t i;

	for (i = 0; i < num; i++)
		if (!attrs[mandatory[i]])
			return -EINVAL;

	return 0;
}

static int nlquery_error_cb(struct sockaddr_nl *nla __unused,
			    struct nlmsgerr *nlerr, void *arg)
{
	struct nlquery_opts *query_opts = arg;

	query_opts->err = nlerr->error;

	return NL_STOP;
}

static int nlquery_stop_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	int *error = nlmsg_data(nlh);

	if (*error)
		query_opts->err = *error;

	return NL_STOP;
}

int netlink_query_common(const char *mesh_iface, uint8_t nl_cmd,
			 nl_recvmsg_msg_cb_t callback,
			 struct nlquery_opts *query_opts)
{
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int ifindex;
	int family;
	int ret;

	query_opts->err = 0;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	ret = genl_connect(sock);
	if (ret < 0) {
		query_opts->err = ret;
		goto err_free_sock;
	}

	family = genl_ctrl_resolve(sock, BATADV_NL_NAME);
	if (family < 0) {
		query_opts->err = -EOPNOTSUPP;
		goto err_free_sock;
	}

	ifindex = if_nametoindex(mesh_iface);
	if (!ifindex) {
		query_opts->err = -ENODEV;
		goto err_free_sock;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		query_opts->err = -ENOMEM;
		goto err_free_sock;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback, query_opts);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, nlquery_stop_cb, query_opts);
	nl_cb_err(cb, NL_CB_CUSTOM, nlquery_error_cb, query_opts);

	msg = nlmsg_alloc();
	if (!msg) {
		query_opts->err = -ENOMEM;
		goto err_free_cb;
	}

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, 0, NLM_F_DUMP,
		    nl_cmd, 1);

	nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX, ifindex);
	nl_send_auto_complete(sock, msg);
	nlmsg_free(msg);

	nl_recvmsgs(sock, cb);

err_free_cb:
	nl_cb_put(cb);
err_free_sock:
	nl_socket_free(sock);

	return query_opts->err;
}
