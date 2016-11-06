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

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <net/ethernet.h>
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

static const int translate_mac_netlink_mandatory[] = {
	BATADV_ATTR_TT_ADDRESS,
	BATADV_ATTR_ORIG_ADDRESS,
};

struct translate_mac_netlink_opts {
	struct ether_addr mac;
	bool found;
	struct nlquery_opts query_opts;
};

static int translate_mac_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct translate_mac_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	uint8_t *addr;
	uint8_t *orig;

	opts = container_of(query_opts, struct translate_mac_netlink_opts,
			    query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_GLOBAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (missing_mandatory_attrs(attrs, translate_mac_netlink_mandatory,
				    ARRAY_SIZE(translate_mac_netlink_mandatory)))
		return NL_OK;

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);
	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	if (memcmp(&opts->mac, addr, ETH_ALEN) != 0)
		return NL_OK;

	memcpy(&opts->mac, orig, ETH_ALEN);
	opts->found = true;
	opts->query_opts.err = 0;

	return NL_STOP;
}

int translate_mac_netlink(const char *mesh_iface, const struct ether_addr *mac,
			  struct ether_addr *mac_out)
{
	struct translate_mac_netlink_opts opts = {
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	memcpy(&opts.mac, mac, ETH_ALEN);

	ret = netlink_query_common(mesh_iface,
				   BATADV_CMD_GET_TRANSTABLE_GLOBAL,
			           translate_mac_netlink_cb, &opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -ENOENT;

	memcpy(mac_out, &opts.mac, ETH_ALEN);

	return 0;
}

static const int get_tq_netlink_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_TQ,
};

struct get_tq_netlink_opts {
	struct ether_addr mac;
	uint8_t tq;
	bool found;
	struct nlquery_opts query_opts;
};

static int get_tq_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct get_tq_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	uint8_t *orig;
	uint8_t tq;

	opts = container_of(query_opts, struct get_tq_netlink_opts,
			    query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (missing_mandatory_attrs(attrs, get_tq_netlink_mandatory,
				    ARRAY_SIZE(get_tq_netlink_mandatory)))
		return NL_OK;

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	tq = nla_get_u8(attrs[BATADV_ATTR_TQ]);

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	if (memcmp(&opts->mac, orig, ETH_ALEN) != 0)
		return NL_OK;

	opts->tq = tq;
	opts->found = true;
	opts->query_opts.err = 0;

	return NL_STOP;
}

int get_tq_netlink(const char *mesh_iface, const struct ether_addr *mac,
		   uint8_t *tq)
{
	struct get_tq_netlink_opts opts = {
		.tq = 0,
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	memcpy(&opts.mac, mac, ETH_ALEN);

	ret = netlink_query_common(mesh_iface,  BATADV_CMD_GET_ORIGINATORS,
			           get_tq_netlink_cb, &opts.query_opts);
	if (ret < 0)
		return ret;

	if (!opts.found)
		return -ENOENT;

	*tq = opts.tq;

	return 0;
}

static int check_nlcmd_cb(struct nl_msg *msg __unused, void *arg __unused)
{
	return NL_STOP;
}

int batadv_interface_check_netlink(const char *mesh_iface)
{
	struct nlquery_opts opts = {
		.err = 0,
	};
	int ret;

	ret = netlink_query_common(mesh_iface,  BATADV_CMD_GET_ORIGINATORS,
				   check_nlcmd_cb, &opts);
	if (ret < 0)
		return ret;

	ret = netlink_query_common(mesh_iface, BATADV_CMD_GET_TRANSTABLE_GLOBAL,
				   check_nlcmd_cb, &opts);
	if (ret < 0)
		return ret;

	return 0;
}
