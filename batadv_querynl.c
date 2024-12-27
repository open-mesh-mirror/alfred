// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <marek.lindner@mailbox.org>, Andrew Lunn <andrew@lunn.ch>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "batadv_querynl.h"

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

#include "alfred.h"
#include "batman_adv.h"
#include "batadv_query.h"
#include "netlink.h"

static const int translate_mac_netlink_mandatory[] = {
	BATADV_ATTR_TT_ADDRESS,
	BATADV_ATTR_ORIG_ADDRESS,
};

struct translate_mac_netlink_opts {
	struct hashtable_t *tg_hash;
	struct nlquery_opts query_opts;
};

static int translate_mac_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct translate_mac_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	struct ether_addr mac_addr;
	struct ether_addr mac_orig;
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

	memcpy(&mac_addr, addr, sizeof(mac_addr));
	memcpy(&mac_orig, orig, sizeof(mac_orig));
	tg_hash_add(opts->tg_hash, &mac_addr, &mac_orig);
	opts->query_opts.err = 0;

	return NL_STOP;
}

int translate_mac_netlink(const char *mesh_iface, struct hashtable_t *tg_hash)
{
	struct translate_mac_netlink_opts opts = {
		.tg_hash = tg_hash,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	ret = netlink_query_common(mesh_iface,
				   BATADV_CMD_GET_TRANSTABLE_GLOBAL,
				   translate_mac_netlink_cb, &opts.query_opts);
	if (ret < 0)
		return ret;

	return 0;
}

static const int get_tq_netlink_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_TQ,
};

struct get_tq_netlink_opts {
	struct hashtable_t *orig_hash;
	struct nlquery_opts query_opts;
};

static int get_tq_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct get_tq_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	uint8_t *orig;
	struct ether_addr mac;
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

	memcpy(&mac, orig, sizeof(mac));
	orig_hash_add(opts->orig_hash, &mac, tq);
	opts->query_opts.err = 0;

	return NL_OK;
}

int get_tq_netlink(const char *mesh_iface, struct hashtable_t *orig_hash)
{
	struct get_tq_netlink_opts opts = {
		.orig_hash = orig_hash,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	ret = netlink_query_common(mesh_iface,  BATADV_CMD_GET_ORIGINATORS,
				   get_tq_netlink_cb, &opts.query_opts);
	if (ret < 0)
		return ret;

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
