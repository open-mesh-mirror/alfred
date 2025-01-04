// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "vis.h"
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "batman_adv.h"
#include "netlink.h"

#define IFACE_STATUS_LEN 256

static struct globals vis_globals;

struct vis_netlink_opts {
	struct globals *globals;
	struct nlquery_opts query_opts;
};

static char *mac_to_str(uint8_t *mac)
{
	static char macstr[20];
	snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return macstr;
}

static int get_if_mac(char *ifname, uint8_t *mac)
{
	struct ifreq ifr;
	int sock, ret;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("can't get interface");
		return -1;
	}

	ret = ioctl(sock, SIOCGIFHWADDR, &ifr);

	close(sock);

	if (ret == -1) {
		perror("can't get MAC address");
		return -1;
	}

	memcpy(mac, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

static int get_if_index_byname(struct globals *globals, char *ifname)
{
	struct iface_list_entry *i_entry;
	int devindex;
	int i;

	if (!ifname)
		return -1;

	i = 0;
	list_for_each_entry(i_entry, &globals->iface_list, list) {
		if (strncmp(ifname, i_entry->name, sizeof(i_entry->name)) == 0)
			return i;
		i++;
	}

	devindex = if_nametoindex(ifname);
	if (!devindex)
		return -1;

	i_entry = malloc(sizeof(*i_entry));
	if (!i_entry)
		return -1;

	if (get_if_mac(ifname, i_entry->mac)) {
		free(i_entry);
		return -1;
	}

	i_entry->devindex = devindex;
	strncpy(i_entry->name, ifname, sizeof(i_entry->name));
	/* just to be safe ... */
	i_entry->name[sizeof(i_entry->name) - 1] = 0;
	list_add_tail(&i_entry->list, &globals->iface_list);

	return i;
}

static int get_if_index_devindex(struct globals *globals, int devindex)
{
	struct iface_list_entry *i_entry;
	char *ifname;
	char ifnamebuf[IF_NAMESIZE];
	int i;

	if (!devindex)
		return -1;

	i = 0;
	list_for_each_entry(i_entry, &globals->iface_list, list) {
		if (i_entry->devindex == devindex)
			return i;
		i++;
	}

	ifname = if_indextoname(devindex, ifnamebuf);
	if (!ifname)
		return -1;

	i_entry = malloc(sizeof(*i_entry));
	if (!i_entry)
		return -1;

	if (get_if_mac(ifname, i_entry->mac)) {
		free(i_entry);
		return -1;
	}

	i_entry->devindex = devindex;
	strncpy(i_entry->name, ifname, sizeof(i_entry->name));
	/* just to be safe ... */
	i_entry->name[sizeof(i_entry->name) - 1] = 0;
	list_add_tail(&i_entry->list, &globals->iface_list);

	return i;
}

static int alfred_open_sock(struct globals *globals)
{
	struct sockaddr_un addr;

	globals->unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (globals->unix_sock < 0) {
		perror("can't create unix socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, globals->unix_path, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

	if (connect(globals->unix_sock, (struct sockaddr *)&addr,
		    sizeof(addr)) < 0) {
		close(globals->unix_sock);
		globals->unix_sock = -1;
		perror("can't connect to unix socket");
		return -1;
	}

	return 0;
}

static const int parse_transtable_local_mandatory[] = {
	BATADV_ATTR_TT_ADDRESS,
};

static int parse_transtable_local_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct vis_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	struct vis_list_entry *v_entry;
	uint8_t *addr;

	opts = container_of(query_opts, struct vis_netlink_opts,
			    query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_LOCAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy)) {
		return NL_OK;
	}

	if (missing_mandatory_attrs(attrs, parse_transtable_local_mandatory,
				    ARRAY_SIZE(parse_transtable_local_mandatory)))
		return NL_OK;

	addr = nla_data(attrs[BATADV_ATTR_TT_ADDRESS]);

	v_entry = malloc(sizeof(*v_entry));
	if (!v_entry)
		return NL_OK;

	memcpy(v_entry->v.mac, addr, ETH_ALEN);
	v_entry->v.ifindex = 255;
	v_entry->v.qual = 0;
	list_add_tail(&v_entry->list, &opts->globals->entry_list);

	return NL_OK;
}

static int parse_transtable_local(struct globals *globals)
{
	struct vis_netlink_opts opts = {
		.globals = globals,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	ret = netlink_query_common(globals->interface,
				   BATADV_CMD_GET_TRANSTABLE_LOCAL,
			           parse_transtable_local_netlink_cb,
				   &opts.query_opts);
	if (ret < 0)
		return ret;

	return 0;
}

static void clear_lists(struct globals *globals)
{
	struct vis_list_entry *v_entry, *v_entry_safe;
	struct iface_list_entry *i_entry, *i_entry_safe;

	list_for_each_entry_safe(v_entry, v_entry_safe, &globals->entry_list,
				 list) {
		list_del(&v_entry->list);
		free(v_entry);
	}

	list_for_each_entry_safe(i_entry, i_entry_safe, &globals->iface_list,
				 list) {
		list_del(&i_entry->list);
		free(i_entry);
	}
}

static int query_rtnl_link(int ifindex, nl_recvmsg_msg_cb_t func, void *arg)
{
	struct ifinfomsg rt_hdr = {
		.ifi_family = IFLA_UNSPEC,
	};
	struct nl_sock *sock;
	struct nl_msg *msg;
	struct nl_cb *cb;
	int err = 0;
	int ret;

	sock = nl_socket_alloc();
	if (!sock)
		return -ENOMEM;

	ret = nl_connect(sock, NETLINK_ROUTE);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_sock;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb) {
		err = -ENOMEM;
		goto err_free_sock;
	}

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, func, arg);

	msg = nlmsg_alloc_simple(RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
	if (!msg) {
		err = -ENOMEM;
		goto err_free_cb;
	}

	ret = nlmsg_append(msg, &rt_hdr, sizeof(rt_hdr), NLMSG_ALIGNTO);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nla_put_u32(msg, IFLA_MASTER, ifindex);
	if (ret < 0) {
		err = -ENOMEM;
		goto err_free_msg;
	}

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto err_free_msg;

	nl_recvmsgs(sock, cb);

err_free_msg:
	nlmsg_free(msg);
err_free_cb:
	nl_cb_put(cb);
err_free_sock:
	nl_socket_free(sock);

	return err;
}

static int get_iface_status_netlink_parse(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[NUM_BATADV_ATTR];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	char *iface_status = arg;
	struct genlmsghdr *ghdr;

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);
	if (ghdr->cmd != BATADV_CMD_GET_HARDIF)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_netlink_policy))
		return NL_OK;

	if (attrs[BATADV_ATTR_ACTIVE])
		strncpy(iface_status, "active\n", IFACE_STATUS_LEN);
	else
		strncpy(iface_status, "inactive\n", IFACE_STATUS_LEN);

	iface_status[IFACE_STATUS_LEN - 1] = '\0';

	return NL_STOP;
}

static char *get_iface_status_netlink(unsigned int meshif, unsigned int hardif,
				      char *iface_status)
{
	char *ret_status = NULL;
	struct nl_sock *sock;
	struct nl_msg *msg;
	int batadv_family;
	struct nl_cb *cb;
	int ret;

	iface_status[0] = '\0';

	sock = nl_socket_alloc();
	if (!sock)
		return NULL;

	ret = genl_connect(sock);
	if (ret < 0)
		goto err_free_sock;

	batadv_family = genl_ctrl_resolve(sock, BATADV_NL_NAME);
	if (batadv_family < 0)
		goto err_free_sock;

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb)
		goto err_free_sock;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, get_iface_status_netlink_parse,
		  iface_status);

	msg = nlmsg_alloc();
	if (!msg)
		goto err_free_cb;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, batadv_family,
		    0, 0, BATADV_CMD_GET_HARDIF, 1);

	nla_put_u32(msg, BATADV_ATTR_MESH_IFINDEX, meshif);
	nla_put_u32(msg, BATADV_ATTR_HARD_IFINDEX, hardif);

	ret = nl_send_auto_complete(sock, msg);
	if (ret < 0)
		goto err_free_msg;

	nl_recvmsgs(sock, cb);

	if (strlen(iface_status) > 0)
		ret_status = iface_status;

err_free_msg:
	nlmsg_free(msg);
err_free_cb:
	nl_cb_put(cb);
err_free_sock:
	nl_socket_free(sock);

	return ret_status;
}

static bool interface_active(unsigned int meshif, unsigned int hardif)
{
	char iface_status[IFACE_STATUS_LEN];
	char *file_content = NULL;
	char *content_newline;
	bool active = false;
	char *status;

	status = get_iface_status_netlink(meshif, hardif, iface_status);
	if (!status)
		return false;

	content_newline = strstr(status, "\n");
	if (content_newline)
		*content_newline = '\0';

	if (strcmp(status, "active") != 0)
		goto free_file;

	active = true;

free_file:
	free(file_content);
	file_content = NULL;

	return active;
}

struct register_interfaces_rtnl_arg {
	struct globals *globals;
	int ifindex;
};

static struct nla_policy link_policy[IFLA_MAX + 1] = {
	[IFLA_IFNAME] = { .type = NLA_STRING, .maxlen = IFNAMSIZ },
	[IFLA_MASTER] = { .type = NLA_U32 },
};

static int register_interfaces_rtnl_parse(struct nl_msg *msg, void *arg)
{
	struct register_interfaces_rtnl_arg *register_arg = arg;
	struct nlattr *attrs[IFLA_MAX + 1];
	struct ifinfomsg *ifm;
	char *ifname;
	int master;
	int ret;

	ifm = nlmsg_data(nlmsg_hdr(msg));
	ret = nlmsg_parse(nlmsg_hdr(msg), sizeof(*ifm), attrs, IFLA_MAX,
			  link_policy);
	if (ret < 0)
		goto err;

	if (!attrs[IFLA_IFNAME])
		goto err;

	if (!attrs[IFLA_MASTER])
		goto err;

	ifname = nla_get_string(attrs[IFLA_IFNAME]);
	master = nla_get_u32(attrs[IFLA_MASTER]);

	/* required on older kernels which don't prefilter the results */
	if (master != register_arg->ifindex)
		goto err;

	if (!interface_active(master, ifm->ifi_index))
		goto err;

	get_if_index_byname(register_arg->globals, ifname);

err:
	return NL_OK;
}

static int register_interfaces(struct globals *globals)
{
	struct register_interfaces_rtnl_arg register_arg = {
		.globals = globals,
	};

	register_arg.ifindex = if_nametoindex(globals->interface);
	if (!register_arg.ifindex)
		return EXIT_FAILURE;


	query_rtnl_link(register_arg.ifindex, register_interfaces_rtnl_parse,
			&register_arg);

	return EXIT_SUCCESS;
}

static const int parse_orig_list_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_TQ,
	BATADV_ATTR_HARD_IFINDEX,
};

static int parse_orig_list_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct nlquery_opts *query_opts = arg;
	struct vis_netlink_opts *opts;
	struct genlmsghdr *ghdr;
	struct vis_list_entry *v_entry;
	uint8_t *orig;
	uint8_t *neigh;
	uint8_t tq;
	uint32_t hardif;

	opts = container_of(query_opts, struct vis_netlink_opts,
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

	if (missing_mandatory_attrs(attrs, parse_orig_list_mandatory,
				    ARRAY_SIZE(parse_orig_list_mandatory)))
		return NL_OK;

	if (!attrs[BATADV_ATTR_FLAG_BEST])
		return NL_OK;

	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	neigh = nla_data(attrs[BATADV_ATTR_NEIGH_ADDRESS]);
	tq = nla_get_u8(attrs[BATADV_ATTR_TQ]);
	hardif = nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]);

	if (tq < 1)
		return NL_OK;

	if (memcmp(orig, neigh, ETH_ALEN) != 0)
		return NL_OK;

	v_entry = malloc(sizeof(*v_entry));
	if (!v_entry)
		return NL_OK;

	memcpy(v_entry->v.mac, orig, ETH_ALEN);
	v_entry->v.ifindex = get_if_index_devindex(opts->globals, hardif);
	v_entry->v.qual = tq;
	list_add_tail(&v_entry->list, &opts->globals->entry_list);

	return NL_OK;
}

static int parse_orig_list(struct globals *globals)
{
	struct vis_netlink_opts opts = {
		.globals = globals,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	ret = netlink_query_common(globals->interface,
				   BATADV_CMD_GET_ORIGINATORS,
			           parse_orig_list_netlink_cb, &opts.query_opts);
	if (ret < 0)
		return ret;

	return 0;
}

static int vis_publish_data(struct globals *globals)
{
	int len, ret;

	/* to push data we have to add a push header, the header for the data
	 * and our own data type.
	 */
	globals->push->tx.id = htons(ntohs(globals->push->tx.id) + 1);

	len = VIS_DATA_SIZE(globals->vis_data);
	globals->push->data->header.length = htons(len);
	len += sizeof(*globals->push) - sizeof(globals->push->header);
	len += sizeof(*globals->push->data);
	globals->push->header.length = htons(len);
	len +=  sizeof(globals->push->header);

	alfred_open_sock(globals);
	if (globals->unix_sock < 0)
		return globals->unix_sock;

	ret = write(globals->unix_sock, globals->buf, len);
	close(globals->unix_sock);
	if (ret < len)
		return -1;

	return 0;
}

static int compile_vis_data(struct globals *globals)
{
	struct iface_list_entry *i_entry;
	struct vis_list_entry *v_entry;
	struct vis_entry *vis_entries;
	int iface_n = 0, entries_n = 0;

	list_for_each_entry(i_entry, &globals->iface_list, list) {
		memcpy(&globals->vis_data->ifaces[iface_n], i_entry->mac, ETH_ALEN);

		iface_n++;
		if (iface_n == 254)
			break;
	}
	globals->vis_data->iface_n = iface_n;
	vis_entries = (struct vis_entry *) &globals->vis_data->ifaces[globals->vis_data->iface_n];

	list_for_each_entry(v_entry, &globals->entry_list, list) {
		memcpy(&vis_entries[entries_n], &v_entry->v, sizeof(v_entry->v));
		entries_n++;
		
		if (entries_n == 255)
			break;
	}
	globals->vis_data->entries_n = entries_n;
	return 0;
}

static int vis_update_data(struct globals *globals)
{
	clear_lists(globals);
	register_interfaces(globals);
	parse_orig_list(globals);
	parse_transtable_local(globals);

	compile_vis_data(globals);

	vis_publish_data(globals);
	return 0;
}

static int vis_request_data(struct globals *globals)
{
	int ret;

	globals->request = (struct alfred_request_v0 *) globals->buf;

	globals->request->header.type = ALFRED_REQUEST;
	globals->request->header.version = ALFRED_VERSION;
	globals->request->header.length = htons(sizeof(*globals->request) - sizeof(globals->request->header));
	globals->request->requested_type = VIS_PACKETTYPE;
	globals->request->tx_id = htons(random());

	alfred_open_sock(globals);
	if (globals->unix_sock < 0)
		return globals->unix_sock;

	ret = write(globals->unix_sock, globals->request, sizeof(*globals->request));
	if (ret < (int)sizeof(*globals->request)) {
		close(globals->unix_sock);
		return -1;
	}

	return globals->unix_sock;
}


static struct vis_v1 *vis_receive_answer_packet(int sock, uint16_t *len)
{
	static uint8_t buf[65536];
	struct alfred_tlv *tlv;
	struct alfred_push_data_v0 *push;
	struct alfred_data *data;
	int l, ret;

	ret = read(sock, buf, sizeof(*tlv));
	if (ret < 0)
		return NULL;

	if (ret < (int)sizeof(*tlv)) 
		return NULL;

	tlv = (struct alfred_tlv *)buf;
	/* TODO: might return an ALFRED_STATUS_ERROR too, handle it */
	if (tlv->type != ALFRED_PUSH_DATA)
		return NULL;

	l = ntohs(tlv->length);
	/* exceed the buffer? don't read */
	if (l > (int)(sizeof(buf) - sizeof(push->header)))
		return NULL;

	/* not enough for even the push packet and header? don't bother. */
	if (l < (int)(sizeof(*push) - sizeof(push->header) + sizeof(*data)))
		return NULL;

	/* read the rest of the packet */
	ret = read(sock, buf + sizeof(*tlv), l);
	if (ret < l)
		return NULL;

	push = (struct alfred_push_data_v0 *)buf;
	data = push->data;
	*len = ntohs(data->header.length);

	if (data->header.type != VIS_PACKETTYPE)
		return NULL;

	if (data->header.version != VIS_PACKETVERSION)
		return NULL;

	return (struct vis_v1 *) data->data;
}

static void vis_dot_preamble(void)
{
	printf("digraph {\n");
}

static void vis_dot_interfaces(uint8_t iface_n, struct vis_iface *ifaces)
{
	int i;

	printf("\tsubgraph \"cluster_%s\" {\n", mac_to_str(ifaces[0].mac));
	for (i = 0; i < iface_n; i++)
		printf("\t\t\"%s\"%s\n", mac_to_str(ifaces[i].mac),
		       i ? " [peripheries=2]":"");
	printf("\t}\n");
}

static void vis_dot_entries(uint8_t entries_n, struct vis_entry *vis_entries,
			    uint8_t iface_n, struct vis_iface *ifaces)
{
	int i;

	for (i = 0; i < entries_n; i++) {
		if (vis_entries[i].ifindex == 255) {
			printf("\t\"%s\" ", mac_to_str(ifaces[0].mac));
			printf("-> \"%s\" [label=\"TT\"]\n",
			       mac_to_str(vis_entries[i].mac));
		} else {
			if (vis_entries[i].ifindex >= iface_n) {
				fprintf(stderr, "ERROR: bad ifindex ...\n");
				continue;
			}
			if (vis_entries[i].qual == 0) {
				fprintf(stderr, "ERROR: quality = 0?\n");
				continue;
			}
			printf("\t\"%s\" ",
			       mac_to_str(ifaces[vis_entries[i].ifindex].mac));
			printf("-> \"%s\" [label=\"%3.3f\"]\n",
			       mac_to_str(vis_entries[i].mac),
			       255.0 / ((float)vis_entries[i].qual));
		}
	}
}

static void vis_dot_postamble(void)
{
	printf("}\n");
}

static void vis_json_preamble(void)
{
}

static void vis_json_interfaces(uint8_t iface_n, struct vis_iface *ifaces)
{
	int i;

	printf("{ \"primary\" : \"%s\" }\n", mac_to_str(ifaces[0].mac));
	for (i = 1; i < iface_n; i++) {
		printf("{ \"secondary\" : \"%s\"", mac_to_str(ifaces[i].mac));
		printf(", \"of\" : \"%s\" }\n", mac_to_str(ifaces[0].mac));
	}
}

static void vis_json_entries(uint8_t entries_n, struct vis_entry *vis_entries,
			     uint8_t iface_n, struct vis_iface *ifaces)
{
	int i;

	for (i = 0; i < entries_n; i++) {
		if (vis_entries[i].ifindex == 255) {
			printf("{ \"router\" : \"%s\"",
			       mac_to_str(ifaces[0].mac));
			printf(", \"gateway\" : \"%s\", \"label\" : \"TT\" }\n",
			       mac_to_str(vis_entries[i].mac));
		} else {
			if (vis_entries[i].ifindex >= iface_n) {
				fprintf(stderr, "ERROR: bad ifindex ...\n");
				continue;
			}
			if (vis_entries[i].qual == 0) {
				fprintf(stderr, "ERROR: quality = 0?\n");
				continue;
			}
			printf("{ \"router\" : \"%s\"",
			       mac_to_str(ifaces[vis_entries[i].ifindex].mac));
			printf(", \"neighbor\" : \"%s\", \"label\" : \"%3.3f\" }\n",
			       mac_to_str(vis_entries[i].mac),
			       255.0 / ((float)vis_entries[i].qual));
		}
	}
}

static void vis_json_postamble(void)
{
}

static void vis_jsondoc_preamble(void)
{
	printf("{\n");
	printf("  \"source_version\" : \"%s\",\n", SOURCE_VERSION);
	printf("  \"algorithm\" : 4,\n");
	printf("  \"vis\" : [\n");
}

static void vis_jsondoc_interfaces(uint8_t iface_n, struct vis_iface *ifaces)
{
	int i;
	static bool first_interface = true;

	if (first_interface)
		first_interface = false;
	else
		printf(",\n");

	printf("    { \"primary\" : \"%s\",\n", mac_to_str(ifaces[0].mac));
	if (iface_n > 1) {
		printf("      \"secondary\" : [ ");
		for (i = 1; i < iface_n; i++) {
			printf("\"%s\"", mac_to_str(ifaces[i].mac));
			if ( i < iface_n - 1)
				printf(",");
		}
		printf("\n       ],\n");
	}
}

static void vis_jsondoc_entries(uint8_t entries_n,
				struct vis_entry *vis_entries,
				uint8_t iface_n, struct vis_iface *ifaces)
{
	bool first_neighbor = true;
	bool first_tt = true;
	int i;

	printf("      \"neighbors\" : [\n");

	for (i = 0; i < entries_n; i++) {
		if (vis_entries[i].ifindex == 255) {
			continue;
		}

		if (vis_entries[i].ifindex >= iface_n) {
			fprintf(stderr, "ERROR: bad ifindex ...\n");
			continue;
		}
		if (vis_entries[i].qual == 0) {
			fprintf(stderr, "ERROR: quality = 0?\n");
			continue;
		}

		if (first_neighbor)
			first_neighbor = false;
		else
			printf(",\n");

		printf("         { \"router\" : \"%s\",\n",
		       mac_to_str(ifaces[vis_entries[i].ifindex].mac));
		printf("           \"neighbor\" : \"%s\",\n",
		       mac_to_str(vis_entries[i].mac));
		printf("           \"metric\" : \"%3.3f\" }",
		       255.0 / ((float)vis_entries[i].qual));
	}

	printf("\n      ],\n");

	printf("      \"clients\" : [\n");

	for (i = 0; i < entries_n; i++) {
		if (vis_entries[i].ifindex == 255) {
			if (first_tt)
				first_tt = false;
			else
				printf(",\n");

			printf("        \"%s\"",
			       mac_to_str(vis_entries[i].mac));
		}
	}
	printf("\n      ]\n");
	printf("    }");
}

static void vis_jsondoc_postamble(void)
{
	printf("\n  ]\n");
	printf("}\n");
}

struct vis_print_ops
{
	void (*preamble)(void);
	void (*interfaces)(uint8_t iface_n, struct vis_iface *ifaces);
	void (*entries)(uint8_t entries_n, struct vis_entry *vis_entries,
			uint8_t iface_n, struct vis_iface *ifaces);
	void (*postamble)(void);
};

static const struct vis_print_ops vis_dot_ops =
{
	vis_dot_preamble,
	vis_dot_interfaces,
	vis_dot_entries,
	vis_dot_postamble
};

static const struct vis_print_ops vis_json_ops =
{
	vis_json_preamble,
	vis_json_interfaces,
	vis_json_entries,
	vis_json_postamble
};

static const struct vis_print_ops vis_jsondoc_ops =
{
	vis_jsondoc_preamble,
	vis_jsondoc_interfaces,
	vis_jsondoc_entries,
	vis_jsondoc_postamble
};

static int vis_read_answer(struct globals *globals)
{
	const struct vis_print_ops *ops;
	struct vis_v1 *vis_data;
	uint16_t len;
	struct vis_iface *ifaces;
	struct vis_entry *vis_entries;

	switch (globals->vis_format) {
	case FORMAT_DOT:
		ops = &vis_dot_ops;
		break;
	case FORMAT_JSON:
		ops = &vis_json_ops;
		break;
	case FORMAT_JSONDOC:
		ops = &vis_jsondoc_ops;
		break;
	default:
		return -1;
	}

	ops->preamble();

	while ((vis_data =
		vis_receive_answer_packet(globals->unix_sock, &len)) != NULL) {
		if (len < sizeof(*vis_data))
			return -1;

		/* check size and skip bogus packets */
		if (len != VIS_DATA_SIZE(vis_data))
			continue;

		if (vis_data->iface_n == 0)
			continue;

		ifaces = vis_data->ifaces;
		vis_entries = (struct vis_entry *) &ifaces[vis_data->iface_n];

		ops->interfaces(vis_data->iface_n, ifaces);

		if (vis_data->entries_n == 0)
			continue;

		ops->entries(vis_data->entries_n, vis_entries,
			     vis_data->iface_n, ifaces);
	}
	ops->postamble();

	return 0;
}

static int vis_get_data(struct globals *globals)
{
	globals->unix_sock = vis_request_data(globals);
	if (globals->unix_sock < 0)
		return -1;

	vis_read_answer(globals);
	close(globals->unix_sock);

	return 0;
}

static void vis_usage(void)
{
	printf("Usage: batadv-vis [options]\n");
	printf("  -i, --interface             specify the batman-adv interface configured on the system (default: bat0)\n");
	printf("  -s, --server                start up in server mode, which regularly updates vis data from batman-adv\n");
	printf("  -f, --format <format>       specify the output format for client mode (either \"json\", \"jsondoc\" or \"dot\")\n");
	printf("  -u, --unix-path <path>      path to unix socket used for alfred server communication (default: \""ALFRED_SOCK_PATH_DEFAULT"\")\n");
	printf("  -v, --version               print the version\n");
	printf("  -h, --help                  this help\n");
	printf("\n");
}

static struct globals *vis_init(int argc, char *argv[])
{
	int opt, opt_ind;
	struct globals *globals;
	struct option long_options[] = {
		{"server",	no_argument,		NULL,	's'},
		{"interface",	required_argument,	NULL,	'i'},
		{"format",	required_argument,	NULL,	'f'},
		{"unix-path", 	required_argument,	NULL,	'u'},
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{NULL,		0,			NULL,	0},
	};

	globals = &vis_globals;
	memset(globals, 0, sizeof(*globals));

	globals->opmode = OPMODE_CLIENT;
	globals->interface = "bat0";
	globals->vis_format = FORMAT_DOT;
	globals->unix_path = ALFRED_SOCK_PATH_DEFAULT;

	while ((opt = getopt_long(argc, argv, "shf:i:vu:", long_options,
				  &opt_ind)) != -1) {
		switch (opt) {
		case 's':
			globals->opmode = OPMODE_SERVER;
			break;
		case 'f':
			if (strncmp(optarg, "dot", 3) == 0)
				globals->vis_format = FORMAT_DOT;
			else if (strncmp(optarg, "jsondoc", 7) == 0)
				globals->vis_format = FORMAT_JSONDOC;
			else if (strncmp(optarg, "json", 4) == 0)
				globals->vis_format = FORMAT_JSON;
			else {
				vis_usage();
				return NULL;
			}
			break;
		case 'i':
			globals->interface = strdup(optarg);
			break;
		case 'u':
			globals->unix_path = optarg;
			break;
		case 'v':
			printf("%s %s\n", argv[0], SOURCE_VERSION);
			printf("VIS alfred client\n");
			return NULL;
		case 'h':
		default:
			vis_usage();
			return NULL;
		}
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		perror("could not register SIGPIPE handler");
	return globals;
}



static int vis_server(struct globals *globals)
{
	globals->push = (struct alfred_push_data_v0 *) globals->buf;
	globals->vis_data = (struct vis_v1 *) (globals->buf + sizeof(*globals->push) + sizeof(struct alfred_data));

	globals->push->header.type = ALFRED_PUSH_DATA;
	globals->push->header.version = ALFRED_VERSION;
	globals->push->tx.id = 0;
	globals->push->tx.seqno = 0;
	globals->push->data->header.type = VIS_PACKETTYPE;
	globals->push->data->header.version = VIS_PACKETVERSION;

	INIT_LIST_HEAD(&globals->iface_list);
	INIT_LIST_HEAD(&globals->entry_list);

	while (1) {
		vis_update_data(globals);
		sleep(UPDATE_INTERVAL);
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct globals *globals;

	globals = vis_init(argc, argv);

	if (!globals)
		return 1;

	switch (globals->opmode) {
	case OPMODE_SERVER:
		return vis_server(globals);
		break;
	case OPMODE_CLIENT:
		return vis_get_data(globals);
		break;
	}

	return 0;
}
