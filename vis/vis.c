/*
 * Copyright (C) 2013-2014 B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
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

#include "vis.h"
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if.h>
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
#include "debugfs.h"

static char *read_file(char *fname)
{
	FILE *fp;
	char *buf = NULL;
	size_t size, ret;

	fp = fopen(fname, "r");

	if (!fp)
		return NULL;

	size = 0;
	while (!feof(fp)) {

		buf = realloc(buf, size + 4097);
		if (!buf)
			return NULL;

		ret = fread(buf + size, 1, 4096, fp);
		size += ret;
	}
	fclose(fp);

	if (buf)
		buf[size] = 0;

	return buf;
}

static char *mac_to_str(uint8_t *mac)
{
	static char macstr[20];
	snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x",
		 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return macstr;
}

static uint8_t *str_to_mac(char *str)
{
	static uint8_t mac[ETH_ALEN];
	int ret;

	if (!str)
		return NULL;

	ret = sscanf(str,
		"%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
		&mac[0], &mac[1], &mac[2],
		&mac[3], &mac[4], &mac[5]);
	
	if (ret != 6)
		return NULL;
	
	return mac;
}

static int get_if_mac(char *ifname, uint8_t *mac)
{
	struct ifreq ifr;
	int sock;

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "can't get interface: %s\n", strerror(errno));
		return -1;
	}

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		fprintf(stderr, "can't get MAC address: %s\n", strerror(errno));
		return -1;
	}

	memcpy(mac, &ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

static int get_if_index(struct globals *globals, char *ifname)
{
	struct iface_list_entry *i_entry;
	int i;

	if (!ifname)
		return -1;

	i = 0;
	list_for_each_entry(i_entry, &globals->iface_list, list) {
		if (strncmp(ifname, i_entry->name, sizeof(i_entry->name)) == 0)
			return i;
		i++;
	}
	i_entry = malloc(sizeof(*i_entry));
	if (!i_entry)
		return -1;

	if (get_if_mac(ifname, i_entry->mac)) {
		free(i_entry);
		return -1;
	}

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
		fprintf(stderr, "can't create unix socket: %s\n",
			strerror(errno));
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strcpy(addr.sun_path, ALFRED_SOCK_PATH);

	if (connect(globals->unix_sock, (struct sockaddr *)&addr,
		    sizeof(addr)) < 0) {
		fprintf(stderr, "can't connect to unix socket: %s\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

static int parse_transtable_local(struct globals *globals)
{
	char *fbuf;
	char *lptr, *tptr;
	char *temp1, *temp2;
	int lnum, tnum;
	uint8_t *mac;
	struct vis_list_entry *v_entry;
	char path[1024];

	debugfs_make_path(DEBUG_BATIF_PATH_FMT "/" "transtable_local", globals->interface, path, sizeof(path));
	path[sizeof(path) - 1] = 0;

	fbuf = read_file(path);
	if (!fbuf)
		return -1;

	for (lptr = fbuf, lnum = 0; ; lptr = NULL, lnum++) {
		lptr = strtok_r(lptr, "\n", &temp1);
		if (!lptr)
			break;

		if (lnum < 1)
			continue;

		for (tptr = lptr, tnum = 0;; tptr = NULL, tnum++) {
			tptr = strtok_r(tptr, "\t ", &temp2);
			if (!tptr)
				break;
			if (tnum == 1) {
				v_entry = malloc(sizeof(*v_entry));
				if (!v_entry)
					continue;

				mac = str_to_mac(tptr);
				if (!mac)
					continue;

				memcpy(v_entry->v.mac, mac, ETH_ALEN);
				v_entry->v.ifindex = 255;
				v_entry->v.qual = 0;
				list_add_tail(&v_entry->list, &globals->entry_list);
			}
		}
	}
	free(fbuf);

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

static int register_interfaces(struct globals *globals)
{
	DIR *iface_base_dir;
	struct dirent *iface_dir;
	char *path_buff, *file_content;

	path_buff = malloc(PATH_BUFF_LEN);
	if (!path_buff) {
		fprintf(stderr, "Error - could not allocate path buffer: out of memory ?\n");
		goto err;
	}

	iface_base_dir = opendir(SYS_IFACE_PATH);
	if (!iface_base_dir) {
		fprintf(stderr, "Error - the directory '%s' could not be read: %s\n",
		       SYS_IFACE_PATH, strerror(errno));
		fprintf(stderr, "Is the batman-adv module loaded and sysfs mounted ?\n");
		goto err_buff;
	}

	while ((iface_dir = readdir(iface_base_dir)) != NULL) {
		snprintf(path_buff, PATH_BUFF_LEN, SYS_MESH_IFACE_FMT, iface_dir->d_name);
		path_buff[PATH_BUFF_LEN - 1] = '\0';
		file_content = read_file(path_buff);
		if (!file_content)
			continue;

		if (file_content[strlen(file_content) - 1] == '\n')
			file_content[strlen(file_content) - 1] = '\0';

		if (strcmp(file_content, "none") == 0)
			goto free_line;

		if (strcmp(file_content, globals->interface) != 0)
			goto free_line;

		free(file_content);
		file_content = NULL;

		snprintf(path_buff, PATH_BUFF_LEN, SYS_IFACE_STATUS_FMT, iface_dir->d_name);
		path_buff[PATH_BUFF_LEN - 1] = '\0';
		file_content = read_file(path_buff);
		if (!file_content)
			continue;

		if (strcmp(file_content, "active") == 0)
			get_if_index(globals, iface_dir->d_name);

free_line:
		free(file_content);
		file_content = NULL;
	}

	free(path_buff);
	closedir(iface_base_dir);
	return EXIT_SUCCESS;

err_buff:
	free(path_buff);
err:
	return EXIT_FAILURE;
}


static int parse_orig_list(struct globals *globals)
{
	char *fbuf;
	char *lptr, *tptr;
	char *temp1, *temp2;
	char *dest, *tq, *neigh, *iface;
	int lnum, tnum, ifindex, tq_val;
	uint8_t *mac;
	char path[1024];
	struct vis_list_entry *v_entry;

	snprintf(path, sizeof(path), "/sys/kernel/debug/batman_adv/%s/originators", globals->interface);
	path[sizeof(path) - 1] = 0;
	fbuf = read_file(path);
	if (!fbuf)
		return -1;

	for (lptr = fbuf, lnum = 0; ; lptr = NULL, lnum++) {
		lptr = strtok_r(lptr, "\n", &temp1);
		if (!lptr)
			break;
		if (lnum < 2)
			continue;

		for (tptr = lptr, tnum = 0;; tptr = NULL, tnum++) {
			tptr = strtok_r(tptr, "\t []()", &temp2);
			if (!tptr)
				break;
			switch (tnum) {
			case 0: dest = tptr; break;
			case 2: tq = tptr; break;
			case 3: neigh = tptr; break;
			case 4: iface = tptr; break;
			default: break;
			}
		}
		if (tnum >= 4) {
			if (strcmp(dest, neigh) == 0) {
				tq_val = strtol(tq, NULL, 10);
				if (tq_val < 1 || tq_val > 255)
					continue;

				mac = str_to_mac(dest);
				if (!mac)
					continue;

				ifindex = get_if_index(globals, iface);
				if (ifindex < 0)
					continue;

				v_entry = malloc(sizeof(*v_entry));
				if (!v_entry)
					continue;

				memcpy(v_entry->v.mac, mac, ETH_ALEN);
				v_entry->v.ifindex = ifindex;
				v_entry->v.qual = tq_val;
				list_add_tail(&v_entry->list, &globals->entry_list);
				
			}
		}

	}
	free(fbuf);

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
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{NULL,		0,			NULL,	0},
	};

	globals = malloc(sizeof(*globals));
	if (!globals)
		return NULL;

	memset(globals, 0, sizeof(*globals));

	globals->opmode = OPMODE_CLIENT;
	globals->interface = "bat0";
	globals->vis_format = FORMAT_DOT;

	while ((opt = getopt_long(argc, argv, "shf:i:v", long_options,
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
		fprintf(stderr, "could not register SIGPIPE handler\n");
	return globals;
}



static int vis_server(struct globals *globals)
{
	char *debugfs_mnt;

	debugfs_mnt = debugfs_mount(NULL);
	if (!debugfs_mnt) {
		fprintf(stderr, "Error - can't mount or find debugfs\n");
		return EXIT_FAILURE;
	}

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
