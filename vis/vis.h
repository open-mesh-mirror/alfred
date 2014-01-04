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

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <stdint.h>
#include "../list.h"
#include "../packet.h"


#ifndef SOURCE_VERSION
#define SOURCE_VERSION				"2014.0.0"
#endif

#define ALFRED_SOCK_PATH			"/var/run/alfred.sock"
#define PATH_BUFF_LEN				200
#define VIS_PACKETTYPE				1
#define	VIS_PACKETVERSION			1
#define UPDATE_INTERVAL				10

#define SYS_IFACE_PATH				"/sys/class/net"
#define DEBUG_BATIF_PATH_FMT			"%s/batman_adv/%s"
#define SYS_MESH_IFACE_FMT			SYS_IFACE_PATH"/%s/batman_adv/mesh_iface"
#define SYS_IFACE_STATUS_FMT			SYS_IFACE_PATH"/%s/batman_adv/iface_status"


enum opmode {
	OPMODE_SERVER,
	OPMODE_CLIENT
};

enum vis_format {
	FORMAT_DOT,
	FORMAT_JSON,
	FORMAT_JSONDOC,
};

struct vis_iface {
	uint8_t mac[ETH_ALEN];
};

struct vis_entry {
	uint8_t mac[ETH_ALEN];
	uint8_t ifindex; 	/* 255 = TT */
	uint8_t qual;		/* zero for TT (maybe flags in the future?)
				 * TQ for batman-adv */
}__packed;

struct vis_v1 {
	uint8_t mac[ETH_ALEN];
	uint8_t iface_n;
	uint8_t entries_n;
	__extension__ struct vis_iface ifaces[0]; /* #iface_n of this */
	/* following:
	 * #vis_entries of vis_entry structs
	 */
}__packed;

struct iface_list_entry {
	char name[256];
	uint8_t mac[ETH_ALEN];
	struct list_head list;
};

struct vis_list_entry {
	struct vis_entry v;
	struct list_head list;
};

#define VIS_DATA_SIZE(vis_data)	\
	(sizeof(*vis_data) + (vis_data)->iface_n * sizeof(struct vis_iface) \
	 		   + (vis_data)->entries_n * sizeof(struct vis_entry))

struct globals {
	const char *interface;
	enum opmode opmode;
	enum vis_format vis_format;
	uint8_t buf[65536];

	/* internal pointers into buf */
	struct alfred_request_v0 *request;
	struct alfred_push_data_v0 *push;
	struct vis_v1 *vis_data;

	/* lists for parsed information used in server only */
	struct list_head iface_list;
	struct list_head entry_list;

	int unix_sock;
};


