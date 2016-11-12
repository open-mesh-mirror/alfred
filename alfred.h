/*
 * Copyright (C) 2012-2016  B.A.T.M.A.N. contributors:
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

#ifndef SOURCE_VERSION
#define SOURCE_VERSION			"2016.5"
#endif

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/select.h>
#include <sys/types.h>
#include "list.h"
#include "packet.h"

#define ALFRED_INTERVAL			10
#define ALFRED_IF_CHECK_INTERVAL	60
#define ALFRED_REQUEST_TIMEOUT		10
#define ALFRED_SERVER_TIMEOUT		60
#define ALFRED_DATA_TIMEOUT		600
#define ALFRED_SOCK_PATH_DEFAULT	"/var/run/alfred.sock"
#define NO_FILTER			-1

enum data_source {
	SOURCE_LOCAL = 0,
	SOURCE_FIRST_HAND = 1,
	SOURCE_SYNCED = 2,
};

struct dataset {
	struct alfred_data data;
	unsigned char *buf;

	struct timespec last_seen;
	enum data_source data_source;
	uint8_t local_data;
};

struct changed_data_type {
	uint8_t data_type;
	struct list_head list;
};

struct transaction_packet {
	struct alfred_push_data_v0 *push;
	struct list_head list;
};

struct transaction_head {
	struct ether_addr server_addr;
	uint16_t id;
	uint8_t requested_type;
	uint16_t txend_packets;
	int num_packet;
	int client_socket;
	struct timespec last_rx_time;
	struct list_head packet_list;
};

struct server {
	struct ether_addr hwaddr;
	struct in6_addr address;
	struct timespec last_seen;
	uint8_t tq;
};

enum opmode {
	OPMODE_SLAVE,
	OPMODE_MASTER,
};

enum clientmode {
	CLIENT_NONE,
	CLIENT_REQUEST_DATA,
	CLIENT_SET_DATA,
	CLIENT_MODESWITCH,
	CLIENT_CHANGE_INTERFACE,
};

struct interface {
	struct ether_addr hwaddr;
	struct in6_addr address;
	uint32_t scope_id;
	char *interface;
	int netsock;
	int netsock_mcast;

	struct hashtable_t *server_hash;

	struct list_head list;
};

struct globals {
	struct list_head interfaces;

	char *change_interface;
	struct server *best_server;	/* NULL if we are a server ourselves */
	const char *mesh_iface;
	enum opmode opmode;
	enum clientmode clientmode;
	int clientmode_arg;
	int clientmode_version;
	int verbose;

	int unix_sock;
	const char *unix_path;

	const char *update_command;
	struct list_head changed_data_types;
	uint16_t changed_data_type_count; /* maximum is 256 */

	struct timespec if_check;
	struct timespec sync_period;

	struct hashtable_t *data_hash;
	struct hashtable_t *transaction_hash;
};

#define debugMalloc(size, num)	malloc(size)
#define debugFree(ptr, num)	free(ptr)

#define MAX_PAYLOAD ((1 << 16) - 1 - sizeof(struct udphdr))

extern const struct in6_addr in6addr_localmcast;

/* server.c */
int alfred_server(struct globals *globals);
int set_best_server(struct globals *globals);
void changed_data_type(struct globals *globals, uint8_t arg);

/* client.c */
int alfred_client_request_data(struct globals *globals);
int alfred_client_set_data(struct globals *globals);
int alfred_client_modeswitch(struct globals *globals);
int alfred_client_change_interface(struct globals *globals);
/* recv.c */
int recv_alfred_packet(struct globals *globals, struct interface *interface,
		       int recv_sock);
struct transaction_head *
transaction_add(struct globals *globals, struct ether_addr mac, uint16_t id);
struct transaction_head *transaction_clean(struct globals *globals,
					   struct transaction_head *head);

static inline bool transaction_finished(struct transaction_head *head)
{
	return head->txend_packets == head->num_packet;
}

/* send.c */
int push_data(struct globals *globals, struct interface *interface,
	      struct in6_addr *destination, enum data_source max_source_level,
	      int type_filter, uint16_t tx_id);
int announce_master(struct globals *globals);
int push_local_data(struct globals *globals);
int sync_data(struct globals *globals);
ssize_t send_alfred_packet(struct interface *interface,
			   const struct in6_addr *dest, void *buf, int length);
/* unix_sock.c */
int unix_sock_read(struct globals *globals);
int unix_sock_open_daemon(struct globals *globals);
int unix_sock_open_client(struct globals *globals);
int unix_sock_close(struct globals *globals);
int unix_sock_req_data_finish(struct globals *globals,
			      struct transaction_head *head);
/* vis.c */
int vis_update_data(struct globals *globals);
/* netsock.c */
int netsock_open_all(struct globals *globals);
void netsock_close_all(struct globals *globals);
int netsock_set_interfaces(struct globals *globals, char *interfaces);
struct interface *netsock_first_interface(struct globals *globals);
void netsock_reopen(struct globals *globals);
int netsock_prepare_select(struct globals *globals, fd_set *fds, int maxsock);
void netsock_check_error(struct globals *globals, fd_set *errfds);
int netsock_receive_packet(struct globals *globals, fd_set *fds);
int netsock_own_address(const struct globals *globals,
			const struct in6_addr *address);
/* util.c */
int time_diff(struct timespec *tv1, struct timespec *tv2,
	      struct timespec *tvdiff);
void time_random_seed(void);
uint16_t get_random_id(void);
bool is_valid_ether_addr(uint8_t *addr);
