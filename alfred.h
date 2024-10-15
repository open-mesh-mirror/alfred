/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef SOURCE_VERSION
#define SOURCE_VERSION			"2024.4"
#endif

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include "bitops.h"
#include "epoll_handle.h"
#include "list.h"
#include "packet.h"

#define ALFRED_INTERVAL			10
#define ALFRED_IF_CHECK_INTERVAL	60
#define ALFRED_REQUEST_TIMEOUT		10
#define ALFRED_SERVER_TIMEOUT		60
#define ALFRED_DATA_TIMEOUT		600
#define ALFRED_SOCK_PATH_DEFAULT	"/var/run/alfred.sock"
#define NO_FILTER			-1

#ifndef __unused
#define __unused __attribute__((unused))
#endif

#define FIXED_TLV_LEN(__tlv_type) \
	htons(sizeof(__tlv_type) - sizeof((__tlv_type).header))

enum data_source {
	SOURCE_LOCAL = 0,
	SOURCE_FIRST_HAND = 1,
	SOURCE_SYNCED = 2,
};

typedef union {
	struct in_addr ipv4;
	struct in6_addr ipv6;
} alfred_addr;

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
	alfred_addr address;
	struct timespec last_seen;
	uint8_t tq;
};

enum opmode {
	OPMODE_SECONDARY,
	OPMODE_PRIMARY,
};

enum clientmode {
	CLIENT_NONE,
	CLIENT_REQUEST_DATA,
	CLIENT_SET_DATA,
	CLIENT_MODESWITCH,
	CLIENT_CHANGE_INTERFACE,
	CLIENT_CHANGE_BAT_IFACE,
	CLIENT_SERVER_STATUS,
	CLIENT_EVENT_MONITOR,
};

struct interface {
	struct ether_addr hwaddr;
	alfred_addr address;
	uint32_t scope_id;
	char *interface;

	int netsock;
	int netsock_mcast;

	struct epoll_handle netsock_epoll;
	struct epoll_handle netsock_mcast_epoll;

	struct hashtable_t *server_hash;

	struct list_head list;
};

struct event_listener {
	int fd;
	struct epoll_handle epoll;

	struct list_head list;
};

struct globals {
	struct list_head interfaces;
	struct list_head event_listeners;

	char *net_iface;
	struct server *best_server;	/* NULL if we are a server ourselves */
	char *mesh_iface;
	enum opmode opmode;
	enum clientmode clientmode;
	int clientmode_arg;
	int clientmode_version;
	uint8_t verbose:1;
	uint8_t ipv4mode:1;
	uint8_t force:1;

	int epollfd;

	int check_timerfd;
	struct epoll_handle check_epoll;

	int unix_sock;
	struct epoll_handle unix_epoll;
	const char *unix_path;

	const char *update_command;
	DECLARE_BITMAP(changed_data_types, ALFRED_NUM_TYPES);

	struct timespec if_check;
	struct timespec sync_period;

	struct hashtable_t *data_hash;
	struct hashtable_t *transaction_hash;
};

#define debugMalloc(size, num)	malloc(size)
#define debugFree(ptr, num)	free(ptr)

#define BUILD_BUG_ON(e) ((void)sizeof(char[1 - 2 * !!(e)]))

#define MAX_PAYLOAD ((1 << 16) - 1 - sizeof(struct udphdr))

extern alfred_addr alfred_mcast;

/* server.c */
int alfred_server(struct globals *globals);
void changed_data_type(struct globals *globals, uint8_t arg);

/* client.c */
int alfred_client_request_data(struct globals *globals);
int alfred_client_set_data(struct globals *globals);
int alfred_client_modeswitch(struct globals *globals);
int alfred_client_change_interface(struct globals *globals);
int alfred_client_change_bat_iface(struct globals *globals);
int alfred_client_server_status(struct globals *globals);
int alfred_client_event_monitor(struct globals *globals);
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
	      alfred_addr *destination, enum data_source max_source_level,
	      int type_filter, uint16_t tx_id);
int announce_primary(struct globals *globals);
int push_local_data(struct globals *globals);
int sync_data(struct globals *globals);
ssize_t send_alfred_packet(struct globals *globals, struct interface *interface,
			   const alfred_addr *dest, void *buf, int length);
/* unix_sock.c */
int unix_sock_open_daemon(struct globals *globals);
int unix_sock_open_client(struct globals *globals);
int unix_sock_close(struct globals *globals);
int unix_sock_req_data_finish(struct globals *globals,
			      struct transaction_head *head);
void unix_sock_events_close_all(struct globals *globals);
void unix_sock_event_notify(struct globals *globals, uint8_t type,
			    const uint8_t source[ETH_ALEN]);
/* vis.c */
int vis_update_data(struct globals *globals);
/* netsock.c */
int netsock_open_all(struct globals *globals);
size_t netsocket_count_interfaces(struct globals *globals);
void netsock_close_all(struct globals *globals);
int netsock_set_interfaces(struct globals *globals, char *interfaces);
struct interface *netsock_first_interface(struct globals *globals);
void netsock_reopen(struct globals *globals);
int netsock_own_address(const struct globals *globals,
			const alfred_addr *address);
/* util.c */
int time_diff(struct timespec *tv1, struct timespec *tv2,
	      struct timespec *tvdiff);
void time_random_seed(void);
uint16_t get_random_id(void);
bool is_valid_ether_addr(uint8_t addr[ETH_ALEN]);
bool is_iface_disabled(char *iface);
int ipv4_arp_request(struct interface *interface, const alfred_addr *addr,
		     struct ether_addr *mac);
