/*
 * Copyright (C) 2012-2017  B.A.T.M.A.N. contributors:
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

#include <errno.h>
#include <inttypes.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include "alfred.h"
#include "bitops.h"
#include "batadv_query.h"
#include "hash.h"
#include "list.h"

static int data_compare(void *d1, void *d2)
{
	/* compare source and type */
	return ((memcmp(d1, d2, ETH_ALEN + 1) == 0) ? 1 : 0);
}

static int data_choose(void *d1, int size)
{
	unsigned char *key = d1;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < ETH_ALEN + 1; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

static int tx_compare(void *d1, void *d2)
{
	struct transaction_head *txh1 = d1;
	struct transaction_head *txh2 = d2;

	if (memcmp(&txh1->server_addr, &txh2->server_addr,
		   sizeof(txh1->server_addr)) == 0 &&
	    txh1->id == txh2->id)
		return 1;
	else
		return 0;
}

static int tx_choose(void *d1, int size)
{
	struct transaction_head *txh1 = d1;
	unsigned char *key = (unsigned char *)&txh1->server_addr;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < ETH_ALEN; i++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += txh1->id;
	hash += (hash << 10);
	hash ^= (hash >> 6);

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

static int create_hashes(struct globals *globals)
{
	globals->data_hash = hash_new(128, data_compare, data_choose);
	globals->transaction_hash = hash_new(64, tx_compare, tx_choose);
	if (!globals->data_hash || !globals->transaction_hash)
		return -1;

	return 0;
}

static int set_best_server(struct globals *globals)
{
	struct hash_it_t *hashit = NULL;
	struct server *best_server = NULL;
	int best_tq = -1;
	struct interface *interface;

	list_for_each_entry(interface, &globals->interfaces, list) {
		while (NULL != (hashit = hash_iterate(interface->server_hash,
						      hashit))) {
			struct server *server = hashit->bucket->data;

			if (server->tq > best_tq) {
				best_tq = server->tq;
				best_server = server;
			}
		}
	}

	globals->best_server = best_server;

	return 0;
}

void changed_data_type(struct globals *globals, uint8_t arg)
{
	if (!globals->update_command)
		return;

	set_bit(arg, globals->changed_data_types);
}

static int purge_data(struct globals *globals)
{
	struct hash_it_t *hashit = NULL;
	struct timespec now, diff;
	struct interface *interface;

	clock_gettime(CLOCK_MONOTONIC, &now);

	while (NULL != (hashit = hash_iterate(globals->data_hash, hashit))) {
		struct dataset *dataset = hashit->bucket->data;

		time_diff(&now, &dataset->last_seen, &diff);
		if (diff.tv_sec < ALFRED_DATA_TIMEOUT)
			continue;

		changed_data_type(globals, dataset->data.header.type);

		hash_remove_bucket(globals->data_hash, hashit);
		free(dataset->buf);
		free(dataset);
	}

	list_for_each_entry(interface, &globals->interfaces, list) {
		while (NULL != (hashit = hash_iterate(interface->server_hash,
						      hashit))) {
			struct server *server = hashit->bucket->data;

			time_diff(&now, &server->last_seen, &diff);
			if (diff.tv_sec < ALFRED_SERVER_TIMEOUT)
				continue;

			if (globals->best_server == server)
				globals->best_server = NULL;

			hash_remove_bucket(interface->server_hash, hashit);
			free(server);
		}
	}

	if (!globals->best_server)
		set_best_server(globals);

	while ((hashit = hash_iterate(globals->transaction_hash, hashit))) {
		struct transaction_head *head = hashit->bucket->data;

		time_diff(&now, &head->last_rx_time, &diff);
		if (diff.tv_sec < ALFRED_REQUEST_TIMEOUT)
			continue;

		hash_remove_bucket(globals->transaction_hash, hashit);
		transaction_clean(globals, head);
		if (head->client_socket < 0)
			free(head);
		else
			unix_sock_req_data_finish(globals, head);
	}

	return 0;
}

static void update_server_info(struct globals *globals)
{
	struct hash_it_t *hashit = NULL;
	struct interface *interface;
	struct ether_addr *macaddr;
	struct hashtable_t *tg_hash = NULL;
	struct hashtable_t *orig_hash = NULL;

	/* TQ is not used for master sync mode */
	if (globals->opmode == OPMODE_MASTER)
		return;

	if (strcmp(globals->mesh_iface, "none") != 0) {
		tg_hash = tg_hash_new(globals->mesh_iface);
		if (!tg_hash) {
			fprintf(stderr, "Failed to create translation hash\n");
			return;
		}

		orig_hash = orig_hash_new(globals->mesh_iface);
		if (!orig_hash) {
			fprintf(stderr, "Failed to create originator hash\n");
			goto free_tg_hash;
		}
	}

	list_for_each_entry(interface, &globals->interfaces, list) {
		while (NULL != (hashit = hash_iterate(interface->server_hash,
						      hashit))) {
			struct server *server = hashit->bucket->data;

			if (!orig_hash) {
				server->tq = 255;
				continue;
			}

			macaddr = translate_mac(tg_hash, &server->hwaddr);
			if (macaddr)
				server->tq = get_tq(orig_hash, macaddr);
			else
				server->tq = 0;
		}
	}

	set_best_server(globals);

	if (orig_hash)
		orig_hash_free(orig_hash);
free_tg_hash:
	if (tg_hash)
		tg_hash_free(tg_hash);
}

static void check_if_socket(struct interface *interface, struct globals *globals)
{
	int sock;
	struct ifreq ifr;

	if (interface->netsock < 0)
		return;

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("can't open socket");
		return;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interface->interface, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		perror("can't get interface, closing netsock");
		goto close;
	}

	if (!globals->ipv4mode && (interface->scope_id != (uint32_t)ifr.ifr_ifindex)) {
		fprintf(stderr,
			"iface index changed from %"PRIu32" to %d, closing netsock\n",
			interface->scope_id, ifr.ifr_ifindex);
		goto close;
	}

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		perror("can't get MAC address, closing netsock");
		goto close;
	}

	if (memcmp(&interface->hwaddr, &ifr.ifr_hwaddr.sa_data, 6) != 0) {
		fprintf(stderr, "iface mac changed, closing netsock\n");
		goto close;
	}

	close(sock);
	return;

close:
	close(interface->netsock);
	close(interface->netsock_mcast);
	interface->netsock = -1;
	interface->netsock_mcast = -1;
	close(sock);
}

static void check_if_sockets(struct globals *globals)
{
	struct timespec now, diff;
	struct interface *interface;

	clock_gettime(CLOCK_MONOTONIC, &now);
	time_diff(&now, &globals->if_check, &diff);

	if (diff.tv_sec < ALFRED_IF_CHECK_INTERVAL)
		return;

	globals->if_check = now;

	list_for_each_entry(interface, &globals->interfaces, list)
		check_if_socket(interface, globals);
}

static void execute_update_command(struct globals *globals)
{
	pid_t script_pid;
	size_t command_len;
	char *command;
	size_t data_type;
	size_t changed_data_type_count;
	/* data type is limited by ALFRED_NUM_TYPES to 255 (3 chars), plus
	 * 1x space for appending + terminating null byte
	 */
	char buf[5];

	if (!globals->update_command)
		return;

	if (bitmap_empty(globals->changed_data_types, ALFRED_NUM_TYPES))
		return;

	changed_data_type_count = bitmap_weight(globals->changed_data_types,
						ALFRED_NUM_TYPES);

	/* length of script + 4 bytes per data type (space +3 chars)
	 * + 1 for terminating null byte
	 */
	command_len = strlen(globals->update_command);
	command_len += 4 * changed_data_type_count + 1;
	command = malloc(command_len);
	if (!command)
		return;

	strncpy(command, globals->update_command, command_len - 1);
	command[command_len - 1] = '\0';

	for_each_set_bit (data_type, globals->changed_data_types,
			  ALFRED_NUM_TYPES) {
		/* append the datatype to command line */
		snprintf(buf, sizeof(buf), " %zu", data_type);
		strncat(command, buf, command_len - strlen(command) - 1);
	}

	bitmap_zero(globals->changed_data_types, ALFRED_NUM_TYPES);

	printf("executing: %s\n", command);

	script_pid = fork();
	if (script_pid == 0) {
		system(command);
		exit(0);
	}

	free(command);
}

int alfred_server(struct globals *globals)
{
	int maxsock, ret, recvs;
	struct timespec last_check, now, tv;
	fd_set fds, errfds;
	int num_socks;

	if (create_hashes(globals))
		return -1;

	if (unix_sock_open_daemon(globals))
		return -1;

	if (list_empty(&globals->interfaces)) {
		fprintf(stderr, "Can't start server: interface missing\n");
		return -1;
	}

	if (strcmp(globals->mesh_iface, "none") != 0 &&
	    batadv_interface_check(globals->mesh_iface) < 0)
		return -1;

	num_socks = netsock_open_all(globals);
	if (num_socks <= 0) {
		fprintf(stderr, "Failed to open interfaces\n");
		return -1;
	}

	if (num_socks > 1 && globals->opmode == OPMODE_SLAVE) {
		fprintf(stderr, "More than one interface specified in slave mode\n");
		return -1;
	}

	clock_gettime(CLOCK_MONOTONIC, &last_check);
	globals->if_check = last_check;

	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &now);

		/* subtract the synchronization period from the current time
		 * NOTE: this is an atypical usage of time_diff as it ignores the return
		 * value and store the result back into now, essentially performing the
		 * operation:
		 * now -= globals->sync_period;
		 */
		time_diff(&now, &globals->sync_period, &now);

		if (!time_diff(&last_check, &now, &tv)) {
			tv.tv_sec = 0;
			tv.tv_nsec = 0;
		}

		netsock_reopen(globals);

		FD_ZERO(&fds);
		FD_ZERO(&errfds);
		FD_SET(globals->unix_sock, &fds);
		maxsock = globals->unix_sock;

		maxsock = netsock_prepare_select(globals, &fds, maxsock);
		maxsock = netsock_prepare_select(globals, &errfds, maxsock);

		ret = pselect(maxsock + 1, &fds, NULL, &errfds, &tv, NULL);

		if (ret == -1) {
			perror("main loop select failed ...");
		} else if (ret) {
			netsock_check_error(globals, &errfds);

			if (FD_ISSET(globals->unix_sock, &fds)) {
				printf("read unix socket\n");
				unix_sock_read(globals);
				continue;
			} else {
				recvs = netsock_receive_packet(globals, &fds);
				if (recvs > 0)
					continue;
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &last_check);

		if (globals->opmode == OPMODE_MASTER) {
			/* we are a master */
			printf("[%ld.%09ld] announce master ...\n", last_check.tv_sec, last_check.tv_nsec);
			announce_master(globals);
			sync_data(globals);
		} else {
			/* send local data to server */
			update_server_info(globals);
			push_local_data(globals);
		}
		purge_data(globals);
		check_if_sockets(globals);
		execute_update_command(globals);
	}

	netsock_close_all(globals);
	unix_sock_close(globals);
	return 0;
}
