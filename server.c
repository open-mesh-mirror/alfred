/*
 * Copyright (C) 2012-2014 B.A.T.M.A.N. contributors:
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
#include <net/ethernet.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include "alfred.h"
#include "batadv_query.h"
#include "hash.h"

static int server_compare(void *d1, void *d2)
{
	struct server *s1 = d1, *s2 = d2;
	/* compare source and type */
	if (memcmp(&s1->hwaddr, &s2->hwaddr, sizeof(s1->hwaddr)) == 0)
		return 1;
	else
		return 0;
}

static int server_choose(void *d1, int size)
{
	struct server *s1 = d1;
	uint32_t hash = 0;
	size_t i;

	for (i = 0; i < sizeof(s1->hwaddr); i++) {
		hash += s1->hwaddr.ether_addr_octet[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}

	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash % size;
}

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
	globals->server_hash = hash_new(64, server_compare, server_choose);
	globals->data_hash = hash_new(128, data_compare, data_choose);
	globals->transaction_hash = hash_new(64, tx_compare, tx_choose);
	if (!globals->server_hash || !globals->data_hash ||
	    !globals->transaction_hash)
		return -1;

	return 0;
}

int set_best_server(struct globals *globals)
{
	struct hash_it_t *hashit = NULL;
	struct server *best_server = NULL;
	int best_tq = -1;

	while (NULL != (hashit = hash_iterate(globals->server_hash, hashit))) {
		struct server *server = hashit->bucket->data;

		if (server->tq > best_tq) {
			best_tq = server->tq;
			best_server = server;
		}
	}

	globals->best_server = best_server;

	return 0;
}

static int purge_data(struct globals *globals)
{
	struct hash_it_t *hashit = NULL;
	struct timespec now, diff;

	clock_gettime(CLOCK_MONOTONIC, &now);

	while (NULL != (hashit = hash_iterate(globals->data_hash, hashit))) {
		struct dataset *dataset = hashit->bucket->data;

		time_diff(&now, &dataset->last_seen, &diff);
		if (diff.tv_sec < ALFRED_DATA_TIMEOUT)
			continue;

		hash_remove_bucket(globals->data_hash, hashit);
		free(dataset->buf);
		free(dataset);
	}

	while (NULL != (hashit = hash_iterate(globals->server_hash, hashit))) {
		struct server *server = hashit->bucket->data;

		time_diff(&now, &server->last_seen, &diff);
		if (diff.tv_sec < ALFRED_SERVER_TIMEOUT)
			continue;

		if (globals->best_server == server)
			globals->best_server = NULL;

		hash_remove_bucket(globals->server_hash, hashit);
		free(server);
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

int alfred_server(struct globals *globals)
{
	int maxsock, ret;
	struct timespec last_check, now, tv;
	fd_set fds, errfds;

	if (create_hashes(globals))
		return -1;

	if (unix_sock_open_daemon(globals, ALFRED_SOCK_PATH))
		return -1;

	if (!globals->interface) {
		fprintf(stderr, "Can't start server: interface missing\n");
		return -1;
	}

	if (strcmp(globals->mesh_iface, "none") != 0 &&
	    batadv_interface_check(globals->mesh_iface) < 0)
		return -1;

	if (netsock_open(globals))
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &last_check);

	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		now.tv_sec -= ALFRED_INTERVAL;
		if (!time_diff(&last_check, &now, &tv)) {
			tv.tv_sec = 0;
			tv.tv_nsec = 0;
		}

		if (globals->netsock < 0)
			netsock_open(globals);

		maxsock = -1;
		if (globals->netsock > maxsock)
			maxsock = globals->netsock;
		if (globals->unix_sock > maxsock)
			maxsock = globals->unix_sock;

		FD_ZERO(&fds);
		FD_ZERO(&errfds);
		FD_SET(globals->unix_sock, &fds);
		if (globals->netsock >= 0) {
			FD_SET(globals->netsock, &fds);
			FD_SET(globals->netsock, &errfds);
		}
		ret = pselect(maxsock + 1, &fds, NULL, &errfds, &tv, NULL);

		if (ret == -1) {
			fprintf(stderr, "main loop select failed ...: %s\n",
				strerror(errno));
		} else if (ret) {
			if (globals->netsock >= 0 &&
			    FD_ISSET(globals->netsock, &errfds)) {
				fprintf(stderr, "Error on netsock detected\n");
				netsock_close(globals->netsock);
				globals->netsock = -1;
			}

			if (FD_ISSET(globals->unix_sock, &fds)) {
				printf("read unix socket\n");
				unix_sock_read(globals);
				continue;
			} else if (globals->netsock >= 0 &&
				   FD_ISSET(globals->netsock, &fds)) {
				recv_alfred_packet(globals);
				continue;
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &last_check);

		if (globals->opmode == OPMODE_MASTER) {
			/* we are a master */
			printf("announce master ...\n");
			announce_master(globals);
			sync_data(globals);
		} else {
			/* send local data to server */
			push_local_data(globals);
		}
		purge_data(globals);
	}

	if (globals->netsock >= 0)
		netsock_close(globals->netsock);
	unix_sock_close(globals);
	return 0;
}


