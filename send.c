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

#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include "alfred.h"
#include "hash.h"
#include "packet.h"

int announce_master(struct globals *globals)
{
	ssize_t ret;
	struct alfred_announce_master_v0 announcement;

	if (globals->netsock < 0)
		return -1;

	announcement.header.type = ALFRED_ANNOUNCE_MASTER;
	announcement.header.version = ALFRED_VERSION;
	announcement.header.length = htons(0);

	ret = send_alfred_packet(globals, &in6addr_localmcast, &announcement,
				 sizeof(announcement));
	if (ret == -EPERM) {
		fprintf(stderr, "Error during announcement\n");
		netsock_close(globals->netsock);
		globals->netsock = -1;
	}


	return 0;
}

int push_data(struct globals *globals, struct in6_addr *destination,
	      enum data_source max_source_level, int type_filter,
	      uint16_t tx_id)
{
	struct hash_it_t *hashit = NULL;
	uint8_t buf[MAX_PAYLOAD];
	struct alfred_push_data_v0 *push;
	struct alfred_data *data;
	uint16_t total_length = 0;
	size_t tlv_length;
	uint16_t seqno = 0;
	uint16_t length;
	struct alfred_status_v0 status_end;

	push = (struct alfred_push_data_v0 *)buf;
	push->header.type = ALFRED_PUSH_DATA;
	push->header.version = ALFRED_VERSION;
	push->tx.id = tx_id;

	while (NULL != (hashit = hash_iterate(globals->data_hash, hashit))) {
		struct dataset *dataset = hashit->bucket->data;

		if (dataset->data_source > max_source_level)
			continue;

		if (type_filter >= 0 &&
		    dataset->data.header.type != type_filter)
			continue;

		/* would the packet be too big? send so far aggregated data
		 * first */
		if (total_length + dataset->data.header.length + sizeof(*data) >
		    MAX_PAYLOAD - sizeof(*push)) {
			tlv_length = total_length;
			tlv_length += sizeof(*push) - sizeof(push->header);
			push->header.length = htons(tlv_length);
			push->tx.seqno = htons(seqno++);
			send_alfred_packet(globals, destination, push,
					   sizeof(*push) + total_length);
			total_length = 0;
		}

		data = (struct alfred_data *)
		       (buf + sizeof(*push) + total_length);
		memcpy(data, &dataset->data, sizeof(*data));
		data->header.length = htons(data->header.length);
		memcpy(data->data, dataset->buf, dataset->data.header.length);

		total_length += dataset->data.header.length + sizeof(*data);
	}
	/* send the final packet */
	if (total_length) {
		tlv_length = total_length;
		tlv_length += sizeof(*push) - sizeof(push->header);
		push->header.length = htons(tlv_length);
		push->tx.seqno = htons(seqno++);
		send_alfred_packet(globals, destination, push,
				   sizeof(*push) + total_length);
	}

	/* send transaction txend packet */
	if (seqno > 0 || type_filter != NO_FILTER) { 
		status_end.header.type = ALFRED_STATUS_TXEND;
		status_end.header.version = ALFRED_VERSION;
		length = sizeof(status_end) - sizeof(status_end.header);
		status_end.header.length = htons(length);

		status_end.tx.id = tx_id;
		status_end.tx.seqno = htons(seqno);

		send_alfred_packet(globals, destination, &status_end,
				sizeof(status_end));
	}

	return 0;
}


int sync_data(struct globals *globals)
{
	struct hash_it_t *hashit = NULL;

	/* send local data and data from our clients to (all) other servers */
	while (NULL != (hashit = hash_iterate(globals->server_hash, hashit))) {
		struct server *server = hashit->bucket->data;

		push_data(globals, &server->address, SOURCE_FIRST_HAND,
			  NO_FILTER, get_random_id());
	}
	return 0;
}

int push_local_data(struct globals *globals)
{
	/* no server - yet */
	if (!globals->best_server)
		return -1;

	push_data(globals, &globals->best_server->address, SOURCE_LOCAL,
		  NO_FILTER, get_random_id());

	return 0;
}

ssize_t send_alfred_packet(struct globals *globals, const struct in6_addr *dest,
			   void *buf, int length)
{
	ssize_t ret;
	struct sockaddr_in6 dest_addr;

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.sin6_family = AF_INET6;
	dest_addr.sin6_port = htons(ALFRED_PORT);
	dest_addr.sin6_scope_id = globals->scope_id;
	memcpy(&dest_addr.sin6_addr, dest, sizeof(*dest));

	if (globals->netsock < 0)
		return 0;

	ret = sendto(globals->netsock, buf, length, 0,
		     (struct sockaddr *)&dest_addr,
		     sizeof(struct sockaddr_in6));

	return ret;
}
