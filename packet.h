/*
 * Copyright (C) 2012-2017  B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich, Sven Eckelmann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

#ifndef _ALFRED_PACKET_H
#define _ALFRED_PACKET_H

#include <net/if.h>	/* IFNAMSIZ */

#define __packed __attribute__ ((packed))

/* basic blocks */

/**
 * struct alfred_tlv - Type (Version) Length part of a TLV
 * @type: Type of the data
 * @version: Version of the data
 * @length: Length of the data without the alfred_tlv header
 */
struct alfred_tlv {
	uint8_t type;
	uint8_t version;
	uint16_t length;
} __packed;

/**
 * struct alfred_data - Data block header
 * @source: Mac address of the original source of the data
 * @header: TLV-header for the data
 * @data: "length" number of bytes followed by the header
 */
struct alfred_data {
	uint8_t source[ETH_ALEN];
	struct alfred_tlv header;
	/* flexible data block */
	__extension__ uint8_t data[0];
} __packed;

/**
 * struct alfred_transaction_mgmt - Transaction Mgmt block for multiple packets
 * @id: random identificator used for this transaction
 * @seqno: Number of packet inside a transaction
 */
struct alfred_transaction_mgmt {
	uint16_t id;
	uint16_t seqno;
} __packed;

/**
 * enum alfred_packet_type - Types of packet stored in the main alfred_tlv
 * @ALFRED_PUSH_DATA: Packet is an alfred_push_data_v*
 * @ALFRED_ANNOUNCE_MASTER: Packet is an alfred_announce_master_v*
 * @ALFRED_REQUEST: Packet is an alfred_request_v*
 * @ALFRED_STATUS_TXEND: Transaction was finished by sender
 * @ALFRED_STATUS_ERROR: Error was detected during the transaction
 * @ALFRED_MODESWITCH: Switch between different operation modes
 * @ALFRED_CHANGE_INTERFACE: Change the listening interface
 */
enum alfred_packet_type {
	ALFRED_PUSH_DATA = 0,
	ALFRED_ANNOUNCE_MASTER = 1,
	ALFRED_REQUEST = 2,
	ALFRED_STATUS_TXEND = 3,
	ALFRED_STATUS_ERROR = 4,
	ALFRED_MODESWITCH = 5,
	ALFRED_CHANGE_INTERFACE = 6,
};

/* packets */

/**
 * struct alfred_push_data_v0 - Packet to push data blocks to another
 * @header: TLV header describing the complete packet
 * @tx: Transaction identificator and sequence number of packet
 * @data: multiple "alfred_data" blocks of arbitrary size (accumulated size
 *  stored in "header.length")
 *
 * alfred_push_data_v0 packets are always sent using unicast
 */
struct alfred_push_data_v0 {
	struct alfred_tlv header;
	struct alfred_transaction_mgmt tx;
	/* flexible data block */
	__extension__  struct alfred_data data[0];
} __packed;

/**
 * struct alfred_announce_master_v0 - Hello packet sent by an alfred master
 * @header: TLV header describing the complete packet
 *
 * Each alfred daemon running in master mode sends it using multicast. The
 * receiver has to calculate the source using the network header
 */
struct alfred_announce_master_v0 {
	struct alfred_tlv header;
} __packed;

/**
 * struct alfred_request_v0 - Request for a specific type
 * @header: TLV header describing the complete packet
 * @requested_type: data type which is requested
 * @tx_id: random identificator used for this transaction
 *
 * Sent as unicast to the node storing it
 */
struct alfred_request_v0 {
	struct alfred_tlv header;
	uint8_t requested_type;
	uint16_t tx_id;
} __packed;

/**
 * enum alfred_modeswitch_type - Mode of the daemon
 * @ALFRED_MODESWITCH_SLAVE: see OPMODE_SLAVE
 * @ALFRED_MODESWITCH_MASTER: see OPMODE_MASTER
 */
enum alfred_modeswitch_type {
	ALFRED_MODESWITCH_SLAVE = 0,
	ALFRED_MODESWITCH_MASTER = 1,
};

/**
 * struct alfred_modeswitch_v0 - Request for a specific type
 * @header: TLV header describing the complete packet
 * @mode: data type which is requested
 *
 * Sent to the daemon by client
 */
struct alfred_modeswitch_v0 {
	struct alfred_tlv header;
	uint8_t mode;
} __packed;

/**
 * struct alfred_change_interface_v0 - Request to change the interface
 * @header: TLV header describing the complete packet
 * @ifaces: interface list (comma separated) to be changed to
 *
 * Sent to the daemon by client
 */
struct alfred_change_interface_v0 {
	struct alfred_tlv header;
	char ifaces[IFNAMSIZ * 16];
} __packed;

/**
 * struct alfred_status_v0 - Status info of a transaction
 * @header: TLV header describing the complete packet
 * @tx: Transaction identificator and sequence number of packet
 *
 * The sequence number has a special meaning. Failure status packets use
 * it to store the error code. Success status packets store the number of
 * transferred packets in it.
 *
 * Sent as unicast to the node requesting the data
 */
struct alfred_status_v0 {
	struct alfred_tlv header;
	struct alfred_transaction_mgmt tx;
} __packed;

#define ALFRED_VERSION			0
#define ALFRED_PORT			0x4242
#define ALFRED_MAX_RESERVED_TYPE	64
#define ALFRED_NUM_TYPES		256

#endif
