// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Simon Wunderlich
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <stddef.h>
#include <sys/socket.h>
#include "alfred.h"
#include "packet.h"

int alfred_client_request_data(struct globals *globals)
{
	struct alfred_request_v0 request;
	struct alfred_push_data_v0 *push;
	struct alfred_status_v0 *status;
	unsigned char buf[MAX_PAYLOAD];
	struct alfred_data *data;
	const size_t buf_data_len = sizeof(buf) - sizeof(*push) - sizeof(*data);
	struct alfred_tlv *tlv;
	unsigned char *pos;
	int data_len;
	int ret;
	int len;
	int i;

	if (unix_sock_open_client(globals))
		return -1;

	len = sizeof(request);

	request.header.type = ALFRED_REQUEST;
	request.header.version = ALFRED_VERSION;
	request.header.length = FIXED_TLV_LEN(request);
	request.requested_type = globals->clientmode_arg;
	request.tx_id = get_random_id();

	ret = write(globals->unix_sock, &request, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	push = (struct alfred_push_data_v0 *)buf;
	tlv = (struct alfred_tlv *)buf;
	while ((ret = read_full(globals->unix_sock, buf, sizeof(*tlv))) > 0) {
		if (ret < (int)sizeof(*tlv))
			break;

		if (tlv->type == ALFRED_STATUS_ERROR)
			goto recv_err;

		if (tlv->type != ALFRED_PUSH_DATA)
			break;

		/* read the rest of the header */
		ret = read_full(globals->unix_sock, buf + sizeof(*tlv),
				sizeof(*push) - sizeof(*tlv));

		/* too short */
		if (ret < (int)(sizeof(*push) - (int)sizeof(*tlv)))
			break;

		/* read the rest of the header */
		ret = read_full(globals->unix_sock, buf + sizeof(*push),
				sizeof(*data));

		if (ret < (ssize_t)sizeof(*data))
			break;

		data = push->data;
		data_len = ntohs(data->header.length);

		/* would it fit? it should! */
		if (data_len > (int)buf_data_len)
			break;

		/* read the data */
		ret = read_full(globals->unix_sock,
				buf + sizeof(*push) + sizeof(*data), data_len);

		/* again too short */
		if (ret < data_len)
			break;

		pos = data->data;

		printf("{ \"%02x:%02x:%02x:%02x:%02x:%02x\", \"",
		       data->source[0], data->source[1],
		       data->source[2], data->source[3],
		       data->source[4], data->source[5]);
		for (i = 0; i < data_len; i++) {
			if (pos[i] == '"')
				printf("\\\"");
			else if (pos[i] == '\\')
				printf("\\\\");
			else if (!isprint(pos[i]))
				printf("\\x%02x", pos[i]);
			else
				printf("%c", pos[i]);
		}

		printf("\"");

		if (globals->verbose)
			printf(", %u", data->header.version);

		printf(" },\n");
	}

	unix_sock_close(globals);

	return 0;

recv_err:
	/* read the rest of the status message */
	ret = read_full(globals->unix_sock, buf + sizeof(*tlv),
			sizeof(*status) - sizeof(*tlv));

	/* too short */
	if (ret < (int)(sizeof(*status) - sizeof(*tlv)))
		return -1;

	status = (struct alfred_status_v0 *)buf;
	fprintf(stderr, "Request failed with %d\n", status->tx.seqno);

	return status->tx.seqno;
}

int alfred_client_set_data(struct globals *globals)
{
	struct alfred_push_data_v0 *push;
	unsigned char buf[MAX_PAYLOAD];
	struct alfred_data *data;
	int ret;
	int len;

	if (unix_sock_open_client(globals))
		return -1;

	push = (struct alfred_push_data_v0 *)buf;
	data = push->data;
	len = sizeof(*push) + sizeof(*data);
	while (!feof(stdin)) {
		ret = fread(&buf[len], 1, sizeof(buf) - len, stdin);
		if (ret == 0) {
			if (ferror(stdin)) {
				fprintf(stderr, "%s: failed to read data from stdin\n",
					__func__);
				unix_sock_close(globals);
				return -1;
			}

			break;
		}

		len += ret;

		if (sizeof(buf) == len)
			break;
	}

	push->header.type = ALFRED_PUSH_DATA;
	push->header.version = ALFRED_VERSION;
	push->header.length = htons(len - sizeof(push->header));
	push->tx.id = get_random_id();
	push->tx.seqno = htons(0);

	/* we leave data->source "empty" */
	memset(data->source, 0, sizeof(data->source));
	data->header.type = globals->clientmode_arg;
	data->header.version = globals->clientmode_version;
	data->header.length = htons(len - sizeof(*push) - sizeof(*data));

	ret = write(globals->unix_sock, buf, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	unix_sock_close(globals);
	return 0;
}

int alfred_client_modeswitch(struct globals *globals)
{
	struct alfred_modeswitch_v0 modeswitch;
	int ret;
	int len;

	if (unix_sock_open_client(globals))
		return -1;

	len = sizeof(modeswitch);

	modeswitch.header.type = ALFRED_MODESWITCH;
	modeswitch.header.version = ALFRED_VERSION;
	modeswitch.header.length = FIXED_TLV_LEN(modeswitch);

	switch (globals->opmode) {
	case OPMODE_SECONDARY:
		modeswitch.mode = ALFRED_MODESWITCH_SECONDARY;
		break;
	case OPMODE_PRIMARY:
		modeswitch.mode = ALFRED_MODESWITCH_PRIMARY;
		break;
	default:
		fprintf(stderr, "%s: unknown opmode %u in modeswitch\n",
			__func__, globals->opmode);
		return -1;
	}

	ret = write(globals->unix_sock, &modeswitch, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	unix_sock_close(globals);
	return 0;
}

static int check_interface(const char *iface)
{
	struct ifreq ifr;
	int sock = -1;

	if (strlen(iface) >= IFNAMSIZ) {
		fprintf(stderr, "%s: interface name list too long, not changing\n",
			__func__);
		return -1;
	}

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("can't open socket");
		return -1;
	}

	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_name[IFNAMSIZ - 1] = '\0';
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		fprintf(stderr, "%s: can't find interface, not changing\n",
			__func__);
		close(sock);
		return -1;
	}

	close(sock);

	return 0;
}

int alfred_client_change_interface(struct globals *globals)
{
	struct alfred_change_interface_v0 change_interface;
	size_t interface_len;
	char *saveptr;
	char *input;
	char *token;
	int ret;
	int len;

	if (unix_sock_open_client(globals))
		return -1;

	interface_len = strlen(globals->net_iface);
	if (interface_len >= sizeof(change_interface.ifaces)) {
		fprintf(stderr, "%s: interface name list too long, not changing\n",
			__func__);
		unix_sock_close(globals);
		return -1;
	}

	len = sizeof(change_interface);

	change_interface.header.type = ALFRED_CHANGE_INTERFACE;
	change_interface.header.version = ALFRED_VERSION;
	change_interface.header.length = FIXED_TLV_LEN(change_interface);
	strncpy(change_interface.ifaces, globals->net_iface,
		sizeof(change_interface.ifaces));
	change_interface.ifaces[sizeof(change_interface.ifaces) - 1] = '\0';

	/* test it before sending
	 * globals->net_iface is now saved in change_interface.ifaces
	 * and can be modified by strtok_r
	 */
	input = globals->net_iface;
	while ((token = strtok_r(input, ",", &saveptr))) {
		input = NULL;

		ret = check_interface(token);
		if (ret < 0) {
			unix_sock_close(globals);
			return -1;
		}
	}

	ret = write(globals->unix_sock, &change_interface, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	unix_sock_close(globals);

	return 0;
}

int alfred_client_change_bat_iface(struct globals *globals)
{
	struct alfred_change_bat_iface_v0 change_bat_iface;
	size_t interface_len;
	int ret;
	int len;

	if (unix_sock_open_client(globals))
		return -1;

	interface_len = strlen(globals->mesh_iface);
	if (interface_len >= sizeof(change_bat_iface.bat_iface)) {
		fprintf(stderr, "%s: batman-adv interface name list too long, not changing\n",
			__func__);
		unix_sock_close(globals);
		return -1;
	}

	len = sizeof(change_bat_iface);

	change_bat_iface.header.type = ALFRED_CHANGE_BAT_IFACE;
	change_bat_iface.header.version = ALFRED_VERSION;
	change_bat_iface.header.length = FIXED_TLV_LEN(change_bat_iface);
	strncpy(change_bat_iface.bat_iface, globals->mesh_iface,
		sizeof(change_bat_iface.bat_iface));
	change_bat_iface.bat_iface[sizeof(change_bat_iface.bat_iface) - 1] = '\0';

	ret = write(globals->unix_sock, &change_bat_iface, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	unix_sock_close(globals);

	return 0;
}

int alfred_client_server_status(struct globals *globals)
{
	struct alfred_server_status_net_iface_v0 *status_net_iface;
	struct alfred_server_status_bat_iface_v0 *status_bat_iface;
	struct alfred_server_status_op_mode_v0 *status_op_mode;
	struct alfred_server_status_rep_v0 *status_rep;
	struct alfred_server_status_req_v0 status_req;
	struct alfred_tlv *status_tlv;
	uint8_t buf[MAX_PAYLOAD];
	int headsize;
	int consumed;
	int tlvsize;
	int ret;
	int len;

	if (unix_sock_open_client(globals))
		return -1;

	len = sizeof(status_req);
	memset(&status_req, 0, len);

	status_req.header.type = ALFRED_SERVER_STATUS;
	status_req.header.version = ALFRED_VERSION;
	status_req.header.length = 0;

	ret = write(globals->unix_sock, (unsigned char *)&status_req, len);
	if (ret != len)
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));

	ret = -1;
	status_rep = (struct alfred_server_status_rep_v0 *)buf;
	headsize = sizeof(status_rep->header);

	/* drop too small packets */
	len = read_full(globals->unix_sock, buf, headsize);
	if (len < 0) {
		perror("read from unix socket failed");
		goto err;
	}

	if (len < headsize) {
		fprintf(stderr, "unexpected header size received from unix socket\n");
		goto err;
	}

	if (status_rep->header.type != ALFRED_SERVER_STATUS) {
		fprintf(stderr, "alfred server_status type mismatch\n");
		goto err;
	}

	if (status_rep->header.version != ALFRED_VERSION) {
		fprintf(stderr, "alfred version mismatch\n");
		goto err;
	}

	tlvsize = ntohs(status_rep->header.length);

	if (tlvsize < (int)(sizeof(*status_rep) - sizeof(status_rep->header)))
		goto err;

	if (tlvsize > (int)(sizeof(buf) - headsize)) {
		fprintf(stderr, "unexpected packet size received from unix socket\n");
		goto err;
	}

	/* read the announced rest of the reply */
	if (read_full(globals->unix_sock, buf + headsize, tlvsize) < tlvsize) {
		fprintf(stderr, "unexpected packet size received from unix socket\n");
		goto err;
	}

	len = headsize + tlvsize;
	consumed = sizeof(*status_rep);

	while (len - consumed > 0) {
		if (len - consumed < (int)sizeof(*status_tlv))
			break;

		status_tlv = (struct alfred_tlv *)(buf + consumed);

		if (status_tlv->version != ALFRED_VERSION)
			break;

		tlvsize = ntohs(status_tlv->length);
		tlvsize += sizeof(*status_tlv);

		if (len - consumed < tlvsize)
			break;

		switch (status_tlv->type) {
		case ALFRED_SERVER_OP_MODE:
			if (tlvsize != sizeof(*status_op_mode))
				break;

			status_op_mode = (struct alfred_server_status_op_mode_v0 *)(buf + consumed);

			switch (status_op_mode->mode) {
			case ALFRED_MODESWITCH_SECONDARY:
				printf("- mode: secondary\n");
				break;
			case ALFRED_MODESWITCH_PRIMARY:
				printf("- mode: primary\n");
				break;
			default:
				printf("- mode: unknown\n");
				break;
			}

			break;
		case ALFRED_SERVER_NET_IFACE:
			if (tlvsize != sizeof(*status_net_iface))
				break;

			status_net_iface = (struct alfred_server_status_net_iface_v0 *)(buf + consumed);
			status_net_iface->net_iface[sizeof(status_net_iface->net_iface) - 1] = 0;
			printf("- interface: %s\n", status_net_iface->net_iface);
			printf("\t- status: %s\n",
			       status_net_iface->active == 1 ? "active" : "inactive");
			break;
		case ALFRED_SERVER_BAT_IFACE:
			if (tlvsize != sizeof(*status_bat_iface))
				break;

			status_bat_iface = (struct alfred_server_status_bat_iface_v0 *)(buf + consumed);
			status_bat_iface->bat_iface[sizeof(status_bat_iface->bat_iface) - 1] = 0;
			printf("- batman-adv interface: %s\n", status_bat_iface->bat_iface);
			break;
		}

		consumed += tlvsize;
	}

	ret = 0;

err:
	unix_sock_close(globals);
	return ret;
}

int alfred_client_event_monitor(struct globals *globals)
{
	struct alfred_event_register_v0 event_register;
	struct alfred_event_notify_v0 event_notify;
	int ret;
	int len;

	if (unix_sock_open_client(globals))
		return -1;

	len = sizeof(event_register);

	event_register.header.type = ALFRED_EVENT_REGISTER;
	event_register.header.version = ALFRED_VERSION;
	event_register.header.length = 0;

	ret = write(globals->unix_sock, &event_register, len);
	if (ret != len) {
		fprintf(stderr, "%s: only wrote %d of %d bytes: %s\n",
			__func__, ret, len, strerror(errno));
		goto err;
	}

	while (true) {
		len = read_full(globals->unix_sock, &event_notify,
				sizeof(event_notify));
		if (len == 0) {
			fprintf(stdout, "Server closed the connection\n");
			goto err;
		}

		if (len < 0) {
			perror("read from unix socket failed");
			goto err;
		}

		if (len != sizeof(event_notify)) {
			fprintf(stderr, "notify read bytes: %d (expected: %zu)\n",
				len, sizeof(event_notify));
				goto err;
		}

		if (event_notify.header.version != ALFRED_VERSION)
			continue;

		if (event_notify.header.type != ALFRED_EVENT_NOTIFY)
			continue;

		fprintf(stdout, "Event: type = %hhu, source = %02x:%02x:%02x:%02x:%02x:%02x\n",
			event_notify.type,
			event_notify.source[0], event_notify.source[1],
			event_notify.source[2], event_notify.source[3],
			event_notify.source[4], event_notify.source[5]);
	}

err:
	unix_sock_close(globals);
	return 0;
}
