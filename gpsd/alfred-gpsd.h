/*
 * Copyright (C) 2013-2014 B.A.T.M.A.N. contributors:
 *
 * Andrew Lunn, Simon Wunderlich
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <gps.h>
#include "../packet.h"
#include "../list.h"

#ifndef SOURCE_VERSION
#define SOURCE_VERSION				"2014.0.0"
#endif

#define ALFRED_SOCK_PATH			"/var/run/alfred.sock"
#define PATH_BUFF_LEN				200
#define GPSD_PACKETTYPE				2
#define	GPSD_PACKETVERSION			1
#define UPDATE_INTERVAL				10

enum opmode {
	OPMODE_SERVER,
	OPMODE_CLIENT
};

enum source {
	SOURCE_CMDLINE,
	SOURCE_GPSD
};

enum gpsd_format {
	FORMAT_JSON
};

#define JSON_DATE_MAX   24      /* ISO8601 timestamp with 2 decimal places */

struct gpsd_v1 {
	uint32_t tpv_len;
	__extension__ char tpv[0];
} __packed;

#define GPSD_INIT_TPV "{\"class\":\"TPV\",\"mode\":0}"

#define GPSD_DATA_SIZE(gpsd_data)	\
	(sizeof(*gpsd_data) + (ntohl(gpsd_data->tpv_len)))

/* struct taken from gpsdclient.h */
struct fixsource_t
{
	char *spec;         /* pointer to actual storage */
	char *server;
	char *port;
	char *device;
};

struct globals {
	enum opmode opmode;
	enum source source;
	enum gpsd_format gpsd_format;
	uint8_t buf[65536];

	/* internal pointers into buf */
	struct alfred_request_v0 *request;
	struct alfred_push_data_v0 *push;
	struct gpsd_v1 *gpsd_data;

	float lat, lon, alt;
	int unix_sock;

	struct fixsource_t gpsdsource;
	struct gps_data_t gpsdata;
	char * tpv;
};
