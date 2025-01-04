// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Andrew Lunn, Simon Wunderlich
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "alfred-gpsd.h"

#include <time.h>

static struct globals gpsd_globals;

static int alfred_open_sock(struct globals *globals)
{
	struct sockaddr_un addr;

	globals->unix_sock = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (globals->unix_sock < 0) {
		perror("can't create unix socket");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	strncpy(addr.sun_path, globals->unix_path, sizeof(addr.sun_path));
	addr.sun_path[sizeof(addr.sun_path) - 1] = '\0';

	if (connect(globals->unix_sock, (struct sockaddr *)&addr,
		    sizeof(addr)) < 0) {
		close(globals->unix_sock);
		globals->unix_sock = -1;
		perror("can't connect to unix socket");
		return -1;
	}

	return 0;
}

static int gpsd_publish_data(struct globals *globals)
{
	int len, ret;

	/* to push data we have to add a push header, the header for the data
	 * and our own data type.
	 */
	globals->push->tx.id = htons(ntohs(globals->push->tx.id) + 1);

	len = GPSD_DATA_SIZE(globals->gpsd_data);
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

static void gpsd_now_to_iso8601(char *tbuf, size_t len)
{
#if GPSD_API_MAJOR_VERSION >= 9
	timespec_t now;

	clock_gettime(CLOCK_REALTIME, &now);
	timespec_to_iso8601(now, tbuf, len);
#else
	timestamp_t now = timestamp();
	unix_to_iso8601(now, tbuf, len);
#endif
}

static void gpsd_get_location(struct globals *globals)
{
	if (globals->source == SOURCE_CMDLINE) {
		char tbuf[JSON_DATE_MAX+1];

		gpsd_now_to_iso8601(tbuf, sizeof(tbuf));
		sprintf(globals->gpsd_data->tpv,
			"{\"class\":\"TPV\",\"device\":\"command line\","
			"\"time\":\"%s\","
			"\"lat\":%f,\"lon\":%f,\"alt\":%f,"
			"\"mode\":3}",
			tbuf, globals->lat, globals->lon, globals->alt);
		globals->gpsd_data->tpv_len =
			htonl(strlen(globals->gpsd_data->tpv) + 1);
	}
}

static int gpsd_update_data(struct globals *globals)
{
	gpsd_get_location(globals);
	gpsd_publish_data(globals);

	return 0;
}

static int gpsd_request_data(struct globals *globals)
{
	int ret;

	globals->request = (struct alfred_request_v0 *) globals->buf;

	globals->request->header.type = ALFRED_REQUEST;
	globals->request->header.version = ALFRED_VERSION;
	globals->request->header.length =
		htons(sizeof(*globals->request) - 
		      sizeof(globals->request->header));
	globals->request->requested_type = GPSD_PACKETTYPE;
	globals->request->tx_id = htons(random());

	alfred_open_sock(globals);
	if (globals->unix_sock < 0)
		return globals->unix_sock;

	ret = write(globals->unix_sock, globals->request,
		    sizeof(*globals->request));
	if (ret < (int)sizeof(*globals->request)) {
		close(globals->unix_sock);
		return -1;
	}

	return globals->unix_sock;
}

static struct gpsd_v1 *gpsd_receive_answer_packet(int sock, uint16_t *len,
						  uint8_t *source)
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

	if (data->header.type != GPSD_PACKETTYPE)
		return NULL;

	if (data->header.version != GPSD_PACKETVERSION)
		return NULL;

	memcpy(source, data->source, ETH_ALEN);
	return (struct gpsd_v1 *) data->data;
}

static int gpsd_read_answer(struct globals *globals)
{
	struct gpsd_v1 *gpsd_data;
	uint16_t len;
	uint8_t source[ETH_ALEN];
	bool first_line = true;

	printf("[\n");

	while ((gpsd_data = gpsd_receive_answer_packet(globals->unix_sock,
						       &len,
						       source)) != NULL) {
		if (len < sizeof(*gpsd_data))
			break;

		/* check size and skip bogus packets */
		if (len != GPSD_DATA_SIZE(gpsd_data))
			continue;

		if (first_line)
			first_line = false;
		else
			printf(",\n");

		printf("  { \"source\" : \"%02x:%02x:%02x:%02x:%02x:%02x\", "
		       "\"tpv\" : %s }",
		       source[0], source[1], source[2],
		       source[3], source[4], source[5],
		       gpsd_data->tpv);
	}
	printf("\n]\n");


	return 0;
}

/* Standard parsing of a GPS data source spec. Taken from gpsdclient.c
 * remove when gpsd 3.25 is minimum supported version
 */
static void alfred_gpsd_source_spec(const char *arg,
				    struct alfred_gpsd_fixsource_t *source)
{
	/* the casts attempt to head off a -Wwrite-strings warning */
	source->server = (char *)"localhost";
	source->port = (char *)DEFAULT_GPSD_PORT;
	source->device = NULL;

	if (arg != NULL) {
		char *colon1, *skipto, *rbrk;
		source->spec = strdup(arg);
		assert(source->spec != NULL);

		skipto = source->spec;
		if (*skipto == '[' && (rbrk = strchr(skipto, ']')) != NULL) {
			skipto = rbrk;
		}
		colon1 = strchr(skipto, ':');

		if (colon1 != NULL) {
			char *colon2;
			*colon1 = '\0';
			if (colon1 != source->spec) {
				source->server = source->spec;
			}
			source->port = colon1 + 1;
			colon2 = strchr(source->port, ':');
			if (colon2 != NULL) {
				*colon2 = '\0';
				source->device = colon2 + 1;
			}
		} else if (strchr(source->spec, '/') != NULL) {
			source->device = source->spec;
		} else {
			source->server = source->spec;
		}
	}

	if (*source->server == '[') {
		char *rbrk = strchr(source->server, ']');
		++source->server;
		if (rbrk != NULL)
			*rbrk = '\0';
	}
}

static int gpsd_get_data(struct globals *globals)
{
	globals->unix_sock = gpsd_request_data(globals);
	if (globals->unix_sock < 0)
		return -1;

	gpsd_read_answer(globals);
	close(globals->unix_sock);

	return 0;
}

static void gpsd_connect_gpsd(struct globals *globals)
{
	unsigned int flags = WATCH_ENABLE | WATCH_JSON;
	int ret;

	ret = gps_open(globals->gpsdsource.server, globals->gpsdsource.port,
		       &globals->gpsdata);

	if (ret) {
		/* Could not connect to gpsd. Set the fd so we don't
		   try to perform select(2) on it. */
		globals->gpsdata.gps_fd = -1;
		return;
	}

	if (globals->gpsdsource.device != NULL)
		flags |= WATCH_DEVICE;

	gps_stream(&globals->gpsdata, flags, globals->gpsdsource.device);
}

static void gpsd_read_gpsd(struct globals *globals)
{
	ssize_t ret;
	size_t cnt;
	bool eol = false;
	char buf[4096];
	const size_t tpv_size = sizeof(globals->buf) -
				sizeof(*globals->push) -
				sizeof(struct alfred_data) -
				sizeof(*globals->gpsd_data);

	cnt = 0;
	do {
		ret = read(globals->gpsdata.gps_fd, &buf[cnt], 1);
		if (ret != 1) {
			gps_close(&globals->gpsdata);
			globals->gpsdata.gps_fd = -1;
			return;
		}

		switch (buf[cnt]) {
		case '\r':
			cnt--;
			break;
		case '\n':
			eol = true;
			buf[cnt] = '\0';
			break;
		}
	} while (cnt++ < sizeof(buf) - 1 && !eol);

	if (!eol) {
		gps_close(&globals->gpsdata);
		globals->gpsdata.gps_fd = -1;
		return;
	}

#define STARTSWITH(str, prefix)	strncmp(str, prefix, sizeof(prefix)-1)==0
	if (STARTSWITH(buf, "{\"class\":\"TPV\"")) {
		strncpy(globals->gpsd_data->tpv, buf, tpv_size);
		globals->gpsd_data->tpv[tpv_size - 1] = '\0';

		globals->gpsd_data->tpv_len =
			htonl(strlen(globals->gpsd_data->tpv) + 1);
	}
}

static void gpsd_usage(void)
{
	printf("Usage: alfred-gpsd [options]\n");
	printf("  -s, --server                start up in server mode, which regularly updates gpsd data from batman-adv\n");
	printf("  -l <lat>,<lon>,<alt>        Static location\n");
	printf("  -g server[:port[:device]]   GPSD source\n");
	printf("  -v, --version               print the version\n");
	printf("  -h, --help                  this help\n");
	printf("\n");
}

static void gpsd_parse_location(struct globals *globals,
				const char * optarg)
{
	int n;
	float lat, lon, alt;

	n = sscanf(optarg, "%f,%f,%f", &lat, &lon, &alt);
	if (n != 3) {
		printf("Unable to parse location\n");
		gpsd_usage();
		exit(EXIT_FAILURE);
	}

	if ((lat < -90) || (lat > 90)) {
		printf("Invalid latitude\n");
		gpsd_usage();
		exit(EXIT_FAILURE);
	}

	if ((lon < -180) || (lon > 180)) {
		printf("Invalid longitude\n");
		gpsd_usage();
		exit(EXIT_FAILURE);
	}

	if ((alt < -1000) || (alt > 9000)) {
		/* No support for aircraft or submarines! */
		printf("Invalid altitude\n");
		gpsd_usage();
		exit(EXIT_FAILURE);
	}

	globals->lat = lat;
	globals->lon = lon;
	globals->alt = alt;
}

static struct globals *gpsd_init(int argc, char *argv[])
{
	bool have_source = false;
	int opt, opt_ind;
	struct globals *globals;
	struct option long_options[] = {
		{"server",	no_argument,		NULL,	's'},
		{"location",    required_argument,	NULL,	'l'},
		{"gpsd",	required_argument,	NULL,	'g'},
		{"unix-path", 	required_argument,	NULL,	'u'},
		{"help",	no_argument,		NULL,	'h'},
		{"version",	no_argument,		NULL,	'v'},
		{NULL,		0,			NULL,	0},
	};

	globals = &gpsd_globals;
	memset(globals, 0, sizeof(*globals));

	globals->opmode = OPMODE_CLIENT;
	globals->source = SOURCE_GPSD;
	globals->gpsd_format = FORMAT_JSON;
	globals->unix_path = ALFRED_SOCK_PATH_DEFAULT;

	while ((opt = getopt_long(argc, argv, "shl:g:vu:", long_options,
				  &opt_ind)) != -1) {
		switch (opt) {
		case 's':
			globals->opmode = OPMODE_SERVER;
			break;
		case 'l':
			globals->source = SOURCE_CMDLINE;
			gpsd_parse_location(globals, optarg);
			break;
		case 'g':
			alfred_gpsd_source_spec(optarg, &globals->gpsdsource);
			have_source = true;
			break;
		case 'u':
			globals->unix_path = optarg;
			break;
		case 'v':
			printf("%s %s\n", argv[0], SOURCE_VERSION);
			printf("GPSD alfred client\n");
			return NULL;
		case 'h':
		default:
			gpsd_usage();
			return NULL;
		}
	}

	if (globals->source == SOURCE_GPSD && !have_source)
		alfred_gpsd_source_spec(NULL, &globals->gpsdsource);

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		perror("could not register SIGPIPE handler");
	return globals;
}

static int gpsd_server(struct globals *globals)
{
	struct timeval tv;
	fd_set fds;
	int max_fd, ret;
	const size_t overhead = sizeof(*globals->push) +
		sizeof(struct alfred_data);
	const size_t tpv_size = sizeof(globals->buf) -
				sizeof(*globals->push) -
				sizeof(struct alfred_data) -
				sizeof(*globals->gpsd_data);
	long interval;

	globals->push = (struct alfred_push_data_v0 *) globals->buf;
	globals->gpsd_data = (struct gpsd_v1 *)
		(globals->buf + overhead);

	globals->push->header.type = ALFRED_PUSH_DATA;
	globals->push->header.version = ALFRED_VERSION;
	globals->push->tx.id = 0;
	globals->push->tx.seqno = 0;
	globals->push->data->header.type = GPSD_PACKETTYPE;
	globals->push->data->header.version = GPSD_PACKETVERSION;

	strncpy(globals->gpsd_data->tpv, GPSD_INIT_TPV, tpv_size);
	globals->gpsd_data->tpv[tpv_size - 1] = '\0';
	globals->gpsd_data->tpv_len =
		htonl(strlen(globals->gpsd_data->tpv) + 1);

	/* If we have a static location, we don't need to update very
	   often. */
	if (globals->source == SOURCE_GPSD) {
		globals->gpsdata.gps_fd = -1;
		interval = 2;
	} else
		interval = 60 * 5;

	while (1) {
		gpsd_update_data(globals);

		/* If we are not connected to gpsd, try to connect. */
		if (globals->source == SOURCE_GPSD &&
		    globals->gpsdata.gps_fd == -1) {
			gpsd_connect_gpsd(globals);
		}

		/* Use linux's select(2) behaviour of setting
		   tv to the remaining time when it exists */
		tv.tv_sec = interval;
		tv.tv_usec = 0;

		do {
			FD_ZERO(&fds);

			if (globals->source == SOURCE_GPSD &&
			    globals->gpsdata.gps_fd != -1) {
				FD_SET(globals->gpsdata.gps_fd, &fds);
				max_fd = globals->gpsdata.gps_fd + 1;
			} else {
				max_fd = 0;
			}

			errno = 0;
			ret = select(max_fd, &fds, NULL, NULL, &tv);
			if (ret == -1 && errno != EINTR)
				perror("select error");

			if (ret == 1)
				gpsd_read_gpsd(globals);
		} while (ret != 0);
	}
	return EXIT_FAILURE;
}

int main(int argc, char *argv[])
{
	struct globals *globals;

	globals = gpsd_init(argc, argv);

	if (!globals)
		return EXIT_FAILURE;

	switch (globals->opmode) {
	case OPMODE_SERVER:
		return gpsd_server(globals);
		break;
	case OPMODE_CLIENT:
		return gpsd_get_data(globals);
		break;
	}

	return EXIT_FAILURE;
}
