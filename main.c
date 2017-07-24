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

#include <arpa/inet.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef CONFIG_ALFRED_CAPABILITIES
#include <sys/prctl.h>
#include <sys/capability.h>
#include <unistd.h>
#endif
#include "alfred.h"
#include "debugfs.h"
#include "packet.h"
#include "list.h"

static struct globals alfred_globals;

static void alfred_usage(void)
{
	printf("Usage: alfred [options]\n");
	printf("client mode options:\n");
	printf("  -s, --set-data [data type]          sets new data to distribute from stdin\n");
	printf("                                      for the supplied data type (0-255)\n");
	printf("  -r, --request [data type]           collect data from the network and prints\n");
	printf("                                      it on the network\n");
	printf("  -d, --verbose                       Show extra information in the data output\n");
	printf("  -V, --req-version                   specify the data version set for -s\n");
	printf("  -M, --modeswitch master             switch daemon to mode master\n");
	printf("                   slave              switch daemon to mode slave\n");
	printf("  -I, --change-interface [interface]  change to the specified interface(s)\n");
	printf("\n");
	printf("server mode options:\n");
	printf("  -i, --interface                     specify the interface (or comma separated list of interfaces) to listen on\n");
	printf("  -b                                  specify the batman-adv interface\n");
	printf("                                      configured on the system (default: bat0)\n");
	printf("                                      use 'none' to disable the batman-adv\n");
	printf("                                      based best server selection\n");
	printf("  -m, --master                        start up the daemon in master mode, which\n");
	printf("                                      accepts data from slaves and syncs it with\n");
	printf("                                      other masters\n");
	printf("  -p, --sync-period [period]          set synchronization period, in seconds\n");
	printf("                                      fractional seconds are supported (i.e. 0.2 = 5 Hz)\n");
	printf("  -4 [group-address]                  specify IPv4 multicast address and operate in IPv4 mode");
	printf("\n");
	printf("  -u, --unix-path [path]              path to unix socket used for client-server\n");
	printf("                                      communication (default: \""ALFRED_SOCK_PATH_DEFAULT"\")\n");
	printf("  -c, --update-command                command to call on data change\n");
	printf("  -v, --version                       print the version\n");
	printf("  -h, --help                          this help\n");
	printf("\n");
}

static int reduce_capabilities(void)
{
	int ret = 0;

#ifdef CONFIG_ALFRED_CAPABILITIES
	cap_t cap_cur;
	cap_t cap_new;
	cap_flag_value_t cap_flag;
	cap_value_t cap_net_raw = CAP_NET_RAW;
	cap_value_t cap_net_admin = CAP_NET_ADMIN;

	/* get current process capabilities */
	cap_cur = cap_get_proc();
	if (!cap_cur) {
		perror("cap_get_proc");
		return -1;
	}

	/* create new capabilities */
	cap_new = cap_init();
	if (!cap_new) {
		perror("cap_init");
		cap_free(cap_new);
		return -1;
	}

	/* copy capability as non-effictive but permitted */
	cap_flag = CAP_CLEAR;
	cap_get_flag(cap_cur, CAP_NET_RAW, CAP_PERMITTED, &cap_flag);
	if (cap_flag != CAP_CLEAR) {
		ret = cap_set_flag(cap_new, CAP_PERMITTED, 1, &cap_net_raw,
				   CAP_SET);
		if (ret < 0) {
			perror("cap_set_flag");
			goto out;
		}
	}

	cap_flag = CAP_CLEAR;
	cap_get_flag(cap_cur, CAP_NET_ADMIN, CAP_PERMITTED, &cap_flag);
	if (cap_flag != CAP_CLEAR) {
		ret = cap_set_flag(cap_new, CAP_PERMITTED, 1, &cap_net_admin,
				   CAP_SET);
		if (ret < 0) {
			perror("cap_set_flag");
			goto out;
		}
	}

	/* set minimal capabilities field */
	ret = cap_set_proc(cap_new);
	if (ret < 0) {
		perror("cap_set_proc");
		goto out;
	}

	/* don't drop capabilities with setuid */
	ret = prctl(PR_SET_KEEPCAPS, 1);
	if (ret < 0) {
		perror("prctl PR_SET_KEEPCAPS(1)");
		goto out;
	}

	/* drop euid */
	ret = setuid(getuid());
	if (ret < 0) {
		perror("setuid");
		goto out;
	}

	/* drop capabilities with setuid */
	ret = prctl(PR_SET_KEEPCAPS, 0);
	if (ret < 0) {
		perror("prctl PR_SET_KEEPCAPS(0)");
		goto out;
	}

out:
	cap_free(cap_new);
	cap_free(cap_cur);
#endif

	return ret;
}

static struct globals *alfred_init(int argc, char *argv[])
{
	int opt, opt_ind, i, ret;
	double sync_period = 0.0;
	struct globals *globals;
	struct option long_options[] = {
		{"set-data",		required_argument,	NULL,	's'},
		{"request",		required_argument,	NULL,	'r'},
		{"interface",		required_argument,	NULL,	'i'},
		{"master",		no_argument,		NULL,	'm'},
		{"help",		no_argument,		NULL,	'h'},
		{"req-version",		required_argument,	NULL,	'V'},
		{"modeswitch",		required_argument,	NULL,	'M'},
		{"change-interface",	required_argument,	NULL,	'I'},
		{"unix-path",		required_argument,	NULL,	'u'},
		{"update-command",	required_argument,	NULL,	'c'},
		{"version",		no_argument,		NULL,	'v'},
		{"verbose",		no_argument,		NULL,	'd'},
		{"sync-period",		required_argument,	NULL,	'p'},
		{NULL,			0,			NULL,	0},
	};

	/* We need full capabilities to mount debugfs, so do that now */
	debugfs_mount(NULL);

	ret = reduce_capabilities();
	if (ret < 0)
		return NULL;

	globals = &alfred_globals;
	memset(globals, 0, sizeof(*globals));

	INIT_LIST_HEAD(&globals->interfaces);
	globals->change_interface = NULL;
	globals->opmode = OPMODE_SLAVE;
	globals->clientmode = CLIENT_NONE;
	globals->best_server = NULL;
	globals->clientmode_version = 0;
	globals->mesh_iface = "bat0";
	globals->unix_path = ALFRED_SOCK_PATH_DEFAULT;
	globals->verbose = 0;
	globals->ipv4mode = 0;
	globals->update_command = NULL;
	globals->sync_period.tv_sec = ALFRED_INTERVAL;
	globals->sync_period.tv_nsec = 0;
	INIT_LIST_HEAD(&globals->changed_data_types);
	globals->changed_data_type_count = 0;

	time_random_seed();

	while ((opt = getopt_long(argc, argv, "ms:r:hi:b:vV:M:I:u:dc:p:4:", long_options,
				  &opt_ind)) != -1) {
		switch (opt) {
		case 'r':
			globals->clientmode = CLIENT_REQUEST_DATA;
			i = atoi(optarg);
			if (i < ALFRED_MAX_RESERVED_TYPE ||
			    i >= ALFRED_NUM_TYPES) {
				fprintf(stderr, "bad data type argument\n");
				return NULL;
			}
			globals->clientmode_arg = i;

			break;
		case 's':
			globals->clientmode = CLIENT_SET_DATA;
			i = atoi(optarg);
			if (i < ALFRED_MAX_RESERVED_TYPE ||
			    i >= ALFRED_NUM_TYPES) {
				fprintf(stderr, "bad data type argument\n");
				return NULL;
			}
			globals->clientmode_arg = i;
			break;
		case 'm':
			globals->opmode = OPMODE_MASTER;
			break;
		case 'i':
			netsock_set_interfaces(globals, optarg);
			break;
		case 'b':
			globals->mesh_iface = strdup(optarg);
			break;
		case 'V':
			i = atoi(optarg);
			if (i < 0 || i > 255) {
				fprintf(stderr, "bad data version argument\n");
				return NULL;
			}
			globals->clientmode_version = atoi(optarg);
			break;
		case 'M':
			if (strcmp(optarg, "master") == 0) {
				globals->opmode = OPMODE_MASTER;
			} else if (strcmp(optarg, "slave") == 0) {
				globals->opmode = OPMODE_SLAVE;
			} else {
				fprintf(stderr, "bad modeswitch argument\n");
				return NULL;
			}
			globals->clientmode = CLIENT_MODESWITCH;
			break;
		case 'I':
			globals->clientmode = CLIENT_CHANGE_INTERFACE;
			globals->change_interface = strdup(optarg);
			break;
		case 'u':
			globals->unix_path = optarg;
			break;
		case 'd':
			globals->verbose++;
			break;
		case 'c':
			globals->update_command = optarg;
			break;
		case 'v':
			printf("%s %s\n", argv[0], SOURCE_VERSION);
			printf("A.L.F.R.E.D. - Almighty Lightweight Remote Fact Exchange Daemon\n");
			return NULL;
		case 'p':
			sync_period = strtod(optarg, NULL);
			globals->sync_period.tv_sec = (int)sync_period;
			globals->sync_period.tv_nsec = (double)(sync_period - (int)sync_period) * 1e9;
			printf(" ** Setting sync interval to: %.9f seconds (%ld.%09ld)\n", sync_period, globals->sync_period.tv_sec, globals->sync_period.tv_nsec);
			break;
		case '4':
			globals->ipv4mode = 1;
			inet_pton(AF_INET, optarg, &alfred_mcast.ipv4);
			printf(" ** IPv4 Multicast Mode: %x\n", alfred_mcast.ipv4.s_addr);
			break;
		case 'h':
		default:
			alfred_usage();
			return NULL;
		}
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
		perror("could not register SIGPIPE handler");
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR)
		perror("could not register SIGCHLD handler");
	return globals;
}

int main(int argc, char *argv[])
{
	struct globals *globals;

	globals = alfred_init(argc, argv);

	if (!globals)
		return 1;

	switch (globals->clientmode) {
	case CLIENT_NONE:
		return alfred_server(globals);
	case CLIENT_REQUEST_DATA:
		return alfred_client_request_data(globals);
	case CLIENT_SET_DATA:
		return alfred_client_set_data(globals);
	case CLIENT_MODESWITCH:
		return alfred_client_modeswitch(globals);
	case CLIENT_CHANGE_INTERFACE:
		return alfred_client_change_interface(globals);
	}

	return 0;
}
