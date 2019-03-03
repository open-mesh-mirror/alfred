// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009 Clark Williams <williams@redhat.com>
 * Copyright (C) 2009 Xiao Guangrong <xiaoguangrong@cn.fujitsu.com>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#include "debugfs.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#ifndef DEBUGFS_MAGIC
#define DEBUGFS_MAGIC          0x64626720
#endif

static int debugfs_premounted;
static char debugfs_mountpoint[MAX_PATH+1];

static const char *debugfs_find_mountpoint(void);
static int debugfs_valid_mountpoint(const char *debugfs);

static const char *debugfs_known_mountpoints[] = {
	"/sys/kernel/debug/",
	"/debug/",
	NULL,
};

/* construct a full path to a debugfs element */
int debugfs_make_path(const char *fmt, const char *mesh_iface, char *buffer,
		      int size)
{
	if (strlen(debugfs_mountpoint) == 0) {
		buffer[0] = '\0';
		return -1;
	}

	return snprintf(buffer, size, fmt, debugfs_mountpoint, mesh_iface);
}

static int debugfs_found;

/* find the path to the mounted debugfs */
static const char *debugfs_find_mountpoint(void)
{
	const char **ptr;
	char type[100];
	FILE *fp;

	if (debugfs_found)
		return (const char *)debugfs_mountpoint;

	ptr = debugfs_known_mountpoints;
	while (*ptr) {
		if (debugfs_valid_mountpoint(*ptr) == 0) {
			debugfs_found = 1;
			strncpy(debugfs_mountpoint, *ptr,
				sizeof(debugfs_mountpoint));
			debugfs_mountpoint[sizeof(debugfs_mountpoint) - 1] = 0;
			return debugfs_mountpoint;
		}
		ptr++;
	}

	/* give up and parse /proc/mounts */
	fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		perror("Error - can't open /proc/mounts for read");
		return NULL;
	}

	while (fscanf(fp, "%*s %"
		      STR(MAX_PATH)
		      "s %99s %*s %*d %*d\n",
		      debugfs_mountpoint, type) == 2) {
		if (strcmp(type, "debugfs") == 0)
			break;
	}
	fclose(fp);

	if (strcmp(type, "debugfs") != 0)
		return NULL;

	debugfs_found = 1;

	return debugfs_mountpoint;
}

/* verify that a mountpoint is actually a debugfs instance */

static int debugfs_valid_mountpoint(const char *debugfs)
{
	struct statfs st_fs;

	if (statfs(debugfs, &st_fs) < 0)
		return -ENOENT;
	else if (st_fs.f_type != (long) DEBUGFS_MAGIC)
		return -ENOENT;

	return 0;
}


int debugfs_valid_entry(const char *path)
{
	struct stat st;

	if (stat(path, &st))
		return -errno;

	return 0;
}

/* mount the debugfs somewhere if it's not mounted */

char *debugfs_mount(const char *mountpoint)
{
	/* see if it's already mounted */
	if (debugfs_find_mountpoint()) {
		debugfs_premounted = 1;
		return debugfs_mountpoint;
	}

	/* if not mounted and no argument */
	if (mountpoint == NULL)
		mountpoint = "/sys/kernel/debug";

	if (mount(NULL, mountpoint, "debugfs", 0, NULL) < 0)
		return NULL;

	/* save the mountpoint */
	strncpy(debugfs_mountpoint, mountpoint, sizeof(debugfs_mountpoint));
	debugfs_mountpoint[sizeof(debugfs_mountpoint) - 1] = '\0';
	debugfs_found = 1;

	return debugfs_mountpoint;
}
