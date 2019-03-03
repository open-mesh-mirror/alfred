/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2009 Clark Williams <williams@redhat.com>
 * Copyright (C) 2009 Xiao Guangrong <xiaoguangrong@cn.fujitsu.com>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef __DEBUGFS_H__
#define __DEBUGFS_H__

#ifndef MAX_PATH
# define MAX_PATH 256
#endif

#ifndef STR
# define _STR(x) #x
# define STR(x) _STR(x)
#endif

extern int debugfs_valid_entry(const char *path);
extern char *debugfs_mount(const char *mountpoint);
extern int debugfs_make_path(const char *fmt, const char *mesh_iface,
			     char *buffer, int size);

#endif /* __DEBUGFS_H__ */
