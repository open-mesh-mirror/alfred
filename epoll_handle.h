// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Sven Eckelmann
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef _ALFRED_EPOLL_HANDLE_H
#define _ALFRED_EPOLL_HANDLE_H

#include <sys/epoll.h>

struct globals;
struct epoll_handle;

typedef void (*epoll_handler)(struct globals *globals,
			      struct epoll_handle *handle,
			      struct epoll_event *ev);

struct epoll_handle {
	epoll_handler handler;
};

#endif /* _ALFRED_EPOLL_HANDLE_H */
