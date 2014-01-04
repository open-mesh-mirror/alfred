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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include "alfred.h"

int time_diff(struct timespec *tv1, struct timespec *tv2,
	      struct timespec *tvdiff) {
	tvdiff->tv_sec = tv1->tv_sec - tv2->tv_sec;
	if (tv1->tv_nsec < tv2->tv_nsec) {
		tvdiff->tv_nsec = 1000000000 + tv1->tv_nsec - tv2->tv_nsec;
		tvdiff->tv_sec -= 1;
	} else {
		tvdiff->tv_nsec = tv1->tv_nsec - tv2->tv_nsec;
	}

	return (tvdiff->tv_sec >= 0);
}

void time_random_seed(void)
{
	struct timespec now;
	uint8_t *c = (uint8_t *)&now;
	size_t i;
	unsigned int s = 0;

	clock_gettime(CLOCK_REALTIME, &now);

	for (i = 0; i < sizeof(now); i++) {
		s *= 127u;
		s += c[i];
	}

	srand(s);
}

uint16_t get_random_id(void)
{
	return random();
}
