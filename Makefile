#!/usr/bin/make -f
# -*- makefile -*-
#
# Copyright (C) 2012-2014 B.A.T.M.A.N. contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#

# alfred build
BINARY_NAME = alfred
OBJ = main.o server.o client.o netsock.o send.o recv.o hash.o unix_sock.o util.o debugfs.o batadv_query.o
MANPAGE = man/alfred.8

# alfred flags and options
CFLAGS += -pedantic -Wall -W -std=gnu99 -fno-strict-aliasing -MD -MP
LDLIBS += -lrt

# disable verbose output
ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

# standard build tools
CC ?= gcc
RM ?= rm -f
INSTALL ?= install
MKDIR ?= mkdir -p
COMPILE.c = $(Q_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(Q_LD)$(CC) $(CFLAGS) $(LDFLAGS) $(TARGET_ARCH)

# standard install paths
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man

# try to generate revision
REVISION= $(shell	if [ -d .git ]; then \
				echo $$(git describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
ifneq ($(REVISION),)
CPPFLAGS += -DSOURCE_VERSION=\"$(REVISION)\"
endif

ifneq ($(CONFIG_ALFRED_VIS),n)
	VIS_ALL=vis-all
	VIS_CLEAN=vis-clean
	VIS_INSTALL=vis-install
endif

ifneq ($(CONFIG_ALFRED_GPSD),n)
	GPSD_ALL=gpsd-all
	GPSD_CLEAN=gpsd-clean
	GPSD_INSTALL=gpsd-install
endif


# default target
all: $(BINARY_NAME) $(VIS_ALL) $(GPSD_ALL)

# standard build rules
.SUFFIXES: .o .c
.c.o:
	$(COMPILE.c) -o $@ $<

$(BINARY_NAME): $(OBJ)
	$(LINK.o) $^ $(LDLIBS) -o $@

clean:	$(VIS_CLEAN) $(GPSD_CLEAN)
	$(RM) $(BINARY_NAME) $(OBJ) $(DEP)

install: $(BINARY_NAME) $(VIS_INSTALL) $(GPSD_INSTALL)
	$(MKDIR) $(DESTDIR)$(SBINDIR)
	$(MKDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 0755 $(BINARY_NAME) $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0644 $(MANPAGE) $(DESTDIR)$(MANDIR)/man8

vis-install:
	$(MAKE) -C vis install

vis-all:
	$(MAKE) -C vis all

vis-clean:
	$(MAKE) -C vis clean

gpsd-install:
	$(MAKE) -C gpsd install

gpsd-all:
	$(MAKE) -C gpsd all

gpsd-clean:
	$(MAKE) -C gpsd clean

# load dependencies
DEP = $(OBJ:.o=.d)
-include $(DEP)

.PHONY: all clean install vis-install vis-all vis-clean \
	gpsd-install gpsd-all gpsd-clean
