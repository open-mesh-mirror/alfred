#!/usr/bin/make -f
# -*- makefile -*-
#
# Copyright (C) 2012-2017  B.A.T.M.A.N. contributors
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
OBJ += batadv_query.o
OBJ += batadv_querynl.o
OBJ += client.o
OBJ += debugfs.o
OBJ += hash.o
OBJ += main.o
OBJ += netlink.o
OBJ += netsock.o
OBJ += recv.o
OBJ += send.o
OBJ += server.o
OBJ += unix_sock.o
OBJ += util.o
MANPAGE = man/alfred.8

# alfred flags and options
CFLAGS += -pedantic -Wall -W -std=gnu99 -fno-strict-aliasing -MD -MP
CPPFLAGS += -D_GNU_SOURCE
LDLIBS += -lrt

# Turn on alfred capability dropping by default - set this to n if you don't want/need it
export CONFIG_ALFRED_CAPABILITIES=y

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

ifeq ($(origin PKG_CONFIG), undefined)
  PKG_CONFIG = pkg-config
  ifeq ($(shell which $(PKG_CONFIG) 2>/dev/null),)
    $(error $(PKG_CONFIG) not found)
  endif
endif

ifeq ($(origin LIBNL_CFLAGS) $(origin LIBNL_LDLIBS), undefined undefined)
  LIBNL_NAME ?= libnl-3.0
  ifeq ($(shell $(PKG_CONFIG) --modversion $(LIBNL_NAME) 2>/dev/null),)
    $(error No $(LIBNL_NAME) development libraries found!)
  endif
  LIBNL_CFLAGS += $(shell $(PKG_CONFIG) --cflags $(LIBNL_NAME))
  LIBNL_LDLIBS +=  $(shell $(PKG_CONFIG) --libs $(LIBNL_NAME))
endif
CFLAGS += $(LIBNL_CFLAGS)
LDLIBS += $(LIBNL_LDLIBS)

ifeq ($(origin LIBNL_GENL_CFLAGS) $(origin LIBNL_GENL_LDLIBS), undefined undefined)
  LIBNL_GENL_NAME ?= libnl-genl-3.0
  ifeq ($(shell $(PKG_CONFIG) --modversion $(LIBNL_GENL_NAME) 2>/dev/null),)
    $(error No $(LIBNL_GENL_NAME) development libraries found!)
  endif
  LIBNL_GENL_CFLAGS += $(shell $(PKG_CONFIG) --cflags $(LIBNL_GENL_NAME))
  LIBNL_GENL_LDLIBS += $(shell $(PKG_CONFIG) --libs $(LIBNL_GENL_NAME))
endif
CFLAGS += $(LIBNL_GENL_CFLAGS)
LDLIBS += $(LIBNL_GENL_LDLIBS)

ifneq ($(CONFIG_ALFRED_CAPABILITIES),n)
  ifeq ($(origin LIBCAP_CFLAGS) $(origin LIBCAP_LDLIBS), undefined undefined)
    LIBCAP_NAME ?= libcap
    ifeq ($(shell $(PKG_CONFIG) --modversion $(LIBCAP_NAME) 2>/dev/null),)
      $(error No $(LIBCAP_NAME) development libraries found!)
    endif
    LIBCAP_CFLAGS += $(shell $(PKG_CONFIG) --cflags $(LIBCAP_NAME))
    LIBCAP_LDLIBS +=  $(shell $(PKG_CONFIG) --libs $(LIBCAP_NAME))
  endif
  CFLAGS += $(LIBCAP_CFLAGS)
  CPPFLAGS += -DCONFIG_ALFRED_CAPABILITIES
  LDLIBS += $(LIBCAP_LDLIBS)
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
