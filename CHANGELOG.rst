.. SPDX-License-Identifier: GPL-2.0

2021.0 (2021-01-28)
===================

* Drop support for batman-adv's sysfs+debugfs

2020.4 (2020-10-27)
===================

* (no changes)

2020.3 (2020-08-24)
===================

* synchronization of batman-adv netlink header

2020.2 (2020-07-06)
===================

* Rephrase names of server roles

2020.1 (2020-04-24)
===================

* (no changes)

2020.0 (2020-03-04)
===================

* fix build against gpsd API 9.0

2019.5 (2019-12-12)
===================

* (no changes)

2019.4 (2019-10-25)
===================

* fix build with musl

2019.3 (2019-08-01)
===================

* avoid some kernel deprecation warning by using more generic netlink over
  sysfs

2019.2 (2019-05-23)
===================

* synchronization of batman-adv netlink header

2019.1 (2019-03-28)
===================

* synchronization of batman-adv netlink header

2019.0 (2019-02-01)
===================

* (no changes)

2018.4 (2018-11-14)
===================

* bugs squashed:

  - fixed detection of own IPv4 packets
  - use manual IPv4 ARP requests to retrieve MAC of neighbors

2018.3 (2018-09-14)
===================

* (no changes)


2018.2 (2018-07-10)
===================

* (no changes)

2018.1 (2018-04-25)
===================

* synchronization of batman-adv netlink header

2018.0 (2018-02-26)
===================

* synchronization of batman-adv netlink and packet headers
* mark licenses clearer, change batman-adv UAPI header from ISC to MIT
* coding style cleanups and refactoring

2017.4 (2017-12-05)
===================

* synchronization of batman-adv netlink header
* coding style cleanups and refactoring
* documentation cleanup
* bugs squashed:

  - only query debugfs when netlink failed
  - handle allocation errors in hashtable iterator


2017.3 (2017-09-28)
===================

* reduction of memory usage when using --update-command


2017.2 (2017-07-28)
===================

* reduce cpu load when rating multiple primary servers
* coding style cleanups and refactoring


2017.1 (2017-05-23)
===================

* (no changes)


2017.0 (2017-02-28)
===================

* support IPv4 multicast distribution
* coding style cleanups


2016.5 (2016-12-15)
===================

* support interface validity checks on systems without debugfs
* remove debugfs check during batadv-vis startup
* allow out-of-order txend packets during transmissions


2016.4 2016-10-27)
===================

* add expert option to specify sync interval
* fix various bugs in batadv-vis netlink integration
* fix build build problems with libnl-tiny


2016.3 (2016-09-01)
===================

* integrate support for batman-adv netlink


2016.2 (2016-06-09)
===================

* add support for automatic debugfs mount with enabled
  CONFIG_ALFRED_CAPABILITIES


2016.1 (2016-04-21)
===================

* add support for primary servers to receive push_data packets with foreign
  source addresses
* various code cleanups
* bugs squashed:

  - ignore invalid EUI64 addresses


2016.0 (2016-01-19)
===================

* various code and documentation cleanups


2015.2 (2015-11-23)
===================

* mention libcap in the README
* Fix typos


2015.1 (2015-08-04)
===================

* add support to run on interfaces with multiple link-local addresses
* various code cleanups
* bugs squashed:

  - reduce of maximum payload size to always fit into UDP datagrams


2015.0 (2015-04-28)
===================

* add support to call commands after data was updated
* automatic reduction of process capabilities when not needed anymore
* allow printing of the data version number in the alfred client mode
* various code cleanups
* bugs squashed:

  - update of the version number when data was updated with different
    version number
  - tighten size check on received packet


2014.4.0 (2014-12-31)
=====================

* add support for multiple interfaces per primary
* add support for changing interfaces on the fly
* changes to support multiple alfred interfaces:

  - bind alfred to a specific interface
  - allow configuring the unix socket path

* enhanced debugging


2014.3.0 (2014-07-21)
=====================

* fix various possible memleak, access errors and strncpy issues
* handle fcntl return codes
* fix altitude verification check in gpsd


2014.2.0 (2014-05-15)
=====================

* Handle EPERM errors on every sendto
* Check for changed interface properties, e.g. recreation or
  changed MAC- and IPv6 addresses


2014.1.0 (2014-03-13)
=====================

* don't leak socket fd in batadv-vis


2014.0.0 (2014-01-04)
=====================

* add installation of the alfred-gpsd manpage
* add -lm to linker flags for libgps in alfred-gpsd


2013.4.0 (2013-10-13)
=====================

* add new json output format for vis
* add gps location information service for alfred
* allow network interface to vanish and return without restart
* allow to switch between primary and secondary operation without restart
* renamed vis to batadv-vis to avoid collisions with other vis binaries
* add manpages
* various code cleanups
* bugs squashed:

  - handle failing write() in unix sockets
  - Fix crash when vis opened empty file


2013.3.0 (2013-07-28)
=====================

* initial release of alfred after beta (synced release cycle with
  batman-adv)
* allows to share arbitrary local information over a (mesh) network
* initial support for vis (previously in-kernel feature of batman-adv
  to visualize the network) included
* easy but flexible communication interface to allow data applications
  of all kinds
* two-tiered architecture (primary and secondaries)
* exchanges data via IPv6 unicast/multicast
