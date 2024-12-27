.. SPDX-License-Identifier: GPL-2.0

==============================================================
A.L.F.R.E.D - Almighty Lightweight Fact Remote Exchange Daemon
==============================================================

    "alfred is a user space daemon to efficiently[tm] flood the network with
    useless data - like vis, weather data, network notes, etc"

    - Marek Lindner, 2012


Introduction
============

alfred is a user space daemon for distributing arbitrary local information over
the mesh/network in a decentralized fashion. This data can be anything which
appears to be useful - originally designed to replace the batman-adv
visualization (vis), you may distribute hostnames, phone books, administration
information, DNS information, the local weather forecast ...

alfred runs as daemon in the background of the system. A user may insert
information by using the alfred binary on the command line, or use special
programs to communicate with alfred (done via unix sockets). alfred then takes
care of distributing the local information to other alfred servers on other
nodes. This is done via IPv6 link-local multicast, and does not require any
configuration. A user can request data from alfred, and will receive the
information available from all alfred servers in the network. Alternatively,
alfred can be configured to distribute the local information via IPv4 multicast.
This is configured by setting the IPv4 multicast group address in the -4 option.


Compilation
===========

alfred depends on:

* librt (usually part of libc)
* IPv6 support in the kernel/host system
* libnl-3 - support for netlink sockets
* libnl-3-genl - support for generic netlink messages

and optionally:

* libgps - if you want to distribute GPS information
* libcap - if you want extra security by dropping unneeded privileges

To compile alfred, simply type::

  $ make

This will compile alfred, batadv-vis & alfred-gpsd. To install, use::

  $ make install

(with the right privileges).

If you don't want to compile batadv-vis, add the directive CONFIG_ALFRED_VIS=n::

  $ make CONFIG_ALFRED_VIS=n
  $ make CONFIG_ALFRED_VIS=n install

If you don't want to compile alfred-gpsd, add the directive
CONFIG_ALFRED_GPSD=n::

  $ make CONFIG_ALFRED_GPSD=n
  $ make CONFIG_ALFRED_GPSD=n install

If don't want to compile with libcap to drop privileges, use::

  $ make CONFIG_ALFRED_CAPABILITIES=n
  $ make CONFIG_ALFRED_CAPABILITIES=n install


Usage
=====

First, alfred must run as daemon (server) in background to be used. This can
either be done by some init-scripts from your distribution (if you have
received alfred as a package with your distribution). Please see their
documentation how to configure alfred in this case. In any event, you can
still run alfred from the command line. The relevant options are (for a full
list of options, run alfred -h):

  -i, --interface             specify the interface to listen on. use 'none'
                              to disable interface operations
  -b                          specify the batman-adv interface configured on
                              the system (default: bat0). use 'none' to disable
                              the batman-adv based best server selection
  -m, --primary               start up the daemon in primary mode, which
                              accepts data from secondaries and syncs it with
                              other primaries

The interface option '-i' is optional. If interface 'none' is specified, the
alfred daemon will not communicate with other alfred instances on the
network unless the interface list is modified at runtime via the unix socket.
The -b option is optional, and only needed if you run alfred on a batman-adv
interface not called bat0, or if you don't use batman-adv at all
(use '-b none'). In this case, alfred will still work but will not be able to
find the best next primary server based on metrics.

alfred servers may either run as primary or secondary in the network. Primaries
will announce their status via broadcast, so that secondaries can find them.
Secondaries will then send their data to their nearest primary (based on TQ).
Primaries will exchange their data (which they have received from secondaries or
got on their own) with other primaries. By using primaries and secondaries,
overhead can be reduced while still keeping redundancy (by having multiple
primaries). Obviously, at least one primary must be present in the network to
let any data exchange happen. Also having all nodes in primary mode is possible
(for maximum decentrality and overhead).

To put it together, let us start alfred in primary mode on our bridge br0
(assuming that this bridge includes the batman interface bat0)::

  $ alfred -i br0 -m

Now that the server is running, let us input some data. This can be done by
using the alfred binary in client mode from the command line::

  $ cat /etc/hostname | alfred -s 64

This will set the hostname as data for datatype 64. Note that 0 - 63 are
reserved (please send us an e-mail if you want to register a datatype), and can
not be used on the commandline. We skipped the version parameter allowing you
to assign a version to your data which can be filtered by other alfred users.
Skipping the parameter entirely has the same effect as setting the parameter
to 0 ('-V 0').

After the hostname has been set on a few alfred hosts, the can be retrieved
again::

  $ alfred -r 64
  { "fe:f1:00:00:01:01", "OpenWRT-node-1\x0a" },
  { "fe:f1:00:00:02:01", "OpenWRT-node-2\x0a" },
  { "fe:f1:00:00:03:01", "OpenWRT-node-3\x0a" },

Note that the information must be periodically written again to alfred, otherwise
it will timeout and alfred will forget about it (after 10 minutes).

One final remark on terminology: If we talk about "servers" and "clients" in
alfred, we mean the local processes on one machine which talk to each other via
unix sockets (client connects and talks to servers). On the other hand, "secondaries"
and "primaries" are the roles alfred can take over in the network between different
machines (secondaries send information to primaries).


Vis
===

batadv-vis can be used to visualize your batman-adv mesh network. It read the
neighbor information and local client table and distributes this information via
alfred in the network. By gathering this local information, any vis node can get
the whole picture of the network.

batadv-vis, similar to to alfred, combines server (daemon) and client
functionality in the 'batadv-vis' binary. The batadv-vis server must be started
to let batadv-vis work::

  $ batadv-vis -i bat0 -s

This server will read the neighbor and client information from batman-adv every
10 seconds and set it in alfred via unix socket. Obviously, the alfred server
must run too to get this information set.

To get a graphviz-compatible vis output, simply type::

  $ batadv-vis
  digraph {
          subgraph "cluster_fe:f0:00:00:04:01" {
                  "fe:f0:00:00:04:01"
          }
          "fe:f0:00:00:04:01" -> "fe:f0:00:00:05:01" [label="1.000"]
          "fe:f0:00:00:04:01" -> "fe:f0:00:00:03:01" [label="1.004"]
          "fe:f0:00:00:04:01" -> "00:00:43:05:00:04" [label="TT"]
          "fe:f0:00:00:04:01" -> "fe:f1:00:00:04:01" [label="TT"]
          subgraph "cluster_fe:f0:00:00:02:01" {
                  "fe:f0:00:00:02:01"
          }
          "fe:f0:00:00:02:01" -> "fe:f0:00:00:03:01" [label="1.000"]
          "fe:f0:00:00:02:01" -> "fe:f0:00:00:01:01" [label="1.008"]
          "fe:f0:00:00:02:01" -> "fe:f0:00:00:08:01" [label="1.000"]
          "fe:f0:00:00:02:01" -> "fe:f1:00:00:02:01" [label="TT"]
          "fe:f0:00:00:02:01" -> "00:00:43:05:00:02" [label="TT"]
          subgraph "cluster_fe:f0:00:00:08:01" {
                  "fe:f0:00:00:08:01"
          }
  [...]
  }

For a json line formatted output, use::

  $ batadv-vis -f json
  { "primary" : "fe:f0:00:00:04:01" }
  { "router" : "fe:f0:00:00:04:01", "neighbor" : "fe:f0:00:00:05:01", "label" : "1.000" }
  { "router" : "fe:f0:00:00:04:01", "neighbor" : "fe:f0:00:00:03:01", "label" : "1.008" }
  { "router" : "fe:f0:00:00:04:01", "gateway" : "00:00:43:05:00:04", "label" : "TT" }
  { "router" : "fe:f0:00:00:04:01", "gateway" : "fe:f1:00:00:04:01", "label" : "TT" }
  { "primary" : "fe:f0:00:00:02:01" }
  { "router" : "fe:f0:00:00:02:01", "neighbor" : "fe:f0:00:00:03:01", "label" : "1.000" }
  { "router" : "fe:f0:00:00:02:01", "neighbor" : "fe:f0:00:00:01:01", "label" : "1.016" }
  { "router" : "fe:f0:00:00:02:01", "neighbor" : "fe:f0:00:00:08:01", "label" : "1.000" }
  { "router" : "fe:f0:00:00:02:01", "gateway" : "fe:f1:00:00:02:01", "label" : "TT" }
  { "router" : "fe:f0:00:00:02:01", "gateway" : "00:00:43:05:00:02", "label" : "TT" }
  { "primary" : "fe:f0:00:00:08:01" }
  [...]

and for output where the complete document is json, use::

  $ batadv-vis -f jsondoc
  {
    "source_version" : "2013.3.0-14-gcd34783",
    "algorithm" : 4,
    "vis" : [
      { "primary" : "fe:f0:00:00:04:01",
        "neighbors" : [
           { "router" : "fe:f0:00:00:04:01",
             "neighbor" : "fe:f0:00:00:05:01",
             "metric" : "1.000" },
           { "router" : "fe:f0:00:00:04:01",
             "neighbor" : "fe:f0:00:00:03:01",
             "metric" : "1.008" }
        ],
        "clients" : [
           "00:00:43:05:00:04",
           "fe:f1:00:00:04:01"
        ]
      },
      { "primary" : "fe:f0:00:00:02:01",
        "neighbors" : [
           { "router" : "fe:f0:00:00:02:01",
             "neighbor" : "fe:f0:00:00:03:01",
             "metric" : "1.000" },
           { "router" : "fe:f0:00:00:02:01",
             "neighbor" : "fe:f0:00:00:01:01",
             "metric" : "1.016" },
           { "router" : "fe:f0:00:00:02:01",
             "neighbor" : "fe:f0:00:00:08:01",
             "metric" : "1.000" }
        ],
        "clients" : [
          "fe:f1:00:00:02:01",
          "00:00:43:05:00:02"
        ]
      },
      { "primary" : "fe:f0:00:00:08:01",
  [...]


Alfred-gpsd
===========

Alfred-gpsd can be used to distibute GPS location information about
your batman-adv mesh network. This information could be, for example,
combined with Vis to visualize your mesh topology with true geographic
layout. For mobile or nomadic nodes, Alfred-gpsd, can get location
information from gpsd.  Alternatively, a static location can be passed
on the command line, which is useful for static nodes without a GPS.

Alfred-gpsd, similar to to alfred, combines server (daemon) and client
functionality in the 'alfred-gpsd' binary. The alfred-gpsd server must
be started to distribute location information. When retrieving
location information from gpsd, it should be started with::

  $ alfred-gpsd -s

For a static location, use::

  $ alfred-gpsd -s -l 48.858222,2.2945,358

This server will set the location in alfred via unix
socket. Obviously, the alfred server must run too to get this
information set. When using gpsd, it updates alfred every 2
seconds. With a static location, the update it made every 5 minutes.

To get JSON formatted output, use::

  $ alfred-gpsd
  [
    { "source" : "f6:00:48:13:d3:1e", "tpv" : {"class":"TPV","tag":"RMC","device":"/dev/ttyACM0","mode":3,"time":"2013-10-01T10:43:20.000Z","ept":0.005,"lat":52.575485000,"lon":-1.339716667,"alt":122.500,"epx":10.199,"epy":15.720,"epv":31.050,"track":0.0000,"speed":0.010,"climb":0.000,"eps":31.44} },
    { "source" : "8e:4c:77:b3:65:b4", "tpv" : {"class":"TPV","device":"command line","time":"2013-10-01T10:43:05.129Z","lat":48.858222,"lon":2.2945,"alt":358.000000,"mode":3} }
  ]

See gpsd_json(5) for documentation of the tpv object.


Running alfred as non-root user
===============================

Alfred currently requires special capabilities and access rights to work
correctly. The user root is normally the only user having these
capabilities/rights on a standard Linux system.

Operations requiring special capabilities:

* bind to device
* creating the unix socket
* accessing the netlink interface

The first operation can still be executed when the admin grants the special
capability CAP_NET_RAW+CAP_NET_ADMIN to anyone executing the alfred binary.
The unix socket can also be moved using the parameter '-u' to a different
directory which can be accessed by the user::

  $ sudo setcap cap_net_admin,cap_net_raw+ep alfred
  $ ./alfred -u alfred.sock -i eth0


License
=======

alfred, batadv-vis and alfred-gpsd are licensed under the terms of version 2
of the GNU General Public License (GPL). Please see the LICENSE file.

The file "packet.h" is an exception and not licensed with the GPL. Instead,
it is licensed using ISC license (see the head of this file). This allows
programs to include this header file (e.g. for communicating with alfred via
unix sockets) without enforcing the restrions of the GPL license on this third
party program.


Contact
=======

As alfred was developed to help on batman-adv, we share communication channels.
Please send us comments, experiences, questions, anything :)

IRC:
  #batadv on ircs://irc.hackint.org/
Mailing-list:
  b.a.t.m.a.n@lists.open-mesh.org (optional subscription at
  https://lists.open-mesh.org/mailman3/postorius/lists/b.a.t.m.a.n.lists.open-mesh.org/)

If you have test reports/patches/ideas, please read the wiki for further
instruction on how to contribute:

https://www.open-mesh.org/projects/open-mesh/wiki/Contribute

You can also contact the Authors:

* Marek Lindner <marek.lindner@mailbox.org>
* Simon Wunderlich <sw@simonwunderlich.de>
