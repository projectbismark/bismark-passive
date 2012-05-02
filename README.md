BISMark Passive
===============

This software passively monitors network traffic on OpenWRT routers and
periodically sends small anonymized updates to a central server for analysis.
Doing so will enable researchers to better understand how people use home
networks.

See the file `PRIVACY` for a detailed explanation of the information collected
by BISmark Passive and how we will use that information.

Installation instructions
-------------------------

1. Follow instructions at `dp4:/data/users/bismark/openwrt/src/instructions.txt` to
prepare a build tree.
2. From the OpenWRT build directory:
    - `scripts/feeds install bismark-passive-git`
    - `make package/bismark-passive-git/compile`
3. Copy `bin/ar71xx/packages/bismark-passive-git_*.ipk` to an OpenWRT router.
4. `opkg install bismark-passive-git_*.ipk`

Build options
-------------

Use `make menuconfig` to configure build parameters.

Operation instructions
----------------------

Usage: `bismark-passive`

It dumps into `/tmp/bismark-passive/updates/<machine id>-<session id>-<sequence_number>.gz`
every 30 seconds, where sequence\_number is an integer incrementing from 0.

File format for differential updates
------------------------------------

Bismark-passive periodically generates differential updates about the traffic it
has observed since the last update. Updates are gzipped text files with the
following format:

    [file format version]
    [bismark-passive build id]
    [bismark ID] [timestamp at process creation in microseconds] [sequence number] [current timestamp in seconds]
    [(optional) total packets received by pcap] [(optional) total packets dropped by pcap] [(optional) total packets dropped by interface]
    
    [whitelisted domain (only when sequence number is 0)]
    [whitelisted domain (only when sequence number is 0)]
    ...
    [whitelisted domain (only when sequence number is 0)]

    [hash of anonymization key, or "UNANONYMIZED" if not anonymized]
    
    [timestamp of first packet in microseconds] [packets dropped]
    [microseconds offset from previous packet] [packet size bytes] [flow id (see notes)]
    [microseconds offset from previous packet] [packet size bytes] [flow id (see notes)]
    ...
    [microseconds offset from previous packet] [packet size bytes] [flow id (see notes)]
    
    [baseline timestamp in seconds] [num elements in flow table] [total expired flows] [total dropped flows]
    [flow id] [anonymized source?] [(hashed) source IP address] [anonymized destination?] [(hashed) destination IP address] [transport protocol] [source port] [destination port]
    [flow id] [anonymized source?] [(hashed) source IP address] [anonymized destination?] [(hashed) destination IP address] [transport protocol] [source port] [destination port]
    ...
    [flow id] [anonymized source?] [(hashed) source IP address] [anonymized destination?] [(hashed) destination IP address] [transport protocol] [source port] [destination port]
    
    [total dropped A records] [total dropped CNAME records]
    [packet id] [MAC id] [anonymized?] [(hashed) domain name for A record] [(hashed) ip address for A record] [ttl]
    [packet id] [MAC id] [anonymized?] [(hashed) domain name for A record] [(hashed) ip address for A record] [ttl]
    ...
    [packet id] [MAC id] [anonymized?] [(hashed) domain name for A record] [(hashed) ip address for A record] [ttl]
    
    [packet id] [MAC id] [domain anonymized?] [(hashed) domain name for CNAME record] [(optional) cname anonymized?] [(hashed) cname for CNAME record] [ttl]
    [packet id] [MAC id] [domain anonymized?] [(hashed) domain name for CNAME record] [(optional) cname anonymized?] [(hashed) cname for CNAME record] [ttl]
    ...
    [packet id] [MAC id] [domain anonymized?] [(hashed) domain name for CNAME record] [(optional) cname anonymized?] [(hashed) cname for CNAME record] [ttl]
    
    [address id of first address in list] [total size of address table]
    [MAC address with lower 24 bits hashed] [hashed IP address]
    [MAC address with lower 24 bits hashed] [hashed IP address]
    ...
    [MAC address with lower 24 bits hashed] [hashed IP address]

    [size of dropped packet] [number of packets dropped]
    [size of dropped packet] [number of packets dropped]
    ...
    [size of dropped packet] [number of packets dropped]

### Notes

1. (Version 2+) The first few flow IDs are reserved to denote non-IP network
protocols. See the `reserved_flow_indices` enum in `src/constants.h` for the
full list.
2. (Version 2+) Dropped packets support added in file format version 2.
3. (Version 3+) The optional "cnames anonymized?" was added in version 3. It allows cnames and domain names to be anonymized seprately.

Complexity of resource usage
----------------------------

Bismark Passive runs in a resource constrianed environment, so we care about
these performance metrics:

* **Per-packet computational complexity** is proportional to the number of hosts
  on the local network. For DNS packets, computation also depends on the length
  of the packet.
* **Per-update computational complexity** is proportional to the number of
  packets received since the last update, the number of new flows since the last
  update, the number of DNS responses since the last update, and the number of
  devices on the local network.
* **Memory utilization complexity** is proportional to the number of packets
  since the last update, the number of flows within a window (currently 9 hours,
  although inactive flows expire sooner), the number of DNS responses since the
  last update, and the number of hosts on the local network.
* **Network utilization complexity** per update is proportional to the number of
  packets since the last update, the number of new flows since the last update,
  the number of DNS responses since the last update, and the number of hosts on
  the local network.
