# Introduction

This plugin is a *temporary!* copy of VPP's src/plugins/linux-cp/ plugin,
originally by the following authors:
*   Signed-off-by: Neale Ranns <nranns@cisco.com>
*   Signed-off-by: Matthew Smith <mgsmith@netgate.com>
*   Signed-off-by: Jon Loeliger <jdl@netgate.com>
*   Signed-off-by: Pim van Pelt <pim@ipng.nl>
*   Signed-off-by: Neale Ranns <neale@graphiant.com>

See previous work:
*   [interface mirroring](https://gerrit.fd.io/r/c/vpp/+/30759)
*   [netlink listener](https://gerrit.fd.io/r/c/vpp/+/31122)

My work is intended to be re-submitted for review as a cleanup/rewrite of the
existing Linux CP interface mirror and netlink syncer. 

Follow along on [my blog](https://ipng.ch/s/articles/) for my findings while
I work towards a completed plugin that can copy VPP configuration into Linux
interfaces, and copy Linux configuration changes into VPP (ie. a fully
bidirectional pipe between Linux and VPP).

When the code is complete, this plugin should be able to work seamlessly with
a higher level controlplane like [FRR](https://frrouting.org/) or
[Bird](https://bird.network.cz/), for example as a BGP/OSPF speaking ISP router.

## WARNING!!

The only reason that this code is here, is so that I can make some progress
iterating on the Linux CP plugin, and share my findings with some interested
folks. The goal is NOT to use this plugin anywhere other than a bench. I
intend to contribute the plugin back upstream as soon as it's peer reviewed!

***Pull Requests and Issues will be immediately closed without warning***

VPP's code lives at [fd.io](https://gerrit.fd.io/r/c/vpp), and this copy is
shared only for convenience purposes.

## Functionality

The following functionality is supported by the plugin. The VPP->Linux column
shows changes in VPP that are copied into the Linux environment; Linux->VPP
column shows changes in LInux that are copied into VPP.

| Function       | VPP -> Linux  | Linux -> VPP |
| -------------- | ------------- | -------------|
| Up/Down Link   | ✅            | ✅            |
| Change MTU     | ✅            | ✅            |
| Change MAC     | ❌ 1)         | ✅            |
| Add/Del IP4/IP6 Address  | ✅  | ✅            | 
| Route          | ❌ 2)         | ✅            |
| Add/Del Tunnel | ❌            | ❌            |
| Add/Del Phy    | ✅            | 🟠            |
| Add/Del .1q    | ✅            | ✅            |
| Add/Del .1ad   | ✅            | ✅            |
| Add/Del QinQ   | ✅            | ✅            |
| Add/Del QinAD  | ✅            | ✅            |
| Add/Del BondEthernet  | ✅     | 🟠            |
| MPLS P         | 🟠            | ✅            |
| MPLS P/E       | 🟠            | ✅            |

Legend: ✅=supported; 🟠=maybe; ❌=infeasible.

1) There is no callback or macro to register an interest in MAC address changes in VPP.
2) There is no callback or macro to register an interest in FIB changes in VPP.

## Building

First, ensure that you can build and run 'vanilla' VPP by using the
[instructions](https://wiki.fd.io/view/VPP/Pulling,_Building,_Running,_Hacking_and_Pushing_VPP_Code).
Then install one missing dependency (Netlink library), check out this plugin out-of-tree,
symlink it in, and (re)build the code.

```
apt-get install libmnl-dev
mkdir ~/src
cd ~/src
git clone https://github.com/pimvanpelt/lcpng.git
ln -s ~/src/lcpng ~/src/vpp/src/plugins/lcpng
cd ~/src/vpp
make rebuild
make rebuild-release
```

## Running

Ensure this plugin is enabled and the original `linux-cp` plugin is disabled,
that logging goes to stderr (in the debug variant of VPP), and that the features
are dis/enabled, by providing the following `startup.conf`:
```
plugins {
  path ~/src/vpp/build-root/install-vpp_debug-native/vpp/lib/vpp_plugins
  plugin lcpng_if_plugin.so { enable }
  plugin lcpng_nl_plugin.so { enable }
  plugin linux_cp_plugin.so { disable }
}

logging {
   default-log-level info
   default-syslog-log-level crit
   ## Set per-class configuration
   class linux-cp/if { rate-limit 10000 level debug syslog-level debug }
   class linux-cp/nl { rate-limit 10000 level debug syslog-level debug }
}

lcpng {
  default netns dataplane
  lcp-sync
  lcp-auto-subint
}
```

Then, simply `make build` and `make run` VPP which will load the plugin.
```
im@hippo:~/src/vpp$ make run
snort                [debug ]: initialized
snort                [debug ]: snort listener /run/vpp/snort.sock
linux-cp/if          [debug ]: interface_add: [1] sw TenGigabitEthernet3/0/0 is_sub 0 lcp-auto-subint 1
linux-cp/if          [debug ]: mtu_change: sw TenGigabitEthernet3/0/0 0
linux-cp/if          [debug ]: interface_add: [2] sw TenGigabitEthernet3/0/1 is_sub 0 lcp-auto-subint 1
linux-cp/if          [debug ]: mtu_change: sw TenGigabitEthernet3/0/1 0
linux-cp/if          [debug ]: interface_add: [3] sw TenGigabitEthernet3/0/2 is_sub 0 lcp-auto-subint 1
linux-cp/if          [debug ]: mtu_change: sw TenGigabitEthernet3/0/2 0
linux-cp/if          [debug ]: interface_add: [4] sw TenGigabitEthernet3/0/3 is_sub 0 lcp-auto-subint 1
linux-cp/if          [debug ]: mtu_change: sw TenGigabitEthernet3/0/3 0
linux-cp/if          [debug ]: interface_add: [5] sw TwentyFiveGigabitEthernete/0/0 is_sub 0 lcp-auto-subint 1
linux-cp/if          [debug ]: mtu_change: sw TwentyFiveGigabitEthernete/0/0 0
linux-cp/if          [debug ]: interface_add: [6] sw TwentyFiveGigabitEthernete/0/1 is_sub 0 lcp-auto-subint 1
linux-cp/if          [debug ]: mtu_change: sw TwentyFiveGigabitEthernete/0/1 0
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

DBGvpp# 
```

### Notes on MPLS (May 2023)

The MPLS plugin is documented in the 4 VPP [[MPLS articles](https://ipng.ch/s/articles/)] on IPng's website.

Currently, P-router (MPLS forwarding, SWAP, EOS and NEOS) is fully implemented. For P/E, encapsulating MPLS
packets based on destination IPv4 and IPv6 prefixes works. In Netlink messages, all MPLS and IPv4/IPv6 encapsulation
messages are handled correctly.

The netlink handler for MPLS encapsulated IPv4/IPv6 routes requires at least `libnl3` version 3.6. Debian Bullseye
ships with version 3.4.0. It's advised to compile `libnl3` version 3.7.0 from Debian Bookworm. VPP will run with
the older `libnl3` version, but it will not install routes in the FIB.

***NOTE***: this is not required for Debian Bookworm which ships with 3.7.0 already.

Quick build howto (for Debian Bullseye):
```
mkdir -p ~/dist ~/src/libnl/
cd ~/src/libnl/
wget http://deb.debian.org/debian/pool/main/libn/libnl3/libnl3_3.7.0.orig.tar.gz
wget http://deb.debian.org/debian/pool/main/libn/libnl3/libnl3_3.7.0-0.2.debian.tar.xz

tar xzf libnl3_3.7.0.orig.tar.gz
cd libnl-3.7.0
tar xf libnl3_3.7.0-0.2.debian.tar.xz

sudo apt install dpkg-dev debhelper dh-exec cdbs bison flex automake autoconf \
  dh-autoreconf pkg-config
sudo dpkg-buildpackage -b -uc -us

cd ~/src/libnl/
cp libnl-3-200_3.7.0-0.2_amd64.deb libnl-3-dev_3.7.0-0.2_amd64.deb \
  libnl-genl-3-200_3.7.0-0.2_amd64.deb libnl-route-3-200_3.7.0-0.2_amd64.deb \
  libnl-route-3-dev_3.7.0-0.2_amd64.deb ~/dist
```

This will yield the following Debian compatible `libnl3` packages. 

```
pim@bullseye-builder:~/src/libnl$ dpkg -l | grep libnl
ii  libnl-3-200:amd64         3.7.0-0.2   amd64   library for dealing with netlink sockets
ii  libnl-3-dev:amd64         3.7.0-0.2   amd64   development library and headers for libnl-3
ii  libnl-genl-3-200:amd64    3.7.0-0.2   amd64   library for dealing with netlink sockets - generic netlink
ii  libnl-route-3-200:amd64   3.7.0-0.2   amd64   library for dealing with netlink sockets - route interface
ii  libnl-route-3-dev:amd64   3.7.0-0.2   amd64   development library and headers for libnl-route-3
```

Of course, don't forget to load the `mpls_router` kernel module and allow for the Linux Controlplane side
to create MPLS labels:
```
ip netns exec dataplane sysctl -w net.mpls.platform_labels=65535
```
