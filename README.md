This code was taken from VPP's src/plugins/linux-cp/ directory, originally by:
Signed-off-by: Neale Ranns <nranns@cisco.com>
Signed-off-by: Matthew Smith <mgsmith@netgate.com>
Signed-off-by: Jon Loeliger <jdl@netgate.com>
Signed-off-by: Pim van Pelt <pim@ipng.nl>
Signed-off-by: Neale Ranns <neale@graphiant.com>

See previous work:
https://gerrit.fd.io/r/c/vpp/+/30759 (interface mirroring)
https://gerrit.fd.io/r/c/vpp/+/31122 (netlink listener)

It's intended to be re-submitted for review as a cleanup/rewrite of the existing
Linux CP interface mirror and netlink syncer. 

# FAQ

***Why doesn't the plugin listen to new linux interfaces?***

Consider the following two commands:

```
ip link add link e0 name foo type vlan id 10 protocol 802.1ad
ip link add link foo name bar type vlan id 20
```
The two effectively create a dot1ad with an outer tag of 10 and an inner tag of
20 (you could also read this as e0.10.20). The `foo` interface is the untagged
VLAN 10 on e0 with ethernet type 0x8aa8, and the `bar` interface carries any
tagged traffic on `foo`, thus is ethernet type 0x8100 within the e0's ethernet
type 0x8aa8 outer frame.

It's easy to listen to netlink messages like these, but their name will in
no way be easy to map to a VPP subinterface concept. In VPP, all subinterfaces
are numbered on their phy, such as TenGigabitEthernet0/0/0.1000. It is not
clear how to map the linux host interface name `foo` and `bar` to this
numbering scheme in a way that doesn't create collissions.

A second consideration is that these QinQ interfaces can be 802.1ad or 802.1q
tagged on the outer. So what happens if after the above, a new `foo2` interface
is created with protocol 802.1q ? VPP only allows sub interfaces to carry one
(1) number.

Rather than applying heuristics and adding bugs, it is not possible to create
VPP interfaces via Linux, only the other way around. Create any L3 capable
interface or subinterface in VPP, and it'll be created in Linux as well.

### Notes

We'll be able to see if VPP changes the interfaces with a bunch of callback
functions:
```
pim@hippo:~/src/vpp$ grep -r VNET.*_FUNCTION src/vnet/interface.h
#define VNET_HW_INTERFACE_ADD_DEL_FUNCTION(f)                   \
#define VNET_HW_INTERFACE_LINK_UP_DOWN_FUNCTION(f)              \
#define VNET_SW_INTERFACE_MTU_CHANGE_FUNCTION(f)                \
#define VNET_SW_INTERFACE_ADD_DEL_FUNCTION(f)                   \
#define VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(f)             \
```

Super useful for MTU changes, admin up/dn and link up/dn changes (to copy
these into the TAP and the host interface).

Notably missing here is some form of SW_INTERFACE_L2_L3_CHANGE_FUNCTION(f)
which would be useful to remove an LCP if the iface goes into L2 mode, and
(re)create an LCP if the iface goes into L3 mode.

It will also be very useful to create an IP_ADDRESS_ADD_DEL_FUNCTION(f)
of sorts so that we know when VPP sets an IPv4/IPv6 address (so that we
can copy this into the host interface).

#### LCP names

The maximum length of an interface name in Linux is 15 characters. I'd love
to be able to make interfaces like you might find in DANOS:
dp0p6s0f1 but this is already 9 characters, and the slot and PCI bus can be
double digits. The Linux idiom is to make a link as a child of another link,
like:
  ip link add link eth0 name eth0.1234 type vlan id 1234 proto dot1q

You can also make QinQ interfaces in the same way:
  ip link add link eth0.1234 name eth0.1234.1000 type vlan id 1234

This last interface will have 5 characters .1000 for the inner, 5 characters
.1234 for the outer, leaving 5 characters for the full interface name.

I can see two ways out of this:
1.  Make main interfaces very short
For example `et0` for DPDK interfaces, `be1` for BondEthernet, `lo4` for
Loopback interfaces, and possibly `bvi5` for BridgeVirtualInterface (these
are the L3 interfaces in an L2 bridge-group). In such a world, we can create
any number of subinterfaces in a Linux _idiomatic way_, like et192.1234.1000
but BVIs will be limited to 100 interfaces and ethernet's to 1000. This seems
okay, but does paint us in the corner possibly in the future.

1.  Strictly follow VPP's naming
VPP will always have exactly one (integer) numbered subinterface, like
`TenGigabitEthernet3/0/2.1234567890` and the function of such a subint can take
multiple forms (dot1q, dot1ad, double-tagged, etc). In this world, we can create
interface names in Linux that map very cleanly to VPP's subinterfaces, and we
can also auto-create subinterfaces by reading a netlink link message, provided
the chosen name follows an <iface>.<number> pattern, and <iface> maps to a known
LCP.

Here's how I can see the latter approach working:

Creation of VPP sub-interface directly creates the corresponding LCP device
name `e0.1234`. Creating a more complex dot1q/dot1q or dot1ad or dot1ad/dot1q
sub-interface will again create a mirror LCP with device name `e0.1235`,
reusing the sub-int number from VPP directly. That's good.

Reading a netlink new link message is a bit trickier, but here's what I
propose:
*   On a physical interface `e0`, one can create a dot1q or dot1ad link with a
    linux name of `e0.1234`; in such a case, a corresponding sub-int will be
    made by the plugin in VPP.
*   On a linux interface `e0.1234`, only a dot1q interface can be made, but
    its name is required to follow the <iface>.<number> pattern, and if so,
    the plugin will make a VPP interface corresponding to that number, but
    considering we already know if the parent is either a .1q interface or a
    .1ad interface, the correct type of VPP interface can be selected.
    *   If an interface name is not valid, the plugin will destroy the link and
        log an error.
    *   Because we'll want to use one TAP interface per LCP (see rationale
        above), the plugin will have to destroy the link and recreate it as a
        new interface with the same name, but not as a child of the originally
        requested parent interface.

With this, we can:

1.  Create a dot1q subinterface on `e0`:
    `ip link add link e0 name e0.1234 type vlan id 1234`
1.  Create a dot1q outer, dot1q inner subinterface on `e0`:
    `ip link add link e0.1234 name e0.1235 type vlan id 1000`
1.  Create a dot1ad subinterface on `e0`:
    `ip link add link e0 name e0.1236 type vlan id 2345 proto 802.1ad`
1.  Create a dot1ad outer, dot1q inner subinterface on `e0`:
    `ip link add link e0.1236 name e0.1237 type vlan id 2345 proto 802.1q`
1.  Fail to create an interface which has an invalid name:
    `ip link add link e0.1234 name e0.1234.2345 type vlan id 2345 proto 802.1q`
    (this interface will be destroyed by the plugin and an error logged)

For each of these interface creations, the user is asking them to be created as
a child of an existing interface (either `e0` or `e0.1234`), but the plugin
will destroy that interface again, and recreate it as a top-level interface
int the namespace, with an accompanying tap interface. So in this plugin, every
LCP has exactly one TAP, and that TAP interface is never a sub-int.
