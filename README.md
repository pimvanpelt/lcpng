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
