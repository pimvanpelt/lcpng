/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2021 Cisco and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <sys/socket.h>
#include <linux/if.h>

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>

#include <vppinfra/linux/netns.h>

#include <plugins/lcpng/lcpng_interface.h>
#include <plugins/lcpng/lcpng_netlink.h>

#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/ip/ip6_ll_table.h>
#include <vnet/ip-neighbor/ip_neighbor.h>
#include <vnet/ip/ip6_link.h>

#ifndef NUD_VALID
#define NUD_VALID                                                             \
  (NUD_PERMANENT | NUD_NOARP | NUD_REACHABLE | NUD_PROBE | NUD_STALE |        \
   NUD_DELAY)
#endif

static void
lcp_nl_mk_ip_addr (const struct nl_addr *rna, ip_address_t *ia)
{
  ip_address_reset (ia);
  ip_address_set (ia, nl_addr_get_binary_addr (rna),
		  nl_addr_get_family (rna) == AF_INET6 ? AF_IP6 : AF_IP4);
}

static void
lcp_nl_mk_mac_addr (const struct nl_addr *rna, mac_address_t *mac)
{
  mac_address_from_bytes (mac, nl_addr_get_binary_addr (rna));
}

void
lcp_nl_neigh_add (struct rtnl_neigh *rn)
{
  lcp_itf_pair_t *lip;
  struct nl_addr *ll;
  ip_address_t nh;
  int state;

  NL_DBG ("neigh_add: netlink %U", format_nl_object, rn);

  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_neigh_get_ifindex (rn)))))
    {
      NL_WARN ("neigh_add: no LCP for %U ", format_nl_object, rn);
      return;
    }

  lcp_nl_mk_ip_addr (rtnl_neigh_get_dst (rn), &nh);
  ll = rtnl_neigh_get_lladdr (rn);
  state = rtnl_neigh_get_state (rn);

  if (ll && (state & NUD_VALID))
    {
      mac_address_t mac;
      ip_neighbor_flags_t flags;
      int rv;

      lcp_nl_mk_mac_addr (ll, &mac);

      if (state & (NUD_NOARP | NUD_PERMANENT))
	flags = IP_NEIGHBOR_FLAG_STATIC;
      else
	flags = IP_NEIGHBOR_FLAG_DYNAMIC;

      rv = ip_neighbor_add (&nh, &mac, lip->lip_phy_sw_if_index, flags, NULL);

      if (rv)
	{
	  NL_ERROR ("neigh_add: Failed %U lladdr %U iface %U",
		    format_ip_address, &nh, format_mac_address, &mac,
		    format_vnet_sw_if_index_name, vnet_get_main (),
		    lip->lip_phy_sw_if_index);
	}
      else
	{
	  NL_NOTICE ("neigh_add: Added %U lladdr %U iface %U",
		     format_ip_address, &nh, format_mac_address, &mac,
		     format_vnet_sw_if_index_name, vnet_get_main (),
		     lip->lip_phy_sw_if_index);
	}
    }
}

void
lcp_nl_neigh_del (struct rtnl_neigh *rn)
{
  ip_address_t nh;
  int rv;
  NL_DBG ("neigh_del: netlink %U", format_nl_object, rn);

  lcp_itf_pair_t *lip;
  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_neigh_get_ifindex (rn)))))
    {
      NL_WARN ("neigh_del: no LCP for %U ", format_nl_object, rn);
      return;
    }

  lcp_nl_mk_ip_addr (rtnl_neigh_get_dst (rn), &nh);
  rv = ip_neighbor_del (&nh, lip->lip_phy_sw_if_index);

  if (rv)
    {
      NL_ERROR ("neigh_del: Failed %U iface %U", format_ip_address, &nh,
		format_vnet_sw_if_index_name, vnet_get_main (),
		lip->lip_phy_sw_if_index);
    }
  else
    {
      NL_NOTICE ("neigh_del: Deleted %U iface %U", format_ip_address, &nh,
		 format_vnet_sw_if_index_name, vnet_get_main (),
		 lip->lip_phy_sw_if_index);
    }
}
