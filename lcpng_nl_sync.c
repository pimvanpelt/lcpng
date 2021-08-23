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

static const mfib_prefix_t ip4_specials[] = {
  /* ALL prefixes are in network order */
  {
   /* (*,224.0.0.0)/24 - all local subnet */
   .fp_grp_addr = {
		   .ip4.data_u32 = 0x000000e0,
		   },
   .fp_len = 24,
   .fp_proto = FIB_PROTOCOL_IP4,
   },
};

static void
lcp_nl_ip4_mroutes_add_del (u32 sw_if_index, u8 is_add)
{
  const fib_route_path_t path = {
    .frp_proto = DPO_PROTO_IP4,
    .frp_addr = zero_addr,
    .frp_sw_if_index = sw_if_index,
    .frp_fib_index = ~0,
    .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
  };
  u32 mfib_index;
  int ii;

  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP4, sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip4_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index, &ip4_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index, &ip4_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
    }
}

static const mfib_prefix_t ip6_specials[] = {
  /* ALL prefixes are in network order */
  {
   /* (*,ff00::)/8 - all local subnet */
   .fp_grp_addr = {
		   .ip6.as_u64[0] = 0x00000000000000ff,
		   },
   .fp_len = 8,
   .fp_proto = FIB_PROTOCOL_IP6,
   },
};

static void
lcp_nl_ip6_mroutes_add_del (u32 sw_if_index, u8 is_add)
{
  const fib_route_path_t path = {
    .frp_proto = DPO_PROTO_IP6,
    .frp_addr = zero_addr,
    .frp_sw_if_index = sw_if_index,
    .frp_fib_index = ~0,
    .frp_weight = 1,
    .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
  };
  u32 mfib_index;
  int ii;

  mfib_index =
    mfib_table_get_index_for_sw_if_index (FIB_PROTOCOL_IP6, sw_if_index);

  for (ii = 0; ii < ARRAY_LEN (ip6_specials); ii++)
    {
      if (is_add)
	{
	  mfib_table_entry_path_update (mfib_index, &ip6_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
      else
	{
	  mfib_table_entry_path_remove (mfib_index, &ip6_specials[ii],
					MFIB_SOURCE_PLUGIN_LOW, &path);
	}
    }
}

static void
lcp_nl_addr_add_del (struct rtnl_addr *ra, int is_del)
{
  lcp_itf_pair_t *lip;
  ip_address_t nh;

  NL_DBG ("addr_%s: netlink %U", is_del ? "del" : "add", format_nl_object, ra);

  if (!(lip = lcp_itf_pair_get (
	  lcp_itf_pair_find_by_vif (rtnl_addr_get_ifindex (ra)))))
    {
      NL_WARN ("addr_%s: no LCP for %U ", is_del ? "del" : "add",
	       format_nl_object, ra);
      return;
    }

  lcp_nl_mk_ip_addr (rtnl_addr_get_local (ra), &nh);

  vlib_worker_thread_barrier_sync (vlib_get_main ());
  if (AF_IP4 == ip_addr_version (&nh))
    {
      ip4_add_del_interface_address (
	vlib_get_main (), lip->lip_phy_sw_if_index, &ip_addr_v4 (&nh),
	rtnl_addr_get_prefixlen (ra), is_del);
      lcp_nl_ip4_mroutes_add_del (lip->lip_phy_sw_if_index, !is_del);
    }
  else if (AF_IP6 == ip_addr_version (&nh))
    {
      if (ip6_address_is_link_local_unicast (&ip_addr_v6 (&nh)))
	if (is_del)
	  ip6_link_disable (lip->lip_phy_sw_if_index);
	else
	  {
	    ip6_link_enable (lip->lip_phy_sw_if_index, NULL);
	    ip6_link_set_local_address (lip->lip_phy_sw_if_index,
					&ip_addr_v6 (&nh));
	  }
      else
	ip6_add_del_interface_address (
	  vlib_get_main (), lip->lip_phy_sw_if_index, &ip_addr_v6 (&nh),
	  rtnl_addr_get_prefixlen (ra), is_del);
      lcp_nl_ip6_mroutes_add_del (lip->lip_phy_sw_if_index, !is_del);
    }
  vlib_worker_thread_barrier_release (vlib_get_main ());

  NL_NOTICE ("addr_%s %U/%d iface %U", is_del ? "del: Deleted" : "add: Added",
	     format_ip_address, &nh, rtnl_addr_get_prefixlen (ra),
	     format_vnet_sw_if_index_name, vnet_get_main (),
	     lip->lip_phy_sw_if_index);
}

void
lcp_nl_addr_add (struct rtnl_addr *ra)
{
  lcp_nl_addr_add_del (ra, 0);
}

void
lcp_nl_addr_del (struct rtnl_addr *ra)
{
  lcp_nl_addr_add_del (ra, 1);
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

      vlib_worker_thread_barrier_sync (vlib_get_main ());
      rv = ip_neighbor_add (&nh, &mac, lip->lip_phy_sw_if_index, flags, NULL);
      vlib_worker_thread_barrier_release (vlib_get_main ());

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
  vlib_worker_thread_barrier_sync (vlib_get_main ());
  rv = ip_neighbor_del (&nh, lip->lip_phy_sw_if_index);
  vlib_worker_thread_barrier_release (vlib_get_main ());

  if (rv == 0 || rv == VNET_API_ERROR_NO_SUCH_ENTRY)
    {
      NL_NOTICE ("neigh_del: Deleted %U iface %U", format_ip_address, &nh,
		 format_vnet_sw_if_index_name, vnet_get_main (),
		 lip->lip_phy_sw_if_index);
    }
  else
    {
      NL_ERROR ("neigh_del: Failed %U iface %U", format_ip_address, &nh,
		format_vnet_sw_if_index_name, vnet_get_main (),
		lip->lip_phy_sw_if_index);
    }
}
