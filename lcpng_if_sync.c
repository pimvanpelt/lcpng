/* Hey Emacs use -*- mode: C -*- */
/*
 * Copyright 2021 Pim van Pelt <pim@ipng.nl>
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

#include <plugins/lcpng/lcpng_interface.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/format_fns.h>
#include <vnet/udp/udp.h>
#include <vnet/tcp/tcp.h>
#include <vnet/devices/tap/tap.h>
#include <vnet/devices/netlink.h>

/* walk function to copy forward all sw interface link state flags into
 * their counterpart LIP link state.
 */
static walk_rc_t
lcp_itf_pair_walk_sync_state_cb (index_t lipi, void *ctx)
{
  lcp_itf_pair_t *lip;
  vnet_sw_interface_t *phy;

  lip = lcp_itf_pair_get (lipi);
  if (!lip)
    return WALK_CONTINUE;

  phy =
    vnet_get_sw_interface_or_null (vnet_get_main (), lip->lip_phy_sw_if_index);
  if (!phy)
    return WALK_CONTINUE;

  LCP_ITF_PAIR_DBG ("walk_sync_state: lip %U flags %u", format_lcp_itf_pair,
		    lip, phy->flags);
  lcp_itf_set_link_state (lip, (phy->flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP));

  return WALK_CONTINUE;
}

static clib_error_t *
lcp_itf_admin_state_change (vnet_main_t * vnm, u32 sw_if_index, u32 flags)
{
  const lcp_itf_pair_t *lip;
  vnet_hw_interface_t *hi;
  vnet_sw_interface_t *si;

  LCP_ITF_PAIR_DBG ("admin_state_change: sw %U %u",
		  format_vnet_sw_if_index_name, vnm, sw_if_index,
		  flags);

  // Sync interface state changes into host
  lip = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (sw_if_index));
  if (!lip) return NULL;

  LCP_ITF_PAIR_INFO ("admin_state_change: %U flags %u", format_lcp_itf_pair, lip, flags);
  lcp_itf_set_link_state (lip, (flags & VNET_SW_INTERFACE_FLAG_ADMIN_UP));

  // Sync PHY carrier changes into TAP
  hi = vnet_get_hw_interface_or_null (vnm, sw_if_index);
  si = vnet_get_sw_interface_or_null (vnm, lip->lip_host_sw_if_index);
  if (!si || !hi) return NULL;
  LCP_ITF_PAIR_DBG ("admin_state_change: hi %U si %U %u",
		    format_vnet_sw_if_index_name, vnm, hi->hw_if_index,
		    format_vnet_sw_if_index_name, vnm, si->sw_if_index, flags);
  tap_set_carrier (si->hw_if_index,
		   (hi->flags & VNET_HW_INTERFACE_FLAG_LINK_UP));

  // When Linux changes link on a master interface, all of its children also
  // change. This is not true in VPP, so we are forced to undo that change by
  // walking the sub-interfaces of a phy and syncing their state back into
  // linux. For simplicity, just walk all interfaces.
  lcp_itf_pair_walk (lcp_itf_pair_walk_sync_state_cb, 0);

  return NULL;
}   

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(lcp_itf_admin_state_change);

static clib_error_t *
lcp_itf_mtu_change (vnet_main_t *vnm, u32 sw_if_index, u32 flags)
{
  const lcp_itf_pair_t *lip;
  vnet_sw_interface_t *si;

  LCP_ITF_PAIR_DBG ("mtu_change: sw %U %u", format_vnet_sw_if_index_name, vnm,
		    sw_if_index, flags);

  // Sync interface state changes into host
  lip = lcp_itf_pair_get (lcp_itf_pair_find_by_phy (sw_if_index));
  if (!lip)
    return NULL;

  si = vnet_get_sw_interface_or_null (vnm, sw_if_index);
  if (!si)
    return NULL;

  LCP_ITF_PAIR_INFO ("mtu_change: %U mtu %u", format_lcp_itf_pair, lip,
		     si->mtu[VNET_MTU_L3]);
  vnet_netlink_set_link_mtu (lip->lip_vif_index, si->mtu[VNET_MTU_L3]);

  return NULL;
}

VNET_SW_INTERFACE_MTU_CHANGE_FUNCTION (lcp_itf_mtu_change);
