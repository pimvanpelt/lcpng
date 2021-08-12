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
  lcp_itf_set_link_state (lip, (flags & VNET_HW_INTERFACE_FLAG_LINK_UP));

  // Sync PHY carrier changes into TAP
  hi = vnet_get_hw_interface_or_null (vnm, sw_if_index);
  si = vnet_get_sw_interface_or_null (vnm, lip->lip_host_sw_if_index);
  if (!si || !hi) return NULL;
  LCP_ITF_PAIR_INFO ("admin_state_change: hi %U si %U %u",
		  format_vnet_sw_if_index_name, vnm, hi->hw_if_index,
		  format_vnet_sw_if_index_name, vnm, si->sw_if_index,
		  flags);

  tap_set_carrier (si->hw_if_index, (flags & VNET_HW_INTERFACE_FLAG_LINK_UP));
  /* TODO(pim): is this right? see tap_set_speed() "Cannot open netns" error
  if (flags & VNET_HW_INTERFACE_FLAG_LINK_UP) {
    tap_set_speed (si->hw_if_index, hi->link_speed);
  } 
  */
  return NULL;
}   

VNET_SW_INTERFACE_ADMIN_UP_DOWN_FUNCTION(lcp_itf_admin_state_change);
