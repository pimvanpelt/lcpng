/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#define _GNU_SOURCE
#include <sched.h>
#include <fcntl.h>

#include <netlink/route/rule.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vppinfra/error.h>

#include <vnet/fib/fib_table.h>

#include <libmnl/libmnl.h>

#include <vppinfra/linux/netns.h>

#include <plugins/lcpng/lcpng_netlink.h>
#include <plugins/lcpng/lcpng_interface.h>

static void lcp_nl_open_socket (u8 *ns);
static void lcp_nl_close_socket (void);

lcp_nl_main_t lcp_nl_main = {
  .rx_buf_size = NL_RX_BUF_SIZE_DEF,
  .tx_buf_size = NL_TX_BUF_SIZE_DEF,
  .batch_size = NL_BATCH_SIZE_DEF,
  .batch_work_ms = NL_BATCH_WORK_MS_DEF,
  .batch_delay_ms = NL_BATCH_DELAY_MS_DEF,
};

u8 *
format_nl_object (u8 *s, va_list *args)
{
  int type;
  struct nl_object *obj = va_arg (*args, struct nl_object *);
  if (!obj)
    return s;

  s = format (s, "%s: ", nl_object_get_type (obj));
  type = nl_object_get_msgtype (obj);
  switch (type)
    {
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
      {
	struct rtnl_route *route = (struct rtnl_route *) obj;
	struct nl_addr *a;
	int n;

	char buf[128];
	s = format (
	  s, "%s family %s", type == RTM_NEWROUTE ? "add" : "del",
	  nl_af2str (rtnl_route_get_family (route), buf, sizeof (buf)));
	s = format (
	  s, " type %d proto %d table %d", rtnl_route_get_type (route),
	  rtnl_route_get_protocol (route), rtnl_route_get_table (route));
	if ((a = rtnl_route_get_src (route)))
	  s = format (s, " src %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_route_get_dst (route)))
	  s = format (s, " dst %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " nexthops {");
	for (n = 0; n < rtnl_route_get_nnexthops (route); n++)
	  {
	    struct rtnl_nexthop *nh;
	    nh = rtnl_route_nexthop_n (route, n);
	    if ((a = rtnl_route_nh_get_via (nh)))
	      s = format (s, " via %s", nl_addr2str (a, buf, sizeof (buf)));
	    if ((a = rtnl_route_nh_get_gateway (nh)))
	      s =
		format (s, " gateway %s", nl_addr2str (a, buf, sizeof (buf)));
	    if ((a = rtnl_route_nh_get_newdst (nh)))
	      s = format (s, " newdst %s", nl_addr2str (a, buf, sizeof (buf)));
	    s = format (s, " idx %d", rtnl_route_nh_get_ifindex (nh));
	  }
	s = format (s, " }");
      }
      break;
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
      {
	struct rtnl_neigh *neigh = (struct rtnl_neigh *) obj;
	int idx = rtnl_neigh_get_ifindex (neigh);
	struct nl_addr *a;
	char buf[128];
	s = format (
	  s, "%s idx %d family %s", type == RTM_NEWNEIGH ? "add" : "del", idx,
	  nl_af2str (rtnl_neigh_get_family (neigh), buf, sizeof (buf)));
	if ((a = rtnl_neigh_get_lladdr (neigh)))
	  s = format (s, " lladdr %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_neigh_get_dst (neigh)))
	  s = format (s, " dst %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " state 0x%04x", rtnl_neigh_get_state (neigh));
	rtnl_neigh_state2str (rtnl_neigh_get_state (neigh), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);

	s = format (s, " flags 0x%04x", rtnl_neigh_get_flags (neigh));
	rtnl_neigh_flags2str (rtnl_neigh_get_flags (neigh), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);
      }
      break;
    case RTM_NEWADDR:
    case RTM_DELADDR:
      {
	struct rtnl_addr *addr = (struct rtnl_addr *) obj;
	int idx = rtnl_addr_get_ifindex (addr);
	struct nl_addr *a;
	char buf[128];

	s = format (
	  s, "%s idx %d family %s", type == RTM_NEWADDR ? "add" : "del", idx,
	  nl_af2str (rtnl_addr_get_family (addr), buf, sizeof (buf)));
	if ((a = rtnl_addr_get_local (addr)))
	  s = format (s, " local %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_addr_get_peer (addr)))
	  s = format (s, " peer %s", nl_addr2str (a, buf, sizeof (buf)));
	if ((a = rtnl_addr_get_broadcast (addr)))
	  s = format (s, " broadcast %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " flags 0x%04x", rtnl_addr_get_flags (addr));
	rtnl_addr_flags2str (rtnl_addr_get_flags (addr), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);
      }
      break;
    case RTM_NEWLINK:
    case RTM_DELLINK:
      {
	struct rtnl_link *link = (struct rtnl_link *) obj;
	struct nl_addr *a;
	char buf[128];
	// mac_addr = rtnl_link_get_addr (l);
	s =
	  format (s, "%s idx %d name %s", type == RTM_NEWLINK ? "add" : "del",
		  rtnl_link_get_ifindex (link), rtnl_link_get_name (link));

	if ((a = rtnl_link_get_addr (link)))
	  s = format (s, " addr %s", nl_addr2str (a, buf, sizeof (buf)));

	s = format (s, " mtu %u carrier %d", rtnl_link_get_mtu (link),
		    rtnl_link_get_carrier (link));

	s = format (s, " operstate 0x%04x", rtnl_link_get_operstate (link));
	rtnl_link_operstate2str (rtnl_link_get_operstate (link), buf,
				 sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);

	s = format (s, " flags 0x%04x", rtnl_link_get_flags (link));
	rtnl_link_flags2str (rtnl_link_get_flags (link), buf, sizeof (buf));
	if (buf[0])
	  s = format (s, " (%s)", buf);

	if (rtnl_link_is_vlan (link))
	  {
	    s =
	      format (s, " vlan { parent-idx %d id %d proto 0x%04x",
		      rtnl_link_get_link (link), rtnl_link_vlan_get_id (link),
		      ntohs (rtnl_link_vlan_get_protocol (link)));
	    s = format (s, " flags 0x%04x", rtnl_link_vlan_get_flags (link));
	    rtnl_link_vlan_flags2str (rtnl_link_vlan_get_flags (link), buf,
				      sizeof (buf));
	    if (buf[0])
	      s = format (s, " (%s)", buf);
	    s = format (s, " }", buf);
	  }
      }
      break;
    default:
      s = format (s, " <unknown>");
      break;
    }
  return s;
}

static void
lcp_nl_dispatch (struct nl_object *obj, void *arg)
{
  /* Here is where we'll sync the netlink messages into VPP */
  vlib_worker_thread_barrier_sync (vlib_get_main ());
  switch (nl_object_get_msgtype (obj))
    {
    case RTM_NEWNEIGH:
      lcp_nl_neigh_add ((struct rtnl_neigh *) obj);
      break;
    case RTM_DELNEIGH:
      lcp_nl_neigh_del ((struct rtnl_neigh *) obj);
      break;
    case RTM_NEWADDR:
      lcp_nl_addr_add ((struct rtnl_addr *) obj);
      break;
    case RTM_DELADDR:
      lcp_nl_addr_del ((struct rtnl_addr *) obj);
      break;
    case RTM_NEWLINK:
      lcp_nl_link_add ((struct rtnl_link *) obj, arg);
      break;
    case RTM_DELLINK:
      lcp_nl_link_del ((struct rtnl_link *) obj);
      break;
    case RTM_NEWROUTE:
      lcp_nl_route_add ((struct rtnl_route *) obj);
      break;
    case RTM_DELROUTE:
      lcp_nl_route_del ((struct rtnl_route *) obj);
      break;
    default:
      NL_WARN ("dispatch: ignored %U", format_nl_object, obj);
      break;
    }
  vlib_worker_thread_barrier_release (vlib_get_main ());
}

static int
lcp_nl_process_msgs (void)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  nl_msg_info_t *msg_info;
  int err, n_msgs = 0;
  f64 start = vlib_time_now (vlib_get_main ());
  u64 usecs = 0;

  /* To avoid loops where VPP->LCP sync fights with LCP->VPP
   * sync, we turn off the former if it's enabled, while we consume
   * the netlink messages in this function, and put it back at the
   * end of the function.
   */
  lcp_main_t *lcpm = &lcp_main;
  u8 old_lcp_sync = lcpm->lcp_sync;
  lcpm->lcp_sync = 0;

  /* process a batch of messages. break if we hit our batch_size
   * count limit or batch_work_ms time limit.
   *
   * We do this, because netlink messages will continue to be sourced
   * by the kernel, and we need to periodically read them before they
   * overflow the netlink socket size. So, only consume a few messages
   * before returning to allow lcp_nl_callback() to read more onto the
   * queue.
   */
  vec_foreach (msg_info, nm->nl_ns.nl_msg_queue)
    {
      if ((err = nl_msg_parse (msg_info->msg, lcp_nl_dispatch, msg_info)) < 0)
	NL_ERROR ("process_msgs: Unable to parse object: %s",
		  nl_geterror (err));
      nlmsg_free (msg_info->msg);

      if (++n_msgs >= nm->batch_size)
	{
	  NL_INFO ("process_msgs: batch_size %u reached, yielding",
		   nm->batch_size);
	  break;
	}
      usecs = (u64) (1e6 * (vlib_time_now (vlib_get_main ()) - start));
      if (usecs >= 1e3 * nm->batch_work_ms)
	{
	  NL_INFO ("process_msgs: batch_work_ms %u reached, yielding",
		   nm->batch_work_ms);
	  break;
	}
    }

  /* remove the messages we processed from the head of the queue */
  if (n_msgs)
    vec_delete (nm->nl_ns.nl_msg_queue, n_msgs, 0);

  if (n_msgs > 0)
    {
      if (vec_len (nm->nl_ns.nl_msg_queue))
	{
	  NL_WARN ("process_msgs: Processed %u messages in %llu usecs, %u "
		   "left in queue",
		   n_msgs, usecs, vec_len (nm->nl_ns.nl_msg_queue));
	}
      else
	{
	  NL_INFO ("process_msgs: Processed %u messages in %llu usecs", n_msgs,
		   usecs);
	}
    }

  lcpm->lcp_sync = old_lcp_sync;

  return n_msgs;
}

#define LCP_NL_PROCESS_WAIT 10.0 // seconds

static uword
lcp_nl_process (vlib_main_t *vm, vlib_node_runtime_t *node,
		vlib_frame_t *frame)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  uword event_type;
  uword *event_data = 0;
  f64 wait_time = LCP_NL_PROCESS_WAIT;

  while (1)
    {
      /* If we process a batch of messages and stop because we reached the
       * batch size limit, we want to wake up after the batch delay and
       * process more. Otherwise we just want to wait for a read event.
       */
      vlib_process_wait_for_event_or_clock (vm, wait_time);
      event_type = vlib_process_get_events (vm, &event_data);

      switch (event_type)
	{
	/* process batch of queued messages on timeout or read event signal */
	case ~0:
	case NL_EVENT_READ:
	  lcp_nl_process_msgs ();
	  wait_time = (vec_len (nm->nl_ns.nl_msg_queue) != 0) ?
			nm->batch_delay_ms * 1e-3 :
			LCP_NL_PROCESS_WAIT;
	  break;

	/* reopen the socket if there was an error polling/reading it */
	case NL_EVENT_READ_ERR:
	  lcp_nl_close_socket ();
	  lcp_nl_open_socket (nm->nl_ns.netns_name);
	  break;

	default:
	  NL_ERROR ("process: Unknown event type: %u", (u32) event_type);
	}

      vec_reset_length (event_data);
    }
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (lcp_nl_process_node, static) = {
  .function = lcp_nl_process,
  .name = "linux-cp-netlink-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 17,
};

static int
lcp_nl_callback (struct nl_msg *msg, void *arg)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  nl_msg_info_t *msg_info = 0;

  /* Add messages to a netlink message queue.
   * We do this so that we can process the messages
   * in batches and ensure we periodically read the
   * netlink socket in case more messages are available
   * from the Kernel.
   */
  vec_add2 (nm->nl_ns.nl_msg_queue, msg_info, 1);

  /* store a timestamp for the message */
  msg_info->ts = vlib_time_now (vlib_get_main ());
  msg_info->msg = msg;
  nlmsg_get (msg);

  return 0;
}

static void
lcp_nl_pair_add_cb (lcp_itf_pair_t *lip)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  // NOTE(pim) - this is where we might add multiple filedescriptors, if the
  // lip->lip_namespace is on a namespace we haven't seen before. An issue
  // with the original plugin is that it will only listen to the one namespace
  // noted in startup.conf (linux-cp default netns foo) so interfaces added
  // with a unique namespace (lcp create X host-if e0 netns bar) will not
  // be able to participate in netlink updates.
  // In future work, this plugin should be able to maintain a list of
  // namespaces to listen on, adding/deleting listeners dynamically, ie every
  // time this callback is invoked.
  NL_DBG ("pair_add_cb: %U refcnt %u", format_lcp_itf_pair, lip,
	  nm->nl_ns.clib_file_lcp_refcnt);

  if ((nm->nl_ns.clib_file_lcp_refcnt > 0) &&
      vec_cmp(nm->nl_ns.netns_name, lip->lip_namespace))
    {
      NL_WARN ("pair_add_cb: Existing netlink listener for netns %v -- this "
	       "itf-pair is in netns %v, will not be listened!",
	       nm->nl_ns.netns_name, lip->lip_namespace);
      return;
    }

  nm->nl_ns.clib_file_lcp_refcnt++;
  if (nm->nl_ns.clib_file_index == ~0)
    {
      NL_INFO ("pair_add_cb: Adding netlink listener for %U",
	       format_lcp_itf_pair, lip);
      lcp_nl_open_socket (lip->lip_namespace);
    }
}

static void
lcp_nl_pair_del_cb (lcp_itf_pair_t *lip)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  // See NOTE in lcp_nl_pair_add_cb().
  NL_DBG ("pair_del_cb: %U refcnt %u", format_lcp_itf_pair, lip,
	  nm->nl_ns.clib_file_lcp_refcnt);

  nm->nl_ns.clib_file_lcp_refcnt--;
  if (nm->nl_ns.clib_file_lcp_refcnt == 0)
    {
      NL_INFO ("pair_del_cb: Removing netlink listener for %U",
	       format_lcp_itf_pair, lip);
      lcp_nl_close_socket ();
      return;
    }
}

static clib_error_t *
lcp_nl_read_cb (clib_file_t *f)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  int err;

  /* Read until there's an error. Unless the error is ENOBUFS, which means
   * the kernel couldn't send a message due to socket buffer overflow.
   * Continue reading when that happens.
   *
   * libnl translates both ENOBUFS and ENOMEM to NLE_NOMEM. So we need to
   * check return status and errno to make sure we should keep going.
   */
  while ((err = nl_recvmsgs_default (nm->nl_ns.sk_route)) > -1 ||
	 (err == -NLE_NOMEM && errno == ENOBUFS))
    ;
  if (err < 0 && err != -NLE_AGAIN)
    {
      NL_ERROR ("read_cb: Error reading netlink socket (fd %d): %s (%d)",
		f->file_descriptor, nl_geterror (err), err);
      vlib_process_signal_event (vlib_get_main (), lcp_nl_process_node.index,
				 NL_EVENT_READ_ERR, 0);
    }
  else
    {
      /* notify process node */
      vlib_process_signal_event (vlib_get_main (), lcp_nl_process_node.index,
				 NL_EVENT_READ, 0);
    }

  return 0;
}

static clib_error_t *
lcp_nl_error_cb (clib_file_t *f)
{
  NL_ERROR ("error_cb: Error polling netlink socket (fd %d)",
	    f->file_descriptor);

  /* notify process node */
  vlib_process_signal_event (vlib_get_main (), lcp_nl_process_node.index,
			     NL_EVENT_READ_ERR, 0);

  return clib_error_return (0, "Error polling netlink socket %d",
			    f->file_descriptor);
}

static void
lcp_nl_close_socket (void)
{
  lcp_nl_main_t *nm = &lcp_nl_main;

  /* delete existing fd from epoll fd set */
  if (nm->nl_ns.clib_file_index != ~0)
    {
      clib_file_main_t *fm = &file_main;
      clib_file_t *f = clib_file_get (fm, nm->nl_ns.clib_file_index);

      if (f)
	{
	  NL_DBG ("close_socket: Stopping poll of netlink fd %u",
		  f->file_descriptor);
	  fm->file_update (f, UNIX_FILE_UPDATE_DELETE);
	}
      nm->nl_ns.clib_file_index = ~0;
    }

  /* If we created a socket, close/free it */
  if (nm->nl_ns.sk_route)
    {
      NL_DBG ("close_socket: Closing netlink socket %d",
	      nl_socket_get_fd (nm->nl_ns.sk_route));
      nl_socket_free (nm->nl_ns.sk_route);
      nm->nl_ns.sk_route = NULL;
    }
}

static void
lcp_nl_open_socket (u8 *ns)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  int dest_ns_fd = -1, orig_ns_fd = -1;
  int err;

  /* Switch to the correct network namespace, if specified. Otherwise,
   * use the default namespace.
   */
  if (ns == 0 || ns[0] == 0)
    ns = lcp_get_default_ns ();

  if (ns && ns[0] != 0)
    {
      orig_ns_fd = clib_netns_open (NULL /* self */);
      dest_ns_fd = clib_netns_open (ns);
      clib_setns (dest_ns_fd);
      nm->nl_ns.netns_name = vec_dup (ns);
    }

  /* Allocate a new socket for netlink messages.
   * Notifications do not use sequence numbers, disable sequence number
   * checking. Define a callback function, which will be called for each
   * notification received.
   */
  nm->nl_ns.sk_route = nl_socket_alloc ();
  nl_socket_disable_seq_check (nm->nl_ns.sk_route);

  nl_connect (nm->nl_ns.sk_route, NETLINK_ROUTE);

  /* Subscribe to all the 'routing' notifications on the route socket */
  nl_socket_add_memberships (
    nm->nl_ns.sk_route, RTNLGRP_LINK, RTNLGRP_IPV6_IFADDR, RTNLGRP_IPV4_IFADDR,
    RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE, RTNLGRP_NEIGH, RTNLGRP_NOTIFY,
#ifdef RTNLGRP_MPLS_ROUTE /* not defined on CentOS/RHEL 7 */
    RTNLGRP_MPLS_ROUTE,
#endif
    RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE, 0);

  /* Set socket in nonblocking mode and increase buffer sizes */
  nl_socket_set_nonblocking (nm->nl_ns.sk_route);
  err = nl_socket_set_buffer_size (nm->nl_ns.sk_route, nm->rx_buf_size,
				   nm->tx_buf_size);
  if (err != 0)
    {
      NL_ERROR ("open_socket: Failed to set buffer size tx %u rx %u error %s",
		nm->tx_buf_size, nm->rx_buf_size, nl_geterror (err));
    }

  if (dest_ns_fd != -1)
    close (dest_ns_fd);

  if (orig_ns_fd != -1)
    {
      clib_setns (orig_ns_fd);
      close (orig_ns_fd);
    }

  if (nm->nl_ns.clib_file_index == ~0)
    /* add the netlink fd into clib file handler */
    {
      clib_file_t rt_file = {
	.read_function = lcp_nl_read_cb,
	.error_function = lcp_nl_error_cb,
	.file_descriptor = nl_socket_get_fd (nm->nl_ns.sk_route),
	.description = format (0, "linux-cp netlink route socket"),
      };

      nm->nl_ns.clib_file_index = clib_file_add (&file_main, &rt_file);
      NL_DBG ("open_socket: Added netlink file idx %u fd %u ns %s",
	      nm->nl_ns.clib_file_index, rt_file.file_descriptor, ns);
    }
  else
    /* clib file already created and socket was closed due to error */
    {
      clib_file_main_t *fm = &file_main;
      clib_file_t *f = clib_file_get (fm, nm->nl_ns.clib_file_index);

      f->file_descriptor = nl_socket_get_fd (nm->nl_ns.sk_route);
      fm->file_update (f, UNIX_FILE_UPDATE_ADD);
      NL_DBG ("open_socket: Updated netlink file idx %u fd %u ns %s",
	      nm->nl_ns.clib_file_index, f->file_descriptor, ns);
    }

  nl_socket_modify_cb (nm->nl_ns.sk_route, NL_CB_VALID, NL_CB_CUSTOM,
		       lcp_nl_callback, NULL);
  NL_NOTICE ("open_socket: Started poll of netlink fd %d ns %s",
	     nl_socket_get_fd (nm->nl_ns.sk_route), nm->nl_ns.netns_name);
}

#include <vnet/plugin/plugin.h>
clib_error_t *
lcp_nl_init (vlib_main_t *vm)
{
  lcp_nl_main_t *nm = &lcp_nl_main;
  lcp_itf_pair_vft_t nl_itf_pair_vft = {
    .pair_add_fn = lcp_nl_pair_add_cb,
    .pair_del_fn = lcp_nl_pair_del_cb,
  };

  nm->nl_ns.clib_file_index = ~0;
  nm->nl_logger = vlib_log_register_class ("linux-cp", "nl");

  lcp_itf_pair_register_vft (&nl_itf_pair_vft);

  /* Add two FIB sources: one for manual routes, one for dynamic routes
   * See lcp_nl_proto_fib_source() */
  nm->fib_src =
    fib_source_allocate ("lcp-rt", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);
  nm->fib_src_dynamic = fib_source_allocate (
    "lcp-rt-dynamic", FIB_SOURCE_PRIORITY_HI + 1, FIB_SOURCE_BH_API);

  return (NULL);
}

VLIB_INIT_FUNCTION (lcp_nl_init) = {
  .runs_after = VLIB_INITS ("lcp_itf_pair_init", "tuntap_init",
			    "ip_neighbor_init"),
};

#include <vpp/app/version.h>
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Linux Control Plane - Netlink listener",
  .default_disabled = 1,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
