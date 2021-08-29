/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>
#include <plugins/lcpng/lcpng.h>

#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/addr.h>
#include <netlink/route/link/vlan.h>

#include <vnet/fib/fib_table.h>
#include <vnet/mfib/mfib_table.h>

typedef enum nl_event_type_t_
{
  NL_EVENT_READ,
  NL_EVENT_READ_ERR,
} nl_event_type_t;

#define NL_RX_BUF_SIZE_DEF    (1 << 27) /* 128 MB */
#define NL_TX_BUF_SIZE_DEF    (1 << 18) /* 256 kB */
#define NL_BATCH_SIZE_DEF     (1 << 11) /* 2048 */
#define NL_BATCH_DELAY_MS_DEF 50	/* 50 ms, max 20 batch/s */

#define NL_DBG(...)    vlib_log_debug (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_INFO(...)   vlib_log_info (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_NOTICE(...) vlib_log_notice (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_WARN(...)   vlib_log_warn (lcp_nl_main.nl_logger, __VA_ARGS__);
#define NL_ERROR(...)  vlib_log_err (lcp_nl_main.nl_logger, __VA_ARGS__);

/* struct type to hold context on the netlink message being processed.
 */
typedef struct nl_msg_info
{
  struct nl_msg *msg;
  f64 ts;
} nl_msg_info_t;

typedef struct lcp_nl_netlink_namespace
{
  struct nl_sock *sk_route;
  nl_msg_info_t *nl_msg_queue;
  uword clib_file_index;    // clib file that holds the netlink socket for this
			    // namespace
  u32 clib_file_lcp_refcnt; // number of interfaces watched in the this netlink
			    // namespace
  u8 netns_name[LCP_NS_LEN]; // namespace name (can be empty, for 'self')
} lcp_nl_netlink_namespace_t;

typedef struct lcp_nl_table_t_
{
  uint32_t nlt_id;
  fib_protocol_t nlt_proto;
  u32 nlt_fib_index;
  u32 nlt_mfib_index;
  u32 nlt_refs;
} lcp_nl_table_t;

typedef struct lcp_nl_main
{
  vlib_log_class_t nl_logger;
  /* TODO(pim): nl_ns should become a list, one for each unique namespace we
   * created LCP pairs in.
   */
  lcp_nl_netlink_namespace_t nl_ns;

  fib_source_t fib_src; // For static routes set manually
  fib_source_t
    fib_src_dynamic; // For routes set by routing software (Bird, FRR, etc)
  uword *table_db[FIB_PROTOCOL_MAX];
  lcp_nl_table_t *table_pool;

  u32 rx_buf_size;
  u32 tx_buf_size;
  u32 batch_size;
  u32 batch_delay_ms;

} lcp_nl_main_t;

extern lcp_nl_main_t lcp_nl_main;

typedef struct lcp_nl_route_path_parse_t_
{
  fib_route_path_t *paths;
  fib_protocol_t route_proto;
  bool is_mcast;
  fib_route_path_flags_t type_flags;
  u8 preference;
} lcp_nl_route_path_parse_t;

u8 *format_nl_object (u8 *s, va_list *args);

/* Functions from lcpng_nl_sync.c
 */
void lcp_nl_neigh_add (struct rtnl_neigh *rn);
void lcp_nl_neigh_del (struct rtnl_neigh *rn);
void lcp_nl_addr_add (struct rtnl_addr *ra);
void lcp_nl_addr_del (struct rtnl_addr *ra);
void lcp_nl_link_add (struct rtnl_link *rl, void *ctx);
void lcp_nl_link_del (struct rtnl_link *rl);
void lcp_nl_route_add (struct rtnl_route *rr);
void lcp_nl_route_del (struct rtnl_route *rr);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
