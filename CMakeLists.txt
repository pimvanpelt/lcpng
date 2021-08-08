# Copyright (c) 2020 Cisco and/or its affiliates.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

vpp_find_path(LIBNL3_INCLUDE_DIR NAMES libnl3/netlink/route/link/vlan.h)

if (NOT LIBNL3_INCLUDE_DIR)
  message(WARNING "-- libnl3 headers not found - lcpng plugin disabled")
  return()
endif()

vpp_plugin_find_library(lcpng LIBNL3_LIB libnl-3.so)
vpp_plugin_find_library(lcpng LIBNL3_ROUTE_LIB libnl-route-3.so.200)

include_directories(${LIBNL3_INCLUDE_DIR}/libnl3)
include_directories(${LIBMNL_INCLUDE_DIR})

add_vpp_library(lcpng
  SOURCES
  lcpng_interface.c
  lcpng_adj.c
  lcpng.c

  LINK_LIBRARIES
  ${LIBNL3_LIB}
  ${LIBNL3_ROUTE_LIB}

  INSTALL_HEADERS
  lcpng_interface.h
  lcpng.h
)

add_vpp_plugin(lcpng_if
  SOURCES
  lcpng_if_api.c
  lcpng_if_cli.c
  lcpng_if_node.c

  API_FILES
  lcpng_if.api

  LINK_LIBRARIES
  lcpng
)

add_vpp_plugin(lcpng_unittest
  SOURCES
  test/lcpng_unittest.c

  LINK_LIBRARIES
  lcpng
)
