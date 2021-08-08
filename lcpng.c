/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

#include <sched.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <net/if.h>

#include <plugins/lcpng/lcpng.h>

lcp_main_t lcp_main;

u8 *
lcp_get_netns (void)
{
  lcp_main_t *lcpm = &lcp_main;

  if (lcpm->netns_name[0] == 0)
    return 0;
  return lcpm->netns_name;
}

int
lcp_get_netns_fd (void)
{
  lcp_main_t *lcpm = &lcp_main;

  return lcpm->netns_fd;
}

/*
 * ns is expected to be or look like a NUL-terminated C string.
 */
int
lcp_set_netns (u8 *ns)
{
  lcp_main_t *lcpm = &lcp_main;
  char *p;
  int len;
  u8 *s;

  p = (char *) ns;
  len = clib_strnlen (p, LCP_NS_LEN);
  if (len >= LCP_NS_LEN)
    return -1;

  if (!p || *p == 0)
    {
      clib_memset (lcpm->netns_name, 0,
		   sizeof (lcpm->netns_name));
      if (lcpm->netns_fd > 0)
	close (lcpm->netns_fd);
      lcpm->netns_fd = 0;
      return 0;
    }

  clib_strncpy ((char *) lcpm->netns_name, p, LCP_NS_LEN - 1);

  s = format (0, "/var/run/netns/%s%c", (char *) lcpm->netns_name, 0);
  lcpm->netns_fd = open ((char *) s, O_RDONLY);
  vec_free (s);

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
