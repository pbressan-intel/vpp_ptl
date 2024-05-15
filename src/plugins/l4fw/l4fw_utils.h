#ifndef __included_l4fw_utils_h__
#define __included_l4fw_utils_h__
#include <stdio.h>
#include <vppinfra/types.h>
#include <vnet/ip/ip.h>

int min(int a, int b);
int max(int a, int b);

int l4fw_ipv4_addr_format (char *s, size_t size, u32 ip);

u32 make_ipv4_mask (u8 prefix_len);

static inline u8 *
get_ip_payload (ip4_header_t *ip4)
{
  return (((u8 *) ip4) + ((ip4->ip_version_and_header_length & 0xf) << 2));
}

#endif // __included_l4fw_utils_h__
