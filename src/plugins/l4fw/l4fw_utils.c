#include "l4fw_utils.h"

int min(int a, int b)
{
    return (a < b) ? a : b;
}

int max(int a, int b)
{
    return (a > b) ? a : b;
}

int
l4fw_ipv4_addr_format (char *s, size_t size, u32 ip)
{
  return snprintf (s, size, "%d.%d.%d.%d", ip & 0xFF, ip >> 8 & 0xFF,
		   ip >> 16 & 0xFF, ip >> 24 & 0xFF);
}

u32
make_ipv4_mask (u8 prefix_len)
{
  u32 mask = ~0;
  return mask << (32 - prefix_len);
}