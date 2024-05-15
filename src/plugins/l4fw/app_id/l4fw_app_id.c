#include "l4fw_app_id.h"
#include "l4fw/l4fw_utils.h"

/**
 * @brief Generate dummy app IDs for testing purposes.
 * Map TCP destination port to a predefined app ID string (80=>"HTTP app1",
 * 81=>"HTTP app2", other=>"TCP", non-TCP/IP=>"none").
 */
void
l4fw_app_id_update (void *l4fw_pkt_ptr, l4fw_meta_t *l4fw_meta_ptr)
{
  ethernet_header_t *eth = (ethernet_header_t *) l4fw_pkt_ptr;
  ip4_header_t *ip4 = (ip4_header_t *) (eth + 1);

  if (clib_net_to_host_u16 (eth->type) != ETHERNET_TYPE_IP4 ||
      ip4->protocol != IP_PROTOCOL_TCP)
    {
      strcpy (l4fw_meta_ptr->app_id, "none");
      return;
    }

  tcp_header_t *tcp = (tcp_header_t *) get_ip_payload (ip4);
  u16 dport = clib_net_to_host_u16 (tcp->dst_port);

  int n;
  if (dport == 80 || dport == 81)
    // Distinguish app1/app2 based on dport.
    n = snprintf (l4fw_meta_ptr->app_id, L4FW_MAX_APP_ID_LEN, "HTTP app%d",
		  dport - 79);
  else
    n = snprintf (l4fw_meta_ptr->app_id, L4FW_MAX_APP_ID_LEN, "TCP");
  ASSERT (0 <= n && n < L4FW_MAX_APP_ID_LEN);
}