#ifndef __included_l4fw_app_id_h__
#define __included_l4fw_app_id_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include "l4fw/l4fw_types.h"

void l4fw_app_id_update (void *l4fw_pkt_ptr, l4fw_meta_t *l4fw_meta_ptr);

#endif /* __included_l4fw_app_id_h__ */