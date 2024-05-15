#ifndef __included_l4fw_types_h__
#define __included_l4fw_types_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include "ct/l4fw_ct.h"

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//                        L4FW COMMON TYPES
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#define L4FW_MAX_APP_ID_LEN 64

/**
 * @brief L4FW metadata.
 */
typedef struct
{
  // state of the connection
  l4fw_ct_state_t ct_state;
  char app_id[L4FW_MAX_APP_ID_LEN];
} l4fw_meta_t;

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#endif /* __included_l4fw_types_h__ */