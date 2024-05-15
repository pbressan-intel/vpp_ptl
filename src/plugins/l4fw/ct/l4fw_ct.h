#ifndef __included_l4fw_ct_h__
#define __included_l4fw_ct_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/buffer.h>

/**
 * @brief The state of a connection
 */
typedef enum l4fw_ct_state_e
{
  L4FW_CT_STATE_NEW,
  L4FW_CT_STATE_ESTABLISHED,
  L4FW_CT_STATE_RELATED
} l4fw_ct_state_t;

/*
 * ----------------------------------------------------------------------------
 * Function Declarations
 * ----------------------------------------------------------------------------
 */

/**
 * @brief Update the state of a connection as needed, and return the
 *      state of the connection after processing the packet.
 * 
 * @param in buffer: a pointer to the L2 (Ethernet) header of the packet
 * @todo Confirm if this is in fact the L2 or L3 layer, or what?!
 * 
 * @returns l4fw_conntrack_state_t: the state of the connection after
 *      processing the packet.
 */
l4fw_ct_state_t l4fw_ct_update(vlib_buffer_t* buffer);

/**
 * @brief The size of the CT flow table.
 * @returns number of entries in CT flow table.
 */
u64 l4fw_ct_count_entries ();

#endif /* __included_l4fw_ct_h__ */