#ifndef __included_l4fw_ct_test_h__
#define __included_l4fw_ct_test_h__

#include "l4fw/ct/l4fw_ct_internal.h"

// define some default subnets (10.10.1.0/24 and 10.10.2.0/24)
#define L4FW_CT_LAN_SUBNET 0x0a0a0100
#define L4FW_CT_WAN_SUBNET 0x0a0a0200

// macro to define the address of a client or server on a given subnet
#define L4FW_CT_LAN_ADDR(i) L4FW_CT_LAN_SUBNET+i
#define L4FW_CT_WAN_ADDR(i) L4FW_CT_WAN_SUBNET+i

/*
 * @brief Test case definition
 *
 * Each test case consists of:
 * - a short name for the test case
 * - a definition of the packet header
 * - the expected state of the corresponding flow after the packet has 
 *   been processed
 */
typedef struct l4fw_ct_test_case_s {
  char* name;
  l4fw_ct_test_hdr_t pkt;
  l4fw_ct_state_t state;
} l4fw_ct_test_case_t;

#endif // __included_l4fw_ct_test_h__
