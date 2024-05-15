#ifndef __included_l4fw_ct_internal_h__
#define __included_l4fw_ct_internal_h__

// @todo Find a "standard" definition of this value somewhere, similar to 
// how IP_PROTOCOL_TCP, etc. are defined
#define L4FW_CT_ETHERTYPE_IPV4 0x0800

#include "l4fw/ct/l4fw_ct.h"

// Declare the string represenation of the state
// @todo Fix the constant (low priority). Assume no more than 8 states
// for now. (Only 3 at time of writing!)
extern char* l4fw_ct_state_str[8];

#ifdef L4FW_CT_TESTING
typedef struct l4fw_ct_test_hdr_s
{
  u16 ethertype;
  u8 protocol; // IPv4 protocol or IPv6 next_header
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
} l4fw_ct_test_hdr_t;

// Accessors for the opaque header
#define L4FW_CT_GET_ETHERTYPE(h) (((l4fw_ct_test_hdr_t *)(h))->ethertype)
#define L4FW_CT_GET_IP4_PROTO(h) (((l4fw_ct_test_hdr_t *)(h))->protocol)
#define L4FW_CT_GET_IP4_SADDR(h) (((l4fw_ct_test_hdr_t *)(h))->saddr)
#define L4FW_CT_GET_IP4_DADDR(h) (((l4fw_ct_test_hdr_t *)(h))->daddr)
#define L4FW_CT_GET_TCP_SPORT(h) (((l4fw_ct_test_hdr_t *)(h))->sport)
#define L4FW_CT_GET_TCP_DPORT(h) (((l4fw_ct_test_hdr_t *)(h))->dport)

#else // !L4FW_CT_TESTING

// Accessors for the opaque header
#define __L4FW_CT_GET_ETH(h) ((ethernet_header_t *) h)
#define __L4FW_CT_GET_IP(h) ((ip4_header_t *)(((ethernet_header_t *) h)+1))
#define __L4FW_CT_GET_TCP(h) ((tcp_header_t *)(get_ip_payload(__L4FW_CT_GET_IP(h))))

#define L4FW_CT_GET_ETHERTYPE(h) clib_net_to_host_u16(__L4FW_CT_GET_ETH(h)->type)
#define L4FW_CT_GET_IP4_PROTO(h) (__L4FW_CT_GET_IP(h)->protocol)
#define L4FW_CT_GET_IP4_SADDR(h) (__L4FW_CT_GET_IP(h)->src_address.data_u32)
#define L4FW_CT_GET_IP4_DADDR(h) (__L4FW_CT_GET_IP(h)->dst_address.data_u32)
#define L4FW_CT_GET_TCP_SPORT(h) clib_net_to_host_u16((__L4FW_CT_GET_TCP(h)->src_port))
#define L4FW_CT_GET_TCP_DPORT(h) clib_net_to_host_u16((__L4FW_CT_GET_TCP(h)->dst_port))

#endif // L4FW_CT_TESTING


/*
 * @brief 5-tuple
 *
 * Note that the 5-tuple is used to store the IP addresses and port numbers
 * in "numerical order", such that it is identical for both directions of a
 * bidirectional flow.
 */
typedef struct l4fw_ct_5tuple_s {
  struct {
    union {
      ip4_address_t ip4_addr[2];
      ip6_address_t ip6_addr[2];
    };
    u8 proto;
  } l3;
  struct {
    u16 port[2];
  } l4;
} l4fw_ct_5tuple_t;

/*
 * @brief 2-tuple
 *
 * This is used to identify the IP address and port number of one "end" of
 * a flow, so that we can distinguish the two directions of a bidirectional
 * flow.
 */
typedef struct l4fw_ct_2tuple_s {
  union {
    ip4_address_t ip4_addr;
    ip6_address_t ip6_addr;
  } l3;
  struct {
    u16 port;
  } l4;
} l4fw_ct_2tuple_t;


/*
 * @brief Flow data structure. 
 *
 * Note that flows are bidirectional by default; when we mean a
 * unidirectional flows, we explicitly refer to them as
 * unidirectional.
 */
typedef struct l4fw_ct_flow_s {
  l4fw_ct_5tuple_t tuple;
  l4fw_ct_2tuple_t first_pkt; // IP address and port number of the first packet seen
  l4fw_ct_state_t state;
} l4fw_ct_flow_t;

/*
 * @brief Flow entry is the data structure that is used for maintaining
 * the linked list.
 * 
 * @todo This will likely disappear when we move to a hash table 
 * implementaiton.
 */
typedef struct l4fw_ct_flow_entry_s {
  l4fw_ct_flow_t *flow;
  struct l4fw_ct_flow_entry_s *next;
} l4fw_ct_flow_entry_t;

/**
 * @brief The (global) flow entries table.
 *
 * @todo Fix so this is not a global!
 */
extern l4fw_ct_flow_entry_t *flow_entries;

/**
 * @brief The (global) flow entries table size.
 *
 * @todo Fix so this is not a global!
 */
extern u64 flow_entries_cnt;

/*
 * @brief Direction of a unidirectional flow. The first packet we see
 * defines the FORWARD direction.
 *
 * For a typical TCP flow where we see the SYN, SYN+ACK, ACK handshake, 
 * the first packet we see will be the SYN going upstream from the client
 * to the server, so this will be the FORWARD direction. 
 * 
 * For flows which were already in flight, we may see a downstream packet
 * first, making this the FORWARD direction. This doesn't affect the state
 * machine: all that matters is that we move to the NEW state once we see
 * traffic in one direction (forward or reverse), and we move to the 
 * ESTABLISHED state once we see traffic in the other direction.
 */
typedef enum {
  L4FW_CT_DIRECTION_FORWARD,
  L4FW_CT_DIRECTION_REVERSE
} l4fw_ct_direction_t;

/*
 * @brief Unidirectional flow data structure
 */
typedef struct l4fw_ct_unidir_flow_s {
  l4fw_ct_flow_t *flow;
  l4fw_ct_direction_t direction;
} l4fw_ct_unidir_flow_t;



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
l4fw_ct_state_t l4fw_ct_update_internal(void *buffer);

/*
 * @brief Print out the table for debug purposes
 */
void
l4fw_ct_dbg_print_table();


#endif /* __included_l4fw_ct_internal_h__ */