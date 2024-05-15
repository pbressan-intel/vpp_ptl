#include <malloc.h>
#include <assert.h>

#include "l4fw_ct_internal.h"
#include "l4fw/l4fw_utils.h" // for min, max functions

/*
 * Debug code to validate parsing of packet headers
 *
 * #define this to include a printout of header information
 * 
 * Note that this will be printed for every packet, so this should only
 * be enabled for debug purposes!
 */
#undef L4FW_DBG_TMP
//#define L4FW_DBG_TMP

#ifdef L4FW_DBG_TMP
static void
l4fw_ct_dbg_print_header(
  char *header_name, 
  u32 header_len,
  unsigned char *bytes)
{
  int i;

  printf("%12s (%02u): ", header_name, header_len);
  for (i=0; i<header_len; i++) {
    printf("%02x, ", bytes[i]);
  }
  printf("\n");
}

static void 
l4fw_ct_dbg_print_buffer(vlib_buffer_t *h)
{
  printf("L4FW_DBG_TMP start\n");

  ethernet_header_t *eth = (ethernet_header_t *) h;
  ip4_header_t *ip4 = (ip4_header_t *) (eth + 1);
  tcp_header_t *tcp = (tcp_header_t *) (ip4 + 1);

  printf("Protocol: %u\n", ip4->protocol);
  printf("IP addresses: %08x, %08x\n", ip4->src_address.as_u32, ip4->dst_address.as_u32);
  printf("TCP port numbers: %hu, %hu\n", tcp->src_port, tcp->dst_port);
  printf("Bytes:\n");

  unsigned char *byte = (unsigned char *) h;
  int i = 0;

  for (i=0; i<64; i++) {
    printf("%02x, ", byte[i]);
    if (((i+1) % 8) == 0)
      printf("\n");
  }

  l4fw_ct_dbg_print_header("Ethernet", sizeof(ethernet_header_t), (unsigned char *) eth);
  l4fw_ct_dbg_print_header("IPv4", sizeof(ip4_header_t), (unsigned char *) ip4);
  l4fw_ct_dbg_print_header("TCP", sizeof(tcp_header_t), (unsigned char *) tcp);

  printf("L4FW_DBG_TMP end\n");
}
#endif

/*
 * @brief State names. Ensure same order as corresponding enum.
 */
char* l4fw_ct_state_str[] = {
  "L4FW_CT_STATE_NEW",
  "L4FW_CT_STATE_ESTABLISHED",
  "L4FW_CT_STATE_RELATED"
};

/**
 * @brief The flow table
 *
 * For now, this is a simple linked list.
 *
 * @todo Make this a hash table
 *
 * @todo This is currently a global. This likely needs to be per-worker
 * thread, as each thread will see different flows and maintain its own
 * flow table. Which also means we need to use a symmetric RSS key in
 * the NIC to ensure both directions of a flow go to the same thread.
 * Need to think on this some more!
 */
l4fw_ct_flow_entry_t *flow_entries = NULL;

/**
 * @brief The size of the flow table.
 *
 * This just reflect the number of entries in \p flow_entries . It should be
 * incremented/decremented as entries are added/removed.
 */
u64 flow_entries_cnt = 0;

/**
 * @brief Extract the flow 5-tuple from the packet header, as well as
 * the 2-tuple for the source of the flow.
 * 
 * @return 0 if no error
 * @return -1 if packet is not IPv4
 * @todo Extend the return codes as required and check for BKMs here
 */
static int
l4fw_ct_extract_tuples(
  vlib_buffer_t *buffer,
  l4fw_ct_5tuple_t *tuple,
			l4fw_ct_2tuple_t *src)
{
  int ret_code = 0;
  u16 ethertype;
  u8 proto;
  u32 src_addr, dst_addr, min_addr, max_addr;
  u16 src_port, dst_port, min_port, max_port;

#ifdef L4FW_DBG_TMP
  l4fw_ct_dbg_print_buffer(buffer);
#endif

  ethertype = L4FW_CT_GET_ETHERTYPE(buffer);
  // For now, just return an error if not IPv4
  // @todo Extend for IPv6
  if (ethertype != L4FW_CT_ETHERTYPE_IPV4) {
    // Log an error message
    // @todo For now use printf; replace with correct logging
    // XXX(tjepsen): I disabled this printf because it causes confusion for Demo 1.
    // printf ("WARNING (%s:%d): Non-IPv4 packet seen, not handled yet\n",
	  //   __FILE__, __LINE__);
    ret_code = -1;
    goto end;
  }

  // extract the IP addresses and port numbers, and sort them so that
  // the 5-tuple is the same for both directions

  src_addr = L4FW_CT_GET_IP4_SADDR(buffer);
  dst_addr = L4FW_CT_GET_IP4_DADDR(buffer);
  min_addr = min(src_addr, dst_addr);
  max_addr = max(src_addr, dst_addr);

  proto = L4FW_CT_GET_IP4_PROTO(buffer);
  switch (proto) {
  case IP_PROTOCOL_TCP:
  case IP_PROTOCOL_UDP:
    src_port = L4FW_CT_GET_TCP_SPORT(buffer);
    dst_port = L4FW_CT_GET_TCP_DPORT(buffer);
    min_port = min(src_port, dst_port);
    max_port = max(src_port, dst_port);
    break;

  case IP_PROTOCOL_ICMP:
    // For now, just use a 3-tuple for ICMP, which is fine for ping. 
    // For ICMP error messages, we should extract the port numbers too.
    // @todo Extend to support ICMP error messages
    src_port = 0;
    min_port = 0;
    max_port = 0;
    break;

  default:
    // For now, assert always for other protocols
    // @todo Extend for other protocols
    assert(false);
    break;
  }


  tuple->l3.proto = proto; 
  tuple->l3.ip4_addr[0].as_u32 = min_addr;
  tuple->l3.ip4_addr[1].as_u32 = max_addr;
  tuple->l4.port[0] = min_port;
  tuple->l4.port[1] = max_port;

  // Extract the client 2-tuple from the packet header
  src->l3.ip4_addr.as_u32 = src_addr;
  src->l4.port = src_port;

end:
  return ret_code;
}

/*
 * @brief Compare two 5-tuples to see if they match
 *
 * @param tuple1, tuple2 are the 5-tuples
 *
 * @returns TRUE if they match, FALSE otherwise
 */
static bool l4fw_ct_5tuple_match(
  l4fw_ct_5tuple_t *tuple1,
  l4fw_ct_5tuple_t *tuple2)
{
  bool match = (
    (tuple1->l3.proto == tuple2->l3.proto) &&
    (tuple1->l3.ip4_addr[0].as_u32 == tuple2->l3.ip4_addr[0].as_u32) &&
    (tuple1->l3.ip4_addr[1].as_u32 == tuple2->l3.ip4_addr[1].as_u32) &&
    (tuple1->l4.port[0] == tuple2->l4.port[0]) &&
    (tuple1->l4.port[1] == tuple2->l4.port[1])
  );

  return match;
}

/*
 * @brief Do a "deep copy" of the fields from tuple2 to tuple1
 * (i.e. tuple1 = tuple2)
 *
 * @param tuple1, tuple2 are the 5-tuples
 */
static void
l4fw_ct_5tuple_copy(
  l4fw_ct_5tuple_t *tuple1,
  l4fw_ct_5tuple_t *tuple2)
{
  tuple1->l3.proto = tuple2->l3.proto;
  tuple1->l3.ip4_addr[0].as_u32 = tuple2->l3.ip4_addr[0].as_u32;
  tuple1->l3.ip4_addr[1].as_u32 = tuple2->l3.ip4_addr[1].as_u32;
  tuple1->l4.port[0] = tuple2->l4.port[0];
  tuple1->l4.port[1] = tuple2->l4.port[1];
}

/*
 * @brief Compare two 2-tuples to see if they match
 *
 * @param tuple1, tuple2 are the 2-tuples
 *
 * @returns TRUE if they match, FALSE otherwise
 */
static bool l4fw_ct_2tuple_match(
  l4fw_ct_2tuple_t *tuple1,
  l4fw_ct_2tuple_t *tuple2)
{
  bool match = (
      (tuple1->l3.ip4_addr.as_u32 == tuple2->l3.ip4_addr.as_u32) &&
		(tuple1->l4.port == tuple2->l4.port)
    );

  return match;
}

/*
 * @brief Do a "deep copy" of the fields from tuple2 to tuple1
 * (i.e. tuple1 = tuple2)
 *
 * @param tuple1, tuple2 are the 2-tuples
 */
static void
l4fw_ct_2tuple_copy(
  l4fw_ct_2tuple_t *tuple1,
  l4fw_ct_2tuple_t *tuple2)
{
  tuple1->l3.ip4_addr.as_u32 = tuple2->l3.ip4_addr.as_u32;
  tuple1->l4.port = tuple2->l4.port;
}

/*
 * @brief Lookup table
 *
 * @param in tuple: the 5-tuple for the flow
 * @param out flow_entry: points to the flow entry, or 0 if not found
 */
static void 
l4fw_ct_lookup(
  l4fw_ct_5tuple_t *tuple,
  l4fw_ct_flow_entry_t **flow_entry
)
{
  l4fw_ct_flow_entry_t *curr_entry = flow_entries;

  while (curr_entry) {
    if (l4fw_ct_5tuple_match(tuple, &curr_entry->flow->tuple)) {
        *flow_entry = curr_entry;
        break;
      }
    curr_entry = curr_entry->next;
  }
}

/*
 * @brief Add entry to table
 *
 * @param in tuple: the 5-tuple for the flow
 * @param in flow_entry: points to the new flow entry
 */
static void
l4fw_ct_add(
  l4fw_ct_5tuple_t *tuple,
  l4fw_ct_flow_entry_t *flow_entry
)
{
  // @todo Replace assertion with error check and return status vs. void
  assert(flow_entry);

  // add entry to start of table, and link to next entry
  flow_entry->next = flow_entries;
  flow_entries = flow_entry;
  flow_entries_cnt++;
}

/*
 * @brief Lookup the flow in the flow table. If it doesn't exist, create
 * a new flow. Then populate the flow  and the direction of the
 * unidirectional flow to which the specific packet belongs. This
 * function also updates the state of the flow.
 */
static void
l4fw_ct_lookup_or_create_flow(
  l4fw_ct_5tuple_t *tuple,
  l4fw_ct_2tuple_t *src,
	l4fw_ct_unidir_flow_t *uflow
)
{
  l4fw_ct_flow_t *flow = 0;
  l4fw_ct_direction_t direction = L4FW_CT_DIRECTION_FORWARD;
  // the existing flow entry found, or the new flow entry
  l4fw_ct_flow_entry_t *flow_entry = 0;
  // pointer to the previous entry's "next" pointer, or (by default) 
  // the start of the table

  // Search the flow table for this flow (i.e., matching 5-tuple)
  // @todo Move to hash-based implementation
  // For now, just walk the linked list (ridiculously poor performance
  // for more than a handful of flows!!!)
  l4fw_ct_lookup(tuple, &flow_entry);

  if (flow_entry) {
    flow = flow_entry->flow;
  }
  else {
    // No flow found, so create one and add it to the end of the table

    // create and populate the flow
    // @todo Allocate from a pool for better performance
    // @todo The memory will be freed (or returned to the pool) by the
    // state machine when the connection closes.
    flow = (l4fw_ct_flow_t *) malloc (sizeof (l4fw_ct_flow_t));
    l4fw_ct_5tuple_copy (&flow->tuple, tuple);
    l4fw_ct_2tuple_copy (&flow->first_pkt, src);

    flow->state = L4FW_CT_STATE_NEW;

    // create and populate the flow entry
    flow_entry = (l4fw_ct_flow_entry_t *) malloc (sizeof (l4fw_ct_flow_entry_t));
    flow_entry->flow = flow;
    flow_entry->next = 0;

    // update the previous table entry, or the "flow entries" table
    // pointer itself, to point to this new entry
    l4fw_ct_add(tuple, flow_entry);
  }

  // Determine the direction
  if (l4fw_ct_2tuple_match(src, &flow->first_pkt))
    direction = L4FW_CT_DIRECTION_FORWARD;
  else {
    direction = L4FW_CT_DIRECTION_REVERSE;
    // Because we've now seen a reverse packet, we should also change
    // (or leave) the state of the flow as ESTABLISHED
    flow->state = L4FW_CT_STATE_ESTABLISHED;
    // @todo Reset timer
  }

  // Populate the return values
  uflow->flow = flow;
  uflow->direction = direction;
}

l4fw_ct_state_t
l4fw_ct_update_internal (
  void *buffer)
{
  int ret_code = 0;
  l4fw_ct_state_t state = L4FW_CT_STATE_NEW;
  l4fw_ct_5tuple_t tuple;
  l4fw_ct_2tuple_t src;
  l4fw_ct_unidir_flow_t uflow;

  ret_code = l4fw_ct_extract_tuples(buffer, &tuple, &src);

  if (ret_code == 0) {
    l4fw_ct_lookup_or_create_flow(&tuple, &src, &uflow);

    // @todo Extract the TCP flags from the packet header
    // @todo For now, not using TCP flags
    // tcp_flags = l4fw_get_tcp_flags(buffer);

    // Note that the connection state is already updated above
    state = uflow.flow->state;
  }

  // Return the state
  return state;
}

/*
 * @brief Print out the flow table as maintained by Connection Tracking component
 */
void
l4fw_ct_dbg_print_table()
{
  l4fw_ct_flow_entry_t *curr_entry = flow_entries;
  l4fw_ct_flow_t *flow = 0;
  int entry_num = 0;

  // Print header
  printf("%6s, %32s, %6s, %10s, %10s, %8s, %8s\n",
    "num", 
    "state", 
    "proto", 
    "min_ip", 
    "max_ip", 
    "min_port", 
    "max_port");

  while (curr_entry)
  {
    flow = curr_entry->flow;
    // @todo Update for non-IPv4, non-TCP/UDP
    printf("%6d, %32s, %6u, 0x%08x, 0x%08x, %8u, %8u\n",
      entry_num++,
      l4fw_ct_state_str[flow->state],
      flow->tuple.l3.proto,
      flow->tuple.l3.ip4_addr[0].as_u32,
      flow->tuple.l3.ip4_addr[1].as_u32,
      flow->tuple.l4.port[0],
      flow->tuple.l4.port[1]);

    curr_entry = curr_entry->next;
  }
}