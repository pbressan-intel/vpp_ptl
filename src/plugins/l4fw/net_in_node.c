/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vnet/ethernet/ethernet.h>
#include <vppinfra/error.h>
#include <l4fw/l4fw.h>

// highlight the plugin node in the trace
#define TRACE_BEGIN "---------- L4FW_NODE - BEGIN ----------"
#define TRACE_END "---------- L4FW_NODE - END ----------"

// PACKET TRACE:
// tracing information
typedef struct
{
  char trace_begin[50];
  char trace_end[50];
  u32 next_index;
  u32 sw_if_index;
  u16 ethertype;
} l4fw_trace_t;

// PACKET TRACE:
// function to display the trace
static u8 *
format_l4fw_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  l4fw_trace_t *t = va_arg (*args, l4fw_trace_t *);

  s = format (s, "%s\n", t->trace_begin);
  s = format (s, "l4fw: sw_if_index %d, next index %d\n",
	      t->sw_if_index, t->next_index);
  s = format (s, "  ethertype=0x%x\n", t->ethertype);
  s = format (s, "%s", t->trace_end);

  return s;
}

extern vlib_node_registration_t l4fw_node;

#define foreach_l4fw_error \
_(COUNTER, "Generic counter.") \
_(DROPPED, "Dropped by callback.") \

typedef enum
{
#define _(sym,str) L4FW_ERROR_##sym,
  foreach_l4fw_error
#undef _
    L4FW_N_ERROR,
} l4fw_error_t;

static char *l4fw_error_strings[] = {
#define _(sym,string) string,
  foreach_l4fw_error
#undef _
};

// PROCESS PACKET VECTORS
VLIB_NODE_FN (l4fw_node) (vlib_main_t * vm, vlib_node_runtime_t * node,
			    vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  l4fw_hook_point_net_in_next_t next_index;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;
      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

	// ******************************************
	// PROCESS 4 PACKETS IN PARALLEL
	// ******************************************
      while (n_left_from >= 8 && n_left_to_next >= 4)
	{
	  u32 bi0, bi1, bi2, bi3;
	  vlib_buffer_t *b0, *b1, *b2, *b3;
	  u32 next0, next1, next2, next3;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p4, *p5, *p6, *p7;
	    p4 = vlib_get_buffer (vm, from[4]);
	    p5 = vlib_get_buffer (vm, from[5]);
	    p6 = vlib_get_buffer (vm, from[6]);
	    p7 = vlib_get_buffer (vm, from[7]);
	    vlib_prefetch_buffer_header (p4, LOAD);
	    vlib_prefetch_buffer_header (p5, LOAD);
	    vlib_prefetch_buffer_header (p6, LOAD);
	    vlib_prefetch_buffer_header (p7, LOAD);
	    clib_prefetch_store (p4->data);
	    clib_prefetch_store (p5->data);
	    clib_prefetch_store (p6->data);
	    clib_prefetch_store (p7->data);
	  }

	  /* speculatively enqueue b0 to b3 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  to_next[2] = bi2 = from[2];
	  to_next[3] = bi3 = from[3];
	  from += 4;
	  to_next += 4;
	  n_left_from -= 4;
	  n_left_to_next -= 4;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  b2 = vlib_get_buffer (vm, bi2);
	  b3 = vlib_get_buffer (vm, bi3);
	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);
	  ASSERT (b2->current_data == 0);
	  ASSERT (b3->current_data == 0);
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);
	  vnet_feature_next (&next2, b2);
	  vnet_feature_next (&next3, b3);

	  // ---------------------------------------------------
	  // PACKET PROCESSING - BEGIN
	  // ---------------------------------------------------
	  // extract ETH hdr
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  ethernet_header_t *eh1 = vlib_buffer_get_current (b1);
	  ethernet_header_t *eh2 = vlib_buffer_get_current (b2);
	  ethernet_header_t *eh3 = vlib_buffer_get_current (b3);
	  // extract ETH type
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);
	  u16 ethertype1 = clib_net_to_host_u16 (eh1->type);
	  u16 ethertype2 = clib_net_to_host_u16 (eh2->type);
	  u16 ethertype3 = clib_net_to_host_u16 (eh3->type);
	  // ===================================================
	  // HOOK POINT: net-in
	  l4fw_meta_t l4fw_meta0;
	  l4fw_meta_t l4fw_meta1;
	  l4fw_meta_t l4fw_meta2;
	  l4fw_meta_t l4fw_meta3;
      // L4FW-TODO: register pointer(s) to l4fw_meta into the vlib buffer
	  next0 = l4fw_hook_point_net_in(vlib_buffer_get_current (b0), &l4fw_meta0);
	  next1 = l4fw_hook_point_net_in(vlib_buffer_get_current (b1), &l4fw_meta1);
	  next0 = l4fw_hook_point_net_in(vlib_buffer_get_current (b2), &l4fw_meta2);
	  next1 = l4fw_hook_point_net_in(vlib_buffer_get_current (b3), &l4fw_meta3);
	  // ===================================================
	  // increment the node pkt counter
	  vlib_node_increment_counter (vm, l4fw_node.index,
				       L4FW_ERROR_COUNTER, 4);
      // PACKET TRACE:
	  // if tracing is active ==> add data to the trace
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l4fw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
		  strcpy(t->trace_begin, TRACE_BEGIN);
		  strcpy(t->trace_end, TRACE_END);
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->next_index = next0;
	      t->ethertype = ethertype0;
	    }
	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l4fw_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
		  strcpy(t->trace_begin, TRACE_BEGIN);
		  strcpy(t->trace_end, TRACE_END);
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	      t->next_index = next1;
	      t->ethertype = ethertype1;
	    }
	  if (b2->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l4fw_trace_t *t = vlib_add_trace (vm, node, b2, sizeof (*t));
		  strcpy(t->trace_begin, TRACE_BEGIN);
		  strcpy(t->trace_end, TRACE_END);
	      t->sw_if_index = vnet_buffer (b2)->sw_if_index[VLIB_TX];
	      t->next_index = next2;
	      t->ethertype = ethertype2;
	    }
	  if (b3->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l4fw_trace_t *t = vlib_add_trace (vm, node, b3, sizeof (*t));
		  strcpy(t->trace_begin, TRACE_BEGIN);
		  strcpy(t->trace_end, TRACE_END);
	      t->sw_if_index = vnet_buffer (b3)->sw_if_index[VLIB_TX];
	      t->next_index = next3;
	      t->ethertype = ethertype3;
	    }
	  // ---------------------------------------------------
	  // PACKET PROCESSING - END
	  // ---------------------------------------------------

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x4 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, bi2, bi3,
					   next0, next1, next2, next3);

    } // 4 packets

      // ******************************************
	  // PROCESS 2 PACKETS IN PARALLEL
	  // ******************************************
      while (n_left_from >= 4 && n_left_to_next >= 2)
	{
	  u32 bi0, bi1;
	  vlib_buffer_t *b0, *b1;
	  u32 next0, next1;

	  /* Prefetch next iteration. */
	  {
	    vlib_buffer_t *p2, *p3;
	    p2 = vlib_get_buffer (vm, from[2]);
	    p3 = vlib_get_buffer (vm, from[3]);
	    vlib_prefetch_buffer_header (p2, LOAD);
	    vlib_prefetch_buffer_header (p3, LOAD);
	    clib_prefetch_store (p2->data);
	    clib_prefetch_store (p3->data);
	  }
	  /* speculatively enqueue b0 and b1 to the current next frame */
	  to_next[0] = bi0 = from[0];
	  to_next[1] = bi1 = from[1];
	  from += 2;
	  to_next += 2;
	  n_left_from -= 2;
	  n_left_to_next -= 2;

	  b0 = vlib_get_buffer (vm, bi0);
	  b1 = vlib_get_buffer (vm, bi1);
	  ASSERT (b0->current_data == 0);
	  ASSERT (b1->current_data == 0);
	  vnet_feature_next (&next0, b0);
	  vnet_feature_next (&next1, b1);

	  // ---------------------------------------------------
	  // PACKET PROCESSING - BEGIN
	  // ---------------------------------------------------
	  // extract ETH hdr
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  ethernet_header_t *eh1 = vlib_buffer_get_current (b1);
	  // extract ETH type
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);
	  u16 ethertype1 = clib_net_to_host_u16 (eh1->type);
	  // ===================================================
	  // HOOK POINT: net-in
	  l4fw_meta_t l4fw_meta0;
	  l4fw_meta_t l4fw_meta1;
      // L4FW-TODO: register pointer(s) to l4fw_meta into the vlib buffer
	  next0 = l4fw_hook_point_net_in(vlib_buffer_get_current (b0), &l4fw_meta0);
	  next1 = l4fw_hook_point_net_in(vlib_buffer_get_current (b1), &l4fw_meta1);
	  // ===================================================
	  // increment the node pkt counter
	  vlib_node_increment_counter (vm, l4fw_node.index,
				       L4FW_ERROR_COUNTER, 2);
      // PACKET TRACE:
	  // if tracing is active ==> add data to the trace
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l4fw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
		  strcpy(t->trace_begin, TRACE_BEGIN);
		  strcpy(t->trace_end, TRACE_END);
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->next_index = next0;
	      t->ethertype = ethertype0;
	    }
	  if (b1->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l4fw_trace_t *t = vlib_add_trace (vm, node, b1, sizeof (*t));
		  strcpy(t->trace_begin, TRACE_BEGIN);
		  strcpy(t->trace_end, TRACE_END);
	      t->sw_if_index = vnet_buffer (b1)->sw_if_index[VLIB_TX];
	      t->next_index = next1;
	      t->ethertype = ethertype1;
	    }
	  // ---------------------------------------------------
	  // PACKET PROCESSING - END
	  // ---------------------------------------------------

	  /* verify speculative enqueues, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x2 (vm, node, next_index,
					   to_next, n_left_to_next,
					   bi0, bi1, next0, next1);

	} // 2 packets

      // ******************************************
      // PROCESS 1 PACKET
      // ******************************************
      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0;
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  b0 = vlib_get_buffer (vm, bi0);
	  vnet_feature_next (&next0, b0);

	  // ---------------------------------------------------
	  // PACKET PROCESSING - BEGIN
	  // ---------------------------------------------------
	  // extract ETH hdr
	  ethernet_header_t *eh0 = vlib_buffer_get_current (b0);
	  // extract ETH type
	  u16 ethertype0 = clib_net_to_host_u16 (eh0->type);
	  // ===================================================
	  // HOOK POINT: net-in
	  l4fw_meta_t l4fw_meta0;
      // L4FW-TODO: register pointer(s) to l4fw_meta into the vlib buffer
	  next0 = l4fw_hook_point_net_in(vlib_buffer_get_current (b0), &l4fw_meta0);
	  // ===================================================
	  // increment the node pkt counter
	  vlib_node_increment_counter (vm, l4fw_node.index,
				       L4FW_ERROR_COUNTER, 1);
      // PACKET TRACE:
	  // if tracing is active ==> add data to the trace
	  if (b0->flags & VLIB_BUFFER_IS_TRACED)
	    {
	      l4fw_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
		  strcpy(t->trace_begin, TRACE_BEGIN);
		  strcpy(t->trace_end, TRACE_END);
	      t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_TX];
	      t->next_index = next0;
	      t->ethertype = ethertype0;
	    }
	  // ---------------------------------------------------
	  // PACKET PROCESSING - END
	  // ---------------------------------------------------

	  /* verify speculative enqueue, maybe switch current next frame */
	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);

	} // 1 packet

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  return frame->n_vectors;
} // vlib node

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (l4fw_node) =
{
  .name = "l4fw",
  .vector_size = sizeof (u32),
  .format_trace = format_l4fw_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(l4fw_error_strings),
  .error_strings = l4fw_error_strings,

  .n_next_nodes = L4FW_N_NEXT,
  // LF4W: list next nodes here
  .next_nodes = {
    [L4FW_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */