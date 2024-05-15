#include "l4fw/ct/l4fw_ct_internal.h"

l4fw_ct_state_t
l4fw_ct_update (
  vlib_buffer_t *buffer)
{
  return l4fw_ct_update_internal((void *) buffer); 
}

u64 l4fw_ct_count_entries () {
  return flow_entries_cnt;
}