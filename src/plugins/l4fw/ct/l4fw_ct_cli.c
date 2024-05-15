#include <vlib/vlib.h>
#include <vlib/cli.h>

#include "l4fw/l4fw.h"
#include "l4fw/ct/l4fw_ct.h"
#include "l4fw/ct/l4fw_ct_internal.h"

/**
 * @brief Print out the flow table, as maintained by the connection 
 * tracking sub-component
 * 
 * @todo Merge with l4fw_dbg_print_table()
 */
static clib_error_t *
l4fw_ct_show_table_fn(vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  clib_error_t *error = 0;

  l4fw_ct_flow_entry_t *curr_entry = flow_entries;
  l4fw_ct_flow_t *flow = 0;
  int entry_num = 0;

  vlib_cli_output(vm, "Flows and states, as maintained by L4FW Connection Tracting:\n");

  vlib_cli_output(vm, 
    "%6s, %32s, %6s, %10s, %10s, %8s, %8s\n",
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
    vlib_cli_output(vm, 
      "%6d, %32s, %6u, 0x%08x, 0x%08x, %8u, %8u\n",
      entry_num++,
      l4fw_ct_state_str[flow->state],
      flow->tuple.l3.proto,
      flow->tuple.l3.ip4_addr[0].as_u32,
      flow->tuple.l3.ip4_addr[1].as_u32,
      flow->tuple.l4.port[0],
      flow->tuple.l4.port[1]);

    curr_entry = curr_entry->next;
  }

  return error;
}

VLIB_CLI_COMMAND (l4fw_ct_show_table_command, static) = {
    .path = "show l4fw ct",
    .short_help = "show l4fw ct: show the connection tracking table (i.e., flows and their states)",
    .function = l4fw_ct_show_table_fn,
};
