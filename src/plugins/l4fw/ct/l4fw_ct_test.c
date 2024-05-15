#ifndef L4FW_CT_TESTING
#define L4FW_CT_TESTING
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include "l4fw/ct/l4fw_ct_internal.h"
#include "l4fw/ct/l4fw_ct_test.h"

static bool is_verbose = false;
static bool is_extremely_verbose = false;

// test cases
l4fw_ct_test_case_t test_cases[] = {
  {
    .name = "flow 1, packet 1, forward",
    .pkt = {
      .ethertype = (u16) L4FW_CT_ETHERTYPE_IPV4,
      .protocol = (u8) IP_PROTOCOL_TCP,
      .saddr = L4FW_CT_LAN_ADDR(1),
      .daddr = L4FW_CT_WAN_ADDR(1),
      .sport = 2000,
      .dport = 80
    },
    .state = L4FW_CT_STATE_NEW
  },
  {
    .name = "flow 1, packet 2, forward",
    .pkt = {
      .ethertype = (u16) L4FW_CT_ETHERTYPE_IPV4,
      .protocol = (u8) IP_PROTOCOL_TCP,
      .saddr = L4FW_CT_LAN_ADDR(1),
      .daddr = L4FW_CT_WAN_ADDR(1),
      .sport = 2000,
      .dport = 80
    },
    .state = L4FW_CT_STATE_NEW
  },
  {
    .name = "flow 1, packet 1, reverse",
    .pkt = {
      .ethertype = (u16) L4FW_CT_ETHERTYPE_IPV4,
      .protocol = (u8) IP_PROTOCOL_TCP,
      .saddr = L4FW_CT_WAN_ADDR(1),
      .daddr = L4FW_CT_LAN_ADDR(1),
      .sport = 2000,
      .dport = 80
    },
    .state = L4FW_CT_STATE_ESTABLISHED
  },
  {
    .name = "flow 2, packet 1, forward",
    .pkt = {
      .ethertype = (u16) L4FW_CT_ETHERTYPE_IPV4,
      .protocol = (u8) IP_PROTOCOL_TCP,
      .saddr = L4FW_CT_LAN_ADDR(1),
      .daddr = L4FW_CT_WAN_ADDR(2),
      .sport = 2000,
      .dport = 80
    },
    .state = L4FW_CT_STATE_NEW
  },
  {
    .name = "flow 2, packet 2, forward",
    .pkt = {
      .ethertype = (u16) L4FW_CT_ETHERTYPE_IPV4,
      .protocol = (u8) IP_PROTOCOL_TCP,
      .saddr = L4FW_CT_LAN_ADDR(1),
      .daddr = L4FW_CT_WAN_ADDR(2),
      .sport = 2000,
      .dport = 80
    },
    .state = L4FW_CT_STATE_NEW
  },
  {
    .name = "flow 2, packet 1, reverse",
    .pkt = {
      .ethertype = (u16) L4FW_CT_ETHERTYPE_IPV4,
      .protocol = (u8) IP_PROTOCOL_TCP,
      .saddr = L4FW_CT_WAN_ADDR(2),
      .daddr = L4FW_CT_LAN_ADDR(1),
      .sport = 2000,
      .dport = 80
    },
    .state = L4FW_CT_STATE_ESTABLISHED
  },
  {
    .name = "non-IPv4 packet",
    .pkt = {
      .ethertype = (u16) L4FW_CT_ETHERTYPE_IPV4+1,
    },
    .state = L4FW_CT_STATE_NEW
  }
};

#define NUM_TEST_CASES sizeof(test_cases)/sizeof(l4fw_ct_test_case_t)


void
parse_args (int argc, char *argv[])
{
  int c;
  char *prog_name = argv[0];

  while ((c = getopt (argc, argv, "vxh?")) != -1) {
    switch (c) {
	  case 'x':
	    is_extremely_verbose = true;
	    // fall through and set "is_verbose" as well

	  case 'v':
	    is_verbose = 1;
	    break;
      
	  case 'h':
    case '?':
    default:
	    printf("Usage: %s [-v] [-x] [-h]\n", prog_name);
      printf("    Tests the L4FW Connection Tracking subcomponent.\n");
      printf("Flags\n");
      printf("    -v: verbose\n");
      printf("    -x: extremely verbose\n");
      printf("    -h: print this help and exit\n");
	    exit (-1);
	    break;
	  }
  }
}

void
test_state (char *test_case_name, l4fw_ct_state_t actual,
	    l4fw_ct_state_t expected)
{
  if (is_verbose)
    {
      printf ("++++++++\n");
      printf ("Test case: %s\n", test_case_name);
      printf ("  expected = %s,\n    actual = %s\n",
        l4fw_ct_state_str[expected],
        l4fw_ct_state_str[actual]);

      if (is_extremely_verbose)
        l4fw_ct_dbg_print_table();

      printf ("--------\n");
    }
  assert (actual == expected);
}

int
main (int argc, char *argv[])
{
  // setup packets
  int i;
  l4fw_ct_state_t state;

  parse_args (argc, argv);

  printf ("Testing l4fw conntrack\n");

  for (i = 0; i < NUM_TEST_CASES; i++) {
    state = l4fw_ct_update_internal(&test_cases[i].pkt);
    test_state(test_cases[i].name, state, test_cases[i].state);
  }

  return 0;
}