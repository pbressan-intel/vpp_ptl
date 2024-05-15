#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include "string.h"

#include "l4fw_policy_engine.h"

/**
 * Tests for the Policy Engine.
 * 
 * Run the tests:
 *     gcc -DL4FW_POLICY_ENGINE_TESTING -g -O3 -o l4fw_policy_engine_test l4fw_utils.c l4fw_policy_engine.c l4fw_policy_engine_test.c && ./l4fw_policy_engine_test
 *
 * Run it through Valgrind:
 *     valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=valgrind-out.txt ./l4fw_policy_engine_test && less valgrind-out.txt
 */


void
test_append_one_rule ()
{
  l4fw_table_t tbl;
  l4fw_table_init (&tbl);
  l4fw_rule_t rule1;
  l4fw_rule_init (&rule1);
  assert (l4fw_table_count_rules (&tbl) == 0);
  l4fw_table_append_rule (&tbl, &rule1);
  assert (l4fw_table_count_rules (&tbl) == 1);
  assert (l4fw_table_get_rule (&tbl, 1) == &rule1);
}

void
test_append_and_remove_rules ()
{
  l4fw_table_t tbl;
  l4fw_table_init (&tbl);
  l4fw_rule_t rule1;
  l4fw_rule_init (&rule1);
  l4fw_rule_t rule2;
  l4fw_rule_init (&rule2);
  l4fw_rule_t rule3;
  l4fw_rule_init (&rule3);
  // Removing on empty table should return NULL.
  assert (l4fw_table_rule_remove (&tbl, 1) == NULL);
  l4fw_table_append_rule (&tbl, &rule1);
  l4fw_table_append_rule (&tbl, &rule2);
  assert (l4fw_table_count_rules (&tbl) == 2);
  assert (l4fw_table_get_rule (&tbl, 1) == &rule1);
  assert (l4fw_table_get_rule (&tbl, 2) == &rule2);
  // Remove head first.
  assert (l4fw_table_rule_remove (&tbl, 1) == &rule1);
  assert (l4fw_table_count_rules (&tbl) == 1);
  assert (l4fw_table_get_rule (&tbl, 1) == &rule2);
  assert (l4fw_table_rule_remove (&tbl, 1) == &rule2);
  assert (l4fw_table_count_rules (&tbl) == 0);
  // Again, but remove tail first.
  l4fw_table_append_rule (&tbl, &rule1);
  l4fw_table_append_rule (&tbl, &rule2);
  assert (l4fw_table_rule_remove (&tbl, 2) == &rule2);
  assert (l4fw_table_count_rules (&tbl) == 1);
  assert (l4fw_table_get_rule (&tbl, 1) == &rule1);
  assert (l4fw_table_rule_remove (&tbl, 1) == &rule1);
  assert (l4fw_table_count_rules (&tbl) == 0);
  // Again, but remove middle first first.
  l4fw_table_append_rule (&tbl, &rule1);
  l4fw_table_append_rule (&tbl, &rule2);
  l4fw_table_append_rule (&tbl, &rule3);
  assert (l4fw_table_rule_remove (&tbl, 2) == &rule2);
  assert (l4fw_table_count_rules (&tbl) == 2);
  assert (l4fw_table_get_rule (&tbl, 1) == &rule1);
  assert (l4fw_table_get_rule (&tbl, 2) == &rule3);
  assert (l4fw_table_rule_remove (&tbl, 1) == &rule1);
  assert (l4fw_table_rule_remove (&tbl, 1) == &rule3);
  assert (l4fw_table_count_rules (&tbl) == 0);
}

void
test_add_table ()
{
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  // Add a single table.
  l4fw_table_id_t new_table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  const char *new_table_name =
    l4fw_policy_engine_table_name_from_id (ctx, new_table_id);
  assert (strcmp (new_table_name, "main") == 0);
  assert (new_table_id == l4fw_policy_engine_table_id_from_name (ctx, "main"));
  assert (strcmp (l4fw_policy_engine_get_table (ctx, new_table_id)->table_name,
		  "main") == 0);
  // Try adding table with existing name (should return error).
  assert (l4fw_policy_engine_context_add_table (ctx, "main") == -1);
  // Add some more tables.
  char tmp_table_name[L4FW_MAX_TABLE_NAME_SIZE];
  for (int i = 0; i < 32; i++)
    {
      sprintf (tmp_table_name, "table%d", i);
      new_table_id =
	l4fw_policy_engine_context_add_table (ctx, tmp_table_name);
      assert (
	strcmp (l4fw_policy_engine_table_name_from_id (ctx, new_table_id),
		tmp_table_name) == 0);
      assert (new_table_id ==
	      l4fw_policy_engine_table_id_from_name (ctx, tmp_table_name));
    }
  l4fw_policy_engine_context_free (ctx);
}

void
test_lookup_one_rule ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };

  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  l4fw_rule_t rule1;
  l4fw_rule_init (&rule1);
  rule1.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR,
					.value = pkt.daddr,
					.negated = false };
  rule1.action.action_type = L4FW_ACTION_ALLOW;
  l4fw_table_append_rule (tbl, &rule1);
  assert(l4fw_table_get_rule(tbl, 1));
  assert(l4fw_table_get_rule(tbl, 1)->match_list[0].value == pkt.daddr);
  assert(l4fw_policy_engine_get_rule(ctx, table_id, 1) == l4fw_table_get_rule(tbl, 1));
  assert(l4fw_policy_engine_get_rule(ctx, table_id, 2) == NULL);
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule == &rule1);
  assert (term_rule.table_id == table_id);
  assert (term_rule.rule_idx == 1);

  // This daddr shouldn't match any rule.
  pkt.daddr = 0x0a000103;
  term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (l4fw_is_default_table_rule (tbl, term_rule.rule));
  assert (term_rule.table_id == table_id);
  assert (term_rule.rule_idx == 0);
  l4fw_policy_engine_context_free(ctx);
}

void
test_lookup_negated_rule ()
{
  struct mypkt pkt = { .daddr = 0x0a000102, .dport = 80 };

  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  l4fw_rule_t rule1;
  l4fw_rule_init (&rule1);
  rule1.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR,
					.value = 0x0a000103,
					.negated = true };
  rule1.action.action_type = L4FW_ACTION_ALLOW;
  l4fw_table_append_rule (tbl, &rule1);
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule == &rule1);
  assert (term_rule.table_id == table_id);
  assert (term_rule.rule_idx == 1);

  // This daddr shouldn't match any rule.
  pkt.daddr = 0x0a000103;
  assert (l4fw_is_default_table_rule (
    tbl, l4fw_policy_engine_lookup (ctx, &pkt).rule));
  l4fw_policy_engine_context_free(ctx);
}

void
test_lookup_masked_rule ()
{
  struct mypkt pkt = { .daddr = 0x0a000102, .dport = 80 };

  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  l4fw_rule_t rule1;
  l4fw_rule_init (&rule1);
  rule1.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR,
					.value = 0x0a000000,
					.mask = 0xFFFF0000 };
  rule1.action.action_type = L4FW_ACTION_ALLOW;
  l4fw_table_append_rule (tbl, &rule1);
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule == &rule1);
  assert (term_rule.table_id == table_id);
  assert (term_rule.rule_idx == 1);

  // This daddr shouldn't match any rule.
  pkt.daddr = 0x0b000102;
  assert (l4fw_is_default_table_rule (
    tbl, l4fw_policy_engine_lookup (ctx, &pkt).rule));

  // Unless the rule is negated.
  rule1.match_list[0].negated = true;
  term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule == &rule1);

  l4fw_policy_engine_context_free (ctx);
}

void
test_lookup_range_rule ()
{
  struct mypkt pkt = { .daddr = 0x0a000102, .dport = 80 };

  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  l4fw_rule_t rule1, rule2;
  l4fw_rule_init (&rule1);
  l4fw_rule_init (&rule2);
  rule1.match_list[0] = (l4fw_match_t){
    .key = L4FW_MATCH_KEY_TCP_DPORT,
    .range_start = 80,
    .range_end = 81,
    .decorator = L4FW_MATCH_RANGE,
  };
  rule1.action.action_type = L4FW_ACTION_ALLOW;
  rule2.match_list[0] = (l4fw_match_t){
    .key = L4FW_MATCH_KEY_IP4_DADDR,
    .range_start = 0x0a000100,
    .range_end = 0x0a000103,
    .decorator = L4FW_MATCH_RANGE,
  };
  rule2.action.action_type = L4FW_ACTION_ALLOW;
  l4fw_table_append_rule (tbl, &rule1);
  l4fw_table_append_rule (tbl, &rule2);

  // Match the lower end of the range
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);
  // Match the upper end of the range
  pkt.dport = 81;
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);

  // Change the dport, so that the IP range rule matches.
  pkt.dport = 79;
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule2);

  // Change the daddr, so that no rule matches.
  pkt.daddr = 0x0b000102;
  assert (l4fw_is_default_table_rule (
    tbl, l4fw_policy_engine_lookup (ctx, &pkt).rule));

  l4fw_policy_engine_context_free (ctx);
}

void
test_lookup_appid_rule ()
{
  struct mypkt pkt = { .app_id = "foo.bar.com" };

  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  l4fw_rule_t rule1;
  l4fw_rule_init (&rule1);
  rule1.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_APP_ID,
					.decorator = L4FW_MATCH_EQUALS,
					.val_as_str = "foo.bar.com",
					.negated = false };
  rule1.action.action_type = L4FW_ACTION_ALLOW;
  l4fw_table_append_rule (tbl, &rule1);
  // Check equals.
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);
  // Check startswith.
  rule1.match_list[0].decorator = L4FW_MATCH_STARTS_WITH;
  strcpy (rule1.match_list[0].val_as_str, "foo.");
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);
  // Check contains.
  rule1.match_list[0].decorator = L4FW_MATCH_CONTAINS;
  strcpy (rule1.match_list[0].val_as_str, "bar");
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);
  // Check endswith.
  rule1.match_list[0].decorator = L4FW_MATCH_ENDS_WITH;
  strcpy (rule1.match_list[0].val_as_str, "bar.com");
  pkt.app_id = "foo.bar.com";
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);
  // This appid shouldn't match any rule.
  pkt.app_id = "baz";
  assert (l4fw_is_default_table_rule (
    tbl, l4fw_policy_engine_lookup (ctx, &pkt).rule));
  l4fw_policy_engine_context_free (ctx);
}

void
test_lookup_rule_with_multiple_matches ()
{
  struct mypkt pkt = { .saddr = 0x0a000101, .daddr = 0x0a000102, .dport = 80 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  l4fw_rule_t rule1;
  l4fw_rule_init (&rule1);
  rule1.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_SADDR,
					.value = 0x0a000101,
					.negated = false };
  rule1.match_list[1] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR,
					.value = 0x0a000102,
					.negated = false };
  rule1.action.action_type = L4FW_ACTION_ALLOW;
  l4fw_table_append_rule (tbl, &rule1);
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule == &rule1);
  // Add a third match to the conjunction.
  rule1.match_list[2] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_TCP_DPORT,
					.value = 80,
					.negated = false };
  // char formatted_table[2048];
  // l4fw_table_format (formatted_table, sizeof(formatted_table), tbl);
  // printf("%s", formatted_table);
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);
  // With the wrong dport, it shouldn't match any rule.
  pkt.dport = 1234;
  assert (l4fw_is_default_table_rule (
    tbl, l4fw_policy_engine_lookup (ctx, &pkt).rule));
  // But it should match if the third match is negated.
  rule1.match_list[2].negated = true;
  assert (l4fw_policy_engine_lookup (ctx, &pkt).rule == &rule1);
  l4fw_policy_engine_context_free (ctx);
}

void
test_lookup_rule_with_log ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table1_id =
    l4fw_policy_engine_context_add_table (ctx, "table1");
  l4fw_table_t *tbl1 = l4fw_policy_engine_get_table (ctx, table1_id);
  l4fw_rule_t log_rule1, log_rule2;
  l4fw_rule_init (&log_rule1);
  log_rule1.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR,
					    .value = pkt.daddr,
					    .negated = false };
  log_rule1.action.action_type = L4FW_ACTION_LOG;
  l4fw_table_append_rule (tbl1, &log_rule1);
  // Initialize the counter for LOG action with rule_idx 1 and 2.
  test_log_counter[1] = 0;
  test_log_counter[2] = 0;
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (l4fw_is_default_table_rule (tbl1, term_rule.rule));
  assert (term_rule.rule_idx == 0);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_LOG) == 1);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 1);
  assert (test_log_counter[1] == 1);
  // To test two LOGs in a row, append another LOG rule.
  memcpy(&log_rule2, &log_rule1, sizeof(log_rule1));
  l4fw_table_append_rule (tbl1, &log_rule2);
  assert (l4fw_is_default_table_rule (
    tbl1, l4fw_policy_engine_lookup (ctx, &pkt).rule));
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_LOG) == 3);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 2);
  assert (test_log_counter[1] == 2);
  assert (test_log_counter[2] == 1);
  l4fw_policy_engine_context_free(ctx);
}

void
test_lookup_rule_with_jump ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table1_id =
    l4fw_policy_engine_context_add_table (ctx, "table1");
  l4fw_table_id_t table2_id =
    l4fw_policy_engine_context_add_table (ctx, "table2");
  l4fw_table_t *tbl1 = l4fw_policy_engine_get_table (ctx, table1_id),
	       *tbl2 = l4fw_policy_engine_get_table (ctx, table2_id);
  l4fw_rule_t jump_rule, tbl2_rule;
  l4fw_rule_init (&jump_rule);
  l4fw_rule_init (&tbl2_rule);
  jump_rule.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR,
					    .value = pkt.daddr,
					    .negated = false };
  jump_rule.action.action_type = L4FW_ACTION_JUMP;
  l4fw_table_id_t jump_target = l4fw_policy_engine_table_id_from_name (ctx, "table2");
  jump_rule.action.action_data = jump_target;
  tbl2_rule.match_list[0] = (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR,
					    .value = pkt.daddr,
					    .negated = false };
  tbl2_rule.action.action_type = L4FW_ACTION_ALLOW;
  l4fw_table_append_rule (tbl1, &jump_rule);
  l4fw_table_append_rule (tbl2, &tbl2_rule);
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule == &tbl2_rule);
  assert (term_rule.table_id == table2_id);
  assert (term_rule.rule_idx == 1);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_JUMP) == 1);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 1);
  l4fw_policy_engine_context_free(ctx);
}

void
test_lookup_rule_with_return ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t tbl1_id =
    l4fw_policy_engine_context_add_table (ctx, "table1");
  l4fw_table_id_t tbl2_id =
    l4fw_policy_engine_context_add_table (ctx, "table2");
  l4fw_table_t *tbl1 = l4fw_policy_engine_get_table (ctx, tbl1_id),
	       *tbl2 = l4fw_policy_engine_get_table (ctx, tbl2_id);
  // Add two rules to tbl1.
  l4fw_rule_t ret_rule, jump_rule;
  l4fw_rule_init (&ret_rule);
  l4fw_rule_init (&jump_rule);
  ret_rule.match_list[0] =
    (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR, .value = pkt.daddr };
  ret_rule.action.action_type = L4FW_ACTION_RETURN;
  jump_rule.match_list[0] =
    (l4fw_match_t){ .key = L4FW_MATCH_KEY_IP4_DADDR, .value = pkt.daddr + 1 };
  jump_rule.action.action_type = L4FW_ACTION_JUMP;
  l4fw_table_id_t jump_target =
    l4fw_policy_engine_table_id_from_name (ctx, "table2");
  jump_rule.action.action_data = jump_target;
  l4fw_table_append_rule (tbl1, &ret_rule);
  l4fw_table_append_rule (tbl1, &jump_rule);
  // tbl2 is empty; it only has a default RETURN action.
  l4fw_policy_engine_set_default_action (
    ctx, tbl2_id, (l4fw_action_t){ .action_type = L4FW_ACTION_RETURN });
  // Should match RETURN in tbl1, then tbl1's default ALLOW.
  assert (l4fw_is_default_table_rule (
    tbl1, l4fw_policy_engine_lookup (ctx, &pkt).rule));
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_RETURN) ==
	  1);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 1);
  // Should match JUMP in tbl1, tbl2's default RETURN, then tbl1's default
  // ALLOW.
  pkt.daddr += 1;
  assert (l4fw_is_default_table_rule (
    tbl1, l4fw_policy_engine_lookup (ctx, &pkt).rule));
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_JUMP) == 1);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_RETURN) ==
	  2);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 2);
  l4fw_policy_engine_context_free (ctx);
}

void
test_lookup_default_jump ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table1_id = l4fw_policy_engine_context_add_table(ctx, "table1");
  l4fw_table_id_t table2_id = l4fw_policy_engine_context_add_table(ctx, "table2");
  l4fw_table_t *tbl1 = l4fw_policy_engine_get_table (ctx, table1_id),
	       *tbl2 = l4fw_policy_engine_get_table (ctx, table2_id);
  l4fw_table_id_t jump_target = l4fw_policy_engine_table_id_from_name (ctx, "table2");
  tbl1->default_rule = (l4fw_rule_t){
    .action = (l4fw_action_t){ .action_type = L4FW_ACTION_JUMP,
			       .action_data = jump_target },
    .match_list[0].key =
      L4FW_MATCH_KEY_DEFAULT, // Indicates default rule and action.
  };
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule != NULL);
  assert (term_rule.rule == &tbl2->default_rule);
  assert (term_rule.table_id == table2_id);
  assert (term_rule.rule_idx == 0);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_JUMP) == 1);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 1);
  l4fw_policy_engine_context_free(ctx);
}

void
test_lookup_multiple_default_jumps ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table1_id =
		    l4fw_policy_engine_context_add_table (ctx, "table1"),
		  table2_id =
		    l4fw_policy_engine_context_add_table (ctx, "table2"),
		  table3_id =
		    l4fw_policy_engine_context_add_table (ctx, "table3");
  l4fw_table_t *tbl1 = l4fw_policy_engine_get_table (ctx, table1_id),
	       *tbl2 = l4fw_policy_engine_get_table (ctx, table2_id),
	       *tbl3 = l4fw_policy_engine_get_table (ctx, table3_id);
  tbl1->default_rule = (l4fw_rule_t){
    .action =
      (l4fw_action_t){
	.action_type = L4FW_ACTION_JUMP,
	.action_data = l4fw_policy_engine_table_id_from_name (ctx, "table2") },
    .match_list[0].key =
      L4FW_MATCH_KEY_DEFAULT, // Indicates default rule and action.
  };
  tbl2->default_rule = (l4fw_rule_t){
    .action =
      (l4fw_action_t){
	.action_type = L4FW_ACTION_JUMP,
	.action_data = l4fw_policy_engine_table_id_from_name (ctx, "table3") },
    .match_list[0].key =
      L4FW_MATCH_KEY_DEFAULT, // Indicates default rule and action.
  };
  l4fw_matched_rule_t term_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (term_rule.rule != NULL);
  assert (term_rule.rule == &tbl3->default_rule);
  assert (term_rule.table_id == table3_id);
  assert (term_rule.rule_idx == 0);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_JUMP) == 2);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 1);
  l4fw_policy_engine_context_free(ctx);
}

void
test_policy_engine_basic ()
{
  struct mypkt pkt = { .daddr = 0x0a000102, .dport = 80 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_rule_t rule;
  l4fw_rule_init (&rule);
  rule.action.action_type = L4FW_ACTION_ALLOW;
  rule.match_list[0].key = L4FW_MATCH_KEY_IP4_DADDR;
  rule.match_list[0].value = pkt.daddr;
  rule.match_list[1].key = L4FW_MATCH_KEY_TCP_DPORT;
  rule.match_list[1].value = pkt.dport;
  int num_table_rules = l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL);
  assert (num_table_rules == 1);
  l4fw_matched_rule_t terminating_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (terminating_rule.rule != NULL);
  assert (memcmp (terminating_rule.rule, &rule, sizeof (rule)) == 0);
  assert (terminating_rule.table_id == table_id);
  assert (terminating_rule.rule_idx == 1);
  // Check stats.
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) == 1);
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_DROP) == 0);
  l4fw_policy_engine_context_free (ctx);
}

void
test_policy_engine_named_rule ()
{
  struct mypkt pkt = { .daddr = 0x0a000102, .dport = 80 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_rule_t rule;
  l4fw_rule_init (&rule);
  rule.action.action_type = L4FW_ACTION_ALLOW;
  rule.match_list[0].key = L4FW_MATCH_KEY_IP4_DADDR;
  rule.match_list[0].value = pkt.daddr;
  const char *rule_name = "Hello world! My named rule.";
  int num_table_rules = l4fw_policy_engine_rule_append (ctx, table_id, rule, rule_name);
  assert (num_table_rules == 1);
  l4fw_matched_rule_t terminating_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (terminating_rule.rule != NULL);
  assert (terminating_rule.rule->name != NULL);
  assert (strcmp (terminating_rule.rule->name, rule_name) == 0);
  l4fw_policy_engine_context_free (ctx);
}

void
test_policy_engine_set_default_action ()
{
  struct mypkt pkt = { .daddr = 0x0a000102, .dport = 80 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  assert (l4fw_policy_engine_set_default_action (
    ctx, table_id, (l4fw_action_t){ .action_type = L4FW_ACTION_DROP }));
  l4fw_matched_rule_t terminating_rule = l4fw_policy_engine_lookup (ctx, &pkt);
  assert (terminating_rule.rule != NULL);
  assert (terminating_rule.rule->match_list[0].key == L4FW_MATCH_KEY_DEFAULT);
  assert (terminating_rule.rule->action.action_type == L4FW_ACTION_DROP);
  assert (terminating_rule.table_id == table_id);
  assert (terminating_rule.rule_idx == 0);
  // RETURN is an invalid action for the default table.
  assert (l4fw_policy_engine_set_default_action (
	    ctx, table_id,
	    (l4fw_action_t){ .action_type = L4FW_ACTION_RETURN }) == false);
  l4fw_policy_engine_context_free (ctx);
}

void
test_policy_engine_invalid_rule ()
{
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_rule_t ret_rule;
  l4fw_rule_init (&ret_rule);
  ret_rule.action.action_type = L4FW_ACTION_RETURN;
  // Appending RETURN rule to default table should error.
  assert (l4fw_policy_engine_rule_append (ctx, table_id, ret_rule, NULL) < 0);
  l4fw_policy_engine_context_free (ctx);
}

void
test_policy_engine_rule_allocation ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  // Append until all freelist rules have been allocated.
  l4fw_rule_t rule;
  l4fw_rule_init (&rule);
  rule.action.action_type = L4FW_ACTION_ALLOW;
  rule.match_list[0].key = L4FW_MATCH_KEY_IP4_DADDR;
  rule.match_list[0].value = pkt.daddr;
  int prev_allocated_nodes = ctx->num_allocated_rule_nodes;
  int rule_cnt;
  for (rule_cnt = 0; rule_cnt < ctx->num_allocated_rule_nodes; rule_cnt++)
    {
      assert (l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL) ==
	      rule_cnt + 1);
      rule.match_list[0].value++;
    }
  assert (ctx->num_allocated_rule_nodes == rule_cnt);
  assert (l4fw_table_count_rules (tbl) == rule_cnt);
  assert (ctx->rule_mem_pool_head == 0);
  assert (ctx->rules_freelist == NULL);
  // Check that all the rules can be matched.
  for (int i = 0; i < rule_cnt; i++)
    {
      l4fw_matched_rule_t matched_rule = l4fw_policy_engine_lookup (
	ctx, &(struct mypkt){ .daddr = pkt.daddr + i });
      assert (matched_rule.rule != NULL);
      assert (matched_rule.rule->match_list[0].key != L4FW_MATCH_KEY_DEFAULT);
      assert (matched_rule.table_id == table_id);
      assert (matched_rule.rule_idx == i + 1);
    }
  int expected_matches = rule_cnt;
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) ==
	  expected_matches);
  // Append another rule, triggering freelist grow.
  assert (l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL) ==
	  rule_cnt + 1);
  assert (ctx->num_allocated_rule_nodes == rule_cnt * 2);
  assert (ctx->rule_mem_pool_head == 1);
  assert (ctx->rules_freelist != NULL);
  rule.match_list[0].value++;
  rule_cnt++;
  // Grow it again.
  for (; rule_cnt < ctx->num_allocated_rule_nodes; rule_cnt++)
    {
      assert (l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL) ==
	      rule_cnt + 1);
      rule.match_list[0].value++;
    }
  assert (ctx->num_allocated_rule_nodes == rule_cnt);
  assert (ctx->rule_mem_pool_head == 1);
  assert (ctx->rules_freelist == NULL);
  // Append another rule, triggering freelist grow.
  assert (l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL) ==
	  rule_cnt + 1);
  assert (ctx->num_allocated_rule_nodes == rule_cnt * 2);
  assert (ctx->rule_mem_pool_head == 2);
  assert (ctx->rules_freelist != NULL);
  void *prev_freelist = ctx->rules_freelist;
  rule.match_list[0].value++;
  rule_cnt++;
  // Pop all the rules.
  for (int i = 0; i < rule_cnt; i++)
    {
      assert (l4fw_policy_engine_rule_remove (ctx, table_id, 1));
    }
  assert (l4fw_table_count_rules (tbl) == 0);
  // Add back the same number of rules
  rule.match_list[0].value = pkt.daddr;
  for (int i = 0; i < rule_cnt; i++)
    {
      assert (l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL) == i + 1);
      rule.match_list[0].value++;
    }
  assert (l4fw_table_count_rules (tbl) == rule_cnt);
  // Since we appended the same number of rules, the freelist should point to
  // the same node as before.
  assert (ctx->rules_freelist == prev_freelist);
  // Check that all the rules can be matched.
  for (int i = 0; i < rule_cnt; i++)
    {
      l4fw_matched_rule_t matched_rule = l4fw_policy_engine_lookup (
	ctx, &(struct mypkt){ .daddr = pkt.daddr + i });
      assert (matched_rule.rule != NULL);
      assert (matched_rule.rule->match_list[0].key != L4FW_MATCH_KEY_DEFAULT);
      assert (matched_rule.table_id == table_id);
      assert (matched_rule.rule_idx == i + 1);
    }
  expected_matches += rule_cnt;
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_ALLOW) ==
	  expected_matches);

  l4fw_policy_engine_context_free (ctx);
}

void
test_policy_engine_clear_table ()
{
  struct mypkt pkt = { .daddr = 0x0a000102 };
  l4fw_policy_engine_context_t *ctx = l4fw_policy_engine_context_new ();
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (ctx, "main");
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  l4fw_rule_t rule;
  l4fw_rule_init (&rule);
  rule.action.action_type = L4FW_ACTION_REJECT;
  rule.match_list[0].key = L4FW_MATCH_KEY_IP4_DADDR;
  rule.match_list[0].value = pkt.daddr;
  int rule_cnt = 100;
  for (int rule_idx = 1; rule_idx <= rule_cnt; rule_idx++)
    {
      assert (l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL) ==
	      rule_idx);
      rule.match_list[0].value++;
    }
  assert (l4fw_table_count_rules (tbl) == rule_cnt);

  l4fw_policy_engine_clear_table (ctx, table_id);
  assert (l4fw_table_count_rules (tbl) == 0);

  // Add back the same number of rules.
  rule.match_list[0].value = pkt.daddr;
  for (int rule_idx = 1; rule_idx <= rule_cnt; rule_idx++)
    {
      assert (l4fw_policy_engine_rule_append (ctx, table_id, rule, NULL) ==
	      rule_idx);
      rule.match_list[0].value++;
    }
  assert (l4fw_table_count_rules (tbl) == rule_cnt);

  // Check that all the rules can be matched.
  for (int i = 0; i < rule_cnt; i++)
    {
      l4fw_matched_rule_t matched_rule = l4fw_policy_engine_lookup (
	ctx, &(struct mypkt){ .daddr = pkt.daddr + i });
      assert (matched_rule.rule != NULL);
      assert (matched_rule.rule_idx == i + 1);
    }
  assert (l4fw_policy_engine_get_action_counter (ctx, L4FW_ACTION_REJECT) ==
	  rule_cnt);

  l4fw_policy_engine_context_free (ctx);
}

int
main ()
{
  test_append_one_rule ();
  test_append_and_remove_rules ();
  test_add_table ();
  test_lookup_one_rule ();
  test_lookup_negated_rule ();
  test_lookup_masked_rule ();
  test_lookup_range_rule ();
  test_lookup_appid_rule ();
  test_lookup_rule_with_multiple_matches ();
  test_lookup_rule_with_log ();
  test_lookup_rule_with_jump ();
  test_lookup_rule_with_return ();
  test_lookup_default_jump ();
  test_lookup_multiple_default_jumps ();
  test_policy_engine_basic ();
  test_policy_engine_named_rule ();
  test_policy_engine_set_default_action ();
  test_policy_engine_invalid_rule ();
  test_policy_engine_rule_allocation ();
  test_policy_engine_clear_table();
  return 0;
}