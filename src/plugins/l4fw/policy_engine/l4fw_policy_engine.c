#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <signal.h>
#include "string.h"

#include "l4fw_policy_engine.h"
#include "l4fw/l4fw_utils.h"

#ifdef L4FW_POLICY_ENGINE_TESTING
int test_log_counter[L4FW_MAX_LOG_COUNTER_RULES];
#endif

const char *
l4fw_action_type_to_string (l4fw_action_type_t a)
{
  switch (a)
    {
    case L4FW_ACTION_DROP:
      return "DROP";
    case L4FW_ACTION_ALLOW:
      return "ALLOW";
    case L4FW_ACTION_REJECT:
      return "REJECT";
    case L4FW_ACTION_LOG:
      return "LOG";
    case L4FW_ACTION_JUMP:
      return "JUMP";
    case L4FW_ACTION_RETURN:
      return "RETURN";
    default:
      fprintf (stderr, "Error: unknown action type.\n");
    }
  return NULL;
}

l4fw_action_type_t
l4fw_action_type_from_string (const char *s)
{
  if (strcmp (s, "DROP") == 0)
    return L4FW_ACTION_DROP;
  else if (strcmp (s, "ALLOW") == 0)
    return L4FW_ACTION_ALLOW;
  else if (strcmp (s, "REJECT") == 0)
    return L4FW_ACTION_REJECT;
  else if (strcmp (s, "LOG") == 0)
    return L4FW_ACTION_LOG;
  else if (strcmp (s, "JUMP") == 0)
    return L4FW_ACTION_JUMP;
  else if (strcmp (s, "RETURN") == 0)
    return L4FW_ACTION_RETURN;
  fprintf (stderr, "Error: unknown action type: `%s'.\n", s);
  return L4FW_ACTION_INVALID;
}

const char *
l4fw_match_key_to_string (l4fw_match_key_t k)
{
  switch (k)
    {
    case L4FW_MATCH_KEY_TRUE:
      return "TRUE";
    case L4FW_MATCH_KEY_IP4_SADDR:
      return "IP4_SADDR";
    case L4FW_MATCH_KEY_IP4_DADDR:
      return "IP4_DADDR";
    case L4FW_MATCH_KEY_TCP_SPORT:
      return "TCP_SPORT";
    case L4FW_MATCH_KEY_TCP_DPORT:
      return "TCP_DPORT";
    case L4FW_MATCH_KEY_UDP_SPORT:
      return "UDP_SPORT";
    case L4FW_MATCH_KEY_UDP_DPORT:
      return "UDP_DPORT";
    case L4FW_MATCH_KEY_APP_ID:
      return "APP_ID";
    case L4FW_MATCH_KEY_CONN_STATE:
      return "CONN_STATE";
    case L4FW_MATCH_KEY_DEFAULT:
      return "TABLE_DEFAULT";
    default:
      fprintf (stderr, "Error: unknown match key type.\n");
    }
  return NULL;
}

l4fw_match_key_t
l4fw_match_key_from_string (const char *s)
{
  if (strcmp (s, "TRUE") == 0)
    return L4FW_MATCH_KEY_TRUE;
  else if (strcmp (s, "IP4_SADDR") == 0)
    return L4FW_MATCH_KEY_IP4_SADDR;
  else if (strcmp (s, "IP4_DADDR") == 0)
    return L4FW_MATCH_KEY_IP4_DADDR;
  else if (strcmp (s, "TCP_SPORT") == 0)
    return L4FW_MATCH_KEY_TCP_SPORT;
  else if (strcmp (s, "TCP_DPORT") == 0)
    return L4FW_MATCH_KEY_TCP_DPORT;
  else if (strcmp (s, "UDP_SPORT") == 0)
    return L4FW_MATCH_KEY_UDP_SPORT;
  else if (strcmp (s, "UDP_DPORT") == 0)
    return L4FW_MATCH_KEY_UDP_DPORT;
  else if (strcmp (s, "APP_ID") == 0)
    return L4FW_MATCH_KEY_APP_ID;
  else if (strcmp (s, "CONN_STATE") == 0)
    return L4FW_MATCH_KEY_CONN_STATE;
  else if (strcmp (s, "TABLE_DEFAULT") == 0)
    return L4FW_MATCH_KEY_DEFAULT;
  else
    fprintf (stderr, "Error: unknown match key type: %s.\n", s);
  return L4FW_MATCH_KEY_INVALID;
}

const char *
l4fw_decorator_to_string (l4fw_match_decorator_t d)
{
  switch (d)
    {
    case L4FW_MATCH_EQUALS:
      return "==";
    case L4FW_MATCH_STARTS_WITH:
      return "starts-with";
    case L4FW_MATCH_CONTAINS:
      return "contains";
    case L4FW_MATCH_ENDS_WITH:
      return "ends-with";
    case L4FW_MATCH_RANGE:
      return "range";
    default:
      fprintf (stderr, "Error: unknown decorator type.\n");
    }
  return NULL;
}

l4fw_match_decorator_t
l4fw_decorator_from_string (const char *s)
{
  if (strcmp (s, "==") == 0)
    return L4FW_MATCH_EQUALS;
  else if (strcmp (s, "starts-with") == 0)
    return L4FW_MATCH_STARTS_WITH;
  else if (strcmp (s, "contains") == 0)
    return L4FW_MATCH_CONTAINS;
  else if (strcmp (s, "ends-with") == 0)
    return L4FW_MATCH_ENDS_WITH;
  else if (strcmp (s, "range") == 0)
    return L4FW_MATCH_RANGE;
  else
    fprintf (stderr, "Error: unknown decorator type: %s.\n", s);
  return L4FW_MATCH_DECORATOR_INVALID;
}

/**
 * @brief Format a five tuple.
 * This doesn't have dependencies on VPP.
 */
int
l4fw_packet_format (char *s, size_t size, void *pkt)
{
  int n = 0;
  u16 eth_type = L4FW_GET_ETH_TYPE (pkt);
  if (eth_type != ETHERNET_TYPE_IP4)
    {
      return snprintf (s + n, size - n, "<eth_type=0x%04x>", eth_type);
    }
  u8 proto = L4FW_GET_IP_PROTO (pkt);
  if (proto == IP_PROTOCOL_TCP)
    n += snprintf (s + n, size - n, "TCP ");
  else if (proto == IP_PROTOCOL_UDP)
    n += snprintf (s + n, size - n, "UDP ");
  else if (proto == IP_PROTOCOL_ICMP)
    n += snprintf (s + n, size - n, "ICMP ");
  n += l4fw_ipv4_addr_format (s + n, size - n, L4FW_GET_IP4_SADDR (pkt));
  if (proto == IP_PROTOCOL_TCP)
    n += snprintf (s + n, size - n, ":%d", L4FW_GET_TCP_SPORT_HE (pkt));
  else if (proto == IP_PROTOCOL_UDP)
    n += snprintf (s + n, size - n, ":%d", L4FW_GET_UDP_SPORT_HE (pkt));
  n += snprintf (s + n, size - n, "=>");
  n += l4fw_ipv4_addr_format (s + n, size - n, L4FW_GET_IP4_DADDR (pkt));
  if (proto == IP_PROTOCOL_TCP)
    n += snprintf (s + n, size - n, ":%d", L4FW_GET_TCP_DPORT_HE (pkt));
  else if (proto == IP_PROTOCOL_UDP)
    n += snprintf (s + n, size - n, ":%d", L4FW_GET_UDP_DPORT_HE (pkt));
  return n;
}

/**
 * @brief Allocate more memory for storing rules.
 * @param ctx policy engine context
 * @param num_additional_rules allocate this many additional rules
 */
void
l4fw_rules_memory_grow (l4fw_policy_engine_context_t *ctx,
			int num_additional_rules)
{
  ctx->num_allocated_rule_nodes += num_additional_rules;
  ctx->rule_mem_pool_head++;
  if (ctx->rule_mem_pool_head >
      (sizeof (ctx->rule_mem_pool) / sizeof (ctx->rule_mem_pool[0])))
    {
      fprintf (stderr, "Error: ran out of memory pool slots for rules.\n");
      exit (1);
    }
  // To grow the memory, we allocate a new buffer and append its pointer to
  // this pointer array.
  ctx->rule_mem_pool[ctx->rule_mem_pool_head] =
    calloc (num_additional_rules, sizeof (l4fw_rule_t));
  // Add the new rule nodes to the freelist.
  for (int i = 0; i < num_additional_rules; i++)
    {
      l4fw_rule_t *r =
	&((l4fw_rule_t *) ctx->rule_mem_pool[ctx->rule_mem_pool_head])[i];
      r->next_rule = ctx->rules_freelist;
      ctx->rules_freelist = r;
    }
}

/**
 * @brief Initialize the action counters for a new context.
 * @param ctx policy engine context
 */
void
l4fw_action_counters_init (l4fw_policy_engine_context_t *ctx)
{
  memset (ctx->action_counters, 0, sizeof (ctx->action_counters));
#ifndef L4FW_POLICY_ENGINE_TESTING
  const char *act_seg_pre = "/l4fw/action/";
  for (l4fw_action_type_t act = L4FW_ACTION_DROP; act < L4FW_NUM_ACTIONS;
       act++)
    {
      const char *act_name = l4fw_action_type_to_string (act);
      ctx->action_counters[act].name = malloc (strlen (act_name) + 1);
      strcpy (ctx->action_counters[act].name, act_name);
      // Format the stat segment as "/l4fw/action/<action_name>".
      ctx->action_counters[act].stat_segment_name =
	malloc (strlen (act_seg_pre) + strlen (act_name) + 1);
      strcpy (ctx->action_counters[act].stat_segment_name, act_seg_pre);
      strcpy (ctx->action_counters[act].stat_segment_name +
		strlen (act_seg_pre),
	      act_name);
      vlib_validate_simple_counter (&ctx->action_counters[act], 0);
      vlib_zero_simple_counter (&ctx->action_counters[act], 0);
    }
#endif
}
/**
 * @brief Free the action counters and remove the stat entry.
 * @param ctx policy engine context
 */
void
l4fw_action_counters_free (l4fw_policy_engine_context_t *ctx)
{
#ifndef L4FW_POLICY_ENGINE_TESTING
  for (l4fw_action_type_t act = L4FW_ACTION_DROP; act < L4FW_NUM_ACTIONS;
       act++)
    {
      vlib_free_simple_counter (&ctx->action_counters[act]);
      assert (ctx->action_counters[act].name);
      free (ctx->action_counters[act].name);
      assert (ctx->action_counters[act].stat_segment_name);
      free (ctx->action_counters[act].stat_segment_name);
    }
#endif
}

l4fw_policy_engine_context_t *
l4fw_policy_engine_context_new ()
{
  l4fw_policy_engine_context_t *ctx = (l4fw_policy_engine_context_t *) malloc (
    sizeof (l4fw_policy_engine_context_t));
  ctx->num_tables = 0;
  ctx->tables = NULL;
  ctx->default_table = 0;
  l4fw_action_counters_init (ctx);
  // Initialize the memory pool for rules.
  ctx->num_allocated_rule_nodes = 0;
  ctx->rules_freelist = NULL;
  ctx->rule_mem_pool_head = -1;
  // Default configuration.
  ctx->enable_counters = true;
  ctx->enable_print_match = false;
  // TODO(tjepsen): configure the starting number of allocated rules.
  int initial_allocated_rules = 128;
  l4fw_rules_memory_grow (ctx, initial_allocated_rules);
  return ctx;
}

void
l4fw_policy_engine_context_free (l4fw_policy_engine_context_t *ctx)
{
  l4fw_action_counters_free (ctx);
  // Clear each table, in turn freeing each rule, which may free memory
  // associated with each rule (e.g., counters).
  for (l4fw_table_id_t t = 0; t < ctx->num_tables; t++)
    l4fw_policy_engine_clear_table (ctx, t);
  for (int i = 0; i <= ctx->rule_mem_pool_head; i++)
    free (ctx->rule_mem_pool[i]);
  if (ctx->tables != NULL)
    free (ctx->tables);
  assert (ctx);
  free (ctx);
}

l4fw_table_id_t
l4fw_policy_engine_table_id_from_name (l4fw_policy_engine_context_t *ctx,
				       const char *table_name)
{
  for (l4fw_table_id_t table_id = 0; table_id < ctx->num_tables; table_id++)
    if (strcmp (ctx->tables[table_id].table_name, table_name) == 0)
      return table_id;
  return -1;
}

const char *
l4fw_policy_engine_table_name_from_id (l4fw_policy_engine_context_t *ctx,
				       l4fw_table_id_t table_id)
{
  return l4fw_policy_engine_get_table (ctx, table_id)->table_name;
}

l4fw_table_t *
l4fw_policy_engine_get_table (l4fw_policy_engine_context_t *ctx,
			      l4fw_table_id_t table_id)
{
  assert (0 <= table_id && table_id < ctx->num_tables);
  return &ctx->tables[table_id];
}

/**
 * @brief Allocate and initialize counter for rule matches.
 * @param ctx policy engine context
 * @param rule the rule that is being added
 * @param table_id the table that contains \p rule
 * @param rule_idx the index of \p rule in \p table_id
 */
void
l4fw_init_rule_counter (l4fw_policy_engine_context_t *ctx,
			      l4fw_rule_t *rule, l4fw_table_id_t table_id,
			      int rule_idx)
{
#ifndef L4FW_POLICY_ENGINE_TESTING
  rule->counter = calloc (1, sizeof (*rule->counter));
  rule->counter->name = "rule-match-count";
#define L4FW_MAX_STAT_SEG_NAME_LEN 128
  char tmp_seg_name[L4FW_MAX_STAT_SEG_NAME_LEN];
  // Create a new VLIB stats segment using the path format:
  // /l4fw/rule/<table_name>/<rule_idx>[_<rule_name>]
  // TODO(tjepsen): ensure stats seg name uniqueness. If rules are
  // added/removed to the table, this rule's index may change. We should
  // migrate this rule's stats seg name when the rule's index changes.
  int n = snprintf (
    tmp_seg_name, L4FW_MAX_STAT_SEG_NAME_LEN, "/l4fw/rule/%sfilter.%s/%d%s%s",
    table_id == ctx->default_table ? "net-in." : "",
    l4fw_policy_engine_table_name_from_id (ctx, table_id), rule_idx,
    rule->name ? "_" : "", rule->name ? rule->name : "");
  assert (n < L4FW_MAX_STAT_SEG_NAME_LEN);
  rule->counter->stat_segment_name = malloc (strlen (tmp_seg_name) + 1);
  strcpy (rule->counter->stat_segment_name, tmp_seg_name);
  vlib_validate_simple_counter (rule->counter, 0);
  vlib_zero_simple_counter (rule->counter, 0);
#endif
}

/**
 * @brief Free memory and remove stats entry for rule match counter.
 * @param ctx policy engine context
 * @param rule the rule that is being removed
 * @param table_id the table that contained \p rule
 * @param rule_idx the index of \p rule in \p table_id
 */
void
l4fw_free_rule_counter (l4fw_policy_engine_context_t *ctx,
			      l4fw_rule_t *rule, l4fw_table_id_t table_id,
			      int rule_idx)
{
#ifndef L4FW_POLICY_ENGINE_TESTING
  assert (rule->counter != NULL);
  vlib_free_simple_counter (rule->counter);
  assert (rule->counter->stat_segment_name != NULL);
  free (rule->counter->stat_segment_name);
  free (rule->counter);
#endif
}

l4fw_table_id_t
l4fw_policy_engine_context_add_table (l4fw_policy_engine_context_t *ctx,
				      const char *table_name)
{
  // Check that the table name is available.
  if (l4fw_policy_engine_table_id_from_name (ctx, table_name) >= 0)
    return -1;
  l4fw_table_id_t new_table_id = ctx->num_tables;
  ctx->num_tables++;
  ctx->tables = (l4fw_table_t *) realloc (ctx->tables, sizeof (l4fw_table_t) *
							 (ctx->num_tables));
  l4fw_table_init (&ctx->tables[new_table_id]);
  assert (strlen (table_name) + 1 < L4FW_MAX_TABLE_NAME_SIZE);
  strcpy (ctx->tables[new_table_id].table_name, table_name);
  l4fw_init_rule_counter (ctx, &ctx->tables[new_table_id].default_rule, new_table_id, 0);
  return new_table_id;
}

int
l4fw_policy_engine_rule_append (l4fw_policy_engine_context_t *ctx,
				l4fw_table_id_t table_id, l4fw_rule_t rule,
				const char *name)
{
  assert (table_id < ctx->num_tables);
  // It's invalid for the default (main) table to RETURN. Error.
  if (ctx->default_table == table_id &&
      rule.action.action_type == L4FW_ACTION_RETURN)
    return -1;
  l4fw_table_t *t = &ctx->tables[table_id];
  // Grow the rule node freelist if it's empty.
  if (ctx->rules_freelist == NULL)
    l4fw_rules_memory_grow (ctx, ctx->num_allocated_rule_nodes);
  // Get rule node from freelist.
  l4fw_rule_t *new_rule = ctx->rules_freelist;
  ctx->rules_freelist = new_rule->next_rule;
  l4fw_rule_init(new_rule);
  // Copy the fields from the argument rule.
  new_rule->action = rule.action;
  memcpy (&new_rule->match_list, &rule.match_list, sizeof (rule.match_list));
  if (name != NULL) {
    new_rule->name = malloc(strlen(name) + 1);
    strcpy(new_rule->name, name);
  }
  int rule_idx = l4fw_table_append_rule (t, new_rule);
  // Initialize the rules's match counter.
  if (ctx->enable_counters)
    l4fw_init_rule_counter (ctx, new_rule, table_id, rule_idx);
  return rule_idx;
}

l4fw_rule_t *
l4fw_policy_engine_get_rule (l4fw_policy_engine_context_t *ctx,
			     l4fw_table_id_t table_id, int rule_idx)
{
  assert (table_id < ctx->num_tables);
  l4fw_table_t *t = &ctx->tables[table_id];
  return l4fw_table_get_rule (t, rule_idx);
}

bool
l4fw_policy_engine_rule_remove (l4fw_policy_engine_context_t *ctx,
				l4fw_table_id_t table_id, u32 idx)
{
  assert (table_id < ctx->num_tables);
  l4fw_table_t *t = &ctx->tables[table_id];
  l4fw_rule_t *removed_rule = l4fw_table_rule_remove(t, idx);
  if (removed_rule == NULL) // Rule not found.
    return false;
  // Free the rule's counter, if initialized.
#ifndef L4FW_POLICY_ENGINE_TESTING
  if (removed_rule->counter != NULL)
    l4fw_free_rule_counter (ctx, removed_rule, table_id, idx);
#endif
  // Free the rule's name, if allocated.
  if (removed_rule->name != NULL)
    free (removed_rule->name);
  // Return the rule to the freelist.
  removed_rule->next_rule = ctx->rules_freelist;
  ctx->rules_freelist = removed_rule;
  return true;
}

void
l4fw_rule_init (l4fw_rule_t *rule)
{
  // This can be done implicitly with a memset(0):
  // rule->next_rule = NULL;
  // for (int i = 0; i < L4FW_RULE_MAX_MATCHES; i++)
  //   rule->match_list[i].key = L4FW_MATCH_KEY_INVALID;
  // rule->action =
  //   (l4fw_action_t){ .action_type = L4FW_ACTION_NOP, .action_data = 0 };
  memset(rule, 0, sizeof(*rule));
}

bool
l4fw_rule_add_match (l4fw_rule_t *rule, l4fw_match_t *match)
{
  // Seek to the last unused match.
  for (int i = 0; i < L4FW_RULE_MAX_MATCHES; i++)
    {
      if (rule->match_list[i].key != L4FW_MATCH_KEY_INVALID)
	continue;
      memcpy (&rule->match_list[i], match, sizeof (*match));
    }
  return false;
}

void
l4fw_table_init (l4fw_table_t *tbl)
{
  tbl->default_rule = (l4fw_rule_t){
    .action = (l4fw_action_t){ .action_type = L4FW_ACTION_ALLOW },
    .match_list[0].key = L4FW_MATCH_KEY_DEFAULT,
  };
  tbl->rules = NULL;
}

int
l4fw_table_append_rule (l4fw_table_t *t, l4fw_rule_t *rule)
{
  int num_rules = 1;
  rule->next_rule = NULL; // Mark this rule as the last, since we're appending.
  if (t->rules == NULL)
    { // The table's empty.
      t->rules = rule;
    }
  else
    {
      // Seek to the last rule.
      l4fw_rule_t *last = t->rules;
      while (last->next_rule != NULL)
	{
    num_rules++;
	  last = last->next_rule;
	}
      last->next_rule = rule;
      num_rules++;
    }
  return num_rules;
}

int
l4fw_table_count_rules (l4fw_table_t *t)
{
  int n = 0;
  for (l4fw_rule_t *r = t->rules; r != NULL; r = r->next_rule)
    n++;
  return n;
}

l4fw_rule_t *
l4fw_table_rule_remove (l4fw_table_t *t, u32 idx)
{
  u32 i = 0;
  l4fw_rule_t *prev_rule = NULL;
  for (l4fw_rule_t *r = t->rules; r != NULL; r = r->next_rule, i++)
    {
      if (i != idx - 1)
	{
	  prev_rule = r;
	  continue;
	}
      if (prev_rule == NULL)
	t->rules = r->next_rule;
      else
	prev_rule->next_rule = r->next_rule;
      return r;
    }
  return NULL;
}

l4fw_rule_t *
l4fw_table_get_rule (l4fw_table_t *t, u32 idx)
{
  if (idx == 0) return &t->default_rule;
  u32 i = 0;
  for (l4fw_rule_t *r = t->rules; r != NULL; r = r->next_rule, i++)
    if (i == idx - 1)
      return r;
  return NULL;
}

/**
 * @brief Check whether a string ends with another string.
 * @param s string to search in
 * @param end the expected ending of \p s
 * @return true iif \p s ends with \p end
 */
bool
l4fw_str_ends_with (const char *s, const char *end)
{
  if (s == NULL || end == NULL)
    return false;
  size_t str_len = strlen (s);
  size_t end_len = strlen (end);
  return str_len >= end_len &&
	 strncmp (s + (str_len - end_len), end, end_len) == 0;
}

/**
 * @brief Check whether the application ID matches.
 * @param pred the predicate containing the app id
 * @param pkt the headers and metadata to match against
 * @return true iif the app id matches
 */
bool
l4fw_match_app_id (l4fw_match_t *pred, void *pkt)
{
  char *app_id = L4FW_GET_APP_ID (pkt);
  assert (app_id != NULL);
  bool matches = false;
  switch (pred->decorator)
    {
    case L4FW_MATCH_EQUALS:
      matches = strcmp (pred->val_as_str, app_id) == 0;
      break;
    case L4FW_MATCH_STARTS_WITH:
      matches =
	strncmp (pred->val_as_str, app_id, strlen (pred->val_as_str)) == 0;
      break;
    case L4FW_MATCH_CONTAINS:
      matches = strstr (app_id, pred->val_as_str) != NULL;
      break;
    case L4FW_MATCH_ENDS_WITH:
      matches = l4fw_str_ends_with (app_id, pred->val_as_str);
      break;
    default:
      break;
    }
  return (!pred->negated && matches) || (pred->negated && !matches);
}

/**
 * @brief Match a single predicate (mask, range, etc.)
 * @param m rule to match against
 * @param value value from the packet
 */
static inline bool
l4fw_match_value (l4fw_match_t *m, u128 value)
{
  bool matches;
  if (m->decorator == L4FW_MATCH_RANGE)
    {
#ifdef L4FW_POLICY_ENGINE_TESTING
      // All testing values are host (little) endian.
      matches = m->range_start <= value && value <= m->range_end;
#else
      // Packet values are network-endian, so convert to host-endion.
      u32 value_he;
      switch (m->key)
	{
	case L4FW_MATCH_KEY_IP4_SADDR:
	case L4FW_MATCH_KEY_IP4_DADDR:
	  value_he = clib_net_to_host_u32 (value);
	  break;
	case L4FW_MATCH_KEY_TCP_SPORT:
	case L4FW_MATCH_KEY_TCP_DPORT:
	case L4FW_MATCH_KEY_UDP_SPORT:
	case L4FW_MATCH_KEY_UDP_DPORT:
	  value_he = clib_net_to_host_u16 (value);
	  break;
	default:
	  value_he = value;
	  fprintf (stderr, "Error: range match unsupported for this field.\n");
	}
      matches = m->range_start <= value_he && value_he <= m->range_end;
#endif
    }
  else if (m->mask != 0)
    {
      u128 masked_val = m->mask == 0 ? value : value & m->mask;
      matches = m->value == masked_val;
    }
  else
    {
      matches = m->value == value;
    }

  if (m->negated)
    return !matches;
  else
    return matches;
}

/**
 * @brief Check whether a conjunction of matches is true.
 * @param match_list one or matches in the conjunction
 * @param pkt the header and metadata to match against
 * @return true iif all the matches are true
 */
bool
l4fw_match_all_match (l4fw_match_t match_list[], void *pkt)
{
  for (int i = 0;
       i < L4FW_RULE_MAX_MATCHES && match_list[i].key != L4FW_MATCH_KEY_INVALID;
       i++)
    {
      l4fw_match_t *m = &match_list[i];
#define MAYBE_MASK(val, mask) (((mask) == 0) ? (val) : (val) & (mask))
      switch (m->key)
	{
	case L4FW_MATCH_KEY_TRUE: // Always matches.
	  break;
	case L4FW_MATCH_KEY_IP4_SADDR:
	  if (l4fw_match_value (m, L4FW_GET_IP4_SADDR (pkt)))
	    break;
	  else
	    return false;
	case L4FW_MATCH_KEY_IP4_DADDR:
	  if (l4fw_match_value (m, L4FW_GET_IP4_DADDR (pkt)))
	    break;
	  else
	    return false;
	case L4FW_MATCH_KEY_TCP_SPORT:
	  if (L4FW_GET_IP_PROTO (pkt) == IP_PROTOCOL_TCP &&
	      l4fw_match_value (m, L4FW_GET_TCP_SPORT (pkt)))
	    break;
	  else
	    return false;
	case L4FW_MATCH_KEY_TCP_DPORT:
	  if (L4FW_GET_IP_PROTO (pkt) == IP_PROTOCOL_TCP &&
	      l4fw_match_value (m, L4FW_GET_TCP_DPORT (pkt)))
	    break;
	  else
	    return false;
	case L4FW_MATCH_KEY_UDP_SPORT:
	  if (L4FW_GET_IP_PROTO (pkt) == IP_PROTOCOL_UDP &&
	      l4fw_match_value (m, L4FW_GET_UDP_SPORT (pkt)))
	    break;
	  else
	    return false;
	case L4FW_MATCH_KEY_UDP_DPORT:
	  if (L4FW_GET_IP_PROTO (pkt) == IP_PROTOCOL_UDP &&
	      l4fw_match_value (m, L4FW_GET_UDP_DPORT (pkt)))
	    break;
	  else
	    return false;
	case L4FW_MATCH_KEY_APP_ID:
	  if (l4fw_match_app_id (m, pkt))
	    break;
	  else
	    return false;
	case L4FW_MATCH_KEY_CONN_STATE:
	  if (l4fw_match_value (m, L4FW_GET_CONN_STATE (pkt)))
	    break;
	  else
	    return false;
	default:
	  fprintf (stderr, "Error: unknown match key.\n");
	}
    }
  return true;
}

/**
 * @brief Check whether the rule matches the packet.
 * @param rule the rule to check
 * @param pkt the header and metadata to match against
 * @return true iif the rule matches the packet
 */
bool
l4fw_rule_matches (l4fw_rule_t *rule, void *pkt)
{
  return l4fw_match_all_match (rule->match_list, pkt);
}

bool
l4fw_is_default_table_rule (l4fw_table_t *tbl, l4fw_rule_t *rule)
{
  return &tbl->default_rule == rule;
}

/**
 * @brief This hook is called each time a rule is matched.
 * Currently, the only purpose of this function is for collecting stats.
 * @param ctx policy engine context
 * @param rule the rule that matched
 * @param rule_table_id the table of the matched \p rule
 * @param rule_idx the index of \p rule in the table \p rule_table_id
 * @param pkt the packet to match against in the lookup
*/
void
l4fw_rule_matched (l4fw_policy_engine_context_t *ctx, l4fw_rule_t *rule,
		   l4fw_table_id_t rule_table_id, int rule_idx, void *pkt)
{
  // Increment counter each time a rule is matched, even if its action is
  // non-terminating.
#ifdef L4FW_POLICY_ENGINE_TESTING
  ctx->action_counters[rule->action.action_type]++;
#else
  if (ctx->enable_counters)
    {
      u32 thread_index = vlib_get_thread_index ();
      vlib_increment_simple_counter (
	&ctx->action_counters[rule->action.action_type], thread_index, 0, 1);
      if (rule->counter != NULL)
	vlib_increment_simple_counter (rule->counter, thread_index, 0, 1);
    }
#endif

#ifndef L4FW_POLICY_ENGINE_TESTING
  // Optionally print debug if running from VPP.
  if (ctx->enable_print_match)
    {
      char rule_desc[256];
      l4fw_rule_format (rule_desc, sizeof (rule_desc), rule);
      char pkt_desc[256];
      l4fw_packet_format (pkt_desc, sizeof (pkt_desc), pkt);
      printf ("Pkt %s matched rule %sfilter.%s.%d: %s\n", pkt_desc,
	      rule_table_id == ctx->default_table ? "net-in." : "",
	      l4fw_policy_engine_get_table (ctx, rule_table_id)->table_name,
	      rule_idx, rule_desc);
    }
#endif
}

/**
 * @brief Execute the LOG action of a rule that matched.
 * @param ctx policy engine context
 * @param rule the rule that matched
 * @param rule_table_id the table of the matched \p rule
 * @param rule_idx the index of \p rule in the table \p rule_table_id
 * @param pkt the packet
 */
void
l4fw_log_action_execute (l4fw_policy_engine_context_t *ctx, l4fw_rule_t *rule,
			 l4fw_table_id_t rule_table_id, int rule_idx,
			 void *pkt)
{
  assert (rule->action.action_type == L4FW_ACTION_LOG);
#ifdef L4FW_POLICY_ENGINE_TESTING
  assert (rule_idx < L4FW_MAX_LOG_COUNTER_RULES);
  test_log_counter[rule_idx]++;
#else
  elog_l4fw_X2 ("LOG action: tbl=%d rule_idx=%d", "i4i4", rule_table_id,
		rule_idx);
#endif
}

// Forward declaration.
l4fw_matched_rule_t
l4fw_continue_lookup_from_table (l4fw_policy_engine_context_t *ctx,
				 l4fw_table_id_t table_id, void *pkt);

/**
 * @brief If a rule matched, execute the traversal related operations (jump, log, etc.).
 * @param ctx policy engine context
 * @param rule the rule that matched
 * @param rule_table_id the table of the matched \p rule
 * @param rule_idx the index of \p rule in the table \p rule_table_id
 * @param pkt the packet to match against in the lookup
 * @return a terminating rule, otherwise `.rule=NULL`.
 */
l4fw_matched_rule_t
l4fw_rule_follow (l4fw_policy_engine_context_t *ctx, l4fw_rule_t *rule,
		  l4fw_table_id_t rule_table_id, int rule_idx, void *pkt)
{
  switch (rule->action.action_type)
    {
    case L4FW_ACTION_JUMP:
      {
	while (rule->action.action_type == L4FW_ACTION_JUMP)
	  {
	    l4fw_table_id_t next_tbl_id = rule->action.action_data;
	    l4fw_matched_rule_t matched_rule =
	      l4fw_continue_lookup_from_table (ctx, next_tbl_id, pkt);
	    rule = matched_rule.rule;
	    rule_idx = matched_rule.rule_idx;
	    rule_table_id = matched_rule.table_id;
	  }
      }
    case L4FW_ACTION_ALLOW:
    case L4FW_ACTION_DROP:
    case L4FW_ACTION_REJECT:
    case L4FW_ACTION_RETURN:
      return (l4fw_matched_rule_t){ .table_id = rule_table_id,
				    .rule_idx = rule_idx,
				    .rule = rule };
    case L4FW_ACTION_LOG:
      l4fw_log_action_execute (ctx, rule, rule_table_id, rule_idx, pkt);
      // Default rules that LOG are considered terminating.
      if (rule->match_list[0].key == L4FW_MATCH_KEY_DEFAULT)
	return (l4fw_matched_rule_t){ .table_id = rule_table_id,
				      .rule_idx = rule_idx,
				      .rule = rule };
      break; // Otherwise, this is non-terminating.
    default:
      fprintf (stderr, "Error: unknown action type.\n");
      exit (1);
      break;
    }
  return (l4fw_matched_rule_t){ .rule = NULL }; // Non-terminating action
}

/**
 * @brief Recursive method for performing lookups.
 * @param ctx policy engine context
 * @param table_id table from which to continue the lookup
 * @param pkt the packet to match against in the lookup
 * @return a terminating rule, otherwise `.rule=NULL`.
 */
l4fw_matched_rule_t
l4fw_continue_lookup_from_table (l4fw_policy_engine_context_t *ctx,
				 l4fw_table_id_t table_id, void *pkt)
{
  assert (table_id < ctx->num_tables);
  l4fw_table_t *t = &ctx->tables[table_id];
  int rule_idx = 1;
  for (l4fw_rule_t *rule = t->rules; rule != NULL; rule = rule->next_rule, rule_idx++)
    {
      if (!l4fw_rule_matches (rule, pkt))
	continue;
      l4fw_rule_matched (ctx, rule, table_id, rule_idx, pkt);
      l4fw_matched_rule_t term_rule =
	l4fw_rule_follow (ctx, rule, table_id, rule_idx, pkt);
      // The rule matched, but it's non-terminating. Continue.
      if (term_rule.rule == NULL)
	continue;
      // Another table RETURNed to this table. Continue.
      if (term_rule.rule->action.action_type == L4FW_ACTION_RETURN &&
	  term_rule.table_id != table_id)
	continue;
      // This is the default (main) table RETURNing.
      if (table_id == ctx->default_table &&
	  term_rule.rule->action.action_type == L4FW_ACTION_RETURN &&
	  term_rule.table_id == table_id)
	break; // Go to this table's default rule.
      return term_rule;
    }
  // No terminating rule matched, so execute the default.
  l4fw_rule_matched (ctx, &t->default_rule, table_id, 0, pkt);
  l4fw_matched_rule_t term_rule =
    l4fw_rule_follow (ctx, &t->default_rule, table_id, 0, pkt);
  if (term_rule.rule != NULL)
    return term_rule;
  return (l4fw_matched_rule_t){ .table_id = table_id,
				.rule_idx = 0, // Indicates default rule.
				.rule = &t->default_rule };
}

l4fw_matched_rule_t
l4fw_policy_engine_lookup (l4fw_policy_engine_context_t *ctx, void *pkt)
{
  if (ctx->num_tables == 0) // No tables have been defined.
    return (l4fw_matched_rule_t){ .rule = false };
  l4fw_matched_rule_t matched_rule =
    l4fw_continue_lookup_from_table (ctx, ctx->default_table, pkt);
  return matched_rule;
}

u64
l4fw_policy_engine_get_action_counter (l4fw_policy_engine_context_t *ctx,
				       l4fw_action_type_t action_type)
{
  assert (action_type < L4FW_NUM_ACTIONS);
#ifdef L4FW_POLICY_ENGINE_TESTING
  return ctx->action_counters[action_type];
#else
  return vlib_get_simple_counter (&ctx->action_counters[action_type], 0);
#endif
}

bool l4fw_policy_engine_set_default_action (l4fw_policy_engine_context_t *ctx,
					    l4fw_table_id_t table_id,
					    l4fw_action_t act)
{
  assert (table_id < ctx->num_tables);
  // It's invalid for the default (main) table to RETURN. Error.
  if (ctx->default_table == table_id && act.action_type == L4FW_ACTION_RETURN)
    return false;
  l4fw_table_t *t = &ctx->tables[table_id];
  t->default_rule.action = act;
  return true;
}

void
l4fw_policy_engine_clear_table (l4fw_policy_engine_context_t *ctx,
				l4fw_table_id_t table_id)
{
  assert (table_id < ctx->num_tables);
  l4fw_table_t *t = &ctx->tables[table_id];
  int num_rules = l4fw_table_count_rules (t);
  for (int i = 0; i < num_rules; i++)
    l4fw_policy_engine_rule_remove (ctx, table_id, 1);
  assert (l4fw_table_count_rules (t) == 0);
}

void
l4fw_policy_engine_table_reset_counters (l4fw_policy_engine_context_t *ctx,
					 l4fw_table_id_t table_id)
{
  l4fw_table_t *t = l4fw_policy_engine_get_table (ctx, table_id);
#ifndef L4FW_POLICY_ENGINE_TESTING
  if (t->default_rule.counter)
    vlib_zero_simple_counter (t->default_rule.counter, 0);
#endif
  for (l4fw_rule_t *rule = t->rules; rule != NULL; rule = rule->next_rule)
    {
#ifndef L4FW_POLICY_ENGINE_TESTING
      if (rule->counter)
	vlib_zero_simple_counter (rule->counter, 0);
#endif
    }
}

void
l4fw_policy_engine_reset_action_counters (l4fw_policy_engine_context_t *ctx)
{
  for (l4fw_action_type_t act = L4FW_ACTION_DROP; act < L4FW_NUM_ACTIONS;
       act++)
    {
#ifdef L4FW_POLICY_ENGINE_TESTING
      ctx->action_counters[act] = 0;
#else
      vlib_zero_simple_counter (&ctx->action_counters[act], 0);
#endif
    }
}

/**
 * @brief Format a 128-bit value to a string (similar to snprintf).
 * @param s pointer to the destination string
 * @param size write at most \p size bytes
 * @param val the 16 byte value to format
 */
static inline int
l4fw_u128_format (char *s, size_t size, u128 val)
{
  u64 val_hi = val >> 64, val_lo = (u64) val;
  if (val_hi)
    return snprintf (s, size, "0x%lX%016lX", val_hi, val_lo);
  else
    return snprintf (s, size, "0x%lX", val_lo);
}

int
l4fw_rule_format (char *s, size_t size, l4fw_rule_t *rule)
{
  int n = 0;
  for (int i = 0; i < L4FW_RULE_MAX_MATCHES &&
		  rule->match_list[i].key != L4FW_MATCH_KEY_INVALID;
       i++)
    {
      l4fw_match_t *m = &rule->match_list[i];
      if (m->key == L4FW_MATCH_KEY_DEFAULT)
	n += snprintf (s + n, size - n, "(default)");
      else
	{
	  if (i > 0)
	    n += snprintf (s + n, size - n, ", ");
	  n += snprintf (s + n, size - n, "%s ",
			 l4fw_match_key_to_string (m->key));
	  n += snprintf (s + n, size - n, "%s%s ", m->negated ? "!" : "",
			 l4fw_decorator_to_string (m->decorator));
	  n += l4fw_u128_format (s + n, size - n, m->value);
	  if (m->decorator == L4FW_MATCH_RANGE)
	    {
	      n += snprintf (s + n, size - n, "-");
	      n += l4fw_u128_format (s + n, size - n, m->range_end);
	    }
	  else if (m->mask)
	    {
	      n += snprintf (s + n, size - n, "&");
	      n += l4fw_u128_format (s + n, size - n, m->mask);
	    }
	}
    }
  n += snprintf (s + n, size - n, " => %s",
		 l4fw_action_type_to_string (rule->action.action_type));
  switch (rule->action.action_type)
    {
    case L4FW_ACTION_DROP:
    case L4FW_ACTION_ALLOW:
    case L4FW_ACTION_REJECT:
      break; // Don't print action data for these actions.
    default:
      n += snprintf (s + n, size - n, " ");
      n += l4fw_u128_format (s + n, size - n, rule->action.action_data);
    }
  if (rule->name != NULL)
    n += snprintf (s + n, size - n, " (%s)", rule->name);
  return n;
}

int
l4fw_table_format (char *s, size_t size, l4fw_table_t *tbl)
{
  assert(tbl != NULL);
  assert(s != NULL);
  int idx = 1;
  int n = 0;
  char formatted_rule[L4FW_MAX_EXPECTED_RULE_STRING_SIZE];
  formatted_rule[0] = '\0';
  n += snprintf(s + n, size - n, "====== %s ======\n", tbl->table_name);
  for (l4fw_rule_t *rule = tbl->rules; rule != NULL; rule = rule->next_rule)
    {
      if (l4fw_rule_format (formatted_rule, sizeof(formatted_rule), rule) > 0)
	n += snprintf (s + n, size - n, "%d: %s\n", idx++, formatted_rule);
    }
  if (l4fw_rule_format (formatted_rule, sizeof (formatted_rule), &tbl->default_rule) > 0)
    n += snprintf (s + n, size - n, "%s\n", formatted_rule);
  return n;
}