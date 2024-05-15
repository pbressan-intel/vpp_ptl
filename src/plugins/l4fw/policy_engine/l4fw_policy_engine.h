#ifndef __included_l4fw_policy_engine_h__
#define __included_l4fw_policy_engine_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#ifdef L4FW_POLICY_ENGINE_TESTING
// This struct is only used for testing. It's a comibination of packet header
// fields and L4FW metadata.
struct mypkt
{
  // Packet header fields.
  u16 eth_type;
  u8 ip_proto;
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  // L4FW metadata.
  char *app_id;
  int conn_state;
};

// Accessors for the opaque header
#define L4FW_GET_ETH_TYPE(h) (((struct mypkt *)(h))->eth_type)
#define L4FW_GET_IP_PROTO(h) (((struct mypkt *)(h))->ip_proto)
#define L4FW_GET_IP4_SADDR(h) (((struct mypkt *)(h))->saddr)
#define L4FW_GET_IP4_DADDR(h) (((struct mypkt *)(h))->daddr)
#define L4FW_GET_TCP_SPORT(h) (((struct mypkt *)(h))->sport)
#define L4FW_GET_TCP_DPORT(h) (((struct mypkt *)(h))->dport)
#define L4FW_GET_TCP_SPORT_HE(h) L4FW_GET_TCP_SPORT(h)
#define L4FW_GET_TCP_DPORT_HE(h) L4FW_GET_TCP_DPORT(h)
#define L4FW_GET_UDP_SPORT(h) (((struct mypkt *)(h))->sport)
#define L4FW_GET_UDP_DPORT(h) (((struct mypkt *)(h))->dport)
#define L4FW_GET_UDP_SPORT_HE(h) L4FW_GET_UDP_SPORT(h)
#define L4FW_GET_UDP_DPORT_HE(h) L4FW_GET_UDP_DPORT(h)
#define L4FW_GET_APP_ID(h) (((struct mypkt *)(h))->app_id)
#define L4FW_GET_CONN_STATE(h) (((struct mypkt *) (h))->conn_state)

// Count the number of times a LOG action is executed. Maps the rule_idx of the
// LOG to the counter.
#define L4FW_MAX_LOG_COUNTER_RULES 1024
extern int test_log_counter[L4FW_MAX_LOG_COUNTER_RULES];

#define L4FW_POLICY_ENGINE_PRINT_DEBUG 0
#else
#include "l4fw/l4fw_types.h"
#include "l4fw/elog_l4fw.h"

#define L4FW_POLICY_ENGINE_PRINT_DEBUG 1
typedef struct {
  ethernet_header_t *eth;
  l4fw_meta_t *meta;
} l4fw_packet_t;

#define __L4FW_GET_ETH(p) (((l4fw_packet_t *)p)->eth)
#define __L4FW_GET_IP(p) ((ip4_header_t *)((((l4fw_packet_t *)p)->eth)+1))
#define __L4FW_GET_TCP(p) ((tcp_header_t *)(get_ip_payload(__L4FW_GET_IP(p))))
#define __L4FW_GET_UDP(p) ((udp_header_t *)(get_ip_payload(__L4FW_GET_IP(p))))
#define L4FW_GET_ETH_TYPE(p) (clib_net_to_host_u16(__L4FW_GET_ETH(p)->type))
#define L4FW_GET_IP_PROTO(p) (__L4FW_GET_IP(p)->protocol)
#define L4FW_GET_IP4_SADDR(p) (__L4FW_GET_IP(p)->src_address.data_u32)
#define L4FW_GET_IP4_DADDR(p) (__L4FW_GET_IP(p)->dst_address.data_u32)
#define L4FW_GET_TCP_SPORT(p) (__L4FW_GET_TCP(p)->src_port)
#define L4FW_GET_TCP_DPORT(p) (__L4FW_GET_TCP(p)->dst_port)
#define L4FW_GET_TCP_SPORT_HE(p)                                              \
  (clib_big_to_host_u16 (L4FW_GET_TCP_SPORT (p)))
#define L4FW_GET_TCP_DPORT_HE(p)                                              \
  (clib_big_to_host_u16 (L4FW_GET_TCP_DPORT (p)))
#define L4FW_GET_UDP_SPORT(p) (__L4FW_GET_UDP(p)->src_port)
#define L4FW_GET_UDP_DPORT(p) (__L4FW_GET_UDP(p)->dst_port)
#define L4FW_GET_UDP_SPORT_HE(p)                                              \
  (clib_big_to_host_u16 (L4FW_GET_UDP_SPORT (p)))
#define L4FW_GET_UDP_DPORT_HE(p)                                              \
  (clib_big_to_host_u16 (L4FW_GET_UDP_DPORT (p)))
#define L4FW_GET_APP_ID(p)    (((l4fw_packet_t *) p)->meta->app_id)
#define L4FW_GET_CONN_STATE(p) (((l4fw_packet_t *) p)->meta->ct_state)
#endif


// For formatting rules and tables.
#define L4FW_MAX_EXPECTED_RULE_STRING_SIZE 1024

typedef enum
{
  L4FW_MATCH_KEY_INVALID = 0,
  L4FW_MATCH_KEY_TRUE,
  L4FW_MATCH_KEY_IP4_SADDR,
  L4FW_MATCH_KEY_IP4_DADDR,
  L4FW_MATCH_KEY_TCP_SPORT,
  L4FW_MATCH_KEY_TCP_DPORT,
  L4FW_MATCH_KEY_UDP_SPORT,
  L4FW_MATCH_KEY_UDP_DPORT,
  L4FW_MATCH_KEY_APP_ID,
  L4FW_MATCH_KEY_CONN_STATE,
  L4FW_MATCH_KEY_DEFAULT,
} l4fw_match_key_t;

// Although these decorators are defined here, they are not used within the
// policy engine, which uses masks instead.
typedef enum
{
  L4FW_MATCH_DECORATOR_INVALID = 0,
  L4FW_MATCH_EQUALS,
  L4FW_MATCH_STARTS_WITH,
  L4FW_MATCH_CONTAINS,
  L4FW_MATCH_ENDS_WITH,
  L4FW_MATCH_RANGE,
} l4fw_match_decorator_t;

/**
 * @brief A single predicate on packet or metadata.
 * Depending on the type of match (decorator), values are stored in different
 * endianness:
 * - Exact match: `value` is stored in network order, to avoid `ntohs`.
 * - Range match: `range_` is stored in host order, for >/< arithmetic.
 *                Requires `ntohs` on packet fields.
 *
 * @todo would "predicate" be a more appropriate name than "match"?
 */
typedef struct l4fw_match
{
  l4fw_match_key_t key;
  bool negated;
  l4fw_match_decorator_t decorator;
  union
  {
    u128 value;
    u128 range_start;
    char val_as_str[16];
  };
  union
  {
    u128 range_end;
    u128 mask; // Unused if zero.
  };
} l4fw_match_t;

typedef enum
{
  L4FW_ACTION_INVALID = 0,
  L4FW_ACTION_NOP,
  L4FW_ACTION_DROP,
  L4FW_ACTION_ALLOW,
  L4FW_ACTION_REJECT,
  L4FW_ACTION_LOG,
  L4FW_ACTION_JUMP,
  L4FW_ACTION_RETURN,
  L4FW_NUM_ACTIONS
} l4fw_action_type_t;

typedef struct
{
  l4fw_action_type_t action_type;
  u128 action_data;
} l4fw_action_t;

#define L4FW_RULE_MAX_MATCHES 4
typedef struct l4fw_rule
{
  l4fw_match_t match_list[L4FW_RULE_MAX_MATCHES];
  l4fw_action_t action;
#ifndef L4FW_POLICY_ENGINE_TESTING
  vlib_simple_counter_main_t *counter;
#endif
  char *name; // Optional.
  struct l4fw_rule *next_rule;
} l4fw_rule_t;

typedef struct
{
  l4fw_rule_t default_rule;
  l4fw_rule_t *rules;
#define L4FW_MAX_TABLE_NAME_SIZE 64
  char table_name[L4FW_MAX_TABLE_NAME_SIZE];
} l4fw_table_t;

typedef int l4fw_table_id_t;

typedef struct
{
  l4fw_table_id_t table_id;
  int rule_idx;
  l4fw_rule_t *rule;
} l4fw_matched_rule_t;

typedef struct
{
  // Configuration.
  bool enable_print_match;
  bool enable_counters;

  // Memory pools.
  int num_allocated_rule_nodes;
  void *rule_mem_pool[8];
  int rule_mem_pool_head;
  l4fw_rule_t *rules_freelist;

  // Stats.
#ifdef L4FW_POLICY_ENGINE_TESTING
  u64 action_counters[L4FW_NUM_ACTIONS];
#else
  vlib_simple_counter_main_t action_counters[L4FW_NUM_ACTIONS];
#endif

  // Tables.
  int num_tables;
  l4fw_table_id_t default_table;
  l4fw_table_t *tables;

} l4fw_policy_engine_context_t;

const char *l4fw_action_type_to_string (l4fw_action_type_t a);
const char *l4fw_match_key_to_string (l4fw_match_key_t k);
const char *l4fw_decorator_to_string (l4fw_match_decorator_t d);
l4fw_action_type_t l4fw_action_type_from_string (const char *s);
l4fw_match_key_t l4fw_match_key_from_string (const char *s);
l4fw_match_decorator_t l4fw_decorator_from_string (const char *s);

/**
 * @brief Allocate and initialize tables for the policy engine.
 * @return pointer to a newly allocated context
 */
l4fw_policy_engine_context_t *l4fw_policy_engine_context_new ();

/**
 * @brief Free an allocated policy engine context.
 * @param ctx policy engine context
 */
void l4fw_policy_engine_context_free (l4fw_policy_engine_context_t *ctx);

/**
 * @brief Add a new table to the context.
 * If this is the first table to be added, it will be the default table.
 * The default table action is initialized to ALLOW.
 * @todo Add function for setting the default table for this context.
 * @todo Add function for removing a table.
 * @param ctx policy engine context
 * @param table_name name of the new table (string)
 * @return ID of the newly added table, or -1 if the table name already exists
 */
l4fw_table_id_t
l4fw_policy_engine_context_add_table (l4fw_policy_engine_context_t *ctx,
				      const char *table_name);

/**
 * @brief Get the table ID associated with a table name.
 * @param ctx policy engine context
 * @param table_name the name of the table (string)
 * @return the ID of the table, or -1 if the table doesn't exist
 */
l4fw_table_id_t
l4fw_policy_engine_table_id_from_name (l4fw_policy_engine_context_t *ctx,
				       const char *table_name);

/**
 * @brief Get the table name associated with a table ID.
 * @param ctx policy engine context
 * @param table_id the ID of the table
 * @return the name of the table (string)
 */
const char *
l4fw_policy_engine_table_name_from_id (l4fw_policy_engine_context_t *ctx,
				       l4fw_table_id_t table_id);
/**
 * @brief Get the table associated with a table ID.
 * @param ctx policy engine context
 * @param table_id the ID of the table
 * @return pointer to the table datastructure
 */
l4fw_table_t*
l4fw_policy_engine_get_table (l4fw_policy_engine_context_t *ctx,
				       l4fw_table_id_t table_id);

/**
 * @brief Append a rule to a table.
 * N.B.: the caller is responsible for ensuring the correct endianess of values
 * in `rule`. See documentation for \ref l4fw_match_t.
 * @param ctx policy engine context
 * @param table_id ID of the table to append to
 * @param rule rule to be copied and appended to the table
 * @param name if not NULL, a name will be copied to a newly allocated string
 * @return the index of the rule (starting from 1), or -1 on error
 */
int l4fw_policy_engine_rule_append (l4fw_policy_engine_context_t *ctx,
				    l4fw_table_id_t table_id, l4fw_rule_t rule,
				    const char *name);

/**
 * @brief Get a rule from a table.
 * Rule indices are 1-based. \p idx == 0 returns the default rule.
 * @param ctx policy engine context
 * @param table_id ID of the table to append to
 * @param rule_idx index of the rule in the table
 * @return pointer to the rule, or NULL if not found
 */
l4fw_rule_t *l4fw_policy_engine_get_rule (l4fw_policy_engine_context_t *ctx,
					  l4fw_table_id_t table_id,
					  int rule_idx);

/**
 * @brief Remove a rule from a table.
 * @param ctx policy engine context
 * @param table_id ID of the table to remove from
 * @param idx the index of the rule to remove
 * @return true iif rule was successfully removed
 */
bool l4fw_policy_engine_rule_remove (l4fw_policy_engine_context_t *ctx,
				    l4fw_table_id_t table_id, u32 idx);

/**
 * @brief Initialize a new rule for the policy table.
 * @param rule pointer to uninitialized rule memory
 */
void l4fw_rule_init (l4fw_rule_t *rule);

/**
 * @brief Add a match to an existing rule.
 * @param rule existing rule
 * @param match match to add to existing rule
 * @return true on success
 */
bool l4fw_rule_add_match (l4fw_rule_t *rule, l4fw_match_t *match);

/**
 * @brief Initialize a new policy table.
 * @param tbl pointer to uninitialized table memory
 */
void l4fw_table_init (l4fw_table_t *tbl);

/**
 * @brief Append a rule to an existing table.
 * N.B.: the caller is responsible for ensuring the correct endianess of values
 * in `rule`. See documentation for \ref l4fw_match_t.
 * @param tbl the table to which the rule will be appended
 * @param rule the rule to be appended
 * @return total number of rules in table after this append
 */
int l4fw_table_append_rule (l4fw_table_t *tbl, l4fw_rule_t *rule);

/**
 * @brief Count the number of rules in a table.
 * @param tbl the table to count
 * @return number of rules
 */
int l4fw_table_count_rules (l4fw_table_t *tbl);

/**
 * @brief Find the rule at a specified index in a table.
 * Rule indices are 1-based. \p idx == 0 returns the default rule.
 * @param tbl pointer to a table
 * @param idx the index of the rule to return
 * @return pointer to the rule or NULL if rule doesn't exist
 */
l4fw_rule_t *l4fw_table_get_rule (l4fw_table_t *tbl, u32 idx);

/**
 * @brief Remove the rule at a specified index in a table.
 * @param tbl pointer to a table
 * @param idx the index of the rule to remove
 * @return pointer to the removed rule or NULL if rule doesn't exist
 */
l4fw_rule_t *l4fw_table_rule_remove (l4fw_table_t *tbl, u32 idx);

/**
 * @brief Check whether \p rule is the default rule for \p table.
 * @param tbl pointer to a table
 * @param rule pointer to the rule to check
 * @return true iif \p rule is the default rule for \p table
 */
bool l4fw_is_default_table_rule (l4fw_table_t *tbl, l4fw_rule_t *rule);

/**
 * @brief Check whether \p rule is a default rule (of any table).
 * @param rule pointer to the rule to check
 * @return true iif \p rule is the default rule for any table
 */
bool l4fw_rule_is_default (l4fw_rule_t *rule);

/**
 * @brief Perform a lookup, including jumps, until terminating rule is matched.
 * This lookup will begin at the default table. If there aren't any tables,
 * this lookup returns `NULL`.
 * @param ctx policy engine context
 * @param pkt the header and metadata to match against in the lookup
 * @return pointer to the terminating rule (possibly the default rule), or NULL
 * on error (e.g., no tables defined)
 */
l4fw_matched_rule_t
l4fw_policy_engine_lookup (l4fw_policy_engine_context_t *ctx, void *pkt);

/**
 * @brief Return an action's counter (number of times it was terminating action).
 * @param ctx policy engine context
 * @param action_type read the counter of actions with this type
 * @return number of times this was the terminating action
 */
u64
l4fw_policy_engine_get_action_counter (l4fw_policy_engine_context_t *ctx,
			   l4fw_action_type_t action_type);

/**
 * @brief Set the default action for a table.
 * @param ctx policy engine context
 * @param table_id the ID of the table on which to set the default action
 * @param pkt the default action to set
 * @return true on success, otherwise false
 */
bool l4fw_policy_engine_set_default_action (l4fw_policy_engine_context_t *ctx,
					    l4fw_table_id_t table_id,
					    l4fw_action_t act);

/**
 * @brief Clear the rules in a table.
 * Rules will be freed and returned to the freelist in \p ctx .
 * @param ctx policy engine context
 * @param table_id clear the rules from this table.
 */
void l4fw_policy_engine_clear_table (l4fw_policy_engine_context_t *ctx,
				     l4fw_table_id_t table_id);

/**
 * @brief Reset the counters in a table.
 * @param ctx policy engine context
 * @param table_id the ID of the table to search for counters to reset
 */
void l4fw_policy_engine_table_reset_counters (l4fw_policy_engine_context_t *ctx,
					    l4fw_table_id_t table_id);

/**
 * @brief Reset action counters.
 * @param ctx policy engine context
 */
void
l4fw_policy_engine_reset_action_counters (l4fw_policy_engine_context_t *ctx);

/**
 * @brief Format a rule as a string (similar to snprintf).
 * @param s pointer to the destination string
 * @param size write at most \p size bytes
 * @param rule pointer to the rule to format
 * @return number of characters printed, excluding NULL byte
 */
int
l4fw_rule_format (char *s, size_t size, l4fw_rule_t *rule);

/**
 * @brief Format a table as a string (similar to snprintf).
 * @param s pointer to the destination string
 * @param size write at most \p size bytes
 * @param table pointer to the table to format
 * @return number of characters printed, excluding NULL byte
 */
int
l4fw_table_format (char *s, size_t size, l4fw_table_t *tbl);

/**
 * @brief Generate a mask for matching starting bits (big-endian)
 * @param val generate the mask for this value
 * @return a mask from 0 to MSB of val
*/
u128 make_starts_with_mask_be(u128 val_be);

/**
 * @brief Generate a mask for matching ending bits (big-endian)
 * @param val generate the mask for this value
 * @return a mask from MSB of container to LSB of val
*/
u128 make_ends_with_mask_be(u128 val_be);

#endif /* __included_l4fw_policy_engine_h__ */