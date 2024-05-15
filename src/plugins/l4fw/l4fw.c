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
/**
 * @file
 * @brief Eth No-Op Plugin, plugin API / trace / CLI handling.
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <l4fw/l4fw.h>
#include <l4fw/l4fw_utils.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>

#include <l4fw/l4fw.api_enum.h>
#include <l4fw/l4fw.api_types.h>

#define REPLY_MSG_ID_BASE sm->msg_id_base
#include <vlibapi/api_helper_macros.h>

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = L4FW_PLUGIN_BUILD_VER,
    .description = "L4FW VPP Plugin",
};
/* *INDENT-ON* */

l4fw_main_t l4fw_main;

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//                                   API functions
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * @brief Enable/disable the l4fw plugin. 
 */
int l4fw_enable_disable (l4fw_main_t * sm, u32 sw_if_index,
                                   int enable_disable)
{
  vnet_sw_interface_t * sw;
  int rv = 0;

  /* Utterly wrong? */
  if (pool_is_free_index (sm->vnet_main->interface_main.sw_interfaces, 
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* Not a physical port? */
  sw = vnet_get_sw_interface (sm->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  vnet_feature_enable_disable ("device-input", "l4fw",
                               sw_if_index, enable_disable, 0, 0);

  return rv;
}
static void vl_api_l4fw_enable_disable_t_handler
(vl_api_l4fw_enable_disable_t * mp)
{
  vl_api_l4fw_enable_disable_reply_t * rmp;
  l4fw_main_t * sm = &l4fw_main;
  int rv;

  rv = l4fw_enable_disable (sm, ntohl(mp->sw_if_index), 
                                      (int) (mp->enable_disable));
  
  REPLY_MACRO(VL_API_L4FW_ENABLE_DISABLE_REPLY);
}

/**
 * @brief Enable/disable a feature of the l4fw plugin.
 * @return zero on success, otherwise non-zero on error
 * @todo implement the corresponding API function for en/disabling a feature.
 */
int
l4fw_feature_enable_disable (l4fw_main_t *lm, l4fw_feature_t feature,
			     bool enable)
{
  int rv = 0;
  if (feature >= L4FW_NUM_FEATURES)
    return -1;
  lm->features_enabled[feature] = enable;
  switch (feature) // Propogate config to policy engine.
    {
    case L4FW_FEATURE_COUNTERS:
      lm->engine_ctx->enable_counters = enable;
      break;
    case L4FW_FEATURE_PRINT_MATCH:
      lm->engine_ctx->enable_print_match = enable;
      break;
    default:
      break;
    }
  return rv;
}

/* API definitions */
#include <l4fw/l4fw.api.c>

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//                                   CLI un/formatters
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * @brief Parse the action type.
*/
uword
unformat_l4fw_action_type (unformat_input_t *input, va_list *args)
{
  l4fw_action_type_t *ret_action_type = va_arg (*args, l4fw_action_type_t *);
  char *action_name;
  if (!unformat (input, "%s", &action_name))
    return 0;
  l4fw_action_type_t action_type = l4fw_action_type_from_string (action_name);
  if (action_type == L4FW_ACTION_INVALID)
    return 0;
  *ret_action_type = action_type;
  return 1;
}

/**
 * @brief Parse connection state.
*/
uword
unformat_l4fw_conn_state (unformat_input_t *input, va_list *args)
{
  l4fw_ct_state_t *ret_conn_state = va_arg (*args, l4fw_ct_state_t *);
  char *state_str;
  if (!unformat (input, "%s", &state_str))
    return 0;
  if (strcmp (state_str, "NEW") == 0)
    *ret_conn_state = L4FW_CT_STATE_NEW;
  else if (strcmp (state_str, "ESTABLISHED") == 0)
    *ret_conn_state = L4FW_CT_STATE_ESTABLISHED;
  else if (strcmp (state_str, "RELATED") == 0)
    *ret_conn_state = L4FW_CT_STATE_RELATED;
  else
    return 0;
  return 1;
}

/**
 * @brief Parse table name.
 * @param ctx pointer to the policy engine context
 * @param table_id pointer to store the parsed table ID
 */
uword
unformat_l4fw_table_name (unformat_input_t *input, va_list *args)
{
  l4fw_policy_engine_context_t *ctx =
    va_arg (*args, l4fw_policy_engine_context_t *);
  ASSERT (ctx);
  l4fw_table_id_t *ret_table_id = va_arg (*args, l4fw_table_id_t *);

  bool hookpoint_specified = true;
  char *hookpoint_name = NULL, *table_name = NULL, *sf_name = NULL;
  if (!unformat (input, "%s.%s.%s", &hookpoint_name, &sf_name, &table_name))
    {
      if (!unformat (input, "%s.%s", &sf_name, &table_name))
	return 0;
      hookpoint_specified = false;
    }
  // TODO(tjepsen): lookup table context specific to sf_name. For now we assume
  // ctx is only for filter.
  if ((hookpoint_specified && strcmp (hookpoint_name, "net-in")) != 0 ||
      strcmp (sf_name, "filter") != 0)
    return 0;
  l4fw_table_id_t table_id =
    l4fw_policy_engine_table_id_from_name (ctx, table_name);
  if (table_id < 0) // If table name wasn't found.
    return 0;
  *ret_table_id = table_id;
  return 1;
}

/**
 * @brief Parse the match decorator.
 * @param decorator store resulting decorator to this pointer
 * @param negated store negation flag to this pointer
 */
uword
unformat_l4fw_match_decorator (unformat_input_t *input, va_list *args)
{
  l4fw_match_decorator_t *ret_decorator =
    va_arg (*args, l4fw_match_decorator_t *);
  bool *ret_negated = va_arg (*args, bool *);
  if (unformat (input, "!"))
    *ret_negated = true;
  else
    *ret_negated = false;
  char *decorator_str;
  if (!unformat (input, "%s", &decorator_str))
    return 0;
  l4fw_match_decorator_t decorator = l4fw_decorator_from_string (decorator_str);
  if (decorator == L4FW_MATCH_DECORATOR_INVALID)
    return 0;
  *ret_decorator = decorator;
  return 1;
}

/**
 * @brief Parse the name of a L4FW feature.
 * @param feature store the feature to this pointer
 */
uword
unformat_l4fw_feature (unformat_input_t *input, va_list *args)
{
  l4fw_feature_t *ret_feature = va_arg (*args, l4fw_feature_t *);
  char *feat_str = NULL;
  if (!unformat (input, "%s", &feat_str))
    return 0;
  for (l4fw_feature_t feat = L4FW_FEATURE_CT; feat < L4FW_NUM_FEATURES; feat++)
    {
      if (strcmp (l4fw_feature_strings[feat], feat_str) != 0)
	continue;
      *ret_feature = feat;
      return 1;
    }
  return 0;
}

/**
 * @brief Format a table.
*/
u8 *
format_l4fw_table (u8 *s, va_list *args)
{
  l4fw_policy_engine_context_t *ctx =
    va_arg (*args, l4fw_policy_engine_context_t *);
  char *table_name = va_arg (*args, char *);

  l4fw_table_id_t table_id =
    l4fw_policy_engine_table_id_from_name (ctx, table_name);
  l4fw_table_t *tbl = l4fw_policy_engine_get_table (ctx, table_id);
  int num_rules = l4fw_table_count_rules (tbl);
  size_t formatted_table_size =
    L4FW_MAX_EXPECTED_RULE_STRING_SIZE * (num_rules + 1);
  char *formatted_table = (char *) malloc (formatted_table_size);
  int nchars = l4fw_table_format (formatted_table, formatted_table_size, tbl);
  ASSERT (nchars <= formatted_table_size &&
	  "Not enough memory for formatting table.");
  s = format (s, "%s", formatted_table);
  if (formatted_table)
    free (formatted_table);

  return s;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//                                   CLI commands
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * @brief Enable/disable the l4fw plugin.
 */
static clib_error_t *
l4fw_enable_disable_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  l4fw_main_t * sm = &l4fw_main;
  u32 sw_if_index = ~0;
  bool enable = true;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = true;
      else if (unformat (input, "disable"))
	enable = false;
    else if (unformat (input, "%U", unformat_vnet_sw_interface,
                       sm->vnet_main, &sw_if_index))
	;
      else
	break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "[ERROR] Please specify an interface.");

  rv = l4fw_enable_disable (sm, sw_if_index, enable);

  switch(rv) {
  case 0:
    break;

  case VNET_API_ERROR_INVALID_SW_IF_INDEX:
    return clib_error_return (
      0, "[ERROR] Invalid interface, only works on physical ports");
    break;

  case VNET_API_ERROR_UNIMPLEMENTED:
    return clib_error_return (
      0, "[ERROR] Device driver doesn't support redirection");
    break;

  default:
    return clib_error_return (0, "[ERROR] l4fw_enable_disable returned %d",
			      rv);
  }
  return 0;
}
VLIB_CLI_COMMAND (sr_content_command, static) = {
    .path = "l4fw",
    .short_help = 
    "l4fw <enable|disable> <interface-name>",
    .function = l4fw_enable_disable_command_fn,
};

/**
 * @brief Enable/disable a feature of the l4fw plugin.
 */
static clib_error_t *
l4fw_feature_enable_disable_command_fn (vlib_main_t *vm,
					unformat_input_t *input,
					vlib_cli_command_t *cmd)
{
  l4fw_main_t *lm = &l4fw_main;
  l4fw_feature_t feature = ~0;
  bool enable = true;
  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = true;
      else if (unformat (input, "disable"))
	enable = false;
      else if (unformat (input, "%U", unformat_l4fw_feature, &feature))
	;
      else
	break;
    }
  if (feature == ~0)
    return clib_error_return (0, "[ERROR] Please specify a feature.");
  rv = l4fw_feature_enable_disable (lm, feature, enable);
  if (rv != 0)
    return clib_error_return (0, "[ERROR] en/disabling L4FW feature %s.",
			      l4fw_feature_strings[feature]);
  return 0;
}
VLIB_CLI_COMMAND (l4fw_feature_enable_disable_command, static) = {
  .path = "l4fw feature",
  .short_help = "l4fw feature <enable|disable> <feature-name>",
  .function = l4fw_feature_enable_disable_command_fn,
};

/**
 * @brief Add a table to a security function.
 */
static clib_error_t *
l4fw_add_table_command_fn (vlib_main_t *vm, unformat_input_t *input,
			   vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;
  char *sf_name = NULL, *table_name = NULL;
  if (!unformat (input, "%s.%s", &sf_name, &table_name))
    {
      error = clib_error_return (0, "[ERROR] expecting table name, got `%U'.",
				 format_unformat_error, input);
      goto done;
    }
  // TODO(tjepsen): lookup table context specific to sf_name. For now we assume
  // ctx is only for filter.
  if (strcmp (sf_name, "filter") != 0)
    {
      error = clib_error_return (
	0, "[ERROR] unexpected security function, got `%s'.", sf_name);
      goto done;
    }
  l4fw_table_id_t table_id =
    l4fw_policy_engine_context_add_table (sm->engine_ctx, table_name);
  if (table_id < 0)
    {
      error = clib_error_return (
	0, "[ERROR] table name already exists: `%s.%s'.", sf_name, table_name);
      goto done;
    }
  // Set the default action for the new table.
  l4fw_policy_engine_set_default_action (
    sm->engine_ctx, table_id,
    (l4fw_action_t){ .action_type = L4FW_ACTION_RETURN });
  vlib_cli_output (vm, "Added table %s.%s (id=%d)", sf_name, table_name,
		   table_id);
done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_add_table_command, static) = {
  .path = "l4fw_add_table",
  .short_help = "l4fw_add_table <table-name>",
  .function = l4fw_add_table_command_fn,
};

/**
 * @brief Add a rule to a table.
 */
static clib_error_t *
l4fw_add_rule_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;
  u8 *v;
  // When appending the rule, the policy engine will allocate memory
  // and copy this string.
#define L4FW_MAX_RULE_NAME_LEN 64
  char tmp_rule_name[L4FW_MAX_RULE_NAME_LEN];
  char *rule_name = NULL;

  if (unformat (input, "name %U", unformat_double_quoted_string, &v))
    {
      if (vec_len (v) > L4FW_MAX_RULE_NAME_LEN)
	{
	  error =
	    clib_error_return (0, "[ERROR] rule name too long: `%s'.", v);
	  vec_free (v);
	  goto done;
	}
      memcpy (tmp_rule_name, v, vec_len (v));
      tmp_rule_name[vec_len (v)] = '\0';
      rule_name = tmp_rule_name;
    }

  l4fw_table_id_t table_id;
  if (!unformat (input, "table %U", unformat_l4fw_table_name, sm->engine_ctx,
		 &table_id))
    {
      error = clib_error_return (0, "[ERROR] expecting table name, got `%U'.",
				 format_unformat_error, input);
      goto done;
    }

  l4fw_rule_t rule;
  l4fw_rule_init (&rule);
  u8 match_cnt = 0;
  ip4_address_t ip4, ip4_start, ip4_end;
  u32 int32;
  l4fw_ct_state_t conn_state;
  u8 pre_len;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      bool val_is_string = false;
      char *match_key;
      if (!unformat (input, "match %s", &match_key))
	break;
      rule.match_list[match_cnt].key = l4fw_match_key_from_string (match_key);

      if (!unformat (input, "%U", unformat_l4fw_match_decorator, &rule.match_list[match_cnt].decorator,
		     &rule.match_list[match_cnt].negated))
	{
	  error =
	    clib_error_return (0, "[ERROR] expecting decorator, got `%U'.",
			       format_unformat_error, input);
	  goto done;
	}
      if (unformat (input, "%d-%d", &rule.match_list[match_cnt].range_start,
		    &rule.match_list[match_cnt].range_end))
	{
	  if (rule.match_list[match_cnt].decorator != L4FW_MATCH_RANGE)
	    {
	      error = clib_error_return (
		0, "[ERROR] unexpected number range for `%s' match decorator.",
		l4fw_decorator_to_string (
		  rule.match_list[match_cnt].decorator));
	      goto done;
	    }
	}
      else if (unformat (input, "%U-%U", unformat_ip4_address, &ip4_start,
			 unformat_ip4_address, &ip4_end))
	{
	  // XXX Convert to host-endian so they can be used in arithmetic.
	  rule.match_list[match_cnt].range_start =
	    clib_big_to_host_u32 (ip4_start.as_u32);
	  rule.match_list[match_cnt].range_end =
	    clib_big_to_host_u32 (ip4_end.as_u32);
	  if (rule.match_list[match_cnt].decorator != L4FW_MATCH_RANGE)
	    {
	      error = clib_error_return (
		0, "[ERROR] unexpected IP range for `%s' match decorator.",
		l4fw_decorator_to_string (
		  rule.match_list[match_cnt].decorator));
	      goto done;
	    }
	}
      else if (unformat (input, "%U/%d", unformat_ip4_address, &ip4, &pre_len))
	{
	  rule.match_list[match_cnt].value = ip4.as_u32;
	  rule.match_list[match_cnt].mask =
	    clib_host_to_big_u32 (make_ipv4_mask (pre_len));
	}
      else if (unformat (input, "%U", unformat_ip4_address, &ip4))
	{
	  rule.match_list[match_cnt].value = ip4.as_u32;
	}
      else if (unformat (input, "0x%U", unformat_hex_string, &v))
	{
	  // XXX Converts little-endian to big-endian (network endian).
	  rule.match_list[match_cnt].value = 0;
	  for (int i = vec_len (v) - 1; i >= 0; i--)
	    rule.match_list[match_cnt].value |= (v[i] << 8 * i);
	  vec_free (v);
	}
      else if (unformat (input, "%d", &int32))
	{
	  // TODO(tjepsen): find a more robust, scalable way of determining the
	  // width of the value for the match type (key).
	  switch (rule.match_list[match_cnt].key)
	    {
	    case L4FW_MATCH_KEY_IP4_SADDR:
	    case L4FW_MATCH_KEY_IP4_DADDR:
	      rule.match_list[match_cnt].value = clib_host_to_big_u32 (int32);
	      break;
	    case L4FW_MATCH_KEY_TCP_SPORT:
	    case L4FW_MATCH_KEY_TCP_DPORT:
	    case L4FW_MATCH_KEY_UDP_SPORT:
	    case L4FW_MATCH_KEY_UDP_DPORT:
	      rule.match_list[match_cnt].value = clib_host_to_big_u16 (int32);
	      break;
	    default:
	      error = clib_error_return (
		0, "[ERROR] not expecting integer %d for this match type.",
		int32);
	      goto done;
	    }
	}
      else if (unformat (input, "%U", unformat_double_quoted_string, &v))
	{
	  if (vec_len (v) > sizeof (rule.match_list[match_cnt].val_as_str) - 1)
	    {
	      error = clib_error_return (
		0, "[ERROR] match string too long: `%s'.", v);
	      vec_free (v);
	      goto done;
	    }
	  memcpy (rule.match_list[match_cnt].val_as_str, v, vec_len (v));
	  rule.match_list[match_cnt].val_as_str[vec_len (v)] = '\0';
	  val_is_string = true;
	  vec_free (v);
	}
      else if (unformat (input, "%U", unformat_l4fw_conn_state, &conn_state))
	{
	  if (rule.match_list[match_cnt].key != L4FW_MATCH_KEY_CONN_STATE)
	    {
	      error = clib_error_return (
		0, "[ERROR] connection state unexpected for this match type");
	      goto done;
	    }
	  rule.match_list[match_cnt].value = conn_state;
	}
      else
	{
	  error =
	    clib_error_return (0, "[ERROR] expecting match value, got `%U'.",
			       format_unformat_error, input);
	  goto done;
	}

      // Parse an optional mask on the value.
      if (unformat (input, "mask 0x%U", unformat_hex_string, &v))
	{
	  // XXX Converts little-endian to big-endian (network endian).
	  rule.match_list[match_cnt].mask = 0;
	  for (int i = vec_len (v) - 1; i >= 0; i--)
	    rule.match_list[match_cnt].mask |= (v[i] << 8 * i);
	  vec_free (v);
	}
      else if (unformat (input, "mask %U", unformat_ip4_address, &ip4))
	{
	  rule.match_list[match_cnt].mask = ip4.as_u32;
	}

      if (rule.match_list[match_cnt].key == L4FW_MATCH_KEY_CONN_STATE &&
	  rule.match_list[match_cnt].decorator != L4FW_MATCH_EQUALS)
	{
	  error = clib_error_return (
	    0, "[ERROR] connection state decorator must be equality");
	  goto done;
	}
      if (val_is_string)
	{ // Check the decorator for string values.
	  switch (rule.match_list[match_cnt].decorator)
	    {
	    case L4FW_MATCH_EQUALS:
	    case L4FW_MATCH_STARTS_WITH:
	    case L4FW_MATCH_CONTAINS:
	    case L4FW_MATCH_ENDS_WITH:
	      break; // OK.
	    case L4FW_MATCH_RANGE:
	      error = clib_error_return (
		0, "[ERROR] Unexpected decorator `%s' for string value.",
		l4fw_decorator_to_string (
		  rule.match_list[match_cnt].decorator));
	      goto done;
	    default:
	      error = clib_error_return (0, "[ERROR] unknown decorator type.");
	      goto done;
	    }
	}
      else
	{ // Check the decorator for non-string values.
	  switch (rule.match_list[match_cnt].decorator)
	    {
	    case L4FW_MATCH_EQUALS:
	    case L4FW_MATCH_RANGE:
	      break; // OK.
	    case L4FW_MATCH_STARTS_WITH:
	    case L4FW_MATCH_CONTAINS:
	    case L4FW_MATCH_ENDS_WITH:
	      error = clib_error_return (
		0, "[ERROR] Unexpected decorator `%s' for non-string value.",
		l4fw_decorator_to_string (
		  rule.match_list[match_cnt].decorator));
	      goto done;
	    default:
	      error = clib_error_return (0, "[ERROR] unknown decorator type.");
	      goto done;
	    }
	}
      match_cnt++;
    }

  if (!unformat (input, "action %U", unformat_l4fw_action_type,
		 &rule.action.action_type))
    {
      error = clib_error_return (0, "[ERROR] expecting action name, got `%U'.",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat_eof (input, NULL))
    {
      if (rule.action.action_type == L4FW_ACTION_JUMP)
	{
	  error = clib_error_return (
	    0, "[ERROR] expecting JUMP target table, got EOF.");
	  goto done;
	}
    }
  else
    {
      if (rule.action.action_type == L4FW_ACTION_JUMP)
	{
	  if (!unformat (input, "%U", unformat_l4fw_table_name, sm->engine_ctx,
			 &rule.action.action_data))
	    {
	      error = clib_error_return (
		0, "[ERROR] expecting JUMP target table, got `%U'.",
		format_unformat_error, input);
	      goto done;
	    }
	}
      // Optional action data.
      else if (unformat (input, "%U", unformat_ip4_address, &ip4))
	{
	  rule.action.action_data = ip4.as_u32;
	}
      else if (unformat (input, "0x%U", unformat_hex_string, &v))
	{
	  // XXX Store as little-endian.
	  rule.action.action_data = 0;
	  for (int i = 0; i < vec_len (v); i++)
	    rule.action.action_data |= (v[i] << 8 * i);
	  vec_free (v);
	}
      else if (unformat (input, "%d", &int32))
	{
	  rule.action.action_data = int32;
	}
      else
	{
	  error = clib_error_return (
	    0, "[ERROR] expecting optional action data, got `%U'.",
	    format_unformat_error, input);
	  goto done;
	}
    }

  int num_rules =
    l4fw_policy_engine_rule_append (sm->engine_ctx, table_id, rule, rule_name);
  if (num_rules < 0)
    {
      error = clib_error_return (
	0, "[ERROR] Failed to add `%s' rule to table `%s'.",
	l4fw_action_type_to_string (rule.action.action_type),
	l4fw_policy_engine_table_name_from_id (sm->engine_ctx, table_id));
      goto done;
    }
  l4fw_rule_t *new_rule =
    l4fw_policy_engine_get_rule (sm->engine_ctx, table_id, num_rules);
  char formatted_rule[L4FW_MAX_EXPECTED_RULE_STRING_SIZE];
  int nchars =
    l4fw_rule_format (formatted_rule, sizeof (formatted_rule), new_rule);
  ASSERT (nchars <= sizeof (formatted_rule) &&
	  "Not enough memory for formatting rule.");
  vlib_cli_output (
    vm, "Added rule to table %s (id=%d): %d: %s",
    l4fw_policy_engine_table_name_from_id (sm->engine_ctx, table_id), table_id,
    num_rules, formatted_rule);

done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_add_rule_command, static) = {
  .path = "l4fw_add_rule",
  .short_help = "l4fw_add_rule [name \"<rule-name>\"] table <table-name> "
		"[match <key> [!] <decorator> <val> [mask <mask>]]... "
		"action <action> [<data>]",
  .function = l4fw_add_rule_command_fn,
};

/**
 * @brief Clear all the rules in a table.
 */
static clib_error_t *
l4fw_clear_table_command_fn (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;

  l4fw_table_id_t table_id;
  if (!unformat (input, "%U", unformat_l4fw_table_name, sm->engine_ctx,
		 &table_id))
    {
      error = clib_error_return (0, "[ERROR] expecting table name, got `%U'.",
				 format_unformat_error, input);
      goto done;
    }

  l4fw_policy_engine_clear_table (sm->engine_ctx, table_id);
done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_clear_table_command, static) = {
    .path = "l4fw_clear_table",
    .short_help =
    "l4fw_clear_table <table-name>",
    .function = l4fw_clear_table_command_fn,
};

/**
 * @brief Set the default action for a table.
 */
static clib_error_t *
l4fw_set_default_command_fn (vlib_main_t *vm, unformat_input_t *input,
			  vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;

  l4fw_table_id_t table_id;
  if (!unformat (input, "table %U", unformat_l4fw_table_name, sm->engine_ctx,
		 &table_id))
    {
      error = clib_error_return (0, "[ERROR] expecting table name, got `%U'.",
				 format_unformat_error, input);
      goto done;
    }

  l4fw_action_t action;
  if (!unformat (input, "action %U", unformat_l4fw_action_type,
		 &action.action_type))
    {
      error = clib_error_return (0, "[ERROR] expecting action name, got `%U'.",
				 format_unformat_error, input);
      goto done;
    }

  if (unformat_eof (input, NULL))
    {
      if (action.action_type == L4FW_ACTION_JUMP)
	{
	  error = clib_error_return (
	    0, "[ERROR] expecting JUMP target table, got EOF.");
	  goto done;
	}
    }
  else
    // Optional action data.
    {
      ip4_address_t ip4;
      u8 *v;
      u32 int32;
      if (action.action_type == L4FW_ACTION_JUMP)
	{
	  if (!unformat (input, "%U", unformat_l4fw_table_name, sm->engine_ctx,
			 &action.action_data))
	    {
	      error = clib_error_return (
		0, "[ERROR] expecting JUMP target table, got `%U'.",
		format_unformat_error, input);
	      goto done;
	    }
	}
      else if (unformat (input, "%U", unformat_ip4_address, &ip4))
	{
	  action.action_data = ip4.as_u32;
	}
      else if (unformat (input, "0x%U", unformat_hex_string, &v))
	{
	  // XXX Converts little-endian to big-endian (network endian).
	  action.action_data = 0;
	  for (int i = vec_len (v) - 1; i >= 0; i--)
	    action.action_data |= (v[i] << 8 * i);
	  vec_free (v);
	}
      else if (unformat (input, "%d", &int32))
	{
	  action.action_data = htonl (int32);
	}
      else
	{
	  error = clib_error_return (
	    0, "[ERROR] expecting optional action data, got `%U'.",
	    format_unformat_error, input);
	  goto done;
	}
    }

  if (!l4fw_policy_engine_set_default_action (sm->engine_ctx, table_id, action))
    {
      error = clib_error_return (
	0, "[ERROR] Failed to set default action for `%s' to `%s'.",
	l4fw_policy_engine_table_name_from_id (sm->engine_ctx, table_id),
	l4fw_action_type_to_string (action.action_type));
      goto done;
    }
done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_set_default_command, static) = {
    .path = "l4fw_set_default",
    .short_help =
    "l4fw_set_default table <table-name> action <action> [<data>]",
    .function = l4fw_set_default_command_fn,
};

/**
 * @brief Read action counters.
 */
static clib_error_t *
l4fw_show_counters_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;

  if (!unformat_eof (input, NULL))
    {
      l4fw_action_type_t action_type;
      if (!unformat (input, "%U", unformat_l4fw_action_type, &action_type))
	{
	  error =
	    clib_error_return (0, "[ERROR] expecting action name, got `%U'.",
			       format_unformat_error, input);
	  goto done;
	}
      // TODO(tjepsen): specify the security function.
      vlib_cli_output (
	vm, "%ld\n",
	l4fw_policy_engine_get_action_counter (sm->engine_ctx, action_type));
    }
  else
    {
      for (l4fw_action_type_t act = L4FW_ACTION_DROP; act < L4FW_NUM_ACTIONS;
	   act++)
	{
	  vlib_cli_output (
	    vm, "%-10s %ld\n", l4fw_action_type_to_string (act),
	    l4fw_policy_engine_get_action_counter (sm->engine_ctx, act));
	}
    }
done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_show_counters_command, static) = {
    .path = "show l4fw counters",
    .short_help =
    "show l4fw counters [<action-type>]",
    .function = l4fw_show_counters_command_fn,
};

/**
 * @brief Read the rule match counter.
 */
static clib_error_t *
l4fw_show_rule_match_counters_command_fn (vlib_main_t *vm,
					  unformat_input_t *input,
					  vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;
  l4fw_table_id_t table_id = ~0;
  u32 rule_idx = ~0;

  if (!unformat_eof (input, NULL) &&
      !unformat (input, "%U", unformat_l4fw_table_name, sm->engine_ctx,
		 &table_id))
    {
      error = clib_error_return (
	0, "[ERROR] expecting <table> [<log_id>], got `%U'.",
	format_unformat_error, input);
      goto done;
    }

  if (!unformat_eof (input, NULL) && !unformat (input, "%d", &rule_idx))
    {
      error = clib_error_return (
	0, "[ERROR] expecting <table> [<log_id>], got `%U'.",
	format_unformat_error, input);
      goto done;
    }

  vlib_cli_output (vm, "TABLE\tRULE\tCOUNTER\n");
  if (table_id != ~0)
    {
      l4fw_table_t *tbl =
	l4fw_policy_engine_get_table (sm->engine_ctx, table_id);
      ASSERT (tbl);
      for (int i = 0; i <= l4fw_table_count_rules (tbl); i++)
	{
	  if (rule_idx != ~0 && i != rule_idx)
	    continue;
	  l4fw_rule_t *rule = l4fw_table_get_rule (tbl, i);
	  if (rule->counter == NULL)
	    continue;
	  vlib_cli_output (
	    vm, "%sfilter.%s\t%d%s%s\t%lld\n",
	    table_id == sm->engine_ctx->default_table ? "net-in." : "",
	    l4fw_policy_engine_table_name_from_id (sm->engine_ctx, table_id),
	    i, rule->name ? "_" : "", rule->name ? rule->name : "",
	    vlib_get_simple_counter (rule->counter, 0));
	}
    }
  else
    {
      for (l4fw_table_id_t table_id = 0; table_id < sm->engine_ctx->num_tables;
	   table_id++)
	{
	  l4fw_table_t *tbl =
	    l4fw_policy_engine_get_table (sm->engine_ctx, table_id);
	  ASSERT (tbl);
	  for (int i = 0; i <= l4fw_table_count_rules (tbl); i++)
	    {
	      l4fw_rule_t *rule = l4fw_table_get_rule (tbl, i);
	      if (!rule->counter)
		continue;
	      vlib_cli_output (
		vm, "%sfilter.%s\t%d%s%s\t%lld\n",
		table_id == sm->engine_ctx->default_table ? "net-in." : "",
		l4fw_policy_engine_table_name_from_id (sm->engine_ctx,
						       table_id),
		i, rule->name ? "_" : "", rule->name ? rule->name : "",
		vlib_get_simple_counter (rule->counter, 0));
	    }
	}
    }
done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_show_rule_match_counters_command, static) = {
  .path = "show l4fw rule-counter",
  .short_help = "show l4fw rule-counter [<table-name> [<rule_idx>]]",
  .function = l4fw_show_rule_match_counters_command_fn,
};

/**
 * @brief Print a table.
 */
static clib_error_t *
l4fw_show_table_command_fn (vlib_main_t *vm, unformat_input_t *input,
			    vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;

  if (unformat_eof (input, NULL))
    {
      // Print all the table names.
      // TODO: print the tables for all hookpoints and security functions.
      const char *hookpoint_name = "net-in.";
      const char *sf_name = "filter";
      // TODO(tjepsen): this breaks the abstraction because it assumes
      // table_id_t is an index, while it's actually an opaque ID. We should
      // use a table iterator instead.
      for (l4fw_table_id_t i = 0; i < sm->engine_ctx->num_tables; i++)
	{
	  vlib_cli_output (
	    vm, "%d: %s%s.%s\n", i,
	    i == sm->engine_ctx->default_table ? hookpoint_name : "", sf_name,
	    l4fw_policy_engine_table_name_from_id (sm->engine_ctx, i));
	}
    }
  else
    {
      // Print the contents of a specific table.
      l4fw_table_id_t table_id;
      if (!unformat (input, "%U", unformat_l4fw_table_name, sm->engine_ctx,
		     &table_id))
	{
	  error =
	    clib_error_return (0, "[ERROR] expecting table name, got `%U'.",
			       format_unformat_error, input);
	  goto done;
	}
      vlib_cli_output (
	vm, "%U", format_l4fw_table, sm->engine_ctx,
	l4fw_policy_engine_table_name_from_id (sm->engine_ctx, table_id));
    }

done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_show_table_command, static) = {
    .path = "show l4fw table",
    .short_help =
    "show l4fw table [<table-name>]",
    .function = l4fw_show_table_command_fn,
};

/**
 * @brief Clear stats.
 */
static clib_error_t *
l4fw_clear_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  l4fw_main_t *sm = &l4fw_main;
  clib_error_t *error = 0;
  bool clear_rule_counters = false, clear_action_counters = false;
  bool name_provided = false;

  while (!unformat_eof (input, NULL))
    {
      name_provided = true;
      if (unformat (input, "counters"))
	clear_rule_counters = clear_action_counters = true;
      else if (unformat (input, "rule-counters"))
	clear_rule_counters = true;
      else if (unformat (input, "action-counters"))
	clear_action_counters = true;
      else
	{
	  error = clib_error_return (0, "[ERROR] Unrecognized stats name.");
	  goto done;
	}
    }
  if (!name_provided)
    {
      error = clib_error_return (0, "[ERROR] Expected a stats name.");
      goto done;
    }
  if (clear_action_counters)
    l4fw_policy_engine_reset_action_counters (sm->engine_ctx);
  if (clear_rule_counters)
    for (l4fw_table_id_t i = 0; i < sm->engine_ctx->num_tables; i++)
      l4fw_policy_engine_table_reset_counters (sm->engine_ctx, i);
done:
  return error;
}
VLIB_CLI_COMMAND (l4fw_clear_command, static) = {
  .path = "clear l4fw",
  .short_help = "clear l4fw counters|action-counters|rule-counters",
  .function = l4fw_clear_command_fn,
};

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//                                   L4FW HOOK POINTS
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * @brief Logic of security function: "filter".
 */
l4fw_hook_point_net_in_next_t
l4fw_sf_filter (
  void *l4fw_pkt_ptr, // Pointer to l4fw packet.
  l4fw_meta_t *l4fw_meta_ptr // Pointer to l4fw metadata structure.
)
{
  ethernet_header_t *eh = (ethernet_header_t *) l4fw_pkt_ptr;
  // Allow non-IPv4 packets.
  if (eh->type != clib_host_to_big_u16 (ETHERNET_TYPE_IP4))
    return L4FW_N_NEXT;
  l4fw_packet_t pkt = { .eth = l4fw_pkt_ptr, .meta = l4fw_meta_ptr };
  l4fw_matched_rule_t terminating_rule =
    l4fw_policy_engine_lookup (l4fw_main.engine_ctx, &pkt);
  ASSERT (terminating_rule.rule != NULL);
  elog_l4fw_X2 ("L4FW: match key: %d, action: %d", "i4i4",
		terminating_rule.rule->match_list[0].key,
		terminating_rule.rule->action.action_type);
  switch (terminating_rule.rule->action.action_type)
    {
    case L4FW_ACTION_ALLOW:
    case L4FW_ACTION_LOG:
      break;
    case L4FW_ACTION_REJECT:
    case L4FW_ACTION_DROP:
      // TODO(tjepsen): how do we handle REJECT differently than DROP?
      return L4FW_NEXT_DROP;
    default:
      fprintf (stderr, "Error: unexpected L4FW action type.\n");
    }
  return L4FW_N_NEXT;
}

/**
 * @brief Logic of hook point: "net-in".
 */
l4fw_hook_point_net_in_next_t l4fw_hook_point_net_in(
  void *l4fw_pkt_ptr, // Pointer to l4fw packet.
  l4fw_meta_t *l4fw_meta_ptr // Pointer to l4fw metadata structure.
)
{
  if (l4fw_main.features_enabled[L4FW_FEATURE_CT])
    {
      l4fw_meta_ptr->ct_state = l4fw_ct_update (l4fw_pkt_ptr);
      // XXX See TODO above about thread_index.
      u32 thread_index = 0;
      vlib_set_simple_counter (&l4fw_main.ct_conn_counter, thread_index, 0,
			       l4fw_ct_count_entries ());
    }

  // L4FW-TODO: call "external" functions, e.g. conntrack, DPI, reputation score, ...

  // APP ID
  if (l4fw_main.features_enabled[L4FW_FEATURE_APP_ID])
    l4fw_app_id_update (l4fw_pkt_ptr, l4fw_meta_ptr);

  // SECURITY FUNCTION: mangle
  // L4FW-TODO: implement security function

  // SECURITY FUNCTION: nat
  // L4FW-TODO: implement security function

  // Default: ALLOW packet, passing it to the next VPP node.
  l4fw_hook_point_net_in_next_t next = L4FW_N_NEXT;

  // SECURITY FUNCTION: filter
  if (l4fw_main.features_enabled[L4FW_FEATURE_SF_FILTER])
    next = l4fw_sf_filter (l4fw_pkt_ptr, l4fw_meta_ptr);
  return next;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//                        initialize the plugin
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

/**
 * @brief Initialize counters for the l4fw plugin.
 */
void
l4fw_counters_init (vlib_main_t *vm, l4fw_main_t *sm)
{
  // Connection tracker counter.
  sm->ct_conn_counter.name = "ct-connections";
  sm->ct_conn_counter.stat_segment_name = "/l4fw/ct/connections";
  vlib_validate_simple_counter (&sm->ct_conn_counter, 0);
  vlib_zero_simple_counter (&sm->ct_conn_counter, 0);
}

/**
 * @brief Initialize the l4fw plugin.
 */
static clib_error_t * l4fw_init (vlib_main_t * vm)
{

  l4fw_main_t * sm = &l4fw_main;

  sm->vnet_main =  vnet_get_main ();

  /* Add our API messages to the global name_crc hash table */
  sm->msg_id_base = setup_message_id_table ();

  /* Initialize the policy engine. */
  sm->engine_ctx = l4fw_policy_engine_context_new ();
  // Add the default table "main" for each SF.
  l4fw_table_id_t filter_table_id =
    l4fw_policy_engine_context_add_table (sm->engine_ctx, "main");
  l4fw_policy_engine_set_default_action (
    sm->engine_ctx, filter_table_id,
    (l4fw_action_t){ .action_type = L4FW_ACTION_ALLOW });

  // Setup logging.
  sm->logger = vlib_log_register_class ("l4fw", 0);
  L4FW_DBG("Initialized L4FW!!!.");

  // Initialize counters.
  l4fw_counters_init (vm, sm);

  // Set default en/disabled for all features.
  for (l4fw_feature_t feat = L4FW_FEATURE_CT; feat < L4FW_NUM_FEATURES; feat++)
    {
      switch (feat)
	{
	case L4FW_FEATURE_PRINT_MATCH:
	  l4fw_feature_enable_disable (sm, feat, false);
	  break;
	default:
	  l4fw_feature_enable_disable (sm, feat, true);
	}
    }

  return 0;
}

VLIB_INIT_FUNCTION (l4fw_init);

/**
 * @brief Hook the l4fw plugin into the VPP graph hierarchy.
 */
VNET_FEATURE_INIT (l4fw, static) = 
{
  // L4FW-TODO: insert the plugin in the right place!
  .arc_name = "device-input",
  .node_name = "l4fw",
  .runs_before = VNET_FEATURES ("ethernet-input"),
};