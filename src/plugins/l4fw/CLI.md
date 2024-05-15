# CLI Commands


## Enabling Interfaces and Features

### l4fw
```bash
l4fw <enable|disable> <interface-name>
```
Enable or disable the l4fw node on the interface specified by `<interface-name>`.

### l4fw feature
```bash
l4fw feature <enable|disable> <feature-name>",
```
Enable or disable a L4FW feature (not to be confused with _VPP features_). E.g., `l4fw feature enable ct`.
Current features (from [l4fw_feature_strings](./l4fw.h)):
- `ct`: connection tracking.
- `app_id`: inferring application ID and adding it to metadata.
- `sf_filter`: the "filter" security function.
- `counters`: counting executed actions and matched rules.
- `print_match`: printing matched rules to stdout.


## Tables and Rules

For all these commands, the `<table-name>` is in the format `<security-function>.<table>` for user-defined, and `<hookpoint>.<security-function>.<table>` for built-in tables. E.g., `net-in.filter.main`, `filter.http`.

### l4fw_add_table
```bash
l4fw_add_table <table-name>
```
- `<table-name>`: name of a user-defined table to add.

### l4fw_add_rule
```bash
l4fw_add_rule [name "<rule-name>"] table <table-name>
               [match <key> [!] <decorator> <val> [mask <mask>]] ...
                action <action> [<data>]
```
- `<rule-name>`: the optional name (label) for the rule.
- `<table-name>`: add the rule to this table.
- `<key>`: e.g., `IP4_SADDR`, `TCP_DPORT`. See [l4fw_match_key_t](policy_engine/l4fw_policy_engine.h).
- `!`: if indicated, negate the match.
- `<decorator>`: `==`, `range`. See [l4fw_match_decorator_t](policy_engine/l4fw_policy_engine.h).
- `<val>`: ipv4 address, base 10 number, hex, e.g., `10.10.10.1`, `10.10.0.0/24`, `80`, `0x0a`.
- `<mask>`: masked on value for exact match, e.g., `10.10.0.0 mask 0xffff0000`.
- `<action>`: the name of the action to execute, e.g., `ALLOW`, `DROP`, `JUMP`. See [l4fw_action_typet_t](policy_engine/l4fw_policy_engine.h).
- `<data>`: action data: table name (for jump), or value in hex, e.g.,, `0x03`.

### l4fw_clear_table
```
l4fw_clear_table <table-name>
```
- `<table-name>`: name of a table to clear.

### l4fw_set_default
```
l4fw_set_default table <table-name> action <action> [<data>]
```
- `<table-name>`: set the default action of this table.
- `<action> [<data>]`: see description in `l4fw_add_rule`, since they use the same arguments.

### show l4fw table
```bash
show l4fw table [<table-name>]
```
Print all the tables currently in l4fw.
- `<table-name>`: if specified, print all the rules in this table.

## Counters and Statistics

### show l4fw counters
```bash
show l4fw counters [<action-type>]
```
Print the number of times each action type was executed.
- `<action-type>`: get the counter only for this action type, e.g., `ALLOW`, `DROP`, `JUMP`. See [l4fw_action_typet_t](policy_engine/l4fw_policy_engine.h).

### show l4fw rule-counter
```bash
show l4fw rule-counter [<table-name> [<rule-idx>]]
```
Print the number of times each rule matched. Optionally, only print the counters for rules in `<table-name>`, or specifically the rule at index `<rule-idx>`.

### clear l4fw
```bash
clear l4fw counters|action-counters|rule-counters
```
- `counters`: clear both action and rule counters.
- `action-counters`: clear action counters.
- `rule-counters`: clear rule counters.

## Connection Tracking

### show l4fw ct
```
show l4fw ct
```
Prints the flow table, as maintained by the connection tracking subsystem. The output is in the
form of a CSV file for ease of processing offline, if required. The columns are as follows:

- `num`: Flow number (zero-based index into the table). May change over time as flows are added/deleted.
- `state`: one of the following:
  - `NEW`: flow has seen packets in one direction only
  - `ESTABLISHED`: flow has seen packets in both directions
  - (other states may be supported in future)
- `proto`: The protocol (e.g. 1 for ICMP, 6 for TCP, 17 for UDP, etc.)
- `min_ip`, `max_ip`: The source and destination IP addresses, ordered by the lowest value, 
  numerically. This is to ensure that both directions of a flow will have the same 5-tuple.
- `min_port`, `max_port`: The source and destination port numbers, for TCP and UDP, ordered by
  the lowest value, numerically. This is to ensure that both directions of a flow will have
  the same 5-tuple.