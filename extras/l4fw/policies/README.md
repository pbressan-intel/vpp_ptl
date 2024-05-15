# Format of the YAML config files

## Table Definition

```yaml
---
table_name: <TABLE_NAME>

# "User-defined" tables do not include the hook point.
# The only hook point we support for now is "net-in".
# In future, we plan to support additional hook points.
{hook_point: <HOOK_POINT>}

# The only security function supported for now is "filter". 
# In future, we plan to support additional security functions.
sf: <SECURITY_FUNCTION>

# The default action is optional since all tables are created with a default action in the data-plane.
# Users can provide a different default action.
{default_action:
  action_name: <ACTION_NAME>
  # Action data is needed only for actions that require it, e.g. the 
  # jump action needs action data to specify the table to which to jump.
  {data: <ACTION_DATA>}}

# Object support for various selector types.
# Users can define objects and refer them from multiple policies.
{objects:
  {<OBJECT_NAME>: <IP_ADDR> | <IP_PREFIX>/<IP_PREFIX_LEN> | <IP_ADDR>-<IP_ADDR> | <PORT_NBR> | <PORT_NBR>-<PORT_NBR> | <CONNTRACK_STATE> | <APP_ID>}
  {<OBJECT_NAME>: <IP_ADDR> | <IP_PREFIX>/<IP_PREFIX_LEN> | <IP_ADDR>-<IP_ADDR> | <PORT_NBR> | <PORT_NBR>-<PORT_NBR> | <CONNTRACK_STATE> | <APP_ID>}
  ...}

rules:

  - action:
      action_name: <ACTION_NAME>
      {data: <ACTION_DATA>}
    # Rule name is optional
    {rule_name: <RULE_NAME>}
    # All match criteria are implicitly ANDed.
    # To achieve a logical OR of match criteria, use separate rules.
    # We support ORing of values within a given match key.
    # The same match key cannot be repeated in a rule.
    matches:
      - key: <MATCH_KEY>
        {operators: [<OPERATOR>, <OPERATOR>, ...]}
        # Values can be a single value, a range, or a list of values 
        # and/or ranges
        values: [<VALUE> | <RANGE>, <VALUE> | <RANGE>, ...]
      - key: <MATCH_KEY>
        {operators: [<OPERATOR>, <OPERATOR>, ...]}
        values: [<VALUE> | <RANGE>, <VALUE> | <RANGE>, ...]
      ...

  ...

...
```

## Match Entries

### IPv4 and IPv6 Addresses

```yaml
# IP addresses can be specified using either
# an exact match or a network prefix and length (CIDR) or a range.
- key: ip_saddr | ip_daddr
  # There can be at most one operator, namely "not".
  {operators: [not]}
  # Values can be an IP address, an IP prefix and length, an IP range,
  # or a list of IP addresses and/or IP prefixes and lengths and/or IP ranges.
  values: [<IP_ADDR> | <IP_PREFIX>/<IP_PREFIX_LEN> | <IP_ADDR>-<IP_ADDR>]
```

### TCP and UDP Ports

```yaml
# Ports can be specified using either an exact match or a range.
- key: tcp_sport | tcp_dport | udp_sport | udp_dport
  # There can be at most one operator, namely "not".
  {operators: [not]}
  # Values can be a port number, a port range,
  # or a list of port numbers and/or port ranges.
  values: [<PORT_NBR> | <PORT_NBR>-<PORT_NBR>]
```

### Connection Tracking

```yaml
# Connection tracking state can be specified using an exact match.
- key: conntrack_state
  # There can be at most one operator, namely "not".
  {operators: [not]}
  values: [<CONNTRACK_STATE>]
```

### Application ID

```yaml
# Application ID can be specified, along with an operator which specifies
# the match "type" (e.g. equals, starts_with, etc.).
- key: app_id
  # Operators is optional and can be one of the operators "equals",
  # "starts_with", "ends_with", or "contains", and optionally also include "not".
  {operators: [not, equals, starts_with, ends_with, contains]}
  values: [<APP_ID>]
```
