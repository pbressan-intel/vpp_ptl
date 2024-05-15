use cidr::IpCidr;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

// Types of values
#[derive(Debug, Clone)]
pub enum Values {
    IpAddr(IpCidr),
    IpRange(IpCidr, IpCidr),
    Port(u32),
    PortRange(u32, u32),
    ConntrackState(ConntrackStates),
    AppId(String),
}

/// Supported actions
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Actions {
    Void,
    #[serde(alias = "drop")]
    Drop,
    #[serde(alias = "allow")]
    Allow,
    #[serde(alias = "jump")]
    Jump,
    #[serde(alias = "log")]
    Log,
}

/// Supported keys
#[derive(Debug, Clone, Copy, Serialize, Deserialize, strum_macros::Display)]
pub enum Keys {
    #[serde(alias = "ip_saddr")]
    IpSaddr,
    #[serde(alias = "ip_daddr")]
    IpDaddr,
    #[serde(alias = "tcp_sport")]
    TcpSport,
    #[serde(alias = "tcp_dport")]
    TcpDport,
    #[serde(alias = "udp_sport")]
    UdpSport,
    #[serde(alias = "udp_dport")]
    UdpDport,
    #[serde(alias = "conntrack_state")]
    ConntrackState,
    #[serde(alias = "app_id")]
    AppId,
}

/// Supported conntrack_states
#[derive(Debug, Clone, Copy, EnumIter, strum_macros::Display)]
#[allow(non_camel_case_types)]
pub enum ConntrackStates {
    new,
    established,
}

/// Supported operators
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum Operators {
    Void,
    #[serde(alias = "not")]
    Not,
    #[serde(alias = "equals")]
    Equals,
    #[serde(alias = "starts_with")]
    StartsWith,
    #[serde(alias = "ends_with")]
    EndsWith,
    #[serde(alias = "contains")]
    Contains,
}

/// Supported hook points
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum HookPoints {
    Void,
    #[serde(alias = "net-in")]
    NetIn,
}

/// Supported security functions
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Sfs {
    #[serde(alias = "mangle")]
    Mangle,
    #[serde(alias = "nat")]
    Nat,
    #[serde(alias = "filter")]
    Filter,
}

/// MatchEntry depends on: Keys, Operators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchEntry {
    pub key: Keys,
    pub operators: Option<Vec<Operators>>,
    pub values: Vec<String>,
}
impl MatchEntry {
    /// Get key
    pub fn get_key(&self) -> Keys {
        return self.key;
    }
    /// Get operators
    pub fn get_operators(&self) -> Result<Vec<Operators>, &'static str> {
        match self.key {
            Keys::AppId => {
                if self.operators.is_some() {
                    if self.operators.as_ref().unwrap().len() == 1 {
                        match self.operators.as_ref().unwrap()[0] {
                            Operators::Void => {
                                return Err(format!(
                                    "Invalid operator for key: {}",
                                    self.key.to_string()
                                ))
                                .unwrap();
                            }
                            Operators::Not => {
                                return Err(format!(
                                    "Invalid operator for key: {}",
                                    self.key.to_string()
                                ))
                                .unwrap();
                            }
                            _ => return Ok(self.operators.clone().unwrap()),
                        }
                    } else if self.operators.as_ref().unwrap().len() == 2 {
                        if self.operators.as_ref().unwrap()[0] == Operators::Not {
                            return Ok(self.operators.clone().unwrap());
                        } else {
                            return Err(format!(
                                "Invalid operator for key: {}",
                                self.key.to_string()
                            ))
                            .unwrap();
                        }
                    } else {
                        return Err(format!(
                            "Key: {} supports either one, or two operators",
                            self.key.to_string()
                        ))
                        .unwrap();
                    }
                } else {
                    return Err(format!(
                        "Missing operators for key: {}",
                        self.key.to_string()
                    ))
                    .unwrap();
                }
            }
            _ => {
                if self.operators.is_some() {
                    if self.operators.as_ref().unwrap().contains(&Operators::Not) {
                        match self.get_value().unwrap() {
                            Values::IpRange(_, _) => {
                                // Range: Not without Equals
                                return Ok(vec![Operators::Not]);
                            }
                            Values::PortRange(_, _) => {
                                // Range: Not without Equals
                                return Ok(vec![Operators::Not]);
                            }
                            _ => {
                                // Others: Not with Equals
                                return Ok(vec![Operators::Not, Operators::Equals]);
                            }
                        }
                    } else {
                        return Err(format!(
                            "Unsupported operators: {:?}",
                            self.operators.as_ref().unwrap()
                        ))
                        .unwrap();
                    }
                } else {
                    match self.get_value().unwrap() {
                        Values::IpRange(_, _) => {
                            // Range: implicit Equals
                            return Ok(vec![Operators::Void]);
                        }
                        Values::PortRange(_, _) => {
                            // Range: implicit Equals
                            return Ok(vec![Operators::Void]);
                        }
                        _ => {
                            // Other: explicit Equals
                            return Ok(vec![Operators::Equals]);
                        }
                    }
                }
            }
        }
    }
    /// Get value
    pub fn get_value(&self) -> Result<Values, &'static str> {
        match self.key {
            Keys::IpSaddr => self.get_ip(),
            Keys::IpDaddr => self.get_ip(),
            Keys::TcpSport => self.get_port(),
            Keys::TcpDport => self.get_port(),
            Keys::UdpSport => self.get_port(),
            Keys::UdpDport => self.get_port(),
            Keys::ConntrackState => self.get_conntrack_state(),
            Keys::AppId => self.get_app_id(),
        }
    }
    /// Get IP values
    fn get_ip(&self) -> Result<Values, &'static str> {
        // check if it is a range
        match self.values[0].find('-') {
            // range
            Some(index) => {
                // start
                let start_ip: IpCidr;
                match IpCidr::from_str(&self.values[0][..index]) {
                    Ok(ip) => {
                        // IPv6 protocol is not supported yet !
                        if ip.is_ipv6() {
                            return Err("IPv6 protocol is not supported yet !".to_string())
                                .unwrap();
                        } else {
                            start_ip = ip;
                        }
                    }
                    Err(e) => {
                        return Err(e.to_string().as_str()).unwrap();
                    }
                }
                // end
                let end_ip: IpCidr;
                match IpCidr::from_str(&self.values[0][(index + 1)..]) {
                    Ok(ip) => {
                        // IPv6 protocol is not supported yet !
                        if ip.is_ipv6() {
                            return Err("IPv6 protocol is not supported yet !".to_string())
                                .unwrap();
                        } else {
                            end_ip = ip;
                        }
                    }
                    Err(e) => {
                        return Err(e.to_string().as_str()).unwrap();
                    }
                }
                return Ok(Values::IpRange(start_ip, end_ip));
            }
            None => {
                // value
                match IpCidr::from_str(self.values[0].as_str()) {
                    Ok(ip) => {
                        // IPv6 protocol is not supported yet !
                        if ip.is_ipv6() {
                            return Err("IPv6 protocol is not supported yet !".to_string())
                                .unwrap();
                        } else {
                            return Ok(Values::IpAddr(ip));
                        }
                    }
                    Err(e) => {
                        return Err(e.to_string().as_str()).unwrap();
                    }
                }
            }
        }
    }
    /// Get PORT values and ranges
    fn get_port(&self) -> Result<Values, &'static str> {
        // check if it is a range
        match self.values[0].find('-') {
            // range
            Some(index) => {
                let start_port: u32;
                let end_port: u32;
                // start_port
                match self.values[0][..index].parse::<u32>() {
                    Ok(port_nbr) => {
                        start_port = port_nbr;
                    }
                    Err(_) => {
                        return Err("Start port number format is not supported.");
                    }
                }
                // end_port
                match self.values[0][(index + 1)..].parse::<u32>() {
                    Ok(port_nbr) => {
                        end_port = port_nbr;
                    }
                    Err(_) => {
                        return Err("End port number format is not supported.");
                    }
                }
                return Ok(Values::PortRange(start_port, end_port));
            }
            None => match self.values[0].parse::<u32>() {
                Ok(port_nbr) => {
                    return Ok(Values::Port(port_nbr));
                }
                Err(_) => {
                    return Err("Unrecognised port number format.");
                }
            },
        }
    }
    /// Get conntrack_state value
    fn get_conntrack_state(&self) -> Result<Values, &'static str> {
        for state in ConntrackStates::iter() {
            if state.to_string() == self.values[0].to_string() {
                return Ok(Values::ConntrackState(state));
            }
        }
        return Err("Connection tracking state is not supported.");
    }
    /// Get app id value
    fn get_app_id(&self) -> Result<Values, &'static str> {
        return Ok(Values::AppId(self.values[0].to_string()));
    }
}

/// Action depends on: Actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub action_name: Actions,
    pub data: Option<String>,
}
impl Action {
    pub fn get_name(&self) -> Actions {
        return self.action_name;
    }
    pub fn get_data(&self) -> String {
        return self.data.as_ref().unwrap_or(&"".to_string()).to_string();
    }
}

/// Rule depends on: Action, MatchEntry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub action: Action,
    pub rule_name: Option<String>,
    pub matches: Vec<MatchEntry>,
}
impl Rule {
    pub fn get_action(&self) -> Action {
        return self.action.clone();
    }
    pub fn get_rule_name(&self) -> String {
        return format!(
            "\"{}\"",
            self.rule_name
                .as_ref()
                .unwrap_or(&"".to_string())
                .to_string()
        );
    }
    pub fn get_matches(&self) -> &Vec<MatchEntry> {
        return self.matches.as_ref();
    }
}

/// Table depends on: HookPoints, Sfs, Action, Rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    pub table_name: String,
    pub hook_point: Option<HookPoints>,
    pub sf: Sfs,
    pub default_action: Option<Action>,
    pub rules: Vec<Rule>,
}
impl Table {
    pub fn get_table_name(&self) -> String {
        return self.table_name.clone();
    }
    pub fn get_hook_point(&self) -> HookPoints {
        return self.hook_point.unwrap_or(HookPoints::Void);
    }
    pub fn get_sf(&self) -> Sfs {
        return self.sf;
    }
    pub fn get_def_action(&self) -> &Action {
        return self.default_action.as_ref().unwrap_or(&Action {
            action_name: (Actions::Void),
            data: (None),
        });
    }
    pub fn get_rules(&self) -> &Vec<Rule> {
        return self.rules.as_ref();
    }
}
