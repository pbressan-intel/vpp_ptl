use std::{
    env,
    path::PathBuf,
    process::{Command, Stdio},
};
use which::which;

use crate::ir;

// ---------------------------------------------------------------------------
//                              VPP ENVIRONMENT
// ---------------------------------------------------------------------------

/// Setup env to use VPP CLI
pub fn set_env_path() -> Result<(), &'static str> {
    // get project_root_dir
    let mut project_root_dir: PathBuf;
    match env::current_exe() {
        Ok(dir) => project_root_dir = dir,
        Err(e) => return Err(e.to_string().as_str()).unwrap(),
    };
    // remove name of the executable from path
    match project_root_dir.parent() {
        Some(parent) => project_root_dir = parent.to_path_buf(),
        None => {
            return Err(format!(
                "Invalid project root dir: {}",
                project_root_dir.display()
            ))
            .unwrap()
        }
    };
    let vpp_root_dir = project_root_dir.join("../../../../../..");
    let vpp_install_dir: PathBuf;
    // check if the program is running in devel mode or in release mode
    if project_root_dir
        .to_str()
        .unwrap()
        .contains("target/release")
    {
        // release mode
        #[cfg(all(feature = "debug"))]
        println!("Running program in release mode ...");
        // vpp_install_dir
        vpp_install_dir = vpp_root_dir.join("build-root/install-vpp-native/vpp/bin/");
    } else {
        // devel mode
        #[cfg(all(feature = "debug"))]
        println!("Running program in devel mode ...");
        // vpp_install_dir
        vpp_install_dir = vpp_root_dir.join("build-root/install-vpp_debug-native/vpp/bin/");
    }
    // assemble path string
    let path_str: String = format!(
        "{}{}{}",
        env::var("PATH").unwrap_or("".to_string()),
        ":".to_string(),
        vpp_install_dir.to_str().unwrap(),
    );
    // set PATH env variable
    env::set_var("PATH", path_str);
    Ok(())
}

/// Check if SUDO is available
fn check_sudo() -> bool {
    match which("sudo") {
        Ok(_) => {
            return true;
        }
        Err(_) => {
            return false;
        }
    }
}

// ---------------------------------------------------------------------------
//                       SERIALIZATION: IR --> VPP CLI FORMAT
// ---------------------------------------------------------------------------

/// Values -> String in VPP CLI format
fn value_to_string(vr: &ir::Values) -> String {
    match vr {
        ir::Values::IpAddr(ip) => {
            return ip.to_string();
        }
        ir::Values::IpRange(start, end) => {
            return format!("{}-{}", start.to_string(), end.to_string());
        }
        ir::Values::Port(number) => return format!("{}", number.to_string()),
        ir::Values::PortRange(start, end) => {
            return format!("{}-{}", start.to_string(), end.to_string())
        }
        ir::Values::ConntrackState(state) => {
            return format!("{}", state.to_string().to_uppercase())
        }
        ir::Values::AppId(id) => return format!("\"{}\"", id.to_string()),
    }
}

/// Actions -> String in VPP CLI format
fn actions_to_string(action: &ir::Actions) -> String {
    match action {
        ir::Actions::Void => return "".to_string(),
        ir::Actions::Drop => return "DROP".to_string(),
        ir::Actions::Allow => return "ALLOW".to_string(),
        ir::Actions::Jump => return "JUMP".to_string(),
        ir::Actions::Log => return "LOG".to_string(),
    }
}

/// Keys -> String in VPP CLI format
fn keys_to_string(key: &ir::Keys) -> String {
    match key {
        // IPv6 protocol is not supported yet !
        ir::Keys::IpSaddr => return "IP4_SADDR".to_string(),
        ir::Keys::IpDaddr => return "IP4_DADDR".to_string(),
        ir::Keys::TcpSport => return "TCP_SPORT".to_string(),
        ir::Keys::TcpDport => return "TCP_DPORT".to_string(),
        ir::Keys::UdpSport => return "UDP_SPORT".to_string(),
        ir::Keys::UdpDport => return "UDP_DPORT".to_string(),
        ir::Keys::ConntrackState => return "CONN_STATE".to_string(),
        ir::Keys::AppId => return "APP_ID".to_string(),
    }
}

/// Operators -> String in VPP CLI format
fn operators_to_string(ops: &Vec<ir::Operators>) -> String {
    let mut ret_str: String = "".to_string();
    for op in ops {
        match op {
            ir::Operators::Void => {
                ret_str = format!("{}{}", ret_str, "".to_string());
            }
            ir::Operators::Not => {
                ret_str = format!("{}{}", ret_str, "!".to_string());
            }
            ir::Operators::Equals => {
                ret_str = format!("{}{}", ret_str, "==".to_string());
            }
            ir::Operators::StartsWith => {
                ret_str = format!("{}{}", ret_str, "starts-with".to_string());
            }
            ir::Operators::EndsWith => {
                ret_str = format!("{}{}", ret_str, "ends-with".to_string());
            }
            ir::Operators::Contains => {
                ret_str = format!("{}{}", ret_str, "contains".to_string());
            }
        }
    }
    return ret_str;
}

/// HookPoints -> String in VPP CLI format
fn hooks_to_string(hook: &ir::HookPoints) -> String {
    match hook {
        ir::HookPoints::Void => return "".to_string(),
        ir::HookPoints::NetIn => return "net-in".to_string(),
    }
}

/// Sfs -> String in VPP CLI format
fn sfs_to_string(sf: &ir::Sfs) -> String {
    match sf {
        ir::Sfs::Mangle => return "mangle".to_string(),
        ir::Sfs::Nat => return "nat".to_string(),
        ir::Sfs::Filter => return "filter".to_string(),
    }
}

/// Full table name in VPP CLI format
fn get_full_table_name(table: &ir::Table) -> String {
    match table.get_hook_point() {
        ir::HookPoints::Void => {
            return format!(
                "{}.{}",
                sfs_to_string(&table.get_sf()),
                table.get_table_name()
            );
        }
        ir::HookPoints::NetIn => {
            return format!(
                "{}.{}.{}",
                hooks_to_string(&table.get_hook_point()),
                sfs_to_string(&table.get_sf()),
                table.get_table_name()
            );
        }
    }
}

/// Get rule CMD based on type of match entry
fn get_rule_cmd(match_entry: &ir::MatchEntry) -> String {
    let mut command = format!(
        "{} {} {} ",
        "match".to_string(),
        keys_to_string(&match_entry.get_key()),
        operators_to_string(&match_entry.get_operators().unwrap()),
    );
    match &match_entry.get_value().unwrap() {
        ir::Values::IpRange(_, _) => {
            command.push_str("range ");
            command.push_str(value_to_string(&match_entry.get_value().unwrap()).as_str());
        }
        ir::Values::PortRange(_, _) => {
            command.push_str("range ");
            command.push_str(value_to_string(&match_entry.get_value().unwrap()).as_str());
        }
        _ => {
            command.push_str(value_to_string(&match_entry.get_value().unwrap()).as_str());
        }
    }
    command.push_str(" ");
    return command;
}

// ---------------------------------------------------------------------------
//                              VPP CLI COMMANDS
// ---------------------------------------------------------------------------

/// CLI: Craft the VPPCTL command
fn cli_vppctl_cmd() -> Command {
    if check_sudo() {
        let mut vppctl_cmd = Command::new(format!("sudo"));
        let path_str: String = format!("PATH={}", env::var("PATH").unwrap_or("".to_string()));
        vppctl_cmd.args(["env", path_str.as_str()]);
        vppctl_cmd.args(["vppctl", "-s", "/run/vpp/cli.sock"]);
        return vppctl_cmd;
    } else {
        let mut vppctl_cmd = Command::new("vppctl");
        vppctl_cmd.env("PATH", env::var("PATH").unwrap_or("".to_string()));
        vppctl_cmd.args(["-s", "/run/vpp/cli.sock"]);
        return vppctl_cmd;
    }
}

/// CLI: check for errors
fn _cli_check_err(ret_str: String) -> Result<String, &'static str> {
    if ret_str.contains("[ERROR]") {
        return Err("Error: VPP CLI command failed !");
    } else {
        #[cfg(all(feature = "debug"))]
        {
            println!("RETURNED STRING:\n{}", ret_str);
        }
        return Ok(ret_str);
    }
}

/// CLI: execute request command --> get response
fn cli_exec_reqrply(req: String) -> Result<String, &'static str> {
    #[cfg(all(feature = "debug"))]
    println!("{}", req);
    let mut cmd = cli_vppctl_cmd();
    cmd.arg(req);
    let out = cmd.stdout(Stdio::piped()).output().unwrap();
    match String::from_utf8(out.stdout) {
        Ok(res) => match _cli_check_err(res) {
            Ok(res) => return Ok(res),
            Err(e) => return Err(e),
        },
        Err(e) => return Err(e.to_string().as_str()).unwrap(),
    }
}

/// CLI: get existing tables from L4FW
pub fn cli_get_tables() -> Result<Vec<String>, &'static str> {
    let str_out: String;
    match cli_exec_reqrply("show l4fw table".to_string()) {
        Ok(s) => str_out = s,
        Err(e) => return Err(e),
    }
    let vec_out: Vec<String> = str_out
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(_, tbl_name)| tbl_name.trim().to_string())
        .collect();
    return Ok(vec_out);
}

/// CLI: check if a table exists in L4FW
pub fn cli_table_exist(table: &ir::Table) -> Result<bool, &'static str> {
    let tables: Vec<String>;
    match cli_get_tables() {
        Ok(v) => tables = v,
        Err(e) => return Err(e),
    }
    return Ok(tables.contains(&get_full_table_name(table)));
}

/// CLI: dump content of a L4FW table
pub fn _cli_dump_table_data(table: &ir::Table) -> Result<String, &'static str> {
    match cli_table_exist(table) {
        Ok(res) => match res {
            true => {
                let cmd = format!(
                    "{} {}",
                    "show l4fw table".to_string(),
                    get_full_table_name(table)
                );
                let str_out = cli_exec_reqrply(cmd);
                return str_out;
            }
            false => Err(format!(
                "Table: {} does not exist.",
                get_full_table_name(table)
            ))
            .unwrap(),
        },
        Err(e) => return Err(e),
    }
}

/// CLI: add a table to L4FW
pub fn cli_add_table(table: &ir::Table) -> Result<(), &'static str> {
    match cli_table_exist(table) {
        Ok(res) => match res {
            true => {
                println!("Skipping existing table: {}", get_full_table_name(table));
                return Ok(());
            }
            false => {
                let cmd = format!(
                    "{} {}",
                    "l4fw_add_table".to_string(),
                    get_full_table_name(table)
                );
                let _ = cli_exec_reqrply(cmd);
                return Ok(());
            }
        },
        Err(e) => return Err(e),
    }
}

/// CLI: set default action to a table in L4FW
pub fn cli_set_default(table: &ir::Table) -> Result<(), &'static str> {
    match cli_table_exist(table) {
        Ok(res) => match res {
            true => {
                // check if default action exists
                match &table.get_def_action().get_name() {
                    ir::Actions::Void => return Ok(()),
                    _ => {
                        let cmd = format!(
                            "{} {} {} {} {}",
                            "l4fw_set_default table".to_string(),
                            get_full_table_name(table),
                            "action".to_string(),
                            actions_to_string(&table.get_def_action().get_name()),
                            table.get_def_action().get_data(),
                        );
                        let _ = cli_exec_reqrply(cmd);
                        return Ok(());
                    }
                }
            }
            false => Err(format!(
                "Table: {} does not exist.",
                get_full_table_name(table)
            ))
            .unwrap(),
        },
        Err(e) => return Err(e),
    }
}

/// CLI: set rules to a table in L4FW
pub fn cli_set_rules(table: &ir::Table) -> Result<(), &'static str> {
    // check if the table exists
    match cli_table_exist(table) {
        Ok(res) => match res {
            true => {
                // iterate over the rules in a table
                for rule in table.get_rules() {
                    // craft base CMD
                    let mut cmd = format!(
                        "{} {} {} {} {} ",
                        "l4fw_add_rule",
                        "name",
                        rule.get_rule_name(),
                        "table".to_string(),
                        get_full_table_name(table),
                    );
                    // iterate over the match entries in a rule
                    for match_entry in rule.get_matches() {
                        // complete the CMD based on the type of match entry
                        match match_entry.get_value() {
                            // IP address
                            Ok(vr) => match vr {
                                ir::Values::IpAddr(_) => {
                                    cmd.push_str(&get_rule_cmd(match_entry));
                                }
                                // IP range
                                ir::Values::IpRange(_, _) => {
                                    cmd.push_str(&get_rule_cmd(match_entry));
                                }
                                // Port
                                ir::Values::Port(_) => {
                                    cmd.push_str(&get_rule_cmd(match_entry));
                                }
                                // Port range
                                ir::Values::PortRange(_, _) => {
                                    cmd.push_str(&get_rule_cmd(match_entry));
                                }
                                // Connection Tracking State
                                ir::Values::ConntrackState(_) => {
                                    cmd.push_str(&get_rule_cmd(match_entry));
                                }
                                // App ID
                                ir::Values::AppId(_) => {
                                    cmd.push_str(&get_rule_cmd(match_entry));
                                }
                            },
                            Err(e) => return Err(e),
                        }
                    }
                    // add action to CMD
                    let action_name = actions_to_string(&rule.get_action().get_name());
                    let action_data: String;
                    match action_name.as_str() {
                        "JUMP" => {
                            action_data = format!(
                                "{}.{}",
                                sfs_to_string(&table.get_sf()),
                                rule.get_action().get_data()
                            )
                        }
                        _ => {
                            action_data = rule.get_action().get_data();
                        }
                    }
                    let cmd = format!(
                        "{} {} {} {}",
                        cmd,
                        "action".to_string(),
                        action_name,
                        action_data,
                    );
                    // execute CMD
                    cli_exec_reqrply(cmd).unwrap();
                }
                return Ok(());
            }
            false => Err(format!(
                "Table: {} does not exist.",
                get_full_table_name(table)
            ))
            .unwrap(),
        },
        Err(e) => return Err(e),
    }
}
