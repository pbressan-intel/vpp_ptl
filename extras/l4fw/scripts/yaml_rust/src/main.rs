use clap::Parser;
use std::path::Path;
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

mod ir;
mod parser;
mod vpp_cli;

// command-line argument parser
#[derive(Parser)]
#[command(about, long_about = None, ignore_errors = true)]
struct PrgArgs {
    /// Format of the policy files.
    #[arg(long, default_value = "yaml")]
    cfg_type: String,
    /// Path to the policy file or directory that contains the policy files.
    #[arg(long)]
    cfg_path: String,
}

/// Supported file types
#[derive(Debug, Clone, EnumIter, strum_macros::Display)]
#[allow(non_camel_case_types)]
enum FileTypes {
    yaml,
}

// Check if file type is supported
fn check_file_type(file_type: String) -> Result<FileTypes, &'static str> {
    for ftype in FileTypes::iter() {
        if ftype.to_string() == file_type {
            return Ok(ftype);
        }
    }
    return Err("Format of the policy files is not supported.");
}

/// Print error message and terminate
fn exit_with_error(error: String) {
    eprintln!("Error: {}", error);
    std::process::exit(1);
}

fn main() {
    // parse command line args
    let args = PrgArgs::parse();
    let mut cfg_type: Option<FileTypes> = None;
    match check_file_type(args.cfg_type.to_lowercase()) {
        Ok(ftype) => {
            cfg_type = Some(ftype);
        }
        Err(e) => {
            exit_with_error(e.to_string());
        }
    };
    let cfg_path = Path::new(args.cfg_path.as_str());

    // Load policy files into IR
    let mut tables: Option<Vec<ir::Table>> = None;
    match parser::load_policies(&cfg_type.unwrap(), cfg_path) {
        Ok(t) => tables = Some(t),
        Err(e) => exit_with_error(e.to_string()),
    }

    #[cfg(all(feature = "debug"))]
    {
        // Dump IR
        print!("\n-------------------------------------------------\n");
        print!("\tIntermediate Representation\n");
        print!("-------------------------------------------------\n");
        print!("{:#?}\n", tables.as_ref().unwrap());
    }

    // Load IR into the data-plane
    match vpp_cli::set_env_path() {
        // PATH set Ok
        Ok(_) => {
            // Create tables before populating them
            for table in tables.as_ref().unwrap() {
                let status: Result<(), &str>;
                // Create an empty table
                status = vpp_cli::cli_add_table(&table);
                if status.is_err() {
                    exit_with_error(status.unwrap_err().to_string());
                }
            }
            // Populate the tables
            for table in tables.as_ref().unwrap() {
                let mut status: Result<(), &str>;
                // Add default action to a table
                status = vpp_cli::cli_set_default(&table);
                if status.is_err() {
                    exit_with_error(status.unwrap_err().to_string());
                }
                // Add rules to a table
                status = vpp_cli::cli_set_rules(&table);
                if status.is_err() {
                    exit_with_error(status.unwrap_err().to_string());
                }
                #[cfg(all(feature = "debug"))]
                {
                    // Dump table content
                    print!("\n-------------------------------------------------\n");
                    print!("\tL4FW Table\n");
                    print!("-------------------------------------------------\n");
                    print!("{}\n", vpp_cli::_cli_dump_table_data(&table).unwrap());
                }
            }
        }
        // Cannot set PATH
        Err(e) => exit_with_error(e.to_string()),
    }

    println!("\n---> Data-plane configuration succeeded !!! <---\n")
}
