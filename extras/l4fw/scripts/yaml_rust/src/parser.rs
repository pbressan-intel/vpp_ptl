use filename::file_name;
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::{self, File, ReadDir},
    io::Read,
    path::Path,
};

use crate::{ir, FileTypes};

// Replace references with objects
fn replace_references(line: String, objects: &HashMap<String, String>) -> String {
    let mut output: String = "".to_string();
    // check if value includes references
    for sub_line in line.split(" ") {
        if sub_line.contains("$") {
            // replace object in line
            let key = &sub_line.replace("$", "");
            let value = objects.get(&key.trim().to_string());
            if value.is_none() {
                return Err(format!("Object not found in hashmap: {:?}", key)).unwrap();
            }
            output.push_str(value.unwrap());
            // output.push_str(" ");
        } else {
            output.push_str(sub_line);
            output.push_str(" ");
        }
    }
    return output;
}

/// Process objects in YAML policy file
fn preprocess_yaml(file_string: &String) -> Result<String, &'static str> {
    let mut out_file_string: String = "".to_string();
    // check if file contains objects
    if file_string.contains("objects:") {
        let mut obj_idx: usize = 0;
        let mut rules_idx: usize = 0;
        let mut objects: HashMap<String, String> = HashMap::new();
        // locate "objects" section
        for (index, line) in file_string.lines().enumerate() {
            if line.eq("objects:") {
                obj_idx = index;
            } else if line.eq("rules:") {
                rules_idx = index;
            } else {
            }
        }
        // copy lines to the output file
        for (index, line) in file_string.lines().enumerate() {
            if index < obj_idx {
                // copy line to output file
                out_file_string.push_str(format!("{}\n", line).as_str());
            } else if (index > obj_idx) && (index < rules_idx) {
                if line.contains(":") {
                    // extract key and value
                    let line_key = line
                        .split_at(line.find(":").unwrap())
                        .0
                        .to_string()
                        .trim()
                        .to_string();
                    let line_value = line
                        .split_at((line.find(":").unwrap()) + 1)
                        .1
                        .trim()
                        .to_string();
                    // store objects in hasmap
                    objects.insert(line_key, replace_references(line_value, &objects));
                } else if line.is_empty() {
                    // skip empty line
                    out_file_string.push_str(format!("{}\n", line).as_str());
                } else {
                    // comment unrecognized line
                    out_file_string.push_str(format!("# {}\n", line).as_str());
                }
            } else if index >= rules_idx {
                // check if line contains reference to object
                if line.contains("$") {
                    // extract key and value
                    let line_key = line.split_at(line.find(":").unwrap()).0.to_string();
                    let line_value = line
                        .split_at((line.find(":").unwrap()) + 1)
                        .1
                        .trim()
                        .replace("[", "")
                        .replace("]", "")
                        .to_string();
                    out_file_string.push_str(
                        format!(
                            "{}: [{}]\n",
                            line_key,
                            replace_references(line_value, &objects)
                        )
                        .as_str(),
                    );
                } else {
                    // copy line to output file
                    out_file_string.push_str(format!("{}\n", line).as_str());
                }
            } else {
                // skip line
            }
        }
    } else {
        out_file_string.push_str(file_string);
    }
    return Ok(out_file_string);
}

/// Load YAML policy file into IR
fn parse_yaml(file: &File, file_string: &String) -> Result<Option<ir::Table>, &'static str> {
    // map YAML file to Table structure
    let deserializer = serde_yaml::Deserializer::from_str(file_string.as_str());
    let mut _table: Option<ir::Table> = None;
    match ir::Table::deserialize(deserializer) {
        Ok(tab) => {
            _table = Some(tab);
        }
        Err(_) => {
            println!(
                "Skipping unsupported policy file: {:?}",
                file_name(file).unwrap()
            );
            return Ok(None);
        }
    };
    return Ok(_table);
}

/// Load policy file into IR
fn parse_file(file_type: &FileTypes, mut file: File) -> Result<Option<ir::Table>, &'static str> {
    // read file as String
    let mut file_string = String::new();
    match file.read_to_string(&mut file_string) {
        Ok(bytes) => {
            if bytes <= 0 {
                return Err(format!("Empty policy file: {:?}", file)).unwrap();
            }
        }
        Err(e) => {
            return Err(e.to_string().as_str()).unwrap();
        }
    };
    let mut _table: Option<ir::Table> = None;
    // select parser based on file type
    match file_type {
        FileTypes::yaml => {
            // preprocess file as YAML
            match preprocess_yaml(&file_string) {
                Ok(fs) => file_string = fs,
                _ => return Err(format!("Failed to preprocess policy file: {:?}", file)).unwrap(),
            }
            // parse file as YAML
            match parse_yaml(&file, &file_string) {
                Ok(Some(tab)) => _table = Some(tab),
                Ok(None) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
    // L4FW-TODO: remove when lists are supported
    for rule in _table.as_ref().unwrap().get_rules() {
        for mtch in rule.get_matches() {
            if mtch.values.len() > 1 {
                return Err(format!("Lists are not supported yet: {:?}", mtch.values)).unwrap();
            }
        }
    }
    // ----------------------------------------
    return Ok(_table);
}

/// Scan input files and directories and send to parser
pub fn load_policies(
    cfg_type: &FileTypes,
    cfg_path: &Path,
) -> Result<Vec<ir::Table>, &'static str> {
    let mut tables: Vec<ir::Table> = vec![];
    if cfg_path.is_file() {
        match File::open(cfg_path) {
            Ok(f) => {
                match parse_file(&cfg_type, f) {
                    Ok(t) => {
                        if t.is_some() {
                            tables.push(t.unwrap())
                        }
                    }
                    Err(e) => return Err(e),
                };
            }
            Err(e) => {
                return Err(e.to_string().as_str()).unwrap();
            }
        };
    } else if cfg_path.is_dir() {
        let mut _entries: ReadDir;
        match fs::read_dir(cfg_path) {
            Ok(dir_entries) => {
                _entries = dir_entries;
            }
            Err(e) => {
                return Err(e.to_string().as_str()).unwrap();
            }
        }
        for entry in _entries {
            let path = entry.unwrap().path();
            if path.is_file() {
                match File::open(path) {
                    Ok(f) => {
                        match parse_file(&cfg_type, f) {
                            Ok(t) => {
                                if t.is_some() {
                                    tables.push(t.unwrap())
                                }
                            }
                            Err(e) => return Err(e),
                        };
                    }
                    Err(e) => return Err(e.to_string().as_str()).unwrap(),
                };
            } else if path.is_dir() {
                println!("Skipping sub-directory: {}", path.to_str().unwrap());
            } else {
                println!("Skipping unrecognised path: {}", path.to_str().unwrap());
            }
        }
    } else {
        let error = format!(
            "Path is not a valid file or directory: {}",
            cfg_path.to_str().unwrap()
        );
        return Err(error.as_str()).unwrap();
    }
    return Ok(tables);
}
