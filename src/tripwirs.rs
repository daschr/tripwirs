use serde::{Deserialize, Serialize};
use std::collections::{hash_set::HashSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;

enum ActionType {
    Scan,
    Ignore,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    scans: Vec<String>,
    ignores: HashSet<String>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            scans: Vec::new(),
            ignores: HashSet::new(),
        }
    }
}

pub fn gen_config(infile: &str, outfile: &str, passphrase: &str) -> std::io::Result<()> {
    let mut fd = BufReader::new(File::open(infile)?);
    let mut config = Config::new();

    let mut line = String::new();
    let mut current_type: ActionType = ActionType::Scan;

    while fd.read_line(&mut line)? != 0 {
        match line.as_str() {
            "[SCAN]" | "[scan]" => {
                current_type = ActionType::Scan;
            }
            "[IGNORE]" | "[ignore]" => {
                current_type = ActionType::Ignore;
            }
            _ => match &current_type {
                ActionType::Scan => {
                    config.scans.push(line.clone());
                }
                ActionType::Ignore => {
                    config.ignores.insert(line.clone());
                }
            },
        }
        line.clear();
    }

    let s_config: Vec<u8> = bincode::serialize(&config).expect("failed to serialize config");

    File::create(outfile)?.write_all(&s_config)?;

    Ok(())
}

pub fn get_config(infile: &str, passphrase: &str) -> std::io::Result<Config> {
    let mut s_config: Vec<u8> = Vec::new();

    File::open(infile)?.read_to_end(&mut s_config)?;
    Ok(bincode::deserialize(&s_config).expect("could not deserialize config"))
}

fn scan_path(config: &Config, path: &str) -> u64 {}

pub fn gen_db(config: &Config, outfile: &str) -> std::io::Result<()> {
    let mut db: HashMap<&str, u64> = HashMap::new();

    for root_path in &config.scans {}

    Ok(())
}
