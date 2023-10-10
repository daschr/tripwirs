use crate::crypto::{read_decrypted, save_encrypted, CryptoError};
use rand::prelude::*;
use std::collections::hash_set::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

pub enum ActionType {
    Scan,
    Ignore,
}

#[derive(bincode::Encode, bincode::Decode)]
pub struct Config {
    pub secret: [u8; 192],
    pub scans: Vec<String>,
    pub ignores: HashSet<PathBuf>,
}

impl Config {
    pub fn new() -> Self {
        let mut c = Self {
            secret: [0u8; 192],
            scans: Vec::new(),
            ignores: HashSet::new(),
        };

        c.gen_new_secret();

        c
    }

    pub fn gen_new_secret(&mut self) {
        let mut rng = rand::thread_rng();
        rng.fill(&mut self.secret[0..128]);
        rng.fill(&mut self.secret[128..192]);
    }
}

pub fn gen_config(infile: &str, outfile: &str, passphrase: &str) -> Result<(), CryptoError> {
    let mut fd = BufReader::new(File::open(infile)?);
    let mut config = Config::new();

    let mut line = String::new();
    let mut current_type: ActionType = ActionType::Scan;

    while fd.read_line(&mut line)? != 0 {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            line.clear();
            continue;
        }

        match line.as_str() {
            "[SCAN]\n" | "[scan]\n" => {
                current_type = ActionType::Scan;
            }
            "[IGNORE]\n" | "[ignore]\n" => {
                current_type = ActionType::Ignore;
            }
            _ => match &current_type {
                ActionType::Scan => {
                    config.scans.push(String::from(line.trim_end_matches('\n')));
                }
                ActionType::Ignore => {
                    config
                        .ignores
                        .insert(PathBuf::from(line.trim_end_matches('\n')));
                }
            },
        }
        line.clear();
    }

    save_encrypted(config, outfile, passphrase)?;

    Ok(())
}

#[inline]
pub fn get_config(infile: &str, passphrase: &str) -> Result<Config, CryptoError> {
    read_decrypted(infile, passphrase)
}
