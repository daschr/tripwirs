use core::hash::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::{hash_set::HashSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::Xxh3;

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

fn get_filehash(file: &str) -> std::io::Result<u64> {
    let mut fd = File::open(file)?;
    let mut buf = [0u8; 1024];
    let mut hasher = Xxh3::new();

    loop {
        let read_bytes = fd.read(&mut buf)?;
        if read_bytes == 0 {
            break;
        }

        hasher.write(&buf[0..read_bytes]);
    }

    let hash = hasher.finish();

    Ok(hash)
}

enum NodeType {
    F(u64),
    D,
}

fn scan_path(
    config: &Config,
    root_path: &str,
    db: &mut HashMap<&str, NodeType>,
) -> std::io::Result<()> {
    let mut pathstack: Vec<PathBuf> = Vec::new();
    pathstack.push(PathBuf::from(root_path));

    while pathstack.len() != 0 {
        let e = pathstack.pop().unwrap();
        let path: &Path = e.as_path();

        if path.is_file() {
            let p_str: &str = &e.to_str().unwrap();
            db.insert(p_str, NodeType::F(get_filehash(p_str)?));
            continue;
        }

        let it = match path.read_dir() {
            Ok(e) => e,
            Err(_) => continue,
        };
        let mut n_elems = 0;

        for i in it {
            n_elems += 1;
            if let Ok(e) = i {
                pathstack.push(e.path());
            }
        }

        if n_elems == 0 {
            db.insert(&e.to_str().unwrap(), NodeType::D);
            println!("[dir] {:?}", &e);
        }
    }

    Ok(())
}

pub fn gen_db(config: &Config, outfile: &str) -> std::io::Result<()> {
    let mut db: HashMap<&str, NodeType> = HashMap::new();

    for root_path in &config.scans {}

    Ok(())
}
