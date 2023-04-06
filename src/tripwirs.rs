use core::hash::Hasher;
use std::collections::{hash_set::HashSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::Xxh3;

enum ActionType {
    Scan,
    Ignore,
}

#[derive(bincode::Encode, bincode::Decode)]
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
            "[SCAN]\n" | "[scan]\n" => {
                current_type = ActionType::Scan;
            }
            "[IGNORE]\n" | "[ignore]\n" => {
                current_type = ActionType::Ignore;
            }
            _ => match &current_type {
                ActionType::Scan => {
                    config.scans.push(String::from(line.trim_end_matches("\n")));
                }
                ActionType::Ignore => {
                    config
                        .ignores
                        .insert(String::from(line.trim_end_matches("\n")));
                }
            },
        }
        line.clear();
    }

    let mut fd = File::create(outfile)?;
    bincode::encode_into_std_write(config, &mut fd, bincode::config::standard())
        .expect("failed to encode config");

    Ok(())
}

pub fn get_config(infile: &str, passphrase: &str) -> std::io::Result<Config> {
    let mut s_config: Vec<u8> = Vec::new();

    let mut fd = File::open(infile)?;
    Ok(
        bincode::decode_from_std_read(&mut fd, bincode::config::standard())
            .expect("could not decode config"),
    )
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

#[derive(bincode::Encode, bincode::Decode)]
enum NodeType {
    F(u64),
    D,
}

fn scan_path(
    config: &Config,
    root_path: &str,
    db: &mut HashMap<String, NodeType>,
) -> std::io::Result<()> {
    let mut pathstack: Vec<PathBuf> = Vec::new();
    pathstack.push(PathBuf::from(root_path));

    while pathstack.len() != 0 {
        let e = pathstack.pop().unwrap();
        let path: &Path = e.as_path();
        let e_str: &str = &e.to_str().unwrap();

        if config.ignores.contains(e_str) {
            println!("Skipping \"{}\"", e_str);
            continue;
        }

        if path.is_file() {
            db.insert(String::from(e_str), NodeType::F(get_filehash(e_str)?));
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
            db.insert(String::from(e_str), NodeType::D);
            println!("[dir] {:?}", &e);
        }
    }

    Ok(())
}

pub fn gen_db(config: &Config, outfile: &str) -> std::io::Result<()> {
    let mut db: HashMap<String, NodeType> = HashMap::new();

    for root_path in &config.scans {
        scan_path(config, root_path, &mut db)?;
    }

    let mut fd = File::create(outfile)?;
    bincode::encode_into_std_write(db, &mut fd, bincode::config::standard())
        .expect("could not encode db");
    Ok(())
}

pub fn compare_db(config: &Config, dbfile: &str) -> std::io::Result<()> {}
