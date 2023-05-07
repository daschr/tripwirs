use core::hash::Hasher;
use std::collections::{hash_set::HashSet, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::Xxh3;

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};

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

struct FixedNonceSequence {
    first: u64,
    second: u32,
}

impl FixedNonceSequence {
    fn new() -> Self {
        Self {
            first: 0,
            second: 0,
        }
    }
}

impl NonceSequence for FixedNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.first += 1;
        if self.first == 0u64 {
            self.second += 1;
        }

        let mut buf = [0u8; 12];
        for (i, x) in self.first.to_le_bytes().into_iter().enumerate() {
            buf[i] = x;
        }

        for (i, x) in self.second.to_le_bytes().into_iter().enumerate() {
            buf[i + 8] = x;
        }

        Ok(Nonce::assume_unique_for_key(buf))
    }
}

fn get_aes_256_compatible_passphrase(passphrase: &str) -> String {
    let mut s = String::from(passphrase);
    let orig_len = passphrase.len();
    if orig_len < AES_256_GCM.key_len() {
        while s.len() != AES_256_GCM.key_len() {
            let nl = {
                if s.len() + orig_len < AES_256_GCM.key_len() {
                    orig_len
                } else {
                    AES_256_GCM.key_len() - s.len()
                }
            };
            s.push_str(&passphrase[0..nl]);
        }
    } else {
        s.truncate(AES_256_GCM.key_len());
    }

    s
}

fn save_encrypted<T: bincode::Encode>(
    obj: T,
    outfile: &str,
    passphrase: &str,
) -> std::io::Result<()> {
    let mut data =
        bincode::encode_to_vec(obj, bincode::config::standard()).expect("failed to encode config");

    let comp_passphrase = get_aes_256_compatible_passphrase(passphrase);

    let seq = FixedNonceSequence::new();
    let unbound_key = UnboundKey::new(&AES_256_GCM, comp_passphrase.as_bytes())
        .expect("Could not create unbound key");
    let mut sealing_key = SealingKey::new(unbound_key, seq);

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .expect("Could not encrypt config");

    File::create(outfile)?.write_all(&data)?;
    Ok(())
}

fn read_decrypted<T: bincode::Decode>(infile: &str, passphrase: &str) -> std::io::Result<T> {
    let comp_passphrase = get_aes_256_compatible_passphrase(passphrase);
    let seq = FixedNonceSequence::new();
    let unbound_key = UnboundKey::new(&AES_256_GCM, comp_passphrase.as_bytes())
        .expect("Could not create unbound key");
    let mut opening_key = OpeningKey::new(unbound_key, seq);

    let mut data: Vec<u8> = Vec::new();

    File::open(infile)?.read_to_end(&mut data)?;

    opening_key
        .open_in_place(Aad::empty(), &mut data)
        .expect("Could not decrypt data");

    Ok(
        bincode::decode_from_slice(&data, bincode::config::standard())
            .expect("could not decode decrypted data")
            .0,
    )
}

pub fn gen_config(infile: &str, outfile: &str, passphrase: &str) -> std::io::Result<()> {
    let mut fd = BufReader::new(File::open(infile)?);
    let mut config = Config::new();

    let mut line = String::new();
    let mut current_type: ActionType = ActionType::Scan;

    while fd.read_line(&mut line)? != 0 {
        if line.trim_start().starts_with("#") || line.trim().len() == 0 {
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

    save_encrypted(config, outfile, passphrase)?;

    Ok(())
}

pub fn get_config(infile: &str, passphrase: &str) -> std::io::Result<Config> {
    let config: Config = read_decrypted(infile, passphrase)?;
    Ok(config)
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

#[inline]
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

pub fn gen_db(config: &Config, outfile: &str, passphrase: &str) -> std::io::Result<()> {
    let mut db: HashMap<String, NodeType> = HashMap::new();

    for root_path in &config.scans {
        scan_path(config, root_path, &mut db)?;
    }

    save_encrypted(db, outfile, passphrase)?;

    Ok(())
}

#[inline]
fn compare_path(
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
            match db.remove(e_str) {
                Some(NodeType::F(old_hash)) => {
                    let new_hash = get_filehash(e_str)?;
                    if old_hash != new_hash {
                        println!(
                            "[{}] HASH CHANGED (old: 0x{:016x}|new: 0x{:016x})",
                            e_str, old_hash, new_hash
                        )
                    }
                }
                Some(NodeType::D) => {
                    println!("[{}] FILE WAS PREVIOUSLY A DIRECTORY", e_str);
                }
                None => println!("[{}] NEW FILE", e_str),
            }
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
            match db.remove(e_str) {
                Some(NodeType::F(_)) => println!("[{}] DIRECTORY IS NOW A FILE", e_str),
                Some(NodeType::D) => (),
                None => println!("[{}] NEW DIRECTORY", e_str),
            }
        }
    }

    Ok(())
}
pub fn compare_db(config: &Config, dbfile: &str, passphrase: &str) -> std::io::Result<()> {
    let mut db: HashMap<String, NodeType> = read_decrypted(dbfile, passphrase)?;

    for root_path in &config.scans {
        compare_path(config, root_path, &mut db)?;
    }

    for (k, v) in db.iter() {
        match v {
            NodeType::F(hash) => println!("[{k}] FILE WITH HASH 0x{hash:016x} IS REMOVED"),
            NodeType::D => println!("[{k}] DIRECTORY IS REMOED"),
        }
    }

    Ok(())
}
