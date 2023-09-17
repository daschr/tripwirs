use core::hash::Hasher;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::Xxh3;

use crate::config::*;
use crate::crypto::{read_decrypted, save_encrypted, CryptoError};

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
    L,
}

#[inline]
fn scan_path(
    config: &Config,
    root_path: &str,
    db: &mut HashMap<String, NodeType>,
) -> std::io::Result<()> {
    let mut pathstack: Vec<PathBuf> = Vec::new();
    pathstack.push(PathBuf::from(root_path));

    while let Some(e) = pathstack.pop() {
        let path: &Path = e.as_path();
        let e_str: &str = e.to_str().unwrap();

        if config.ignores.contains(e_str) {
            println!("Skipping \"{}\"", e_str);
            continue;
        }

        if path.is_symlink() {
            println!("[symlink] {}", e_str);
            db.insert(String::from(e_str), NodeType::L);
            continue;
        }

        if path.is_file() {
            println!("[file] {}", e_str);
            match get_filehash(e_str) {
                Ok(hash) => {
                    db.insert(String::from(e_str), NodeType::F(hash));
                }
                Err(error) => {
                    eprintln!("Exception on: \"{}\" [{:?}]", e_str, error);
                }
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
            db.insert(String::from(e_str), NodeType::D);
            println!("[dir] {:?}", &e);
        }
    }

    Ok(())
}

pub fn gen_db(config: &Config, outfile: &str, passphrase: &str) -> Result<(), CryptoError> {
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

    while let Some(e) = pathstack.pop() {
        let path: &Path = e.as_path();
        let e_str: &str = e.to_str().unwrap();

        if config.ignores.contains(e_str) {
            println!("Skipping \"{}\"", e_str);
            continue;
        }

        if path.is_symlink() {
            match db.remove(e_str) {
                Some(NodeType::F(hash)) => {
                    eprintln!(
                        "[{}] SYMLINK WAS PREVIOUSLY A FILE (0x{:016x})",
                        e_str, hash
                    )
                }
                Some(NodeType::D) => {
                    eprintln!("[{}] SYMLINK WAS PREVIOUSLY A DIRECTORY", e_str);
                }
                Some(NodeType::L) => (),
                None => eprintln!("[{}] NEW SYMLINK", e_str),
            }
            continue;
        }

        if path.is_file() {
            match db.remove(e_str) {
                Some(NodeType::F(old_hash)) => {
                    let new_hash = get_filehash(e_str)?;
                    if old_hash != new_hash {
                        eprintln!(
                            "[{}] HASH CHANGED (old: 0x{:016x}|new: 0x{:016x})",
                            e_str, old_hash, new_hash
                        )
                    }
                }
                Some(NodeType::D) => {
                    eprintln!("[{}] FILE WAS PREVIOUSLY A DIRECTORY", e_str);
                }
                Some(NodeType::L) => {
                    eprintln!("[{}] FILE WAS PREVIOUSLY A SYMLINK", e_str);
                }
                None => eprintln!("[{}] NEW FILE", e_str),
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
                Some(NodeType::F(_)) => eprintln!("[{}] FILE IS NOW A DIRECTORY", e_str),
                Some(NodeType::L) => eprintln!("[{}] SYMLINK IS NOW A DIRECTORY", e_str),
                Some(NodeType::D) => (),
                None => eprintln!("[{}] NEW DIRECTORY", e_str),
            }
        }
    }

    Ok(())
}

pub fn compare_db(config: &Config, dbfile: &str, passphrase: &str) -> Result<(), CryptoError> {
    let mut db: HashMap<String, NodeType> = read_decrypted(dbfile, passphrase)?;

    for root_path in &config.scans {
        compare_path(config, root_path, &mut db)?;
    }

    for (k, v) in db.iter() {
        match v {
            NodeType::F(hash) => eprintln!("[{k}] FILE WITH HASH 0x{hash:016x} IS REMOVED"),
            NodeType::D => eprintln!("[{k}] DIRECTORY IS REMOVED"),
            NodeType::L => eprintln!("[{k}] SYMLINK IS REMOVED"),
        }
    }

    Ok(())
}

pub fn print_db(dbfile: &str, passphrase: &str) -> Result<(), CryptoError> {
    let db: HashMap<String, NodeType> = read_decrypted(dbfile, passphrase)?;

    for (path, _) in db.iter() {
        println!("[{path}]");
    }
    Ok(())
}
