use core::hash::Hasher;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use xxhash_rust::xxh3::Xxh3;

use crate::config::*;
use crate::crypto::{read_decrypted, save_encrypted, CryptoError};

#[inline]
fn get_filehash(hasher: &mut Xxh3, file: &PathBuf) -> std::io::Result<u64> {
    hasher.reset();

    let mut fd = File::open(file)?;
    let mut buf = [0u8; 1024];

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
    db: &mut HashMap<PathBuf, NodeType>,
) -> std::io::Result<()> {
    let mut hasher = Xxh3::with_secret(config.secret.clone());

    let mut pathstack: Vec<PathBuf> = Vec::new();
    pathstack.push(PathBuf::from(root_path));

    while let Some(path) = pathstack.pop() {
        let pathname = path.display();
        if config.ignores.contains(path.as_path()) {
            println!("Skipping \"{}\"", pathname);
            continue;
        }

        if path.is_symlink() {
            println!("[symlink] {}", pathname);
            db.insert(path, NodeType::L);
            continue;
        }

        if path.is_file() {
            println!("[file] {}", pathname);
            match get_filehash(&mut hasher, &path) {
                Ok(hash) => {
                    db.insert(path, NodeType::F(hash));
                }
                Err(error) => {
                    eprintln!("Exception on: \"{}\" [{}]", pathname, error);
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
            println!("[dir] {}", pathname);
            db.insert(path, NodeType::D);
        }
    }

    Ok(())
}

pub fn gen_db(config: &Config, outfile: &str, passphrase: &str) -> Result<(), CryptoError> {
    let mut db: HashMap<PathBuf, NodeType> = HashMap::new();

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
    db: &mut HashMap<PathBuf, NodeType>,
) -> std::io::Result<()> {
    let mut hasher = Xxh3::with_secret(config.secret.clone());

    let mut pathstack: Vec<PathBuf> = Vec::new();
    pathstack.push(PathBuf::from(root_path));

    while let Some(path) = pathstack.pop() {
        let pathname = path.display();

        if config.ignores.contains(path.as_path()) {
            println!("Skipping \"{}\"", pathname);
            continue;
        }

        if path.is_symlink() {
            match db.remove(path.as_path()) {
                Some(NodeType::F(hash)) => {
                    eprintln!(
                        "[{}] SYMLINK WAS PREVIOUSLY A FILE (0x{:016x})",
                        pathname, hash
                    )
                }
                Some(NodeType::D) => {
                    eprintln!("[{}] SYMLINK WAS PREVIOUSLY A DIRECTORY", pathname);
                }
                Some(NodeType::L) => (),
                None => eprintln!("[{}] NEW SYMLINK", pathname),
            }
            continue;
        }

        if path.is_file() {
            match db.remove(path.as_path()) {
                Some(NodeType::F(old_hash)) => {
                    let new_hash = get_filehash(&mut hasher, &path)?;
                    if old_hash != new_hash {
                        eprintln!(
                            "[{}] HASH CHANGED (old: 0x{:016x}|new: 0x{:016x})",
                            pathname, old_hash, new_hash
                        )
                    }
                }
                Some(NodeType::D) => {
                    eprintln!("[{}] FILE WAS PREVIOUSLY A DIRECTORY", pathname);
                }
                Some(NodeType::L) => {
                    eprintln!("[{}] FILE WAS PREVIOUSLY A SYMLINK", pathname);
                }
                None => eprintln!("[{}] NEW FILE", pathname),
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
            match db.remove(path.as_path()) {
                Some(NodeType::F(_)) => eprintln!("[{}] FILE IS NOW A DIRECTORY", pathname),
                Some(NodeType::L) => eprintln!("[{}] SYMLINK IS NOW A DIRECTORY", pathname),
                Some(NodeType::D) => (),
                None => eprintln!("[{}] NEW DIRECTORY", pathname),
            }
        }
    }

    Ok(())
}

pub fn compare_db(config: &Config, dbfile: &str, passphrase: &str) -> Result<(), CryptoError> {
    let mut db: HashMap<PathBuf, NodeType> = read_decrypted(dbfile, passphrase)?;

    for root_path in &config.scans {
        compare_path(config, root_path, &mut db)?;
    }

    for (k, v) in db.iter() {
        let k = k.display();
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
