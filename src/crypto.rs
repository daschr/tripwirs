use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;

use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
    CHACHA20_POLY1305,
};

struct FixedNonceSequence<'a> {
    counter: &'a mut u128,
}

impl<'a> FixedNonceSequence<'a> {
    fn new(counter: &'a mut u128) -> Self {
        Self { counter }
    }
}

impl<'a> NonceSequence for FixedNonceSequence<'a> {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        *self.counter += 1;

        if *self.counter > ((1u128 << 96) - 1) {
            *self.counter = 1;
        }

        let mut buf = [0u8; 12];
        for (i, x) in self.counter.to_le_bytes().into_iter().enumerate() {
            if i == 12 {
                break;
            }
            buf[i] = x;
        }

        Ok(Nonce::assume_unique_for_key(buf))
    }
}

fn get_compatible_passphrase(algo: &Algorithm, passphrase: &str) -> Vec<u8> {
    let mut s: Vec<u8> = Vec::from(passphrase.as_bytes());
    let orig_len = s.len();

    if orig_len < algo.key_len() {
        while s.len() != algo.key_len() {
            let nl = {
                if s.len() + orig_len < algo.key_len() {
                    orig_len
                } else {
                    algo.key_len() - s.len()
                }
            };

            s.extend_from_within(0..nl);
        }
    } else {
        s.truncate(algo.key_len());
    }

    s
}

#[derive(Debug)]
pub enum CryptoError {
    WrongPassphrase,
    CouldNotCreateKey,
    CouldNotEncrypt,
    EncryptedDataTooShort,
    CannotGetNonceFromExistingFile,
    EncodeError(bincode::error::EncodeError),
    DecodeError(bincode::error::DecodeError),
    IoError(std::io::Error),
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<bincode::error::EncodeError> for CryptoError {
    fn from(e: bincode::error::EncodeError) -> Self {
        Self::EncodeError(e)
    }
}

impl From<bincode::error::DecodeError> for CryptoError {
    fn from(e: bincode::error::DecodeError) -> Self {
        Self::DecodeError(e)
    }
}

fn get_next_nonce_from_file<P: Into<PathBuf>>(
    path: P,
    passphrase: &str,
) -> Result<u128, CryptoError> {
    let path: PathBuf = path.into();

    if !path.exists() {
        return Ok(0);
    }

    let mut fd = File::open(path)?;

    if fd.metadata()?.len() < 16 {
        return Err(CryptoError::CannotGetNonceFromExistingFile);
    }

    let mut data = Vec::new();
    fd.read_to_end(&mut data)?;

    let mut nonce: u128 = {
        let mut b = [0u8; 16];
        for i in (0..16).rev() {
            b[i] = data.pop().unwrap();
        }

        u128::from_be_bytes(b)
    };

    let seq = FixedNonceSequence::new(&mut nonce);

    let comp_passphrase = get_compatible_passphrase(&CHACHA20_POLY1305, passphrase);
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &comp_passphrase)
        .map_err(|_| CryptoError::CouldNotCreateKey)?;
    let mut opening_key = OpeningKey::new(unbound_key, seq);

    opening_key
        .open_in_place(Aad::empty(), &mut data)
        .map_err(|_| CryptoError::CannotGetNonceFromExistingFile)?;

    Ok(nonce + 1)
}

pub fn save_encrypted<T: bincode::Encode>(
    obj: T,
    outfile: &str,
    passphrase: &str,
) -> Result<(), CryptoError> {
    let mut data = bincode::encode_to_vec(obj, bincode::config::standard())?;

    let comp_passphrase = get_compatible_passphrase(&CHACHA20_POLY1305, passphrase);

    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &comp_passphrase)
        .map_err(|_| CryptoError::CouldNotCreateKey)?;

    let mut nonce: u128 = get_next_nonce_from_file(outfile, passphrase)?;
    let first_nonce = nonce;

    let seq = FixedNonceSequence::new(&mut nonce);

    let mut sealing_key = SealingKey::new(unbound_key, seq);

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .map_err(|_| CryptoError::CouldNotEncrypt)?;

    let mut fd = File::create(outfile)?;
    fd.write_all(&data)?;
    fd.write(&first_nonce.to_be_bytes())?;

    Ok(())
}

pub fn read_decrypted<T: bincode::Decode>(
    infile: &str,
    passphrase: &str,
) -> Result<T, CryptoError> {
    let mut data: Vec<u8> = Vec::new();

    File::open(infile)?.read_to_end(&mut data)?;

    if data.len() < 16 {
        return Err(CryptoError::EncryptedDataTooShort);
    }

    let mut nonce: u128 = {
        let mut b = [0u8; 16];
        for i in (0..16).rev() {
            b[i] = data.pop().unwrap();
        }
        u128::from_be_bytes(b)
    };
    let seq = FixedNonceSequence::new(&mut nonce);

    let comp_passphrase = get_compatible_passphrase(&CHACHA20_POLY1305, passphrase);

    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &comp_passphrase)
        .map_err(|_| CryptoError::CouldNotCreateKey)?;
    let mut opening_key = OpeningKey::new(unbound_key, seq);

    opening_key
        .open_in_place(Aad::empty(), &mut data)
        .map_err(|_| CryptoError::WrongPassphrase)?;

    Ok(bincode::decode_from_slice(&data, bincode::config::standard())?.0)
}
