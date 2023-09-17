use std::fs::File;
use std::io::{Read, Write};

use ring::aead::{
    Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey,
    CHACHA20_POLY1305,
};

struct FixedNonceSequence {
    counter: u128,
}

impl FixedNonceSequence {
    fn new() -> Self {
        Self { counter: 0 }
    }
}

impl NonceSequence for FixedNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.counter += 1;

        if self.counter > ((1u128 << 96) - 1) {
            self.counter = 1;
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

pub fn save_encrypted<T: bincode::Encode>(
    obj: T,
    outfile: &str,
    passphrase: &str,
) -> Result<(), CryptoError> {
    let mut data = bincode::encode_to_vec(obj, bincode::config::standard())?;

    let comp_passphrase = get_compatible_passphrase(&CHACHA20_POLY1305, passphrase);

    let seq = FixedNonceSequence::new();
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &comp_passphrase)
        .map_err(|_| CryptoError::CouldNotCreateKey)?;
    let mut sealing_key = SealingKey::new(unbound_key, seq);

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .map_err(|_| CryptoError::CouldNotEncrypt)?;

    File::create(outfile)?.write_all(&data)?;
    Ok(())
}

pub fn read_decrypted<T: bincode::Decode>(
    infile: &str,
    passphrase: &str,
) -> Result<T, CryptoError> {
    let comp_passphrase = get_compatible_passphrase(&CHACHA20_POLY1305, passphrase);
    let seq = FixedNonceSequence::new();
    let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, &comp_passphrase)
        .map_err(|_| CryptoError::CouldNotCreateKey)?;
    let mut opening_key = OpeningKey::new(unbound_key, seq);

    let mut data: Vec<u8> = Vec::new();

    File::open(infile)?.read_to_end(&mut data)?;

    opening_key
        .open_in_place(Aad::empty(), &mut data)
        .map_err(|_| CryptoError::WrongPassphrase)?;

    Ok(bincode::decode_from_slice(&data, bincode::config::standard())?.0)
}
