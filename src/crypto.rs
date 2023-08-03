use std::fs::File;
use std::io::{Read, Write};
use std::str::from_utf8;

use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};

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

fn get_aes_256_compatible_passphrase(passphrase: &str) -> Vec<u8> {
    let mut s: Vec<u8> = Vec::from(passphrase.as_bytes());
    let orig_len = s.len();
    if orig_len < AES_256_GCM.key_len() {
        while s.len() != AES_256_GCM.key_len() {
            let nl = {
                if s.len() + orig_len < AES_256_GCM.key_len() {
                    orig_len
                } else {
                    AES_256_GCM.key_len() - s.len()
                }
            };

            s.extend_from_within(0..nl);
        }
    } else {
        s.truncate(AES_256_GCM.key_len());
    }

    s
}

pub fn save_encrypted<T: bincode::Encode>(
    obj: T,
    outfile: &str,
    passphrase: &str,
) -> std::io::Result<()> {
    let mut data =
        bincode::encode_to_vec(obj, bincode::config::standard()).expect("failed to encode config");

    let comp_passphrase = get_aes_256_compatible_passphrase(passphrase);

    let seq = FixedNonceSequence::new();
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &comp_passphrase).expect("Could not create unbound key");
    let mut sealing_key = SealingKey::new(unbound_key, seq);

    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .expect("Could not encrypt config");

    File::create(outfile)?.write_all(&data)?;
    Ok(())
}

pub fn read_decrypted<T: bincode::Decode>(infile: &str, passphrase: &str) -> std::io::Result<T> {
    let comp_passphrase = get_aes_256_compatible_passphrase(passphrase);
    let seq = FixedNonceSequence::new();
    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &comp_passphrase).expect("Could not create key");
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
