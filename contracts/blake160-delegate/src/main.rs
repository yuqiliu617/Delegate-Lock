#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

use alloc::vec::Vec;
use ckb_hash::blake2b_256;
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, packed::WitnessArgs, prelude::*},
    debug,
    error::SysError,
    high_level::{load_tx_hash, load_witness_args},
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

const PUBKEY_HASH_SIZE: usize = 20;
const SIGNATURE_SIZE: usize = 65;
const UNCOMPRESSED_PUBKEY_SIZE: usize = 65;

#[repr(i8)]
#[derive(Debug)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    ArgsInvalid,
    WitnessInvalid,
    SignatureInvalid,
    PubkeyHashMismatch,
    Unknown,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        match err {
            SysError::IndexOutOfBound => Self::IndexOutOfBound,
            SysError::ItemMissing => Self::ItemMissing,
            SysError::LengthNotEnough(_) => Self::LengthNotEnough,
            SysError::Encoding => Self::Encoding,
            _ => Self::Unknown,
        }
    }
}

fn decode_hex(hex: &[u8]) -> Result<Vec<u8>, Error> {
    if hex.len() % 2 != 0 {
        return Err(Error::ArgsInvalid);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks(2) {
        let high = hex_digit_to_value(chunk[0])?;
        let low = hex_digit_to_value(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_digit_to_value(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::ArgsInvalid),
    }
}

fn generate_sighash_all(first_witness: &WitnessArgs) -> Result<[u8; 32], Error> {
    let tx_hash = load_tx_hash()?;

    // Prepare the first witness
    let lock_len = first_witness.lock().to_opt().map(|l| l.len()).unwrap_or(0);
    let zero_lock = Bytes::from(alloc::vec![0u8; lock_len]);
    let zeroed_witness = first_witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let zeroed_witness_bytes = zeroed_witness.as_bytes();

    // Hash tx_hash + witness length + witness data
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(&tx_hash);
    hasher.update(&(zeroed_witness_bytes.len() as u64).to_le_bytes());
    hasher.update(&zeroed_witness_bytes);

    // Hash remaining witnesses in the same script group
    for i in 1.. {
        match ckb_std::high_level::load_witness(i, Source::GroupInput) {
            Ok(witness) => {
                hasher.update(&(witness.len() as u64).to_le_bytes());
                hasher.update(&witness);
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(e) => return Err(e.into()),
        }
    }

    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    Ok(hash)
}

fn verify_signature(
    expected_pubkey_hash: &[u8; PUBKEY_HASH_SIZE],
    signature_bytes: &[u8; SIGNATURE_SIZE],
    message_hash: &[u8; 32],
) -> Result<(), Error> {
    // Recover the public key from the signature
    let signature =
        Signature::from_slice(&signature_bytes[0..64]).map_err(|_| Error::SignatureInvalid)?;
    let recovery_id = RecoveryId::from_byte(signature_bytes[64]).ok_or(Error::SignatureInvalid)?;
    let recovered_key = VerifyingKey::recover_from_prehash(message_hash, &signature, recovery_id)
        .map_err(|_| Error::SignatureInvalid)?;

    // Compute blake160 hash of public key
    let pubkey_bytes = recovered_key.to_encoded_point(false);
    let pubkey_raw = &pubkey_bytes.as_bytes()[1..UNCOMPRESSED_PUBKEY_SIZE];
    let pubkey_hash = blake2b_256(pubkey_raw);
    let pubkey_hash_160: [u8; PUBKEY_HASH_SIZE] = pubkey_hash[0..PUBKEY_HASH_SIZE]
        .try_into()
        .map_err(|_| Error::Unknown)?;

    if pubkey_hash_160 != *expected_pubkey_hash {
        return Err(Error::PubkeyHashMismatch);
    }
    Ok(())
}

fn run() -> Result<(), Error> {
    // Parse pubkey hash from argv[0] (hex-encoded)
    let argv = ckb_std::env::argv();
    if argv.len() != 1 {
        return Err(Error::ArgsInvalid);
    }
    let args_hex = argv[0].to_bytes();
    let args = decode_hex(args_hex)?;
    if args.len() != PUBKEY_HASH_SIZE {
        return Err(Error::ArgsInvalid);
    }
    let expected_pubkey_hash: [u8; PUBKEY_HASH_SIZE] =
        args.try_into().map_err(|_| Error::ArgsInvalid)?;

    // Load the first witness
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let lock_bytes: Bytes = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::WitnessInvalid)?
        .unpack();
    if lock_bytes.len() != SIGNATURE_SIZE {
        return Err(Error::WitnessInvalid);
    }
    let signature: [u8; SIGNATURE_SIZE] = lock_bytes
        .to_vec()
        .try_into()
        .map_err(|_| Error::WitnessInvalid)?;

    // Verify signature
    let message_hash = generate_sighash_all(&witness_args)?;
    verify_signature(&expected_pubkey_hash, &signature, &message_hash)?;
    Ok(())
}

pub fn program_entry() -> i8 {
    match run() {
        Ok(_) => 0,
        Err(e) => {
            debug!("Error: {:?}", e);
            e as i8
        }
    }
}
