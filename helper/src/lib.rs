#![no_std]
#![no_main]
extern crate alloc;
pub mod blake2b;
pub mod error;
pub mod secp256k1_patch;

use crate::blake2b::new_blake2b_stat;
use crate::error::Error;
use alloc::vec;
use ckb_std::ckb_constants::{InputField, Source};
use ckb_std::ckb_types::bytes::Bytes;
use ckb_std::ckb_types::prelude::*;
use ckb_std::debug;
use ckb_std::high_level::{load_tx_hash, load_witness, load_witness_args};
use ckb_std::syscalls::{load_input_by_field, SysError};

pub fn println_hex(name: &str, data: &[u8]) {
    debug!("{}(len={}): {}", name, data.len(), hex::encode(data));
}

/// Decode a hex string into bytes.
/// This is used to parse hex-encoded arguments passed via argv from delegate lock.
pub fn decode_hex(hex: &[u8]) -> Result<alloc::vec::Vec<u8>, Error> {
    if hex.len() % 2 != 0 {
        return Err(Error::HexDecoding);
    }
    let mut bytes = alloc::vec::Vec::with_capacity(hex.len() / 2);
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
        _ => Err(Error::HexDecoding),
    }
}

pub fn generate_sighash_all() -> Result<[u8; 32], Error> {
    let mut blake2b_ctx = new_blake2b_stat();
    let tx_hash = load_tx_hash()?;
    blake2b_ctx.update(&tx_hash);

    let args = load_witness_args(0, Source::GroupInput)?;
    let lock = args.lock().to_opt().ok_or(Error::WrongWitnessArgs)?;
    let lock: Bytes = lock.unpack();
    let lock: Bytes = vec![0u8; lock.len()].into();
    let args = args.as_builder().lock(Some(lock).pack()).build();
    let first_witness = args.as_bytes();
    blake2b_ctx.update(&(first_witness.len() as u64).to_le_bytes());
    blake2b_ctx.update(&first_witness);

    let mut i = 1;
    loop {
        let ret = load_witness(i, Source::GroupInput);
        match ret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(data) => {
                i += 1;
                blake2b_ctx.update(&(data.len() as u64).to_le_bytes());
                blake2b_ctx.update(&data);
            }
        }
    }

    let mut i = calculate_inputs_len()?;

    loop {
        let ret = load_witness(i, Source::Input);
        match ret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(data) => {
                i += 1;
                blake2b_ctx.update(&(data.len() as u64).to_le_bytes());
                blake2b_ctx.update(&data);
            }
        }
    }
    let mut sighash_all = [0u8; 32];
    debug!("hashed {} bytes in sighash_all", blake2b_ctx.count());
    blake2b_ctx.finalize(&mut sighash_all);
    println_hex("sighash_all", &sighash_all);
    Ok(sighash_all)
}

fn calculate_inputs_len() -> Result<usize, Error> {
    let mut temp = [0u8; 8];
    let mut i = 0;
    loop {
        let ret = load_input_by_field(&mut temp, 0, i, Source::Input, InputField::Since);
        match ret {
            Err(SysError::IndexOutOfBound) => break,
            Err(x) => return Err(x.into()),
            Ok(_) => i += 1,
        }
    }
    Ok(i)
}
