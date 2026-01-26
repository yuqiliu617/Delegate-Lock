#![cfg_attr(not(any(feature = "library", test)), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(any(feature = "library", test))]
extern crate alloc;

mod error;

use alloc::{ffi::CString, vec::Vec};
use ckb_std::{
    ckb_constants::{CellField, Source},
    ckb_types::{
        bytes::Bytes,
        core::ScriptHashType,
        packed::{Script, ScriptReader},
        prelude::*,
    },
    debug,
    high_level::{exec_cell, load_cell_data},
    syscalls,
};
use core::ffi::CStr;
use error::Error;

#[cfg(not(any(feature = "library", test)))]
ckb_std::entry!(program_entry);
#[cfg(not(any(feature = "library", test)))]
ckb_std::default_alloc!(16384, 1258306, 64);

const HASH_SIZE: usize = 32;
const TYPE_ID_SCRIPT_LEN: usize = HASH_SIZE + 1 + HASH_SIZE;
const TYPE_ID_PREFIX_SIZE: usize = 20;

pub const TYPE_ID_CODE_HASH: [u8; HASH_SIZE] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 89, 80, 69, 95,
    73, 68,
];

/// Find a cell in cell_deps whose type script args starts with the given type_id prefix.
fn find_type_id_cell(type_id_prefix: &[u8]) -> Result<usize, Error> {
    let mut buf = [0u8; TYPE_ID_SCRIPT_LEN];
    for index in 0.. {
        // Try to load the type script of the cell at this index
        let result =
            syscalls::load_cell_by_field(&mut buf, 0, index, Source::CellDep, CellField::Type);
        match result {
            Ok(len) if len == TYPE_ID_SCRIPT_LEN => {
                if ScriptReader::verify(&buf, false).is_ok() {
                    let type_script = Script::new_unchecked(Bytes::copy_from_slice(&buf));
                    let code_hash: [u8; 32] = type_script.code_hash().unpack();
                    if code_hash == TYPE_ID_CODE_HASH
                        && type_script.hash_type() == ScriptHashType::Type.into()
                        && type_script.args().raw_data().starts_with(type_id_prefix)
                    {
                        return Ok(index);
                    }
                }
            }
            Err(ckb_std::error::SysError::IndexOutOfBound) => {
                break;
            }
            _ => {
                // Mismatched or other errors, continue searching
            }
        }
    }

    Err(Error::TypeIdCellNotFound)
}

const HEX_CHARS: [u8; 16] = *b"0123456789abcdef";

/// Encode bytes as hex string with null terminator for use as CStr.
fn encode_hex(data: &[u8]) -> CString {
    let mut hex = Vec::with_capacity(data.len() * 2 + 1);
    for &b in data {
        hex.push(HEX_CHARS[(b >> 4) as usize]);
        hex.push(HEX_CHARS[(b & 0xf) as usize]);
    }
    unsafe { CString::from_vec_unchecked(hex) }
}

/// Execute the actual lock script using ckb_exec.
fn exec_actual_lock_script(script: &Script) -> Result<(), Error> {
    let code_hash: [u8; 32] = script.code_hash().unpack();
    let hash_type_byte: u8 = script.hash_type().into();
    let hash_type = match hash_type_byte {
        0 => ScriptHashType::Data,
        1 => ScriptHashType::Type,
        2 => ScriptHashType::Data1,
        4 => ScriptHashType::Data2,
        _ => return Err(Error::Encoding),
    };
    let script_args: Bytes = script.args().unpack();
    let args_cstr = encode_hex(&script_args);
    let argv: [&CStr; 1] = [&args_cstr];
    exec_cell(&code_hash, hash_type, &argv)?;
    Ok(())
}

fn run() -> Result<(), Error> {
    let script = ckb_std::high_level::load_script()?;
    let args: Bytes = script.args().unpack();
    if args.len() != TYPE_ID_PREFIX_SIZE {
        return Err(Error::ArgsInvalid);
    }
    let cell_index = find_type_id_cell(&args)?;
    let cell_data = load_cell_data(cell_index, Source::CellDep)?;
    ScriptReader::verify(&cell_data, false).map_err(|_| Error::Encoding)?;
    let actual_script = Script::new_unchecked(cell_data.into());
    exec_actual_lock_script(&actual_script)
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
