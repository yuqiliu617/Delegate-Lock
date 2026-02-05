use crate::error::Error;
use alloc::string::String;
use ckb_lock_helper::{blake2b::blake160, generate_sighash_all};
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use ed25519_dalek::{Signature, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH};

fn message_wrap(msg: &str) -> String {
    // Only 32-bytes hex representation of the hash is allowed.
    assert_eq!(msg.len(), 64);
    // Text used to signify that a signed message follows and to prevent inadvertently signing a transaction.
    const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected Solana wallet before signing this message\n";
    [CKB_PREFIX, msg, CKB_SUFFIX].join("")
}

pub fn entry() -> Result<(), Error> {
    // Parse pubkey hash from argv[0] (hex-encoded, passed by delegate lock)
    let argv = ckb_std::env::argv();
    if argv.len() != 1 {
        return Err(Error::ArgsInvalid);
    }
    let args_hex = argv[0].to_bytes();
    let args = ckb_lock_helper::decode_hex(args_hex)?;
    if args.len() != 20 {
        return Err(Error::WrongPubkey);
    }
    let pubkey_hash_expect: [u8; 20] = args.try_into().map_err(|_| Error::WrongPubkey)?;

    let sighash_all = generate_sighash_all()?;
    let sighash_all_hex = hex::encode(&sighash_all);
    let msg = message_wrap(&sighash_all_hex);
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let witness_args_lock = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::WrongSignatureFormat)?
        .raw_data();
    if witness_args_lock.len() != 96 {
        return Err(Error::WrongSignatureFormat);
    }
    let sig =
        Signature::from_slice(&witness_args_lock[..64]).map_err(|_| Error::WrongSignatureFormat)?;
    let mut pubkey = [0u8; PUBLIC_KEY_LENGTH];
    pubkey.copy_from_slice(&witness_args_lock[64..]);
    let pubkey_hash_result = blake160(&pubkey);
    if pubkey_hash_result.as_ref() != pubkey_hash_expect.as_ref() {
        return Err(Error::WrongPubkey);
    }
    let pubkey = VerifyingKey::from_bytes(&pubkey).map_err(|_| Error::WrongPubkey)?;
    pubkey
        .verify(msg.as_bytes(), &sig)
        .map_err(|_| Error::WrongSignature)?;
    Ok(())
}
