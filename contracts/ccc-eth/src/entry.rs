use crate::error::Error;
use alloc::format;
use alloc::vec::Vec;
use ckb_lock_helper::{
    generate_sighash_all, println_hex, secp256k1_patch::recover_from_prehash, DELEGATE_LOCK_MAGIC,
};
use ckb_std::{ckb_constants::Source, high_level::load_witness_args};
use k256::ecdsa::{RecoveryId, Signature};
use sha3::Digest;

fn keccak(msg: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(msg);
    hasher.finalize().into()
}

fn keccak160(msg: &[u8]) -> [u8; 20] {
    let mut output = [0u8; 20];
    output.copy_from_slice(&keccak(msg)[12..]);
    output
}

fn message_hash(msg: &str) -> [u8; 32] {
    // Only 32-bytes hex representation of the hash is allowed.
    assert_eq!(msg.len(), 64);
    // Text used to signify that a signed message follows and to prevent inadvertently signing a transaction.
    const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected Ethereum wallet before signing this message\n";
    const ETH_PREFIX: &str = "Ethereum Signed Message:\n";
    let mut data: Vec<u8> = Vec::new();
    assert_eq!(ETH_PREFIX.len(), 25);
    data.push(25);
    data.extend(ETH_PREFIX.as_bytes());
    data.extend(
        format!(
            "{}",
            (CKB_PREFIX.len() + msg.len() + CKB_SUFFIX.len()) as u8
        )
        .as_bytes(),
    );
    data.extend(CKB_PREFIX.as_bytes());
    data.extend(msg.as_bytes());
    data.extend(CKB_SUFFIX.as_bytes());
    keccak(&data)
}

pub fn entry() -> Result<(), Error> {
    // Verify delegate lock magic and parse pubkey hash from argv[1] (hex-encoded)
    let argv = ckb_std::env::argv();
    if argv.len() != 2 || argv[0].to_bytes() != DELEGATE_LOCK_MAGIC {
        return Err(Error::ArgsInvalid);
    }
    let args_hex = argv[1].to_bytes();
    let args = ckb_lock_helper::decode_hex(args_hex)?;
    if args.len() != 20 {
        return Err(Error::WrongPubkeyHash);
    }
    let pubkey_hash_expect: [u8; 20] = args.try_into().map_err(|_| Error::WrongPubkeyHash)?;

    let sighash_all = generate_sighash_all()?;
    let sighash_all_hex = hex::encode(&sighash_all);
    let digest_hash = message_hash(&sighash_all_hex);
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let sig_raw = witness_args
        .lock()
        .to_opt()
        .ok_or(Error::WrongSignatureFormat)?
        .raw_data();
    if sig_raw.len() != 65 {
        return Err(Error::WrongSignatureFormat);
    }
    let rec_id = sig_raw[64].wrapping_sub(27);
    if rec_id >= 2 {
        return Err(Error::InvalidRecoverId);
    }
    let rec_id = RecoveryId::try_from(rec_id).map_err(|_| Error::InvalidRecoverId)?;
    let sig = Signature::from_slice(&sig_raw[..64]).map_err(|_| Error::WrongSignatureFormat)?;
    let pubkey_result = &recover_from_prehash(&digest_hash, &sig, rec_id)
        .map_err(|_| Error::CanNotRecover)?
        .to_encoded_point(false)
        .to_bytes()[1..];
    assert!(pubkey_result.len() == 64);
    let pubkey_hash_result = keccak160(&pubkey_result);
    println_hex("pubkey_hash_result", pubkey_hash_result.as_ref());
    println_hex("pubkey_hash_expect", pubkey_hash_expect.as_ref());
    if pubkey_hash_result.as_ref() != pubkey_hash_expect.as_ref() {
        return Err(Error::PubkeyHashMismatched);
    }
    Ok(())
}
