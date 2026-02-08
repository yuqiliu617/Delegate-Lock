use ckb_testtool::{
    ckb_error::Error,
    ckb_types::{
        bytes::Bytes,
        core::{Cycle, TransactionView},
    },
    context::Context,
};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(test)]
mod secp256k1_blake160_c;
#[cfg(test)]
mod secp256k1_blake160_rust;

// The exact same Loader code from capsule's template, except that
// now we use MODE as the environment variable
const TEST_ENV_VAR: &str = "MODE";

pub enum TestEnv {
    Debug,
    Release,
}

impl FromStr for TestEnv {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "debug" => Ok(TestEnv::Debug),
            "release" => Ok(TestEnv::Release),
            _ => Err("no match"),
        }
    }
}

pub struct Loader(PathBuf);

impl Default for Loader {
    fn default() -> Self {
        let test_env = match env::var(TEST_ENV_VAR) {
            Ok(val) => val.parse().expect("test env"),
            Err(_) => TestEnv::Release,
        };
        Self::with_test_env(test_env)
    }
}

impl Loader {
    fn with_test_env(env: TestEnv) -> Self {
        let load_prefix = match env {
            TestEnv::Debug => "debug",
            TestEnv::Release => "release",
        };
        let mut base_path = match env::var("TOP") {
            Ok(val) => {
                let mut base_path: PathBuf = val.into();
                base_path.push("build");
                base_path
            }
            Err(_) => {
                let mut base_path = PathBuf::new();
                // cargo may use a different cwd when running tests, for example:
                // when running debug in vscode, it will use workspace root as cwd by default,
                // when running test by `cargo test`, it will use tests directory as cwd,
                // so we need a fallback path
                base_path.push("build");
                if !base_path.exists() {
                    base_path.pop();
                    base_path.push("..");
                    base_path.push("build");
                }
                base_path
            }
        };

        base_path.push(load_prefix);
        Loader(base_path)
    }

    pub fn load_binary(&self, name: &str) -> Bytes {
        let mut path = self.0.clone();
        path.push(name);
        let result = fs::read(&path);
        if result.is_err() {
            panic!("Binary {path:?} is missing!");
        }
        result.unwrap().into()
    }
}

// This helper method runs Context::verify_tx, but in case error happens,
// it also dumps current transaction to failed_txs folder.
pub fn verify_and_dump_failed_tx(
    context: &Context,
    tx: &TransactionView,
    max_cycles: u64,
) -> Result<Cycle, Error> {
    let result = context.verify_tx(tx, max_cycles);
    if result.is_err() {
        let mut path = env::current_dir().expect("current dir");
        path.push("failed_txs");
        std::fs::create_dir_all(&path).expect("create failed_txs dir");
        let mock_tx = context.dump_tx(tx).expect("dump failed tx");
        let json = serde_json::to_string_pretty(&mock_tx).expect("json");
        path.push(format!("0x{:x}.json", tx.hash()));
        std::fs::write(path, json).expect("write");
    }
    result
}

use ckb_testtool::ckb_types::{
    core::ScriptHashType,
    packed::{self, Byte, CellInput, Script, WitnessArgs},
    prelude::*,
};
use k256::ecdsa::{signature::Error as SigError, SigningKey};

pub const PUBKEY_HASH_SIZE: usize = 20;
pub const HASH_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 65;
pub const TYPE_ID_CODE_HASH: [u8; HASH_SIZE] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 89, 80, 69, 95,
    73, 68,
];

pub fn pack_capacity(capacity: u64) -> packed::Uint64 {
    capacity.pack()
}

pub fn build_actual_lock_script_data(
    blake160_code_hash: &[u8; 32],
    pubkey_hash: &[u8; PUBKEY_HASH_SIZE],
) -> Bytes {
    Script::new_builder()
        .code_hash(blake160_code_hash.pack())
        .hash_type(Byte::new(ScriptHashType::Data2 as u8))
        .args(Bytes::from(pubkey_hash.to_vec()).pack())
        .build()
        .as_bytes()
}

pub fn generate_type_id(first_input: &CellInput, output_index: u64) -> [u8; HASH_SIZE] {
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(first_input.as_slice());
    hasher.update(&output_index.to_le_bytes());
    let mut hash = [0u8; HASH_SIZE];
    hasher.finalize(&mut hash);
    hash
}

pub fn compute_sighash_all(tx: &TransactionView) -> [u8; 32] {
    let tx_hash = tx.hash();
    let zero_lock = Bytes::from(vec![0u8; SIGNATURE_SIZE]);
    // FIXME
    let zeroed_witness = WitnessArgs::new_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let zeroed_witness_bytes = zeroed_witness.as_bytes();
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(tx_hash.as_slice());
    hasher.update(&(zeroed_witness_bytes.len() as u64).to_le_bytes());
    hasher.update(&zeroed_witness_bytes);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    hash
}

/// Trait for key pairs that can sign transactions.
pub trait Signer {
    fn pubkey_hash(&self) -> &[u8; PUBKEY_HASH_SIZE];
    fn sign(&self, prehash: &[u8; 32]) -> Result<[u8; SIGNATURE_SIZE], SigError>;
}

pub fn sign_tx<S: Signer>(tx: TransactionView, signer: &S) -> Result<TransactionView, SigError> {
    let sighash = compute_sighash_all(&tx);
    let signature = signer.sign(&sighash)?;
    let witness = Bytes::from(signature.to_vec());
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(witness).pack())
        .build();
    Ok(tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes().pack())
        .build())
}

/// Key pair using compressed public key for blake160 hash (for C scripts).
pub struct CompressedKeyPair {
    signing_key: SigningKey,
    pubkey_hash: [u8; PUBKEY_HASH_SIZE],
}

impl CompressedKeyPair {
    pub fn new() -> Self {
        use k256::{elliptic_curve::rand_core::OsRng, SecretKey};
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let pubkey = signing_key.verifying_key();
        let compressed_pubkey = pubkey.to_encoded_point(true);
        let pubkey_hash = ckb_hash::blake2b_256(compressed_pubkey.as_bytes());
        Self {
            signing_key,
            pubkey_hash: pubkey_hash[0..PUBKEY_HASH_SIZE]
                .try_into()
                .expect("hash size correct"),
        }
    }
}

impl Signer for CompressedKeyPair {
    fn pubkey_hash(&self) -> &[u8; PUBKEY_HASH_SIZE] {
        &self.pubkey_hash
    }

    fn sign(&self, prehash: &[u8; 32]) -> Result<[u8; SIGNATURE_SIZE], SigError> {
        let (signature, recovery_id) = self.signing_key.sign_prehash_recoverable(prehash)?;
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes[0..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();
        Ok(sig_bytes)
    }
}

/// Key pair using uncompressed public key (sans prefix) for blake160 hash (for Rust scripts).
pub struct UncompressedKeyPair {
    signing_key: SigningKey,
    pubkey_hash: [u8; PUBKEY_HASH_SIZE],
}

impl UncompressedKeyPair {
    pub fn new() -> Self {
        use k256::{elliptic_curve::rand_core::OsRng, SecretKey};
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let pubkey = signing_key.verifying_key();
        // Rust script uses uncompressed pubkey without prefix byte
        let pubkey_hash = ckb_hash::blake2b_256(&pubkey.to_encoded_point(false).as_bytes()[1..]);
        Self {
            signing_key,
            pubkey_hash: pubkey_hash[0..PUBKEY_HASH_SIZE]
                .try_into()
                .expect("hash size correct"),
        }
    }
}

impl Signer for UncompressedKeyPair {
    fn pubkey_hash(&self) -> &[u8; PUBKEY_HASH_SIZE] {
        &self.pubkey_hash
    }

    fn sign(&self, prehash: &[u8; 32]) -> Result<[u8; SIGNATURE_SIZE], SigError> {
        let (signature, recovery_id) = self.signing_key.sign_prehash_recoverable(prehash)?;
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes[0..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();
        Ok(sig_bytes)
    }
}
