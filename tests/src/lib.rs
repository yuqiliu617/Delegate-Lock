use ckb_hash::blake2b_256;
use ckb_testtool::{
    ckb_chain_spec::consensus::TYPE_ID_CODE_HASH,
    ckb_error::Error,
    ckb_types::{
        bytes::Bytes,
        core::{Cycle, ScriptHashType, TransactionBuilder, TransactionView},
        packed::{self, Byte, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs},
        prelude::*,
    },
    context::Context,
};
use k256::ecdsa::{signature::Error as SigError, SigningKey};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(test)]
mod ccc_btc;
#[cfg(test)]
mod ccc_eth;
#[cfg(test)]
mod ccc_sol;
#[cfg(test)]
mod delegate_lock;
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

pub const PUBKEY_HASH_SIZE: usize = 20;
pub const HASH_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 65;
pub type Hash = [u8; HASH_SIZE];

pub fn pack_capacity(capacity: u64) -> packed::Uint64 {
    capacity.pack()
}

pub fn build_actual_lock_script_data(code_hash: &Hash, args: &[u8; PUBKEY_HASH_SIZE]) -> Bytes {
    Script::new_builder()
        .code_hash(code_hash.pack())
        .hash_type(Byte::new(ScriptHashType::Data2 as u8))
        .args(Bytes::from(args.to_vec()).pack())
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

pub fn cell_dep(out_point: OutPoint) -> CellDep {
    CellDep::new_builder().out_point(out_point).build()
}

pub fn compute_sighash_all(tx: &TransactionView) -> Hash {
    let tx_hash = tx.hash();
    let witnesses_count = tx.witnesses().len();
    let inputs_count = tx.inputs().len();

    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(tx_hash.as_slice());

    // First witness: zero the lock field, preserving input_type and output_type
    let zeroed_witness = if !tx.witnesses().is_empty() {
        let witness_data: Bytes = tx.witnesses().get(0).unwrap().unpack();
        let witness_args = WitnessArgs::new_unchecked(witness_data);
        let lock_len = witness_args
            .lock()
            .to_opt()
            .map(|l| l.raw_data().len())
            .unwrap_or(SIGNATURE_SIZE);
        let zero_lock: Bytes = vec![0u8; lock_len].into();
        witness_args
            .as_builder()
            .lock(Some(zero_lock).pack())
            .build()
            .as_bytes()
    } else {
        let zero_lock: Bytes = vec![0u8; SIGNATURE_SIZE].into();
        WitnessArgs::new_builder()
            .lock(Some(zero_lock).pack())
            .build()
            .as_bytes()
    };
    hasher.update(&(zeroed_witness.len() as u64).to_le_bytes());
    hasher.update(&zeroed_witness);

    if !tx.witnesses().is_empty() {
        // Remaining witnesses in the same script group (indices 1..inputs_count).
        // Assumes all inputs share the same lock script, which holds for our tests.
        for i in 1..inputs_count {
            if let Some(witness) = tx.witnesses().get(i) {
                let data: Bytes = witness.unpack();
                hasher.update(&(data.len() as u64).to_le_bytes());
                hasher.update(&data);
            }
        }
        // Trailing witnesses (indices >= inputs_count)
        for i in inputs_count..witnesses_count {
            let data: Bytes = tx.witnesses().get(i).unwrap().unpack();
            hasher.update(&(data.len() as u64).to_le_bytes());
            hasher.update(&data);
        }
    }

    let mut hash = [0u8; HASH_SIZE];
    hasher.finalize(&mut hash);
    hash
}

/// Trait for key pairs that can sign transactions.
pub trait Signer {
    fn pubkey_hash(&self) -> &[u8; PUBKEY_HASH_SIZE];
    fn sign(&self, prehash: &Hash) -> Result<[u8; SIGNATURE_SIZE], SigError>;
}

pub fn sign_tx<S: Signer>(tx: TransactionView, signer: &S) -> Result<TransactionView, SigError> {
    let sighash = compute_sighash_all(&tx);
    let signature = signer.sign(&sighash)?;
    let lock_bytes = Bytes::from(signature.to_vec());

    // Build the signed witness, preserving input_type/output_type if present
    let signed_witness = if !tx.witnesses().is_empty() {
        let existing: Bytes = tx.witnesses().get(0).unwrap().unpack();
        WitnessArgs::new_unchecked(existing)
            .as_builder()
            .lock(Some(lock_bytes).pack())
            .build()
    } else {
        WitnessArgs::new_builder()
            .lock(Some(lock_bytes).pack())
            .build()
    };

    // Replace witness[0] (or insert it if none exist)
    let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
    if witnesses.is_empty() {
        witnesses.push(signed_witness.as_bytes().pack());
    } else {
        witnesses[0] = signed_witness.as_bytes().pack();
    }

    Ok(tx.as_advanced_builder().set_witnesses(witnesses).build())
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

    fn sign(&self, prehash: &Hash) -> Result<[u8; SIGNATURE_SIZE], SigError> {
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

    fn sign(&self, prehash: &Hash) -> Result<[u8; SIGNATURE_SIZE], SigError> {
        let (signature, recovery_id) = self.signing_key.sign_prehash_recoverable(prehash)?;
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes[0..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();
        Ok(sig_bytes)
    }
}

/// Shared test base for delegate lock tests.
/// Deploys delegate-lock and always-success binaries, and provides common helpers.
pub struct DelegateTestBase {
    pub context: Context,
    pub delegate_lock_out_point: OutPoint,
    pub delegate_lock_code_hash: Hash,
    pub always_success_out_point: OutPoint,
}

impl DelegateTestBase {
    pub fn new() -> Self {
        let mut context = Context::default();

        let delegate_lock_bin: Bytes = Loader::default().load_binary("delegate-lock");
        let delegate_lock_out_point = context.deploy_cell(delegate_lock_bin.clone());
        let delegate_lock_code_hash: Hash = blake2b_256(&delegate_lock_bin);

        let always_success_bin: Bytes =
            Bytes::from(ckb_always_success_script::ALWAYS_SUCCESS.to_vec());
        let always_success_out_point = context.deploy_cell(always_success_bin);

        Self {
            context,
            delegate_lock_out_point,
            delegate_lock_code_hash,
            always_success_out_point,
        }
    }

    /// Deploy a binary and return its (OutPoint, code_hash).
    pub fn deploy_binary(&mut self, name: &str) -> (OutPoint, Hash) {
        let bin: Bytes = Loader::default().load_binary(name);
        let out_point = self.context.deploy_cell(bin.clone());
        let code_hash: Hash = blake2b_256(&bin);
        (out_point, code_hash)
    }

    pub fn always_success_lock_script(&mut self) -> Script {
        self.context
            .build_script(&self.always_success_out_point, Bytes::new())
            .expect("build always success script")
    }

    pub fn always_success_cell_dep(&self) -> CellDep {
        cell_dep(self.always_success_out_point.clone())
    }

    pub fn setup_type_id(&mut self) -> [u8; HASH_SIZE] {
        let seed_cell = self.context.create_cell(
            CellOutput::new_builder()
                .capacity(pack_capacity(1000))
                .build(),
            Bytes::new(),
        );
        let seed_input = CellInput::new_builder().previous_output(seed_cell).build();
        generate_type_id(&seed_input, 0)
    }

    /// Create a Type ID cell whose data is a serialized Script.
    pub fn create_type_id_cell(
        &mut self,
        type_id: &[u8; HASH_SIZE],
        code_hash: &Hash,
        args: &[u8; PUBKEY_HASH_SIZE],
    ) -> OutPoint {
        let type_script = Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.pack())
            .hash_type(Byte::new(ScriptHashType::Type as u8))
            .args(Bytes::from(type_id.to_vec()).pack())
            .build();
        let lock_script = self.always_success_lock_script();
        let cell_data = build_actual_lock_script_data(code_hash, args);
        self.context.create_cell(
            CellOutput::new_builder()
                .capacity(pack_capacity(1000))
                .lock(lock_script)
                .type_(Some(type_script).pack())
                .build(),
            cell_data,
        )
    }

    pub fn build_delegate_lock_script(&mut self, type_id_prefix: &[u8]) -> Script {
        self.context
            .build_script(
                &self.delegate_lock_out_point,
                Bytes::from(type_id_prefix.to_vec()),
            )
            .expect("build delegate lock script")
    }

    pub fn create_delegate_locked_cell(
        &mut self,
        type_id: &[u8; HASH_SIZE],
        capacity: u64,
    ) -> OutPoint {
        let type_id_prefix = &type_id[0..PUBKEY_HASH_SIZE];
        let lock_script = self.build_delegate_lock_script(type_id_prefix);
        self.context.create_cell(
            CellOutput::new_builder()
                .capacity(pack_capacity(capacity))
                .lock(lock_script)
                .build(),
            Bytes::new(),
        )
    }

    pub fn delegate_lock_cell_dep(&self) -> CellDep {
        cell_dep(self.delegate_lock_out_point.clone())
    }

    /// Build an unlock transaction. Always includes delegate_lock as a cell_dep.
    pub fn build_unlock_tx(
        &mut self,
        inputs: Vec<OutPoint>,
        output_capacity: u64,
        type_id: &[u8; HASH_SIZE],
        extra_cell_deps: Vec<CellDep>,
    ) -> TransactionView {
        let mut tx_builder = TransactionBuilder::default();
        for input_out_point in inputs {
            tx_builder = tx_builder.input(
                CellInput::new_builder()
                    .previous_output(input_out_point)
                    .build(),
            );
        }
        let output = CellOutput::new_builder()
            .capacity(pack_capacity(output_capacity))
            .lock(self.build_delegate_lock_script(&type_id[0..PUBKEY_HASH_SIZE]))
            .build();
        tx_builder = tx_builder
            .output(output)
            .output_data(Bytes::new().pack())
            .cell_dep(self.delegate_lock_cell_dep());
        for dep in extra_cell_deps {
            tx_builder = tx_builder.cell_dep(dep);
        }
        tx_builder.build()
    }
}
