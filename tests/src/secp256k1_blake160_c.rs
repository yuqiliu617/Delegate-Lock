//! Tests for secp256k1_blake160_sighash_all C script with delegate lock integration.
//!
//! These tests verify the C implementation of secp256k1_blake160_sighash_all works correctly
//! when invoked via delegate lock (which passes args via argc/argv).

use crate::{verify_and_dump_failed_tx, Loader};
use ckb_hash::blake2b_256;
use ckb_testtool::{
    ckb_types::{
        bytes::Bytes,
        core::{ScriptHashType, TransactionBuilder, TransactionView},
        packed::{self, *},
        prelude::*,
    },
    context::Context,
};
use k256::{
    ecdsa::{signature::Error as SigError, SigningKey},
    elliptic_curve::rand_core::OsRng,
    SecretKey,
};

const PUBKEY_HASH_SIZE: usize = 20;
const HASH_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 65;
const TYPE_ID_CODE_HASH: [u8; HASH_SIZE] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 84, 89, 80, 69, 95,
    73, 68,
];

/// Key pair for testing, using secp256k1 with compressed public key blake160 hash.
struct Secp256k1KeyPair {
    signing_key: SigningKey,
    /// blake160 of compressed public key (matches C script's behavior)
    pubkey_hash: [u8; PUBKEY_HASH_SIZE],
}

impl Secp256k1KeyPair {
    fn new() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let pubkey = signing_key.verifying_key();
        // C script uses compressed pubkey for blake160 hash
        let compressed_pubkey = pubkey.to_encoded_point(true);
        let pubkey_hash = blake2b_256(compressed_pubkey.as_bytes());
        Self {
            signing_key,
            pubkey_hash: pubkey_hash[0..PUBKEY_HASH_SIZE]
                .try_into()
                .expect("hash size correct"),
        }
    }

    fn sign(&self, prehash: &[u8; 32]) -> Result<[u8; SIGNATURE_SIZE], SigError> {
        let (signature, recovery_id) = self.signing_key.sign_prehash_recoverable(prehash)?;
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes[0..64].copy_from_slice(&signature.to_bytes());
        sig_bytes[64] = recovery_id.to_byte();
        Ok(sig_bytes)
    }
}

fn pack_capacity(capacity: u64) -> packed::Uint64 {
    capacity.pack()
}

fn build_actual_lock_script_data(
    blake160_code_hash: &[u8; 32],
    pubkey_hash: &[u8; PUBKEY_HASH_SIZE],
) -> Bytes {
    Script::new_builder()
        .code_hash(blake160_code_hash.pack())
        .hash_type(Byte::new(ScriptHashType::Data1 as u8))
        .args(Bytes::from(pubkey_hash.to_vec()).pack())
        .build()
        .as_bytes()
}

fn generate_type_id(first_input: &CellInput, output_index: u64) -> [u8; HASH_SIZE] {
    let mut hasher = ckb_hash::new_blake2b();
    hasher.update(first_input.as_slice());
    hasher.update(&output_index.to_le_bytes());
    let mut hash = [0u8; HASH_SIZE];
    hasher.finalize(&mut hash);
    hash
}

fn compute_sighash_all(tx: &TransactionView) -> [u8; 32] {
    let tx_hash = tx.hash();
    let zero_lock = Bytes::from(vec![0u8; SIGNATURE_SIZE]);
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

fn sign_tx(tx: TransactionView, signer: &Secp256k1KeyPair) -> Result<TransactionView, SigError> {
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

/// Test context for secp256k1_blake160_sighash_all with delegate lock.
struct Secp256k1DelegateTestContext {
    context: Context,
    delegate_lock_out_point: OutPoint,
    sighash_all_out_point: OutPoint,
    sighash_all_code_hash: [u8; 32],
    secp256k1_data_out_point: OutPoint,
    always_success_out_point: OutPoint,
}

impl Secp256k1DelegateTestContext {
    fn new() -> Self {
        let mut context = Context::default();

        // Load delegate-lock binary
        let delegate_lock_bin: Bytes = Loader::default().load_binary("delegate-lock");
        let delegate_lock_out_point = context.deploy_cell(delegate_lock_bin);

        // Load C secp256k1_blake160_sighash_all binary
        let sighash_all_bin: Bytes =
            Loader::default().load_binary("secp256k1_blake160_sighash_all");
        let sighash_all_out_point = context.deploy_cell(sighash_all_bin.clone());
        let sighash_all_code_hash: [u8; 32] = blake2b_256(&sighash_all_bin)[0..32]
            .try_into()
            .expect("hash size");

        // Load secp256k1_data (required by C secp256k1 script for signature verification)
        let secp256k1_data_bin: Bytes = Loader::default().load_binary("secp256k1_data");
        let secp256k1_data_out_point = context.deploy_cell(secp256k1_data_bin);

        // Load always-success for Type ID cell lock
        let always_success_bin: Bytes =
            Bytes::from(ckb_always_success_script::ALWAYS_SUCCESS.to_vec());
        let always_success_out_point = context.deploy_cell(always_success_bin);

        Self {
            context,
            delegate_lock_out_point,
            sighash_all_out_point,
            sighash_all_code_hash,
            secp256k1_data_out_point,
            always_success_out_point,
        }
    }

    fn always_success_lock_script(&mut self) -> Script {
        self.context
            .build_script(&self.always_success_out_point, Bytes::new())
            .expect("build always success script")
    }

    /// Create a Type ID cell containing the actual lock script (secp256k1_blake160_sighash_all).
    fn create_type_id_cell(
        &mut self,
        type_id: &[u8; HASH_SIZE],
        pubkey_hash: &[u8; PUBKEY_HASH_SIZE],
    ) -> OutPoint {
        let type_script = Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.pack())
            .hash_type(Byte::new(ScriptHashType::Type as u8))
            .args(Bytes::from(type_id.to_vec()).pack())
            .build();
        let lock_script = self.always_success_lock_script();
        let cell_data = build_actual_lock_script_data(&self.sighash_all_code_hash, pubkey_hash);
        self.context.create_cell(
            CellOutput::new_builder()
                .capacity(pack_capacity(1000))
                .lock(lock_script)
                .type_(Some(type_script).pack())
                .build(),
            cell_data,
        )
    }

    fn build_delegate_lock_script(&mut self, type_id_prefix: &[u8]) -> Script {
        self.context
            .build_script(
                &self.delegate_lock_out_point,
                Bytes::from(type_id_prefix.to_vec()),
            )
            .expect("build delegate lock script")
    }

    fn create_delegate_locked_cell(
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

    fn delegate_lock_cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.delegate_lock_out_point.clone())
            .build()
    }

    fn sighash_all_cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.sighash_all_out_point.clone())
            .build()
    }

    fn secp256k1_data_cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.secp256k1_data_out_point.clone())
            .build()
    }

    fn type_id_cell_dep(&self, out_point: OutPoint) -> CellDep {
        CellDep::new_builder().out_point(out_point).build()
    }

    fn setup_type_id(&mut self) -> [u8; HASH_SIZE] {
        let seed_cell = self.context.create_cell(
            CellOutput::new_builder()
                .capacity(pack_capacity(1000))
                .build(),
            Bytes::new(),
        );
        let seed_input = CellInput::new_builder().previous_output(seed_cell).build();
        generate_type_id(&seed_input, 0)
    }

    fn build_unlock_tx(
        &mut self,
        inputs: Vec<OutPoint>,
        output_capacity: u64,
        type_id: &[u8; HASH_SIZE],
        type_id_cell: OutPoint,
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
            .lock(self.build_delegate_lock_script(&type_id[0..20]))
            .build();
        tx_builder
            .output(output)
            .output_data(Bytes::new().pack())
            .cell_dep(self.delegate_lock_cell_dep())
            .cell_dep(self.sighash_all_cell_dep())
            .cell_dep(self.secp256k1_data_cell_dep())
            .cell_dep(self.type_id_cell_dep(type_id_cell))
            .build()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_sighash_all_delegate_unlock_success() {
    let mut ctx = Secp256k1DelegateTestContext::new();
    let owner = Secp256k1KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, type_id_cell);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let cycles =
        verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000).expect("unlock should succeed");
    println!(
        "secp256k1_blake160_sighash_all delegate unlock cycles: {}",
        cycles
    );
}

#[test]
fn test_sighash_all_delegate_multiple_cells() {
    let mut ctx = Secp256k1DelegateTestContext::new();
    let owner = Secp256k1KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let locked_cell_1 = ctx.create_delegate_locked_cell(&type_id, 1000);
    let locked_cell_2 = ctx.create_delegate_locked_cell(&type_id, 2000);
    let tx = ctx.build_unlock_tx(
        vec![locked_cell_1, locked_cell_2],
        2900,
        &type_id,
        type_id_cell,
    );
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let cycles = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000)
        .expect("multiple cells unlock should succeed");
    println!(
        "secp256k1_blake160_sighash_all multiple cells cycles: {}",
        cycles
    );
}

#[test]
fn test_sighash_all_delegate_wrong_signature() {
    let mut ctx = Secp256k1DelegateTestContext::new();
    let owner = Secp256k1KeyPair::new();
    let attacker = Secp256k1KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, type_id_cell);
    // Sign with attacker's key instead of owner's
    let tx = sign_tx(tx, &attacker).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with wrong signature");
}

#[test]
fn test_sighash_all_delegate_missing_type_id_cell() {
    let mut ctx = Secp256k1DelegateTestContext::new();
    let owner = Secp256k1KeyPair::new();
    let type_id = ctx.setup_type_id();
    // Don't create the type_id_cell, so delegate lock can't find it
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let input = CellInput::new_builder()
        .previous_output(locked_cell)
        .build();
    let output = CellOutput::new_builder()
        .capacity(pack_capacity(990))
        .lock(ctx.build_delegate_lock_script(&type_id[0..20]))
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .cell_dep(ctx.delegate_lock_cell_dep())
        .cell_dep(ctx.sighash_all_cell_dep())
        // Missing: type_id_cell_dep
        .build();
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when Type ID cell is not in deps"
    );
}

#[test]
fn test_sighash_all_delegate_corrupted_witness() {
    let mut ctx = Secp256k1DelegateTestContext::new();
    let owner = Secp256k1KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, type_id_cell);
    // Use corrupted signature (wrong size)
    let corrupted_signature = Bytes::from(vec![0u8; 64]); // Wrong size, should be 65
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(corrupted_signature).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes().pack())
        .build();
    let result = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with corrupted witness");
}
