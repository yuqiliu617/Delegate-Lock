//! Tests for ccc-sol-delegate script with delegate lock integration.
//!
//! These tests verify the SOL CCC lock script works correctly when invoked
//! via delegate lock (which passes args via argc/argv).
//!
//! SOL uses Ed25519 instead of ECDSA, and the witness lock is 96 bytes
//! (64-byte signature + 32-byte pubkey) instead of the standard 65 bytes.

use crate::{
    cell_dep, compute_sighash_all, verify_and_dump_failed_tx, DelegateTestBase, PUBKEY_HASH_SIZE,
};
use ckb_hash::blake2b_256;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::TransactionView,
    packed::{self, CellDep, OutPoint, WitnessArgs},
    prelude::*,
};
use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};

const SOL_WITNESS_LOCK_SIZE: usize = 96;

// =============================================================================
// SOL-specific helpers (reproduce on-chain logic from ccc-sol/src/entry.rs)
// =============================================================================

/// Reproduces the on-chain `message_wrap` from ccc-sol/src/entry.rs.
fn sol_message_wrap(sighash_hex: &str) -> String {
    assert_eq!(sighash_hex.len(), 64);
    const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected Solana wallet before signing this message\n";
    [CKB_PREFIX, sighash_hex, CKB_SUFFIX].join("")
}

// =============================================================================
// SOL key pair
// =============================================================================

struct SolKeyPair {
    signing_key: Ed25519SigningKey,
    pubkey_hash: [u8; PUBKEY_HASH_SIZE],
    pubkey_bytes: [u8; 32],
}

impl SolKeyPair {
    fn new() -> Self {
        use rand::rngs::OsRng;
        let signing_key = Ed25519SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let pubkey_bytes: [u8; 32] = verifying_key.to_bytes();
        let full_hash = blake2b_256(&pubkey_bytes);
        let pubkey_hash: [u8; PUBKEY_HASH_SIZE] =
            full_hash[..PUBKEY_HASH_SIZE].try_into().expect("hash size");
        Self {
            signing_key,
            pubkey_hash,
            pubkey_bytes,
        }
    }

    fn pubkey_hash(&self) -> &[u8; PUBKEY_HASH_SIZE] {
        &self.pubkey_hash
    }
}

// =============================================================================
// SOL-specific transaction signing
// =============================================================================

/// Signs a transaction for SOL verification.
///
/// Must pre-populate witness[0] with a 96-byte placeholder lock before computing
/// sighash_all, because `compute_sighash_all` defaults to 65 bytes when no
/// witness exists. The on-chain code uses 96-byte lock, so the sighash must match.
fn sign_tx_sol(tx: TransactionView, key: &SolKeyPair) -> TransactionView {
    // Insert placeholder witness with 96-byte zeroed lock for correct sighash computation
    let placeholder_lock = Bytes::from(vec![0u8; SOL_WITNESS_LOCK_SIZE]);
    let placeholder_witness = WitnessArgs::new_builder()
        .lock(Some(placeholder_lock).pack())
        .build();
    let tx = {
        let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
        if witnesses.is_empty() {
            witnesses.push(placeholder_witness.as_bytes().pack());
        } else {
            witnesses[0] = placeholder_witness.as_bytes().pack();
        }
        tx.as_advanced_builder().set_witnesses(witnesses).build()
    };

    let sighash = compute_sighash_all(&tx);
    let sighash_hex = hex::encode(sighash);
    let message = sol_message_wrap(&sighash_hex);

    let signature = key.signing_key.sign(message.as_bytes());

    // SOL witness: 64-byte ed25519 signature + 32-byte ed25519 pubkey
    let mut witness_lock = [0u8; SOL_WITNESS_LOCK_SIZE];
    witness_lock[..64].copy_from_slice(&signature.to_bytes());
    witness_lock[64..].copy_from_slice(&key.pubkey_bytes);

    let lock_bytes = Bytes::from(witness_lock.to_vec());
    let signed_witness = WitnessArgs::new_builder()
        .lock(Some(lock_bytes).pack())
        .build();

    let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
    witnesses[0] = signed_witness.as_bytes().pack();
    tx.as_advanced_builder().set_witnesses(witnesses).build()
}

// =============================================================================
// Test context
// =============================================================================

struct TestContext {
    base: DelegateTestBase,
    ccc_sol_out_point: OutPoint,
    ccc_sol_code_hash: [u8; 32],
}

impl TestContext {
    fn new() -> Self {
        let mut base = DelegateTestBase::new();
        let (ccc_sol_out_point, ccc_sol_code_hash) = base.deploy_binary("ccc-sol-delegate");
        Self {
            base,
            ccc_sol_out_point,
            ccc_sol_code_hash,
        }
    }

    fn script_cell_deps(&self) -> Vec<CellDep> {
        vec![cell_dep(self.ccc_sol_out_point.clone())]
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_ccc_sol_unlock_success() {
    let mut ctx = TestContext::new();
    let owner = SolKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_sol_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx_sol(tx, &owner);
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000)
        .expect("unlock should succeed");
    println!("CCC-SOL delegate lock unlock success cycles: {}", cycles);
}

#[test]
fn test_ccc_sol_multiple_cells() {
    let mut ctx = TestContext::new();
    let owner = SolKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_sol_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell_1 = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let locked_cell_2 = ctx.base.create_delegate_locked_cell(&type_id, 2000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell_1, locked_cell_2], 2900, &type_id, deps);
    let tx = sign_tx_sol(tx, &owner);
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000)
        .expect("multiple cells unlock should succeed");
    println!("CCC-SOL multiple cells success cycles: {}", cycles);
}

#[test]
fn test_ccc_sol_wrong_key() {
    let mut ctx = TestContext::new();
    let owner = SolKeyPair::new();
    let attacker = SolKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_sol_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    // Sign with attacker's key — pubkey hash won't match
    let tx = sign_tx_sol(tx, &attacker);
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with wrong pubkey");
}

#[test]
fn test_ccc_sol_wrong_signature() {
    let mut ctx = TestContext::new();
    let owner = SolKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_sol_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    // Build witness with correct pubkey but garbage signature
    let mut bad_witness_lock = [0u8; SOL_WITNESS_LOCK_SIZE];
    bad_witness_lock[64..].copy_from_slice(&owner.pubkey_bytes);
    // bytes[0..64] are zeroed — invalid Ed25519 signature
    let lock_bytes = Bytes::from(bad_witness_lock.to_vec());
    let witness = WitnessArgs::new_builder()
        .lock(Some(lock_bytes).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(witness.as_bytes().pack())
        .build();
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with wrong signature");
}

#[test]
fn test_ccc_sol_missing_type_id_cell() {
    let mut ctx = TestContext::new();
    let owner = SolKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let deps = ctx.script_cell_deps();
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx_sol(tx, &owner);
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when Type ID cell is not in deps"
    );
}

#[test]
fn test_ccc_sol_corrupted_witness() {
    let mut ctx = TestContext::new();
    let owner = SolKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_sol_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    // Use 95-byte lock (one short of the expected 96)
    let corrupted_lock = Bytes::from(vec![0u8; SOL_WITNESS_LOCK_SIZE - 1]);
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(corrupted_lock).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes().pack())
        .build();
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with corrupted witness");
}
