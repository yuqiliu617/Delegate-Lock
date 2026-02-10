//! Tests for ccc-btc-delegate script with delegate lock integration.
//!
//! These tests verify the BTC CCC lock script works correctly when invoked
//! via delegate lock (which passes args via argc/argv).

use crate::{
    cell_dep, compute_sighash_all, verify_and_dump_failed_tx, DelegateTestBase, PUBKEY_HASH_SIZE,
    SIGNATURE_SIZE,
};
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    packed::{self, CellDep, OutPoint, WitnessArgs},
    prelude::*,
};
use k256::ecdsa::SigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

// =============================================================================
// BTC-specific crypto helpers (reproduce on-chain logic from ccc-btc/src/entry.rs)
// =============================================================================

fn sha256(msg: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(msg);
    hasher.finalize().into()
}

fn sha256_sha256(msg: &[u8]) -> [u8; 32] {
    sha256(&sha256(msg))
}

fn ripemd160_sha256(msg: &[u8]) -> [u8; 20] {
    let hash = sha256(msg);
    let mut hasher = Ripemd160::new();
    hasher.update(hash);
    hasher.finalize().into()
}

/// Reproduces the on-chain `message_hash` from ccc-btc/src/entry.rs.
fn btc_message_hash(sighash_hex: &str) -> [u8; 32] {
    assert_eq!(sighash_hex.len(), 64);
    const CKB_PREFIX: &str = "Signing a CKB transaction: 0x";
    const CKB_SUFFIX: &str = "\n\nIMPORTANT: Please verify the integrity and authenticity of connected BTC wallet before signing this message\n";
    const BTC_PREFIX: &str = "Bitcoin Signed Message:\n";
    let mut data: Vec<u8> = Vec::new();
    data.push(24);
    data.extend(BTC_PREFIX.as_bytes());
    data.push((CKB_PREFIX.len() + sighash_hex.len() + CKB_SUFFIX.len()) as u8);
    data.extend(CKB_PREFIX.as_bytes());
    data.extend(sighash_hex.as_bytes());
    data.extend(CKB_SUFFIX.as_bytes());
    sha256_sha256(&data)
}

// =============================================================================
// BTC key pair
// =============================================================================

struct BtcKeyPair {
    signing_key: SigningKey,
    pubkey_hash: [u8; PUBKEY_HASH_SIZE],
}

impl BtcKeyPair {
    fn new() -> Self {
        use k256::{elliptic_curve::rand_core::OsRng, SecretKey};
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let pubkey = signing_key.verifying_key();
        let compressed_pubkey = pubkey.to_encoded_point(true);
        let pubkey_hash = ripemd160_sha256(compressed_pubkey.as_bytes());
        Self {
            signing_key,
            pubkey_hash,
        }
    }

    fn pubkey_hash(&self) -> &[u8; PUBKEY_HASH_SIZE] {
        &self.pubkey_hash
    }
}

// =============================================================================
// BTC-specific transaction signing
// =============================================================================

fn sign_tx_btc(
    tx: ckb_testtool::ckb_types::core::TransactionView,
    key: &BtcKeyPair,
) -> ckb_testtool::ckb_types::core::TransactionView {
    let sighash = compute_sighash_all(&tx);
    let sighash_hex = hex::encode(sighash);
    let digest = btc_message_hash(&sighash_hex);

    let (signature, recovery_id) = key
        .signing_key
        .sign_prehash_recoverable(&digest)
        .expect("sign");

    // BTC format: byte[0] = rec_id + 31 (compressed), bytes[1..65] = r || s
    let mut sig_bytes = [0u8; SIGNATURE_SIZE];
    sig_bytes[0] = recovery_id.to_byte() + 31;
    sig_bytes[1..65].copy_from_slice(&signature.to_bytes());

    let lock_bytes = Bytes::from(sig_bytes.to_vec());
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

    let mut witnesses: Vec<packed::Bytes> = tx.witnesses().into_iter().collect();
    if witnesses.is_empty() {
        witnesses.push(signed_witness.as_bytes().pack());
    } else {
        witnesses[0] = signed_witness.as_bytes().pack();
    }
    tx.as_advanced_builder().set_witnesses(witnesses).build()
}

// =============================================================================
// Test context
// =============================================================================

struct TestContext {
    base: DelegateTestBase,
    ccc_btc_out_point: OutPoint,
    ccc_btc_code_hash: [u8; 32],
}

impl TestContext {
    fn new() -> Self {
        let mut base = DelegateTestBase::new();
        let (ccc_btc_out_point, ccc_btc_code_hash) = base.deploy_binary("ccc-btc-delegate");
        Self {
            base,
            ccc_btc_out_point,
            ccc_btc_code_hash,
        }
    }

    fn script_cell_deps(&self) -> Vec<CellDep> {
        vec![cell_dep(self.ccc_btc_out_point.clone())]
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_ccc_btc_unlock_success() {
    let mut ctx = TestContext::new();
    let owner = BtcKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_btc_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx_btc(tx, &owner);
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000)
        .expect("unlock should succeed");
    println!("CCC-BTC delegate lock unlock success cycles: {}", cycles);
}

#[test]
fn test_ccc_btc_multiple_cells() {
    let mut ctx = TestContext::new();
    let owner = BtcKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_btc_code_hash;
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
    let tx = sign_tx_btc(tx, &owner);
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000)
        .expect("multiple cells unlock should succeed");
    println!("CCC-BTC multiple cells success cycles: {}", cycles);
}

#[test]
fn test_ccc_btc_wrong_signature() {
    let mut ctx = TestContext::new();
    let owner = BtcKeyPair::new();
    let attacker = BtcKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_btc_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx_btc(tx, &attacker);
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with wrong signature");
}

#[test]
fn test_ccc_btc_missing_type_id_cell() {
    let mut ctx = TestContext::new();
    let owner = BtcKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let deps = ctx.script_cell_deps();
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx_btc(tx, &owner);
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when Type ID cell is not in deps"
    );
}

#[test]
fn test_ccc_btc_corrupted_witness() {
    let mut ctx = TestContext::new();
    let owner = BtcKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.ccc_btc_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let corrupted_signature = Bytes::from(vec![0u8; SIGNATURE_SIZE - 1]);
    let witness_args = WitnessArgs::new_builder()
        .lock(Some(corrupted_signature).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(witness_args.as_bytes().pack())
        .build();
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with corrupted witness");
}
