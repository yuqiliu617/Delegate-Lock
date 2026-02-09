//! Tests for secp256k1_blake160_sighash_all C script with delegate lock integration.
//!
//! These tests verify the C implementation of secp256k1_blake160_sighash_all works correctly
//! when invoked via delegate lock (which passes args via argc/argv).

use crate::{
    cell_dep, sign_tx, verify_and_dump_failed_tx, CompressedKeyPair, DelegateTestBase, Signer,
    SIGNATURE_SIZE,
};
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    packed::{OutPoint, WitnessArgs},
    prelude::*,
};

struct TestContext {
    base: DelegateTestBase,
    sighash_all_out_point: OutPoint,
    sighash_all_code_hash: [u8; 32],
    secp256k1_data_out_point: OutPoint,
}

impl TestContext {
    fn new() -> Self {
        let mut base = DelegateTestBase::new();
        let (sighash_all_out_point, sighash_all_code_hash) =
            base.deploy_binary("secp256k1_blake160_sighash_all");
        let (secp256k1_data_out_point, _) = base.deploy_binary("secp256k1_data");
        Self {
            base,
            sighash_all_out_point,
            sighash_all_code_hash,
            secp256k1_data_out_point,
        }
    }

    fn script_cell_deps(&self) -> Vec<ckb_testtool::ckb_types::packed::CellDep> {
        vec![
            cell_dep(self.sighash_all_out_point.clone()),
            cell_dep(self.secp256k1_data_out_point.clone()),
        ]
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn test_sighash_all_delegate_unlock_success() {
    let mut ctx = TestContext::new();
    let owner = CompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.sighash_all_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000)
        .expect("unlock should succeed");
    println!(
        "secp256k1_blake160_sighash_all delegate unlock cycles: {}",
        cycles
    );
}

#[test]
fn test_sighash_all_delegate_multiple_cells() {
    let mut ctx = TestContext::new();
    let owner = CompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.sighash_all_code_hash;
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
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000)
        .expect("multiple cells unlock should succeed");
    println!(
        "secp256k1_blake160_sighash_all multiple cells cycles: {}",
        cycles
    );
}

#[test]
fn test_sighash_all_delegate_wrong_signature() {
    let mut ctx = TestContext::new();
    let owner = CompressedKeyPair::new();
    let attacker = CompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.sighash_all_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    // Sign with attacker's key instead of owner's
    let tx = sign_tx(tx, &attacker).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with wrong signature");
}

#[test]
fn test_sighash_all_delegate_missing_type_id_cell() {
    let mut ctx = TestContext::new();
    let owner = CompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    // Don't create the type_id_cell, so delegate lock can't find it
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let deps = vec![cell_dep(ctx.sighash_all_out_point.clone())];
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when Type ID cell is not in deps"
    );
}

#[test]
fn test_sighash_all_delegate_corrupted_witness() {
    let mut ctx = TestContext::new();
    let owner = CompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.sighash_all_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    // Use corrupted signature (wrong size)
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
