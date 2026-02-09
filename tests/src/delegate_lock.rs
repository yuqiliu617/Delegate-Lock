//! Tests for delegate lock self-delegation (chained delegation).
//!
//! These tests verify that delegate-lock can itself be delegated:
//! outer delegate-lock → inner delegate-lock (same binary, via argv) → actual lock script.

use crate::{
    cell_dep, sign_tx, verify_and_dump_failed_tx, DelegateTestBase, Signer, UncompressedKeyPair,
    PUBKEY_HASH_SIZE,
};
use ckb_testtool::ckb_types::packed::{CellDep, OutPoint};

struct TestContext {
    base: DelegateTestBase,
    blake160_out_point: OutPoint,
    blake160_code_hash: [u8; 32],
}

impl TestContext {
    fn new() -> Self {
        let mut base = DelegateTestBase::new();
        let (blake160_out_point, blake160_code_hash) =
            base.deploy_binary("secp256k1-blake160-delegate");
        Self {
            base,
            blake160_out_point,
            blake160_code_hash,
        }
    }

    fn script_cell_deps(&self) -> Vec<CellDep> {
        vec![cell_dep(self.blake160_out_point.clone())]
    }
}

#[test]
fn test_chained_delegate_unlock_success() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();

    // Inner type ID cell: points to the actual lock script (secp256k1-blake160)
    let inner_type_id = ctx.base.setup_type_id();
    let blake160_code_hash = ctx.blake160_code_hash;
    let inner_type_id_cell =
        ctx.base
            .create_type_id_cell(&inner_type_id, &blake160_code_hash, owner.pubkey_hash());

    // Outer type ID cell: points to delegate-lock with inner_type_id_prefix as args
    let outer_type_id = ctx.base.setup_type_id();
    let inner_type_id_prefix: [u8; PUBKEY_HASH_SIZE] =
        inner_type_id[0..PUBKEY_HASH_SIZE].try_into().unwrap();
    let delegate_lock_code_hash = ctx.base.delegate_lock_code_hash;
    let outer_type_id_cell = ctx.base.create_type_id_cell(
        &outer_type_id,
        &delegate_lock_code_hash,
        &inner_type_id_prefix,
    );

    // Cell locked with outer delegate-lock (script args = outer_type_id_prefix)
    let locked_cell = ctx.base.create_delegate_locked_cell(&outer_type_id, 1000);

    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(outer_type_id_cell));
    deps.push(cell_dep(inner_type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &outer_type_id, deps);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000)
        .expect("chained delegate unlock should succeed");
    println!("Chained delegate lock unlock cycles: {}", cycles);
}

#[test]
fn test_chained_delegate_wrong_signature() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();
    let attacker = UncompressedKeyPair::new();

    let inner_type_id = ctx.base.setup_type_id();
    let blake160_code_hash = ctx.blake160_code_hash;
    let inner_type_id_cell =
        ctx.base
            .create_type_id_cell(&inner_type_id, &blake160_code_hash, owner.pubkey_hash());

    let outer_type_id = ctx.base.setup_type_id();
    let inner_type_id_prefix: [u8; PUBKEY_HASH_SIZE] =
        inner_type_id[0..PUBKEY_HASH_SIZE].try_into().unwrap();
    let delegate_lock_code_hash = ctx.base.delegate_lock_code_hash;
    let outer_type_id_cell = ctx.base.create_type_id_cell(
        &outer_type_id,
        &delegate_lock_code_hash,
        &inner_type_id_prefix,
    );

    let locked_cell = ctx.base.create_delegate_locked_cell(&outer_type_id, 1000);

    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(outer_type_id_cell));
    deps.push(cell_dep(inner_type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &outer_type_id, deps);
    let tx = sign_tx(tx, &attacker).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail with wrong signature in chained delegation"
    );
}

#[test]
fn test_chained_delegate_missing_inner_type_id_cell() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();

    let inner_type_id = ctx.base.setup_type_id();
    // Don't create inner type ID cell — inner delegate-lock won't find it

    let outer_type_id = ctx.base.setup_type_id();
    let inner_type_id_prefix: [u8; PUBKEY_HASH_SIZE] =
        inner_type_id[0..PUBKEY_HASH_SIZE].try_into().unwrap();
    let delegate_lock_code_hash = ctx.base.delegate_lock_code_hash;
    let outer_type_id_cell = ctx.base.create_type_id_cell(
        &outer_type_id,
        &delegate_lock_code_hash,
        &inner_type_id_prefix,
    );

    let locked_cell = ctx.base.create_delegate_locked_cell(&outer_type_id, 1000);

    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(outer_type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &outer_type_id, deps);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when inner Type ID cell is missing"
    );
}
