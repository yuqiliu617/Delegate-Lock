//! Tests for blake160-delegate Rust script with delegate lock integration.

use crate::{
    build_actual_lock_script_data, cell_dep, pack_capacity, sign_tx, verify_and_dump_failed_tx,
    DelegateTestBase, Signer, UncompressedKeyPair, HASH_SIZE, PUBKEY_HASH_SIZE, SIGNATURE_SIZE,
    TYPE_ID_CODE_HASH,
};
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder},
    packed::{self, *},
    prelude::*,
};

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

    fn update_owner(
        &mut self,
        old_type_id_cell: OutPoint,
        type_id: &[u8; HASH_SIZE],
        new_owner_pubkey_hash: &[u8; PUBKEY_HASH_SIZE],
    ) -> OutPoint {
        let type_script = Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.pack())
            .hash_type(Byte::new(ScriptHashType::Type as u8))
            .args(Bytes::from(type_id.to_vec()).pack())
            .build();
        let new_cell_data =
            build_actual_lock_script_data(&self.blake160_code_hash, new_owner_pubkey_hash);
        let new_lock_script = self.base.always_success_lock_script();
        let update_tx = TransactionBuilder::default()
            .input(
                CellInput::new_builder()
                    .previous_output(old_type_id_cell)
                    .build(),
            )
            .output(
                CellOutput::new_builder()
                    .capacity(pack_capacity(1000))
                    .lock(new_lock_script)
                    .type_(Some(type_script).pack())
                    .build(),
            )
            .output_data(new_cell_data.pack())
            .cell_dep(self.base.always_success_cell_dep())
            .build();
        let update_tx = update_tx
            .as_advanced_builder()
            .witness(WitnessArgs::new_builder().build().as_bytes().pack())
            .build();
        verify_and_dump_failed_tx(&self.base.context, &update_tx, 100_000_000)
            .expect("owner update should succeed");
        let new_type_id_cell_out_point = OutPoint::new_builder()
            .tx_hash(update_tx.hash())
            .index({
                let idx: packed::Uint32 = 0u32.pack();
                idx
            })
            .build();
        let new_type_id_cell = update_tx.output(0).unwrap();
        let new_cell_data = update_tx.outputs_data().get(0).unwrap();
        self.base.context.create_cell_with_out_point(
            new_type_id_cell_out_point.clone(),
            new_type_id_cell,
            new_cell_data.unpack(),
        );
        new_type_id_cell_out_point
    }
}

#[test]
fn test_delegate_lock_unlock_success() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.blake160_code_hash;
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
    println!("Delegate lock unlock success cycles: {}", cycles);
}

#[test]
fn test_delegate_lock_multiple_cells() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.blake160_code_hash;
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
    println!("Delegate lock multiple cells success cycles: {}", cycles);
}

#[test]
fn test_delegate_lock_missing_type_id_cell() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let deps = ctx.script_cell_deps();
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
fn test_delegate_lock_invalid_args_length() {
    let mut ctx = TestContext::new();
    let invalid_args = vec![0u8; 19];
    let lock_script = ctx.base.build_delegate_lock_script(&invalid_args);
    let locked_cell = ctx.base.context.create_cell(
        CellOutput::new_builder()
            .capacity(pack_capacity(1000))
            .lock(lock_script)
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(locked_cell)
        .build();
    let output = CellOutput::new_builder()
        .capacity(pack_capacity(990))
        .lock(ctx.base.build_delegate_lock_script(&[0u8; 20]))
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .cell_dep(ctx.base.delegate_lock_cell_dep())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(WitnessArgs::new_builder().build().as_bytes().pack())
        .build();
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with invalid args length");
}

#[test]
fn test_delegate_lock_wrong_type_id_prefix() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.blake160_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let mut wrong_type_id = type_id;
    wrong_type_id[0] ^= 0xFF;
    let locked_cell = ctx.base.create_delegate_locked_cell(&wrong_type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when Type ID prefix doesn't match"
    );
}

#[test]
fn test_delegate_lock_invalid_signature() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();
    let attacker = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.blake160_code_hash;
    let type_id_cell = ctx
        .base
        .create_type_id_cell(&type_id, &code_hash, owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(type_id_cell));
    let tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let tx = sign_tx(tx, &attacker).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.base.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with invalid signature");
}

#[test]
fn test_delegate_lock_corrupted_witness() {
    let mut ctx = TestContext::new();
    let owner = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.blake160_code_hash;
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

#[test]
fn test_delegate_lock_owner_update_success() {
    let mut ctx = TestContext::new();
    let old_owner = UncompressedKeyPair::new();
    let new_owner = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.blake160_code_hash;
    let old_type_id_cell =
        ctx.base
            .create_type_id_cell(&type_id, &code_hash, old_owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let new_type_id_cell = ctx.update_owner(old_type_id_cell, &type_id, new_owner.pubkey_hash());
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(new_type_id_cell));
    let unlock_tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let unlock_tx = sign_tx(unlock_tx, &new_owner).expect("sign tx");
    let cycles = verify_and_dump_failed_tx(&ctx.base.context, &unlock_tx, 100_000_000)
        .expect("new owner should unlock successfully");
    println!("New owner unlock cycles: {}", cycles);
}

#[test]
fn test_delegate_lock_old_owner_cannot_unlock_after_update() {
    let mut ctx = TestContext::new();
    let old_owner = UncompressedKeyPair::new();
    let new_owner = UncompressedKeyPair::new();
    let type_id = ctx.base.setup_type_id();
    let code_hash = ctx.blake160_code_hash;
    let old_type_id_cell =
        ctx.base
            .create_type_id_cell(&type_id, &code_hash, old_owner.pubkey_hash());
    let locked_cell = ctx.base.create_delegate_locked_cell(&type_id, 1000);
    let new_type_id_cell = ctx.update_owner(old_type_id_cell, &type_id, new_owner.pubkey_hash());
    let mut deps = ctx.script_cell_deps();
    deps.push(cell_dep(new_type_id_cell));
    let unlock_tx = ctx
        .base
        .build_unlock_tx(vec![locked_cell], 990, &type_id, deps);
    let unlock_tx = sign_tx(unlock_tx, &old_owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.base.context, &unlock_tx, 100_000_000);
    assert!(
        result.is_err(),
        "Old owner should not be able to unlock after ownership update"
    );
}
