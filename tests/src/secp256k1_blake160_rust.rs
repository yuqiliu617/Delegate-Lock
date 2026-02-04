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

struct KeyPair {
    signing_key: SigningKey,
    pubkey_hash: [u8; PUBKEY_HASH_SIZE],
}

impl KeyPair {
    fn new() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        let signing_key = SigningKey::from(&secret_key);
        let pubkey = signing_key.verifying_key();
        let pubkey_hash = blake2b_256(&pubkey.to_encoded_point(false).as_bytes()[1..]);
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

fn sign_tx(tx: TransactionView, signer: &KeyPair) -> Result<TransactionView, SigError> {
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

struct DelegateLockTestContext {
    context: Context,
    delegate_lock_out_point: OutPoint,
    blake160_delegate_out_point: OutPoint,
    blake160_code_hash: [u8; 32],
    always_success_out_point: OutPoint,
}

impl DelegateLockTestContext {
    fn new() -> Self {
        let mut context = Context::default();
        let delegate_lock_bin: Bytes = Loader::default().load_binary("delegate-lock");
        let delegate_lock_out_point = context.deploy_cell(delegate_lock_bin);
        let blake160_bin: Bytes = Loader::default().load_binary("secp256k1-blake160-delegate");
        let blake160_delegate_out_point = context.deploy_cell(blake160_bin.clone());
        let blake160_code_hash: [u8; 32] = blake2b_256(&blake160_bin)[0..32]
            .try_into()
            .expect("hash size");
        let always_success_bin: Bytes =
            Bytes::from(ckb_always_success_script::ALWAYS_SUCCESS.to_vec());
        let always_success_out_point = context.deploy_cell(always_success_bin);
        Self {
            context,
            delegate_lock_out_point,
            blake160_delegate_out_point,
            blake160_code_hash,
            always_success_out_point,
        }
    }
    fn always_success_lock_script(&mut self) -> Script {
        self.context
            .build_script(&self.always_success_out_point, Bytes::new())
            .expect("build always success script")
    }
    fn always_success_cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.always_success_out_point.clone())
            .build()
    }
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
        let cell_data = build_actual_lock_script_data(&self.blake160_code_hash, pubkey_hash);
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
    fn blake160_delegate_cell_dep(&self) -> CellDep {
        CellDep::new_builder()
            .out_point(self.blake160_delegate_out_point.clone())
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
            .cell_dep(self.blake160_delegate_cell_dep())
            .cell_dep(self.type_id_cell_dep(type_id_cell))
            .build()
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
        let new_lock_script = self.always_success_lock_script();
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
            .cell_dep(self.always_success_cell_dep())
            .build();
        let update_tx = update_tx
            .as_advanced_builder()
            .witness(WitnessArgs::new_builder().build().as_bytes().pack())
            .build();
        verify_and_dump_failed_tx(&self.context, &update_tx, 100_000_000)
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
        self.context.create_cell_with_out_point(
            new_type_id_cell_out_point.clone(),
            new_type_id_cell,
            new_cell_data.unpack(),
        );
        new_type_id_cell_out_point
    }
}

#[test]
fn test_delegate_lock_unlock_success() {
    let mut ctx = DelegateLockTestContext::new();
    let owner = KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, type_id_cell);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let cycles =
        verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000).expect("unlock should succeed");
    println!("Delegate lock unlock success cycles: {}", cycles);
}

#[test]
fn test_delegate_lock_multiple_cells() {
    let mut ctx = DelegateLockTestContext::new();
    let owner = KeyPair::new();
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
    println!("Delegate lock multiple cells success cycles: {}", cycles);
}

#[test]
fn test_delegate_lock_missing_type_id_cell() {
    let mut ctx = DelegateLockTestContext::new();
    let owner = KeyPair::new();
    let type_id = ctx.setup_type_id();
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
        .cell_dep(ctx.blake160_delegate_cell_dep())
        .build();
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when Type ID cell is not in deps"
    );
}

#[test]
fn test_delegate_lock_invalid_args_length() {
    let mut ctx = DelegateLockTestContext::new();
    let invalid_args = vec![0u8; 19];
    let lock_script = ctx.build_delegate_lock_script(&invalid_args);
    let locked_cell = ctx.context.create_cell(
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
        .lock(ctx.build_delegate_lock_script(&[0u8; 20]))
        .build();
    let tx = TransactionBuilder::default()
        .input(input)
        .output(output)
        .output_data(Bytes::new().pack())
        .cell_dep(ctx.delegate_lock_cell_dep())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(WitnessArgs::new_builder().build().as_bytes().pack())
        .build();
    let result = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with invalid args length");
}

#[test]
fn test_delegate_lock_wrong_type_id_prefix() {
    let mut ctx = DelegateLockTestContext::new();
    let owner = KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let mut wrong_type_id = type_id;
    wrong_type_id[0] ^= 0xFF;
    let locked_cell = ctx.create_delegate_locked_cell(&wrong_type_id, 1000);
    let tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, type_id_cell);
    let tx = sign_tx(tx, &owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000);
    assert!(
        result.is_err(),
        "Should fail when Type ID prefix doesn't match"
    );
}

#[test]
fn test_delegate_lock_invalid_signature() {
    let mut ctx = DelegateLockTestContext::new();
    let owner = KeyPair::new();
    let attacker = KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, type_id_cell);
    let tx = sign_tx(tx, &attacker).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.context, &tx, 100_000_000);
    assert!(result.is_err(), "Should fail with invalid signature");
}

#[test]
fn test_delegate_lock_corrupted_witness() {
    let mut ctx = DelegateLockTestContext::new();
    let owner = KeyPair::new();
    let type_id = ctx.setup_type_id();
    let type_id_cell = ctx.create_type_id_cell(&type_id, &owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, type_id_cell);
    let corrupted_signature = Bytes::from(vec![0u8; 64]);
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

#[test]
fn test_delegate_lock_owner_update_success() {
    let mut ctx = DelegateLockTestContext::new();
    let old_owner = KeyPair::new();
    let new_owner = KeyPair::new();
    let type_id = ctx.setup_type_id();
    let old_type_id_cell = ctx.create_type_id_cell(&type_id, &old_owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let new_type_id_cell = ctx.update_owner(old_type_id_cell, &type_id, &new_owner.pubkey_hash);
    let unlock_tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, new_type_id_cell);
    let unlock_tx = sign_tx(unlock_tx, &new_owner).expect("sign tx");
    let cycles = verify_and_dump_failed_tx(&ctx.context, &unlock_tx, 100_000_000)
        .expect("new owner should unlock successfully");
    println!("New owner unlock cycles: {}", cycles);
}

#[test]
fn test_delegate_lock_old_owner_cannot_unlock_after_update() {
    let mut ctx = DelegateLockTestContext::new();
    let old_owner = KeyPair::new();
    let new_owner = KeyPair::new();
    let type_id = ctx.setup_type_id();
    let old_type_id_cell = ctx.create_type_id_cell(&type_id, &old_owner.pubkey_hash);
    let locked_cell = ctx.create_delegate_locked_cell(&type_id, 1000);
    let new_type_id_cell = ctx.update_owner(old_type_id_cell, &type_id, &new_owner.pubkey_hash);
    let unlock_tx = ctx.build_unlock_tx(vec![locked_cell], 990, &type_id, new_type_id_cell);
    let unlock_tx = sign_tx(unlock_tx, &old_owner).expect("sign tx");
    let result = verify_and_dump_failed_tx(&ctx.context, &unlock_tx, 100_000_000);
    assert!(
        result.is_err(),
        "Old owner should not be able to unlock after ownership update"
    );
}
