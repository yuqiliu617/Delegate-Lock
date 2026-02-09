# Delegate Lock

Delegate Lock is a lock script that proxies verification to another script stored in a separate cell. This allows users to update the ownership or unlocking logic of cells without changing the lock script hash, preserving the cell's on-chain identity.

## Data Structure

### Delegate Lock Args

The `args` field stores the first 20 bytes (blake160) of the [Type ID](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0022-transaction-structure/0022-transaction-structure.md#type-id) used by the cell containing the actual lock script. This truncation follows the same convention as other CKB lock scripts and provides sufficient collision resistance while minimizing on-chain storage.

### Witness

Delegate Lock delegates the verification logic. Therefore, the witness structure should follow the format expected by the **actual lock script**. Delegate Lock itself does not impose additional witness requirements.

## Usage Flow

### Lock a Cell

First, create a Type ID cell to store the actual lock script:

```text
Inputs:
    Seed Cell
Outputs:
    Type ID Cell:
        Lock: <lock script for Type ID cell itself>
        Type:
            code_hash: <Type ID code hash>
            hash_type: type
            args: <type id>
        Data: <actual lock script, molecule-encoded>
            code_hash: <actual lock script code hash>
            hash_type: <actual lock script hash type>
            args: <actual lock script args>
```

Second, lock the target cell using Delegate Lock, referencing the Type ID cell:

```text
Outputs:
    Target Cell:
        Lock:
            code_hash: <Delegate Lock code hash>
            hash_type: type
            args: <first 20 bytes of type id>
```

### Unlock a Cell

To unlock the cell, the transaction must include the Type ID cell and the actual lock script binary cell as dependencies:

```text
CellDeps:
    Type ID Cell:
        Type:
            code_hash: <Type ID code hash>
            hash_type: type
            args: <type id>
        Data: <actual lock script, molecule-encoded>
            code_hash: <actual lock script code hash>
            hash_type: <actual lock script hash type>
            args: <actual lock script args>
    Actual Lock Script Binary Cell:
        Data: <actual lock script binary>
Inputs:
    Delegate Lock Cell:
        Lock:
            code_hash: <Delegate Lock code hash>
            hash_type: type
            args: <first 20 bytes of type id>
Witnesses:
    <as required by the actual lock script>
```

### Update Ownership

To change the ownership, update the data in the Type ID cell.

```text
Inputs:
    Old Type ID Cell:
        Lock: <lock script for Type ID cell itself>
        Type:
            code_hash: <Type ID code hash>
            hash_type: type
            args: <type id>
        Data: <old actual lock script, molecule-encoded>
Outputs:
    New Type ID Cell:
        Lock: <lock script for Type ID cell itself>
        Type:
            code_hash: <Type ID code hash>
            hash_type: type
            args: <type id>
        Data: <new actual lock script, molecule-encoded>
```

## Delegation Convention

A lock script typically loads its arguments via the [`ckb_load_script`](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0009-vm-syscalls/0009-vm-syscalls.md#load-script) syscall. However, when used with Delegate Lock, the actual lock script runs in Delegate Lock's context, so `ckb_load_script` returns the Delegate Lock script instead of the expected arguments.

To address this, Delegate Lock uses the following convention when invoking the actual lock script:

- It uses [`ckb_exec`](https://github.com/nervosnetwork/rfcs/blob/master/rfcs/0034-vm-syscalls-2/0034-vm-syscalls-2.md#exec) to execute the actual lock script.
- `source` is set to `CKB_SOURCE_CELL_DEP` (3), `place` is set to 0 (cell data), and `bounds` is set to 0 (entire data).
- The lock script arguments from the Type ID cell data are passed via `argc` and `argv` parameters of `ckb_exec`.
    - `argc` is always 2
    - `argv[0]` contains the magic string `"DELEGATE_LOCK"`, which the actual lock script must verify to confirm it was invoked by Delegate Lock.
    - `argv[1]` contains the hex-encoded script args from the Type ID cell data.
- Delegate lock itself does not impose any additional witness requirements. The actual lock script can load its witness as usual.

Therefore, the actual lock script must read its arguments from `argc` and `argv` instead of `ckb_load_script`. Since most existing lock scripts use `ckb_load_script`, modified versions are provided in this repository (see [Migrated Lock Scripts](#migrated-lock-scripts) below).

To adapt an existing lock script to work with Delegate Lock, follow the following migration guide:
```rust
// Old way: load from script directly
fn run() -> Result<(), Error> {
    let script = ckb_std::high_level::load_script()?;
    let args: Bytes = script.args().unpack();
    // ...
}
```
```rust
// New way: load from argv
const DELEGATE_LOCK_MAGIC: &[u8] = b"DELEGATE_LOCK";

fn run() -> Result<(), Error> {
    let argv = ckb_std::env::argv();
    if argv.len() != 2 || argv[0].to_bytes() != DELEGATE_LOCK_MAGIC {
        return Err(Error::ArgsInvalid);
    }
    let args_hex = argv[1].to_bytes();
    let args = decode_hex(args_hex)?;
    // ...
}
fn decode_hex(hex: &[u8]) -> Result<Vec<u8>, Error> {
    if hex.len() % 2 != 0 {
        return Err(Error::ArgsInvalid);
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for chunk in hex.chunks(2) {
        let high = hex_digit_to_value(chunk[0])?;
        let low = hex_digit_to_value(chunk[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}
fn hex_digit_to_value(c: u8) -> Result<u8, Error> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::ArgsInvalid),
    }
}
```

## Chained Delegation

Delegate Lock supports chaining: a Type ID cell can point to Delegate Lock itself as the actual lock script. This creates a two-level delegation:

```text
Outer Delegate Lock → Inner Delegate Lock (same binary) → Actual Lock Script
```

The outer Delegate Lock finds its Type ID cell, which stores a Script pointing to the Delegate Lock binary with inner args. It then `ckb_exec`s Delegate Lock with those args via the delegation convention. The inner instance receives its args through `argv`, finds a second Type ID cell, and finally executes the actual lock script.

### Unlock with Chained Delegation

```text
CellDeps:
    Outer Type ID Cell:
        Type:
            args: <outer type id>
        Data: <Script pointing to Delegate Lock with inner type id prefix as args>
    Inner Type ID Cell:
        Type:
            args: <inner type id>
        Data: <actual lock script, molecule-encoded>
    Actual Lock Script Binary Cell:
        Data: <actual lock script binary>
Inputs:
    Delegate Lock Cell:
        Lock:
            code_hash: <Delegate Lock code hash>
            args: <first 20 bytes of outer type id>
Witnesses:
    <as required by the actual lock script>
```

This enables use cases where an intermediate authority can be updated independently of the final lock script.

## Migrated Lock Scripts

The following lock scripts have been adapted to work with Delegate Lock by reading arguments from `argv` instead of `ckb_load_script`:

| Script                                                                   | Original                                                                                |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------- |
| [secp256k1-blake160-sighash-all](./c/secp256k1_blake160_sighash_all.c)   | [CKB System Scripts](https://github.com/nervosnetwork/ckb-system-scripts)               |
| [secp256k1-blake160-multisig-all](./c/secp256k1_blake160_multisig_all.c) | [CKB System Scripts](https://github.com/nervosnetwork/ckb-system-scripts)               |
| [ccc-btc](./contracts/ccc-btc)                                           | [CCC Locks](https://github.com/ckb-devrel/ccc-locks/tree/master/contracts/ccc-btc-lock) |
| [ccc-eth](./contracts/ccc-eth)                                           | [CCC Locks](https://github.com/ckb-devrel/ccc-locks/tree/master/contracts/ccc-eth-lock) |
| [ccc-sol](./contracts/ccc-sol)                                           | [CCC Locks](https://github.com/ckb-devrel/ccc-locks/tree/master/contracts/ccc-sol-lock) |

## Security Considerations

- **Type ID Cell Protection**: The security of cells locked by Delegate Lock depends entirely on the lock script of the Type ID cell. If an attacker can modify the Type ID cell's data, they gain control over all cells referencing that Type ID. Choose a secure lock script for the Type ID cell.
- **Actual Lock Script Trust**: The actual lock script executed via `ckb_exec` must be trusted. Delegate Lock does not verify the correctness of the delegated script beyond matching the Type ID.