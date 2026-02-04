#![no_std]
#![no_main]

mod entry;
mod error;

use ckb_std::default_alloc;
ckb_std::entry!(program_entry);
default_alloc!({ 4 * 1024 }, { 1400 * 1024 }, 64);

use entry::entry;

pub fn program_entry() -> i8 {
    match entry() {
        Ok(_) => 0,
        Err(e) => {
            let result = e as i8;
            assert!(result != 0);
            result
        }
    }
}
