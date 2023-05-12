//! Generated by capsule
//!
//! `main.rs` is used to define rust lang items and modules.
//! See `entry.rs` for the `main` function.
//! See `error.rs` for the `Error` type.

#![no_std]
#![cfg_attr(not(test), no_main)]

#[cfg(test)]
extern crate alloc;

#[cfg(not(test))]
use ckb_std::default_alloc;
#[cfg(not(test))]
ckb_std::entry!(program_entry);
#[cfg(not(test))]
default_alloc!();

// define modules
mod blake2b;
mod constant;
mod entry;
mod error;

use ckb_combine_lock_common::logger;
use log::warn;

/// program entry
///
///  Both `argc` and `argv` can be omitted.
fn program_entry() -> i8 {
    drop(logger::init());
    // Call main function and return error code
    match entry::main() {
        Ok(_) => 0,
        Err(err) => {
            warn!("script exit with error: {:?}", err);
            err as i8
        }
    }
}
