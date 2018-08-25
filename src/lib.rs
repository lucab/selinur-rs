//! A pure-Rust library to interact with the SELinux kernel subsystem.

#![deny(missing_docs)]

extern crate errno;
#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate openat;

pub mod errors;
pub mod sys;
mod kernel;

pub use self::kernel::has_selinuxfs;

#[cfg(test)]
mod utest;
