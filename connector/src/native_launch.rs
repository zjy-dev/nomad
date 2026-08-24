//! Rust-owned locked OpenCode launch building blocks.
//!
//! N1a/N1b are compiled only for crate tests until the independently reviewed
//! N1c owner integrates lifecycle and cleanup.  The production supervisor must
//! remain unable to reach these mechanics while the N0 Host-publication gate is
//! unavailable.

mod darwin;
mod inputs;
mod installed;
mod lifecycle;
mod process;
