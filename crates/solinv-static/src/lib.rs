//! The parts of solinv that read a program without building or running it:
//! the Anchor IDL report (`solinv idl`), declared account types from source
//! (`--src`), the source diff (`solinv diff`) and the IDL diff
//! (`solinv diff --base-idl`). No Solana or Crucible
//! dependency, so it builds for `wasm32` and installs in seconds.

pub mod diff;
pub mod idl;
pub mod idl_diff;
pub mod legacy;
pub mod lint;
pub mod native;
pub mod source;
