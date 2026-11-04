//! The parts of solinv that read a program without building or running it:
//! the Anchor IDL report (`solinv idl`), declared account types from source
//! (`--src`), and the source diff (`solinv diff`). No Solana or Crucible
//! dependency, so it builds for `wasm32` and installs in seconds.

pub mod diff;
pub mod idl;
pub mod source;
