//! # solinv-disclose
//!
//! Disclosure report formatter. Generates bug bounty submission
//! templates for Immunefi, Sherlock, and native protocol bounty
//! programs.
//!
//! Output includes:
//! - PoC reproduction code (minimal ix sequence from shrinker)
//! - Impact analysis (severity classification + economic estimate)
//! - Suggested fix (when invariant maps to known remediation pattern)
//! - Structured metadata (program ID, invariant name, slot, env)
//!
//! Supported targets:
//! - Immunefi format (JSON + markdown)
//! - Sherlock format
//! - Native: Drift, Marginfi, Kamino, Jupiter, Phoenix, Mango,
//!   Solana Foundation
