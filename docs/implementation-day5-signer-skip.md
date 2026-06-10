# Phase 1 Day 5 — signer_skip::check Implementation

Date: 2026-05-25
Status: ✅ First concrete invariant implemented + cargo check passes

## Outcomes

| Day 5 goal | Status | Evidence |
|---|---|---|
| Add solana-signer workspace dep | ✅ | needed for `Keypair::pubkey()` via `Signer` trait |
| Update solinv-core Cargo.toml deps | ✅ | solinv-fuzz + crucible-test-context + solana types |
| Create invariants/ module structure | ✅ | mod.rs + util.rs + signer_skip.rs |
| Implement `signer_skip::check<F>()` | ✅ | ~120 lines per Day 3 revised template |
| Fix cyclic dep | ✅ | removed `solinv-core` from solinv-fuzz deps (was wrong direction) |
| `cargo check --workspace` passes | ✅ | 1.04s incremental |

## Files created/changed

```
Cargo.toml                                   M  +1 line (solana-signer added)
crates/solinv-fuzz/Cargo.toml                M  -1 line (solinv-core removed, fixes cycle)
crates/solinv-core/Cargo.toml                M  +5 deps
crates/solinv-core/src/lib.rs                M  +pub mod invariants
crates/solinv-core/src/invariants/mod.rs     +  17 lines
crates/solinv-core/src/invariants/util.rs    +  60 lines (hash_accounts, save_accounts, restore_accounts)
crates/solinv-core/src/invariants/signer_skip.rs  +  110 lines (check function)
```

## Architecture decision: dep direction

Initially Day 4 added `solinv-core = { path = "../solinv-core" }` to
solinv-fuzz, which was wrong. Correct direction per the 6-crate plan:

```
solinv-cli
  ├── solinv-core (invariant implementations)
  │     ├── solinv-fuzz (capability traits + Crucible re-exports)
  │     │     └── crucible-fuzzer + crucible-test-context
  │     ├── crucible-test-context (for TxOutcome, fuzz_assert!)
  │     └── solana-* types
  └── solinv-fuzz (also direct dep — exposes prelude)
```

`solinv-fuzz` MUST NOT depend on `solinv-core`. solinv-fuzz is the
foundational capability layer; solinv-core is invariant implementations
built on top.

## signer_skip implementation summary

Per Day 3 §7 revised template, 7 phases:

1. **Save**: `util::save_accounts(ctx, &pubkeys)` reads each account
   the invariant will mutate. Returns `Vec<(Pubkey, Account)>`.
2. **Hash pre**: `util::hash_accounts(&saves)` DefaultHasher over
   `(pubkey, data, lamports, owner)` quad per account.
3. **Mutate**: clone `spec.accounts`, set `metas[sig_idx].is_signer = false`.
4. **Build signers**: filter `spec.signers` to drop the keypair whose
   pubkey matches the target account.
5. **Execute**: `ctx.raw_call(Instruction { ... }).signers(&refs).send()`.
   Returns `Result<TxOutcome>`.
6. **Hash post**: re-read accounts from ctx, hash again. State change =
   pre_hash != post_hash.
7. **Detect**: `fuzz_assert!(!(succeeded && state_changed), msg)` —
   fires `record_violation` if both true.
8. **Restore**: `util::restore_accounts(ctx_mut, saves)` writes saved
   accounts back via `write_account`. Day 3 finding: NOT
   `restore_snapshot()` which is iteration-scoped.

## Code highlights

The detection core:
```rust
let result = fixture
    .ctx_mut()
    .raw_call(ix)
    .signers(&signer_refs)
    .send();

let post_hash = hash_accounts_now(fixture.ctx(), pubkeys.iter().copied());

let succeeded = matches!(result, Ok(TxOutcome::Success { .. }));
let state_changed = pre_hash != post_hash;

fuzz_assert!(
    !(succeeded && state_changed),
    "[signer-skip:{}] ix {} succeeded with is_signer=false on \
     account {} (pubkey {}); state hash {} → {}",
    spec.program_id, spec.name, sig_idx, dropped_pubkey, pre_hash, post_hash,
);
```

The signer filter (drops keypair that signs the target account):
```rust
let dropped_pubkey = spec.accounts[sig_idx].pubkey;
let signer_refs: Vec<&Keypair> = spec
    .signers
    .iter()
    .filter(|kp| kp.pubkey() != dropped_pubkey)
    .map(|kp| &**kp)
    .collect();
```

Handles the edge case where the same keypair appears at multiple
account indices — all matching positions get dropped (correct
behavior: program should still detect the missing signature).

## Friction observed

| Item | Fix |
|---|---|
| Cyclic dep (Day 4 mis-step) | Removed solinv-core from solinv-fuzz deps |
| `solana_signer::Signer` not in scope | Added solana-signer workspace dep + `use solana_signer::Signer;` |
| Stale workaround code (`_SignerImpl` trait hack) | Removed in favor of clean `use` statement |

All fixes mechanical; no design issues surfaced.

## Day 6+ plan

Implementation roadmap for remaining 4 Critical invariants:

| Day | Invariant | Est lines | New util needs |
|---|---|---|---|
| 6 | owner_skip | ~120 | account constructor utility (build fake account with wrong owner + same data + same lamports) |
| 7 | discriminator_skip | ~110 | discriminator-corrupt helper |
| 8 | pda_forge | ~140 | PDA derivation helper, multi-pass with random pubkey strategy |
| 9 | account_swap | ~100 | (uses spec.swap_alternates directly, no new util) |
| 10 | Test fixture | ~200 | First openhl-solana fuzz harness with planted bugs to validate invariant detection |

Each invariant follows the same 7-phase template; util.rs grows
incrementally as patterns emerge. Day 10 deliverable: openhl-solana
fixture detects planted signer-skip bug end-to-end.

## Day 1-5 cumulative

- Day 1: Crucible install + escrow fuzz + planted bug found (bytecode LCOV)
- Day 2: Source-level LCOV via 3-binary workflow + DWARF mapping
- Day 3: Internals deep-read + 7 critical design corrections
- Day 4: solinv-fuzz capability skeleton compiles against Crucible
- Day 5: First concrete invariant (signer_skip::check) compiles

Commit chain: `3ce0fdf` → `7217257` → `0dd5f3b` → `7805cfc` → (this commit)

By end of Day 10, 5/5 Critical invariants implemented and at least one
validated against openhl-solana planted-bug fixture. Phase 1 Month 1
half-way milestone.
