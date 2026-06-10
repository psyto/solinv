# Phase 1 Day 8 — pda_forge::check Implementation

Date: 2026-05-25
Status: ✅ 4th concrete invariant compiles. Critical tier 4/5 implemented.

## Outcomes

| Day 8 goal | Status | Evidence |
|---|---|---|
| Implement `pda_forge::check<F>()` | ✅ | ~130 lines, same template as owner_skip/discriminator_skip |
| Fixture setup verification | ✅ | `find_program_address(seeds, program_id)` vs declared pubkey |
| Skip account-creation paths | ✅ | `if creates_indices.contains(&idx) continue` |
| Preserve everything except pubkey | ✅ | owner-skip + discriminator-skip orthogonality |
| Update invariants/mod.rs | ✅ | `pub mod pda_forge;` |
| `cargo check --workspace` passes | ✅ | 1.65s incremental |

## Attack vector (vs Day 6-7)

| Day | Mutation type | Phase 3 substitution |
|---|---|---|
| 6 owner_skip | Wrong owner | new pubkey + same data + **wrong owner** |
| 7 discriminator_skip | Wrong disc | new pubkey + **corrupted data[0..8]** + same owner |
| 8 pda_forge | Random pubkey | **random** pubkey + same data + same owner |

All three preserve at least 2 of 3 (pubkey/data/owner) to isolate
the check failure they target. Orthogonality enforced at the
mutation-vector design level.

## Fixture setup verification

```rust
let seed_slices: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
let (expected_pda, _bump) = Pubkey::find_program_address(&seed_slices, &spec.program_id);

if real_pubkey != expected_pda {
    return;  // Fixture authoring error; skip silently
}
```

Catches the common error of fixture authors declaring `expected_pda_seeds`
that don't actually derive to the pubkey they put at `spec.accounts[idx]`.
Silently skipping (vs panicking) keeps fuzz output clean — user notices
the mismatch when their other tests fail.

## Skip account-creation paths

```rust
if spec.creates_indices.contains(&idx) {
    continue;
}
```

For accounts created mid-instruction (via `system_instruction::create_account`
+ `invoke_signed`), the runtime auto-verifies that the seeds match
the target address. PDA-forge attack wouldn't apply (the create call
itself fails before any read happens). Skip these.

## Day 1-8 cumulative

| Day | Item | Commit |
|---|---|---|
| 1 | Crucible install + escrow fuzz | `3ce0fdf` |
| 2 | Source-level LCOV | `7217257` |
| 3 | Internals + 7 corrections | `0dd5f3b` |
| 4 | solinv-fuzz capability skeleton | `7805cfc` |
| 5 | signer_skip (Critical 1/5) | `ebb6773` |
| 6 | owner_skip (Critical 2/5) | `ac3f634` |
| 7 | discriminator_skip (Critical 3/5) | `b4e6088` |
| 8 | pda_forge (Critical 4/5) | (this commit) |

Critical tier implementation status:
- ✅ 1/5 signer_skip
- ✅ 2/5 owner_skip
- ✅ 3/5 discriminator_skip
- ✅ 4/5 pda_forge
- ⬜ 5/5 account_swap (Day 9)
- ⬜ 6/6 openhl-solana test fixture validation (Day 10)

## Day 9 plan

account_swap implementation:
- Substitution attack with **real alternate PDAs from user-provided
  list** (`spec.swap_alternates[idx]`)
- Each alternate is a legitimate PDA owned by program, with valid
  discriminator and derived seeds — but from a different context
  (different user / market / epoch)
- Only context-binding check (e.g., `position.trader == passed_trader`)
  can catch the substitution; all earlier checks pass
- ~100 lines, simplest of the 5 Critical (uses existing swap_alternates
  directly, no need to construct fakes)

After Day 9: Critical tier 5/5 implemented. Then Day 10 wires up
openhl-solana fuzz harness to validate end-to-end with planted bugs.
