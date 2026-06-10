# Phase 1 Day 7 — discriminator_skip::check Implementation

Date: 2026-05-25
Status: ✅ 3rd concrete invariant compiles. Critical tier 3/5 implemented.

## Outcomes

| Day 7 goal | Status | Evidence |
|---|---|---|
| Implement `discriminator_skip::check<F>()` | ✅ | ~140 lines, same template as owner_skip |
| Multi-pass with 3 wrong discriminators | ✅ | sentinel `0xDEADBEEF…`, all-zeros, all-ones |
| Preserve owner correctness (orthogonality) | ✅ | `fake_account.owner = real_account.owner` |
| Update invariants/mod.rs | ✅ | `pub mod discriminator_skip;` |
| `cargo check --workspace` passes | ✅ | 1.40s incremental |

## Orthogonality preserved

The key design decision in this invariant: **preserve owner correctness**.

```rust
let fake_account = Account {
    owner: real_account.owner,  // PRESERVE — orthogonality with owner-skip
    data: fake_data,            // corrupted: data[0..8] = wrong_disc
    lamports: real_account.lamports,
    ...
};
```

This isolates the discriminator-check failure:
- If program checks owner → fake passes (owner preserved)
- If program checks discriminator → fake fails (only path that can catch)
- If program checks neither → owner-skip AND discriminator-skip both fire
  (across campaign, in different iterations)

Quintuple-bug fixture orthogonality contract preserved.

## Multi-pass wrong-discriminator candidates

```rust
const WRONG_DISCRIMINATORS: &[[u8; 8]] = &[
    [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00],   // sentinel
    [0x00; 8],                                            // all-zeros
    [0xFF; 8],                                            // all-ones
];
```

Each pattern catches different bug types:
- **Sentinel**: programs comparing against hardcoded expected value
- **All-zeros**: programs treating default-initialized accounts as valid
- **All-ones**: programs using exclusion (e.g., `disc != [0xFF; 8]`)

Filter excludes `wrong_disc == expected_disc` to avoid no-op tests.

## Template proven across 3 attack classes

| Day | Invariant | Mutation type | Phase 3 (attack vector) |
|---|---|---|---|
| 5 | signer_skip | Flag flip | `metas[idx].is_signer = false` |
| 6 | owner_skip | Account substitution + wrong owner | new pubkey + cloned data + wrong owner |
| 7 | discriminator_skip | Account substitution + corrupted disc | new pubkey + cloned data + first 8 bytes overwritten |

Phases 1-2 (save/hash), 4-5 (signers/execute), 6 (detect), 7-8 (post-
hash/restore) identical across all three. The template generalizes
cleanly.

## Day 1-7 cumulative

| Day | Item | Commit |
|---|---|---|
| 1 | Crucible install + escrow fuzz | `3ce0fdf` |
| 2 | Source-level LCOV | `7217257` |
| 3 | Internals + 7 corrections | `0dd5f3b` |
| 4 | solinv-fuzz capability skeleton | `7805cfc` |
| 5 | signer_skip (Critical 1/5) | `ebb6773` |
| 6 | owner_skip (Critical 2/5) | `ac3f634` |
| 7 | discriminator_skip (Critical 3/5) | (this commit) |

Critical tier implementation status:
- ✅ 1/5 signer_skip
- ✅ 2/5 owner_skip
- ✅ 3/5 discriminator_skip
- ⬜ 4/5 pda_forge (Day 8 — random pubkey substitution, no data preserved is one variant; or random pubkey + copied data is the primary)
- ⬜ 5/5 account_swap (Day 9 — substitute with real alternate PDAs from user-provided list)
- ⬜ 6/6 openhl-solana test fixture validation (Day 10)

## Day 8 plan

pda_forge implementation:
- Substitution attack with `Pubkey::new_unique()` (random off-curve pubkey, no PDA derivation)
- Preserves data + owner (PDA-forge catches "no derivation check at all")
- Skip if `creates_indices.contains(&idx)` — runtime auto-verifies creation
- Variant pass (optional v0.2): substitute PDA from different seeds
  for "verifies-derivation-but-not-context" detection

Estimated ~120 lines, mostly mechanical from existing template.
