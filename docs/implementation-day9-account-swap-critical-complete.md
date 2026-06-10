# Phase 1 Day 9 — account_swap::check + Critical Tier 5/5 Complete

Date: 2026-05-25
Status: ✅ **Critical tier 100% implemented**. 5 of 5 Critical invariants compile.

## Outcomes

| Day 9 goal | Status | Evidence |
|---|---|---|
| Implement `account_swap::check<F>()` | ✅ | ~110 lines, simplest of 5 Critical |
| Use real alt PDAs from `swap_alternates` | ✅ | no fake construction needed |
| Capture state changes in alt's context | ✅ | save+hash includes alt pubkey |
| Update invariants/mod.rs (mark Critical complete) | ✅ | `pub mod account_swap;` + Critical-complete comment |
| `cargo check --workspace` warning-free | ✅ | 1.55s incremental, no warnings |
| **Critical tier 5/5 implemented** | ✅ | first compiled implementation of full account-validation family |

## account_swap is the simplest of 5 Critical

Unlike Days 6-8, account_swap **doesn't construct fake accounts**:

| Day | Phase 3 (mutate) details |
|---|---|
| 6 owner_skip | new pubkey + clone real data + **WRITE fake** with wrong owner |
| 7 discriminator_skip | new pubkey + clone real data + corrupt data[0..8] + **WRITE fake** |
| 8 pda_forge | random pubkey + clone real data + **WRITE fake** |
| **9 account_swap** | **alt pubkey (already in ctx)**, no write needed |

Each `swap_alternates[idx]` entry is already a real legitimate PDA in
the fixture's state. solinv just substitutes the pubkey into metas
and sends the ix. The reduced surface = ~110 lines (vs ~130 for the
others).

## Touched-set state-change detection

Unlike preceding invariants (where mutations affect only canonical
accounts), account_swap can cause state changes in EITHER canonical
OR the alt's context. So the touched set is computed:

```rust
let touched: Vec<Pubkey> = spec.accounts.iter().enumerate()
    .map(|(i, m)| if i == idx { alt_pubkey } else { m.pubkey })
    .collect();
let saves = save_accounts(fixture.ctx(), &touched);
let pre_hash = hash_accounts(&saves);
// ... attack ...
let post_hash = hash_accounts_now(fixture.ctx(), touched.iter().copied());
```

This catches the case where trader B's call (with trader A's position
substituted) modifies trader A's position state — the violation is
the state change in alt's context.

Restore phase also covers the alt, so any attack damage to it is
undone before subsequent invariants run.

## Critical tier acceptance test — readiness assessment

Per Day 3 §3 Correction, the quintuple-bug fixture contract is:

> 5 Critical bugs planted simultaneously in `process_close_position`
> of openhl-solana → 5 distinct violation messages observed across a
> fuzz campaign (not 5 in single iteration; first-violation-wins TLS).

All 5 invariants are now implemented to:
- Isolate ONE missing check via mutation-vector design (orthogonality
  preserved by preserving 2/3 of pubkey+data+owner in substitution
  cases, by preserving everything except is_signer in signer_skip)
- Use the same 7-phase template (save → hash → mutate → exec → check
  → restore)
- Emit a clearly-tagged violation message via `fuzz_assert!`

Ready to wire to openhl-solana fuzz harness (Day 10).

## Critical tier final state

```
crates/solinv-core/src/invariants/
├── mod.rs                       # 5 pub mod + Critical-complete note
├── util.rs                      # 60 lines: hash, save, restore helpers
├── signer_skip.rs               # ~110 lines (Day 5)
├── owner_skip.rs                # ~130 lines (Day 6)
├── discriminator_skip.rs        # ~140 lines (Day 7)
├── pda_forge.rs                 # ~130 lines (Day 8)
└── account_swap.rs              # ~110 lines (Day 9)
                                 # TOTAL: ~680 lines invariant code
```

All 5 follow the template proven over Days 5-9:

```rust
pub fn check<F: HasContext + HasInstructionSet>(fixture: &mut F) {
    for spec in fixture.instructions() {
        // ... per-attack-target iteration ...
        // 1. save touched accounts
        // 2. hash pre
        // 3. mutate per invariant's attack vector
        // 4. build signers (filter if signer_skip)
        // 5. ctx.raw_call(ix).signers(&refs).send()
        // 6. hash post + detect violation
        // 7. restore originals
    }
}
```

## Day 1-9 cumulative

| Day | Item | Commit |
|---|---|---|
| 1 | Crucible install + escrow fuzz | `3ce0fdf` |
| 2 | Source-level LCOV | `7217257` |
| 3 | Internals + 7 corrections | `0dd5f3b` |
| 4 | solinv-fuzz capability skeleton | `7805cfc` |
| 5 | signer_skip (Critical 1/5) | `ebb6773` |
| 6 | owner_skip (Critical 2/5) | `ac3f634` |
| 7 | discriminator_skip (Critical 3/5) | `b4e6088` |
| 8 | pda_forge (Critical 4/5) | `132445d` |
| 9 | **account_swap (Critical 5/5)** | **(this commit)** |

## Day 10 plan — openhl-solana acceptance test

Wire openhl-solana into a Crucible/solinv fuzz harness:

1. **Build openhl-solana with Crucible-compatible deps** (anchor-lang
   1.0.1, solana-* 3.0)
2. **Create `examples/openhl-solana/fuzz/openhl-fuzz/`** mirroring
   Crucible's escrow harness structure
3. **Define `OpenHLFixture`** with multi-context setup (trader_a +
   trader_b, market_a + market_b for swap_alternates)
4. **Implement `HasContext` + `HasInstructionSet`** with concrete
   `InstructionSpec` for ClosePosition (or similar bug-prone ix)
5. **Plant 5 Critical bugs** in `process_close_position`:
   missing signer / owner / discriminator / PDA / context-binding checks
6. **Run fuzz**: `crucible run openhl-fuzz invariant_all --release --timeout 60`
7. **Verify**: 5 distinct violation messages observed across the
   campaign — each invariant catches its planted bug

End-state: solinv proven end-to-end against a realistic Solana
program with planted bugs. Phase 1 Month 1 Days 1-10 = full validation
through actual bug-detection demo.

Estimated Day 10 work: ~2-3 hours (most of it openhl-solana build
adjustment for new Solana version pins, plus first harness scaffolding).

## What this milestone means

Critical tier going from "5/5 specs" to "5/5 compiled code" closes
the major design risk: the 7 Day 3 corrections are all proven
implementable, the template generalizes, and the Crucible-on-top
plugin pattern works.

Remaining work to Phase 1 Day 30 baseline (per CLAUDE.md):
- ⬜ Day 10: end-to-end acceptance test on openhl-solana
- ⬜ Day 11-20: 3-5 High tier invariants (cu-dos, unchecked-math, etc.)
- ⬜ Day 21-25: validation against second protocol (Drift / Marginfi)
- ⬜ Day 26-30: first private bug hunt on real mainnet protocol

The hardest part (designing + implementing 5 orthogonal invariants
that compose cleanly) is done.
