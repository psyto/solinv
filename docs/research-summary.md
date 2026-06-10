# Week 1-2 Validation — Strategic Synthesis

Date: 2026-05-24
Status: **5/5 validation items complete** + **5 Critical invariant specs written**.

## Go decision: ✅ PROCEED with Phase 1 implementation

All three primary validation gates passed AND Critical invariant tier
fully specified:

1. **sBPF coverage feasibility**: ✓ Crucible's stack solves this end-to-end. 3-5 days for integration (not 1-2 weeks). solinv does NOT need to build coverage.
2. **Crucible plugin viability**: ✓ Pattern A confirmed (library composition via capability traits + free invariant functions). No fork, no upstream PR required.
3. **Trident UX baseline**: ✓ Confirmed solinv's wedges (auto-invariants, mainnet corpus, disclosure, Pinocchio support) are genuinely missing. Don't compete on macro UX.
4. **Medusa pattern study**: ✓ 5 portable patterns identified (shrinker, 3-tier taxonomy, corpus pruner, per-entry weighting, replayable artifacts). AGPL prevents code lifts — clean-room only.
5. **5 Critical invariant specs**: ✓ Full account-validation defense family specified — signer-skip, owner-skip, discriminator-skip, pda-forge, account-swap. See [invariants/](invariants/).

## Strategic implications

### Timeline compression (already realized)

Original Phase 1 (Month 1-6) assumed:
- Coverage MVP would take 1-2 weeks → eliminated (Crucible provides)
- Invariant spec would take Days 11-15 → completed pre-Phase-1

**Revised Month 1 plan** (more time for implementation):

| Days | Task | Status |
|---|---|---|
| (pre) | Specs written, research complete | ✅ done |
| 1-3 | Clone Crucible, install platform-tools v1.51, run escrow example with `--coverage`, confirm LCOV output | ⬜ |
| 4-5 | Build `solinv-fuzz` crate that re-exports Crucible + adds capability trait module skeleton | ⬜ |
| 6-10 | Implement Crucible-pattern harness for openhl-solana (1-2 instructions) end-to-end | ⬜ |
| 11-20 | Implement 5 Critical invariants per specs | ⬜ |
| 21-25 | Implement 3-5 High invariants OR validate Critical against openhl-solana | ⬜ |
| 26-30 | Quintuple-bug fixture acceptance test + first private bug hunt on real protocol | ⬜ |

By Month 1 end: **5-10 invariants implemented** + Crucible integration
working + first internal validation done + bug hunting begun.

### License-clean architecture confirmed

| Dep | License | Action |
|---|---|---|
| Crucible | MIT | ✓ safe to depend on |
| LiteSVM | Apache-2.0 | ✓ safe to depend on |
| LimeChain sbpf-coverage | AGPL-3.0 | ✗ do NOT link, use Crucible's MIT LCOV writer |
| Medusa | AGPL-3.0 | ✗ do NOT lift code, clean-room reimplement only |
| Echidna | AGPL-3.0 | ✗ do NOT lift code, clean-room reimplement only |
| Foundry | MIT/Apache-2.0 | ✓ safer reference for code patterns |

solinv stays MIT-or-Apache-2.0 ready for Phase 2 OSS release.

### Top patterns to port from Medusa (clean-room)

1. **Aspect-level shrinker** — 3-pass (drop-failed → shorten → per-aspect). Preserve final tx
2. **Three-tier taxonomy** — `assert_* / property_* / optimize_*` with prefix discovery
3. **Background corpus pruner** — periodic task that drops degenerate corpus entries
4. **Per-entry corpus weighting** — bias rare-edge sequences
5. **Replayable failure artifacts** — JSON `{program_id, actions, signers, sysvar_clock, sysvar_slot, rng_seed}`

### Crucible API stability risk

v0.1.0 release notes warn "API may change before 1.0." Mitigations:
- Pin `tag = "v0.1.0"` in Cargo (NOT `branch = "main"`)
- Budget refactor cycle per Crucible minor bump
- Keep solinv's invariant library decoupled from macro internals (capability traits, not macro extensions)

### Solana version pins

Must match Crucible's workspace:
- `solana-* = "3.0"`
- `anchor-lang = "1.0.1"`
- `litesvm = "0.9.0"` (with `features = ["register-tracing"]`)

Document in `solinv init` so users know their program types must match these versions.

## Critical invariant specs — accumulated design

Five Critical invariants form the **account-validation defense family**:

| # | Invariant | Catches | Substitute used |
|---|---|---|---|
| 1 | signer-skip | Missing `is_signer` check | Same account, is_signer=false |
| 2 | owner-skip | Missing `account.owner` check | Same data, wrong owner |
| 3 | discriminator-skip | Missing type discriminator check | Same owner, corrupted disc |
| 4 | pda-forge | Missing PDA derivation check | Random pubkey, copied data |
| 5 | account-swap | Missing context-binding check | Real alternate PDA, alternate context |

Each catches ONE missing assertion. Quintuple-bug fixture (all 5
planted in `process_close_position` of openhl-solana) is the
end-state acceptance test: 5 bugs → 5 independent violations.

### Final InstructionSpec shape (after 5 Critical specs)

```rust
pub struct InstructionSpec {
    pub program_id: Pubkey,
    pub name: String,
    pub accounts: Vec<AccountMeta>,
    pub signer_indices: Vec<usize>,
    pub optional_signer_indices: Vec<usize>,
    pub expected_owners: Vec<Option<Pubkey>>,
    pub expected_discriminators: Vec<Option<[u8; 8]>>,
    pub expected_pda_seeds: Vec<Option<Vec<Vec<u8>>>>,
    pub creates_indices: Vec<usize>,
    pub swap_alternates: Vec<Vec<Pubkey>>,
    pub data_sample: Vec<u8>,
}
```

4/5 fields auto-fillable from Anchor IDL; only `swap_alternates`
requires manual context-binding declaration (semantic, not introspectable).

## Updated solinv scope

### What solinv builds
1. **`solinv-core`** — 17 Solana-aware invariants as free functions over capability traits (5 Critical specs done; 5 High + 5-7 Medium pending)
2. **`solinv-fuzz`** — Crucible re-exports + capability trait module + 5-pattern Medusa port (clean-room: shrinker, taxonomy, pruner, weighting, replay)
3. **`solinv-cheat`** — convenience wrappers around LiteSVM cheats (warp, lamports, rent-exempt)
4. **`solinv-corpus`** — Yellowstone gRPC client + persistence + Crucible corpus injection
5. **`solinv-disclose`** — Immunefi/Sherlock formatters, severity classification, replayable PoC generation
6. **`solinv-cli`** — `solinv check/fuzz/corpus/disclose` shelling out to `crucible run` where applicable

### What solinv does NOT build
- Coverage instrumentation (use Crucible's)
- LibAFL mutators (use Crucible's)
- SVM execution engine (use LiteSVM via Crucible)
- Engine plugin trait registry (capability traits suffice)
- Macro vocabulary competing with `#[fuzz_fixture]` or `#[flow]`
- Anchor IDL parser (use Crucible's `crucible-idl-gen`)

## Remaining spec work (optional, can be done in parallel with implementation)

### High tier (5 invariants pending)

| # | Name | Bug class |
|---|---|---|
| 8 | cpi-reentrancy | Re-entry through CPI to caller program |
| 9 | cu-dos | Single ix consumes >limit CU → permanent DoS |
| 10 | unchecked-math | Saturating vs wrapping vs checked confusion |
| 11 | realloc-race | `realloc()` race / overflow / rent invariant break |
| 12 | token-2022-hook | Transfer hook violation / extension mishandling |

### Medium tier (5-7 invariants pending)

| # | Name | Bug class |
|---|---|---|
| 13 | close-reopen | Account close-and-reopen with different data |
| 14 | sysvar-manipulation | Clock/Rent sysvar override unhandled |
| 15 | permissionless-misuse | "Anyone can call" ix mis-used in privileged context |
| 16 | rent-exemption | Rent exempt state unauthorized transition |
| 17 | account-init-race | Re-init of allocated account |

These can be specified in parallel with Critical implementation work
in Month 1, or deferred to Month 2.

## Next session priorities

1. **Crucible Day 1** — Clone `asymmetric-research/crucible`, install
   platform-tools v1.51, run escrow example with `--coverage`, confirm
   LCOV output renders. Day-1 code pointers in `research-sbpf-coverage.md`
2. **Build solinv-fuzz** capability trait skeleton + Crucible re-export
3. **Implement Critical invariants** per specs in order
4. **Quintuple-bug fixture** in openhl-solana for acceptance validation
5. Optional: spec High tier in parallel

## Sources

Individual research notes:
- `research-sbpf-coverage.md`
- `research-crucible-integration.md`
- `research-medusa-patterns.md`
- `research-trident-ux-baseline.md`

Invariant specs:
- `invariants/signer-skip.md`
- `invariants/owner-skip.md`
- `invariants/discriminator-skip.md`
- `invariants/pda-forge.md`
- `invariants/account-swap.md`
