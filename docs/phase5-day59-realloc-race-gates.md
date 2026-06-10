# Phase 5 Day 59 — realloc-race Gate 1 + Gate 2 (Phase 2.5 catalog)

Date: 2026-06-09
Spec: [docs/invariants/realloc-race.md](invariants/realloc-race.md) §9 + §10
Prior: [Day 58 cpi-reentrancy Gate 2 (Phase 2.5 framing demonstrated)](phase5-day58-cpi-reentrancy-gate2.md)
Framing: **Phase 2.5 OSS catalog-completion** — 0 violations on
hardened production is the **expected** result; this is catalog
evidence, NOT a kill criterion. Framing transition inherited from
cpi-reentrancy.md §10; no re-justification needed.

## Result — Gate 1 PASS, Gate 2 0/24,381

Detector landed end-to-end in a single session: planted-bug Gate 1
fired 27,999 times in 30s; production Gate 2 (Raydium SwapV2) produced
0 violations in 24,381 executions. Catalog 9/10 complete.

## Important new finding — Solana runtime defense-in-depth

The first Gate 1 attempt produced **0 detections in 7,828 executions**
despite the planted bug being structurally present. Diagnostic logs
revealed why:

```
[realloc-race FAIL] outcome: ProgramError {
  error: InsufficientFundsForRent { account_index: 2 },
  ...
  logs: ["Program ... invoke [1]", "Program log: Instruction: UnsafeReallocGrow",
         "Program ... consumed 4977 of 200000 compute units",
         "Program ... success"]
}
```

The escrow program logs `success` (its `resize(new_len)` syscall
returned Ok), but the **Solana runtime catches the rent shortfall
at tx commit** and rejects the entire tx with
`TransactionError::InsufficientFundsForRent`. The protocol-level
state mutation does NOT persist. The program-side bug is real —
the program intended to commit a rent-deficient state — but the
runtime arrests it before commit, so the post-tx state appears
unchanged from the detector's perspective.

This is structural Solana defense-in-depth, enabled via the rent-
exempt-only feature (in default Solana since 1.8). The realloc-race
bug class is therefore **largely unreachable as a state-mutating
bug** on modern mainnet — but the protocol *intent* is observable
via the runtime error.

### Detector resolution — two-path design

v1 realloc_race::check now has **two detection paths**:

- **Path A (runtime-error)**: pattern-match
  `TxOutcome::ProgramError { error: InsufficientFundsForRent, .. }`
  and fire on it. This is the dominant path on modern Solana — the
  detector catches the program's *intent* even when the runtime
  rolls back the state mutation.
- **Path B (post-state)**: pre/post-ix `(data.len(), lamports)`
  snapshot + rent check (the originally-designed v1 detector). Fires
  on archaic/test-only configurations where the runtime check is
  disabled, or hypothetically on a runtime bug that lets the
  shortfall persist.

Both paths landed in solinv-core@<commit>; the spec doc §3 was
updated to articulate the two paths. The catalog entry is honest
about which path is realistic on modern Solana.

### Why this finding matters for the catalog

The realloc-race entry in the OSS launch's catalog has to be honest
that the bug class is largely arrested by Solana's runtime, not by
the protocol's own logic. This is the kind of "honest calibration"
Phase 2.5 framing was built for — surfacing the bug class without
overstating the protocol's responsibility.

Compare to:
- **unchecked-math**: Solana runtime doesn't catch wrapping/saturating
  arithmetic at all → protocol responsibility is total.
- **cu-dos**: runtime caps per-tx CU at 200K → protocol responsibility
  is to design within the cap.
- **cpi-reentrancy**: runtime locks writable accounts across CPI tree
  but doesn't prevent same-program re-entry on different accounts →
  partial runtime defense.
- **realloc-race**: runtime rejects rent-deficient state at tx commit
  → runtime defense is near-total; protocol responsibility is the
  *intent* layer (don't try to grow without top-up), not the
  *commit* layer.

The catalog entry articulates this scale. solinv detects the bug
class at the layer Solana doesn't cover (intent), surfacing what the
runtime catches "the hard way" via tx rejection.

## Gate 1 setup

```bash
cd ~/src/solinv/examples/escrow-demo
cargo build-sbf --tools-version v1.52 --manifest-path programs/escrow/Cargo.toml
cd fuzz/escrow
cargo build --release --features invariant_realloc_race_only
cd ..
crucible run escrow invariant_realloc_race_only --release --timeout 30
```

Planted bug (programs/escrow/src/lib.rs):
```rust
pub fn unsafe_realloc_grow(
    ctx: Context<UnsafeReallocGrow>, delta: u32,
) -> Result<()> {
    let info = ctx.accounts.vault.to_account_info();
    let pre_len = info.data_len();
    let new_len = (pre_len.saturating_add(delta as usize)).min(pre_len + 10_240);
    info.resize(new_len)?;                  // Solana 3.x: realloc → resize
    // INTENTIONAL BUG: no system_program::transfer to top up lamports.
    Ok(())
}
```

InstructionSpec carries `realloc_check: Some(ReallocCheckConfig::default())`
+ `data_sample` pins `delta = 200` so each detector re-execution
attempts to grow the vault from 88 → 288 bytes.

## Gate 1 result

```
[FUZZ_FINDING] [realloc-race:Esrcw1111…] runtime rejected with
  InsufficientFundsForRent on account_index=2 — program grew account
  data past rent-exempt threshold without lamport top-up
  (ix unsafe_realloc_grow)
```

| Metric | Value |
|---|---:|
| Runtime | 30s |
| Executions | 28,000 |
| Detections | **27,999 (99.99%)** |
| Exec/sec | 959.9 |
| ok rate | 26.2% |
| Edges | 642/3,900 (16.5%) |

Detection rate similar to cpi-reentrancy Gate 1 — the planted bug
is structural so virtually every detector re-execution fires.

## Gate 2 setup

```bash
cd ~/src/solinv/examples/raydium-amm-fuzz/fuzz/raydium_amm
cargo build --release --features invariant_realloc_race_only
cd ..
crucible run raydium_amm invariant_realloc_race_only --release --timeout 30 -j 4
crucible run raydium_amm invariant_realloc_race_only --release --timeout 30 -j 4
```

Both SwapV2 specs now carry `realloc_check:
Some(ReallocCheckConfig::default())`.

## Gate 2 result

| Campaign | Workers | Executions | Crashes | ok rate | Edges |
|---|---|---:|---:|---:|---|
| 1 | 4 | 11,691 | **0** | 210,564 / 224,982 = 93.6% | 629/14,696 (4.3%) |
| 2 | 4 | 12,690 | **0** | 206,524 / 223,263 = 92.5% | 629/14,696 (4.3%) |
| **Total** | — | **24,381** | **0** | — | — |

**0 violations across either campaign.** Edge saturation 629/14,696
(4.3%) — **identical** to cu-dos Day 38, unchecked-math Day 34, and
cpi-reentrancy Day 58. Four different High-tier invariants × same
protocol × same coverage saturation across all four runs.

Raydium AMM SwapV2 doesn't realloc — swap is a pure state-mutation
operation on fixed-size accounts (AmmInfo 752 bytes, vault
TokenAccount 165 bytes, all fixed at init). Detector correctly idles.

## Phase 2.5 cumulative calibration dataset (4 invariants)

| Day | Invariant | Mechanism | Exec | Violations |
|---|---|---|---:|---:|
| 34 | unchecked-math | state mutation (Bounded) | 15,380 | 0 |
| 38 | cu-dos | per-ix CU consumption | 25,650 | 0 |
| 58 | cpi-reentrancy | CPI call-tree logs | 27,573 | 0 |
| **59** | **realloc-race** | **runtime err + post-state** | **24,381** | **0** |
| | | **Total** | **92,984** | **0** |

Four distinct detection mechanisms, same hardened-production
surface, four null results. The catalog calibration backbone now
spans ~93K executions across 4 invariants × Raydium SwapV2. This
is the empirical backbone of solinv's "honest tested-and-found-
nothing" framing for OSS launch.

## Files changed Day 59

- `docs/invariants/realloc-race.md` (new, 700+ LOC, 10 sections inc.
  §9/§10 framing inheritance from cpi-reentrancy).
- `crates/solinv-fuzz/src/capability.rs` — added
  `ReallocCheckConfig` + `realloc_check: Option<ReallocCheckConfig>`
  field on InstructionSpec.
- `crates/solinv-fuzz/src/lib.rs` — re-export ReallocCheckConfig
  from top + prelude.
- `crates/solinv-core/Cargo.toml` — added solana-transaction-error
  dep (for the Path-A `InsufficientFundsForRent` variant match).
- `crates/solinv-core/src/invariants/realloc_race.rs` (new, 250+ LOC
  + 8 unit tests).
- `crates/solinv-core/src/invariants/mod.rs` — register module.
- `crates/solinv-core/src/invariants/regression_tests.rs` — add the
  new field to the base fixture helper.
- 16 InstructionSpec literals across 10 example fuzz crates +
  `escrow-demo/programs/escrow/src/lib.rs` (planted ix) +
  `escrow-demo/fuzz/escrow/src/main.rs` (harness wiring) +
  `examples/raydium-amm-fuzz/fuzz/raydium_amm/src/main.rs` (Gate 2
  enrollment).
- `examples/escrow-demo/fuzz/escrow/Cargo.toml` +
  `examples/raydium-amm-fuzz/fuzz/raydium_amm/Cargo.toml` — new
  `invariant_realloc_race_only` features.

## Next

- **Phase 2.5 catalog: 9/10 implemented.** Remaining: bump-seed-
  canonicalization (the last High-tier item).
- **Public launch prep** (Day 79-83 per CLAUDE.md): the calibration
  dataset can now serve as public-facing material (93K exec × 4
  invariants × 1 hardened-production protocol × 0 false positives).
- **Optional follow-up**: ship a fixture that exercises Path B
  (post-state path) by using a Solana config with rent-exempt-only
  disabled — confirms the detector's full logic works end-to-end.
  Low priority since modern mainnet always has the feature on.
