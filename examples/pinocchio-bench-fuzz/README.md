# pinocchio-bench-fuzz

Wires solinv invariants onto the **W4 matching engine programs** from the
public [`psyto/pinocchio-bench`](https://github.com/psyto/pinocchio-bench)
artifact, closing the loop on what `pinocchio-bench/RESULTS.md` promised:
the 6 invariants a fuzzer would attach to a real Pinocchio rewrite of an
order book.

## Layout

```
examples/pinocchio-bench-fuzz/
├── README.md
└── fuzz/
    ├── matching/                 ← W4 Anchor target (anchor_w4_matching.so)
    │   ├── Cargo.toml
    │   └── src/main.rs           ← solinv harness
    ├── matching-pino/            ← W4 Pinocchio twin (pinocchio_w4_matching.so)
    │   ├── Cargo.toml
    │   └── src/main.rs           ← same harness shape, no Anchor disc/sighash
    ├── matching-diff/            ← W4 differential (both sides at once)
    │   ├── Cargo.toml
    │   └── src/main.rs           ← state-equivalence proof under fuzz
    ├── amm-diff/                 ← W8 AMM differential (anchor↔pinocchio)
    │   ├── Cargo.toml
    │   └── src/main.rs           ← Pool body + 4 token-account body equivalence
    ├── refresh-diff/             ← W9 lending refresh differential
    │   ├── Cargo.toml
    │   └── src/main.rs           ← 5 mut zero-copy account body equivalence
    ├── vault-diff/               ← W10 vault deposit differential (NAV)
    │   ├── Cargo.toml
    │   └── src/main.rs           ← 2 zero-copy + 2 SPL — written using `DifferentialFixture` trait from the start
    ├── oracle-diff/              ← W11 Pyth-style oracle publish differential
    │   ├── Cargo.toml
    │   └── src/main.rs           ← 1 zero-copy, simplest `DifferentialFixture` skeleton
    └── perp-diff/                ← W12 Drift-style perp open_position differential
        ├── Cargo.toml
        └── src/main.rs           ← 5 pairs (3 zc + 2 SPL), caught a W12 spec bug
```

A Pinocchio-targeted twin lives at `fuzz/matching-pino/` and exercises
the same 8 invariants that transfer cleanly (`signer-skip`, `owner-skip`,
`unchecked-math`, `cu-dos`, plus the 3 W4/W5-specific structural checks
plus the `Monotonic` state invariant on `market.sequence`).
`discriminator-skip` and `pda-forge` are excluded — Pinocchio doesn't use
either pattern, so they would always pass vacuously.

The third harness, `fuzz/matching-diff/`, runs both targets simultaneously
under shared fuzz input and asserts state byte-equivalence after every
action — see "Differential harness" section below.

The twin runs roughly **5× the fuzzing throughput** of the Anchor harness
(~950 exec/sec vs ~185 exec/sec on the same hardware) because the
Pinocchio target's surface is smaller (51/280 edges vs 282/3946 — the
~13× smaller `.so` translates directly to less code for the fuzzer to
explore). Same wall-clock buys more invariant-checking depth.

## Required local prerequisite

Build the Anchor target program in the public bench repo first:

```bash
cd ~/src/pinocchio-bench
cargo build-sbf --manifest-path programs/anchor-w4-matching/Cargo.toml
```

`anchor_w4_matching.so` lands in
`~/src/pinocchio-bench/target/deploy/`.

## What this harness asserts

Layer 1 (generic invariants from solinv-core, work on any Anchor program):
- `signer-skip` — calling `place_order` without the declared `signer` AccountMeta as signer must fail
- `owner-skip` — passing accounts not owned by the program must fail
- `pda-forge` — `Market` / `Book` aren't PDAs (no `seeds` constraint), so this is currently a sanity check
- `unchecked-math` — `n_orders += 1` + `count += 1` + `market.sequence = saturating_add(1)` must not silently overflow
- `cu-dos` — `place_order` must stay under its declared 50K CU budget

Layer 2 (W4/W5-specific structural invariants, declared as `StateInvariant`
on the InstructionSpec):
- **Sequence monotonicity** — `market.sequence` is `NonDecreasing` across
  every `place_order` call (one of the 6 invariants from
  `pinocchio-bench/RESULTS.md`)

Inline custom checks (in this harness, not yet upstreamed to solinv-core):
- *Tick price-sort monotonicity* — `book.ticks[i].price < book.ticks[i+1].price`
  after every `place_order`, for `i < count - 1`
- *Order count consistency* — `book.count <= 32` and per-tick
  `n_orders <= 4`
- *Owner attribution* — newly placed order's `owner_pk` equals the
  signer's pubkey

These are domain-specific and not part of solinv-core's catalog of
generic Solana invariants — they ride on top of the harness as
post-action assertions.

## How this maps to the public artifact

`pinocchio-bench/RESULTS.md` lists the 6 invariants as a checklist that a
fuzzer "would attach." This example crate is that fuzzer attaching them
for real — kept in the private solinv repo until Phase 2.5 OSS launch.

The pairing that the [[project-pinocchio-rewrite-service]] wedge sells
("we rewrite hot paths in Pinocchio AND prove the rewrite preserves
invariants") is made concrete here: the public artifact shows the CU
savings; this private artifact shows the safety proof.

## Differential harness (`matching-diff/`)

The strongest demonstration of the wedge isn't "Anchor satisfies its
invariants" plus "Pinocchio satisfies its invariants" as independent
statements. It's: **for any input that both sides accept, both sides
produce the same state.**

`matching-diff/` loads both W4 `.so`s into one `TestContext`, uses the
same `user` keypair to sign both transactions (so the `owner_pk` field
written into Order slots matches across sides), and after every
fuzz-derived `place_order(price, qty)` asserts:

1. **Execution parity** — both transactions succeed or both fail. A
   divergence where one side accepts what the other rejects is a bug.
2. **Market body equivalence** — the 16-byte Market body
   (`sequence + side + pad`) is byte-identical, stripping Anchor's
   8-byte account discriminator from the Anchor side.
3. **Book body equivalence** — the 6,664-byte Book body
   (`count + pad + [Tick; 32]`) is byte-identical with the same
   discriminator shift.
4. **Sequence match** — narrowly verifies that
   `market.sequence` (first 8 bytes of body) increments identically.

### Smoke result (8s campaign, 2026-06-07)

```
3,136 executions
160,226 successful place_order actions (57.4% accepted by both sides)
0 crashes — no state divergence, no execution-parity violation
6.1% edge coverage / 10.9% branch coverage
```

The 16x10⁴ successful actions span the binary-search insertion path,
FIFO append within ticks, full-book rejection, and full-tick rejection.
Across all of them, **the Anchor W4 and Pinocchio W4 programs produce
byte-identical state**. That is the equivalence proof a paying customer
gets along with the CU savings.

### What this catches that single-side fuzz doesn't

- Pinocchio rewrite using `<` instead of `<=` in binary search → wrong
  insertion index → byte-divergence on Book account after first
  ambiguous order. A single-side harness with W4-style invariants would
  still see a well-sorted book (the broken rewrite is internally
  consistent) and miss it.
- Pinocchio rewrite forgetting to bump `market.sequence` → sequence
  field stays at 0 on the Pinocchio side → caught immediately.
- Endian mismatch on any u64 field → caught on the very first
  successful action.
- Off-by-one in `n_orders >= TICK_DEPTH` check → one side rejects what
  the other accepts → execution-parity violation.

### Running it

```bash
cd examples/pinocchio-bench-fuzz/fuzz/matching-diff
cargo build --release --features invariant_diff_smoke --bin invariant_test
./target/release/invariant_test
```

Features map to `#[invariant_test]` variants:
- `invariant_diff_smoke` — runs all checks
- `invariant_diff_execution_parity_only` — succeed/fail parity only
- `invariant_diff_state_equivalent_only` — body byte equality only
- `invariant_diff_sequence_match_only` — sequence counter only

A future extension is to lift the equivalence-comparison logic into
`solinv-fuzz` as a reusable trait (`DifferentialPair { anchor, pinocchio }`)
so AMM (W8), lending (W9), and other rewrite engagements can drop in
without re-implementing the body-strip-and-compare boilerplate.

## Other differential harnesses

### `amm-diff/` — W8 AMM constant-product swap

Drives `swap(amount_in, min_out)` through both `anchor_w8_amm.so` and
`pinocchio_w8_amm.so`. Per-side state: 1 zero-copy `Pool` account
(`reserve_in`, `reserve_out`, `fee_bps`) + 4 SPL `TokenAccount` accounts
(user-src, user-dst, pool-vault-in, pool-vault-out) per side. Shared
mints (mint_a, mint_b) and user keypair across sides so symmetric
SPL Token CPIs produce byte-comparable post-state.

Checks:
1. Execution parity (both succeed or both fail)
2. Pool body equivalence (24 bytes after stripping Anchor's discriminator)
3. Token-account equivalence — all 4 pairs byte-identical
4. Constant-product `k = reserve_in × reserve_out` non-decreasing per side
   (the fee makes it strictly increasing for any nonzero successful swap)

**Smoke result (8s campaign)**: 394 executions / 31,544 successful swap
actions (81.4% both-accepted) / 0 crashes / 0 state divergence.
Coverage: 10.7% edges / 19.7% branches — wider than W4 because the AMM
exercises constant-product math + SPL CPI paths.

### `refresh-diff/` — W9 lending refresh (Kamino shape)

Drives `refresh(current_slot)` through both `anchor_w9_refresh.so` and
`pinocchio_w9_refresh.so`. Per-side state: 5 mut zero-copy accounts —
obligation + 2 reserves + 2 oracles. No CPI in W9, so framework
overhead and math are the only cost — the cleanest differential target.

Checks:
1. Execution parity
2. Obligation body equivalence
3. Reserve body equivalence (both reserve_a and reserve_b)
4. Oracle body equivalence (both oracle_a and oracle_b)
5. `cumulative_borrow_rate` equivalence (isolated for orthogonal libafl reports)
6. `last_update_slot` equivalence on all 5 accounts

**Smoke result (15s wall pulse)**: 1,902 executions / 194,376 successful
refresh actions (100% accepted by both sides — refresh has no rejection
path) / 0 crashes / 0 state divergence. Coverage: 5.4% edges /
9.9% branches.

### `vault-diff/` — W10 vault deposit (Yearn / ERC4626 shape)

**First differential harness written using the `solinv-fuzz::differential`
trait from the start** — matching-diff, amm-diff, refresh-diff pre-date the
trait and were migrated afterward. vault-diff demonstrates the green-field
ergonomics: ~200 lines total, no inline body-compare boilerplate.

Drives `deposit(deposit_amount)` through both `anchor_w10_vault.so` and
`pinocchio_w10_vault.so`. Per-side state: 2 mut zero-copy (Vault +
UserPosition) + 2 SPL token accounts (user_underlying, vault_underlying).
The math under test is NAV-weighted share computation:
`shares = deposit × total_shares / total_assets` (with first-deposit 1:1
special case).

Checks:
1. Execution parity
2. Body equivalence across all 4 pairs (via `check_all_pairs(fixture)`)
3. NAV cross-product equality:
   `anchor.total_assets × pino.total_shares == pino.total_assets × anchor.total_shares`
   (integer-safe ratio comparison — pinpoints rounding bugs to the math
   itself rather than just registering "vault body diverged")

**Smoke result (15s wall pulse)**: 1,277 executions / 107,868 successful
deposit actions / 0 crashes / 0 state divergence. Coverage: 8.3% edges /
15.6% branches.

**Harness code pattern (use this for new surfaces)**:

```rust
impl DifferentialFixture for VaultDiffFixture {
    fn anchor_program_id(&self) -> Pubkey { self.anchor_program_id }
    fn pino_program_id(&self) -> Pubkey { self.pino_program_id }
    fn diff_pairs(&self) -> Vec<DiffAccountPair> {
        vec![
            DiffAccountPair::anchor_disc_8("vault", self.anchor_vault, self.pino_vault, W10_VAULT_BODY),
            DiffAccountPair::anchor_disc_8("user_position", self.anchor_user_position, self.pino_user_position, W10_USER_POSITION_BODY),
            DiffAccountPair::raw("user_underlying", self.anchor_user_underlying, self.pino_user_underlying, TOKEN_ACCOUNT_LEN),
            DiffAccountPair::raw("vault_underlying", self.anchor_vault_underlying, self.pino_vault_underlying, TOKEN_ACCOUNT_LEN),
        ]
    }
}

#[invariant_test]
fn invariant_vault_diff_smoke(fixture: &mut VaultDiffFixture) {
    if let Some(div) = check_all_pairs(fixture) {
        fuzz_assert!(false, "{}", div);
    }
    check_nav_match(fixture);            // surface-specific math invariant
    check_execution_parity(fixture);
}
```

That is the entire equivalence layer. W11/W12 differential harnesses
should follow this skeleton verbatim.

### `oracle-diff/` — W11 Pyth-style oracle publish

Second green-field-trait harness. Smallest possible surface: 1 mutable
zero-copy `PriceFeed` account, no CPI. `publish_price(new_price, new_conf,
new_slot)` enforces strict slot monotonicity and updates a 5-field EMA
struct with α = 1/8 smoothing.

Checks:
1. Execution parity (deterministic probes including stale-slot rejection)
2. Body equivalence (single pair via `check_all_pairs(fixture)`)
3. EMA field equivalence (surface-specific math invariant — pinpoints
   smoothing-formula bugs)
4. Publish count equivalence + sanity (`count > 0 ⇒ last_slot > 0`)

**Smoke result (25s elapsed, 15s wall pulse)**: 7,361 executions /
548,196 total actions / **47,562 successful publishes (8.7% ok rate)** /
0 crashes / 0 state divergence.

The 8.7% ok rate is the harness's strongest signal: random fuzz-derived
slots are usually non-monotonic, so 500K+ actions exercise the rejection
path. **Execution parity holds across all 500K** (no anchor-accepted /
pino-rejected pairs), and the 47K successful publishes verify EMA + slot
bump + publish_count atomicity is byte-identical between sides.

W11 is also the case study for "1 mutable zero-copy state, no CPI" — the
smallest possible differential surface but a high-value target because
oracle programs are the highest-frequency hot paths in DeFi (many feeds
publish every Solana slot ≈ 400ms). The W11 bench measured the CU gap at
Δ=867 — closely matching the W3a 1-mut-zero-copy law (Δ=847) and
confirming that EMA math adds only ~20 CU to the framework-cost floor.

### `perp-diff/` — W12 Drift-style perp open_position

Phase 0's final harness. Largest combined surface in the bench: 5 pairs
(3 mut zero-copy + 2 SPL token accounts) backed by `open_position` with
margin check + fee compute + oracle propagation + 1 SPL CPI.

Checks:
1. Execution parity
2. Body equivalence across all 5 pairs (via `check_all_pairs(fixture)`)
3. Open-interest match: both sides' `perp_market.open_interest` agree,
   and each equals that side's `user.position_size` (single-user fixture)
4. Margin invariant: post-state must satisfy
   `collateral × max_leverage_bps / 10_000 ≥ position_size`

**Smoke result (15s wall pulse)**: 4,832 executions / 273,330 total
actions / 9,664 successful opens (3.5% ok rate) / 0 crashes /
0 state divergence.

The 3.5% ok rate is structural: random fuzz-derived `position_size`
values in 1..100M usually exceed the 99M post-fee margin limit, and
the double-open protection rejects every subsequent call once the
position is open. The 263K rejections all show execution parity (both
sides reject identically); the 9,664 successful opens all show
byte-identical post-state.

#### Caught a real W12 spec bug during build-out

The first version of W12 checked margin **before** debiting the fee.
The `check_margin_invariant` post-state check fired immediately:

```
anchor margin invariant violated:
  collateral=9,900,001 × leverage_bps=100,000 / 10,000 = 99,000,010
  < position_size=99,999,996
```

Both Anchor and Pinocchio implementations had the same flaw (so the
body-equivalence half was clean), but the spec was wrong: an
attacker could open a position at the maximum pre-fee margin, then
end up undermargined immediately by the fee debit.

Real Drift / dYdX / Hyperliquid all check margin **after** fee
debits — solvency must hold against the actual reserve a user has
after costs. W12 was rewritten to compute and debit the fee first,
then check margin against post-fee collateral. After the fix
(both sides updated), perp-diff smoke ran clean.

**This is exactly the failure mode the wedge sells against**: a
Pinocchio rewrite that drops the margin check (or moves it back
pre-fee for "performance") would reproduce the bug. The differential
harness catches it before the rewrite ships.

The math W9 exercises includes `saturating_sub` against arbitrary
fuzz-derived `current_slot` values (including ones that would cause
overflow if not handled), and `cumulative_borrow_rate` accumulates via
`saturating_add` over the campaign to test the saturation path itself.

## Cumulative differential proof (W4 + W8 + W9 + W10 + W11 + W12)

| Surface | Workload shape                    | Actions exercised | Divergence |
| ------- | --------------------------------- | ----------------: | ---------: |
| W4      | Orderbook place_order             |           160,226 |          0 |
| W8      | AMM constant-product swap         |            31,544 |          0 |
| W9      | Lending refresh (5 mut accts)     |           194,376 |          0 |
| W10     | Vault deposit (NAV-weighted)      |           107,868 |          0 |
| W11     | Oracle publish (EMA + slot check) |            47,562 |          0 |
| W12     | Perp open_position (3 zc + 2 SPL + 1 CPI) | 9,664       |          0 |
| **Σ**   |                                   |       **551,240** |      **0** |

Across six of the highest-value Solana DeFi hot-path shapes (orderbook,
AMM, lending, vault, oracle, perp), **the Anchor and Pinocchio rewrites
produce byte-identical state under randomized inputs**. Combined with the CU-savings numbers
quantified by the public `pinocchio-bench` (W4: 1,177 CU saved per
place_order; W8: 4,955 CU saved per swap; W9: 2,271 CU saved per
refresh), this is the rewrite-and-prove wedge demonstrated end-to-end
on three independent surfaces.

## Planted-bug acceptance — W4 matching (`programs/anchor-w4-buggy/` + `fuzz/matching-buggy/`)

A 0-divergence smoke run only proves the wedge if the harnesses would
have caught a divergence had one existed. Following the escrow-demo
discipline, this example crate carries an intentionally buggy variant of
the W4 matching-engine program plus a paired acceptance harness that
verifies each W4 invariant variant actually fires on its target bug. The
same discipline is repeated for W8 AMM and W9 refresh below.

### The four planted bugs (`programs/anchor-w4-buggy/src/lib.rs`)

All four are permanent in the buggy source — no cargo gating in the
program itself. Each is annotated with `// ----- PLANTED BUG X (...)`
comments referencing the invariant that catches it:

| Bug | Plant                                                  | Targets                          |
| --- | ------------------------------------------------------ | -------------------------------- |
| A   | Insert at `count` instead of binary-search `lo`        | tick-sort monotonicity           |
| B   | New tick written with `n_orders: 5` (> `TICK_DEPTH=4`) | count consistency                |
| C   | `market.sequence` flip-flops 0 ↔ 1 across calls        | sequence monotonicity            |
| D   | `Order.owner_pk` written as `[0u8; 32]`                | owner attribution                |

### Acceptance results (2026-06-07)

| Variant feature                          | Catches | Hits  | Time to first hit |
| ---------------------------------------- | ------- | ----: | ----------------- |
| `invariant_tick_sort_only`               | Bug A   | 7,660 | sub-second        |
| `invariant_count_consistency_only`       | Bug B   | 3,420 | sub-second        |
| `invariant_sequence_monotonic_only`      | Bug C   | 9,476 | sub-second        |
| `invariant_owner_attribution_only`       | Bug D   | 5,668 | sub-second        |

Each smoke run was 7–14 seconds wall-clock. Every variant produced
thousands of violation hits with reproducible 1–3 instruction crash
inputs landed in `crashes/invariant_*/`. Bug C uses solinv-core's
`StateInvariant::Monotonic` machinery (driven by the unchecked-math
transition pass); Bugs A/B/D are caught by the inline structural
checks declared at the top of the harness.

Example findings the harness emits:

```
tick-sort violated at tick[2]: prices 612927289 -> 3 not strictly increasing
tick[0].n_orders overflowed TICK_DEPTH=4: got 5
ix place_order violated state invariant 'market_sequence_monotonic':
  account 0 decreased (pre 1, post 0)
owner-attribution violated at tick[0].orders[0]: pk=[0;32] (expected user)
```

### Running it

```bash
# 1. Build the buggy program (separate cargo workspace under examples/)
(cd examples/pinocchio-bench-fuzz/programs/anchor-w4-buggy && cargo build-sbf)

# 2. Build and run the acceptance harness with one variant
cd examples/pinocchio-bench-fuzz/fuzz/matching-buggy
cargo build --release --features invariant_tick_sort_only
./target/release/invariant_test            # fires within seconds

# Repeat with each of the four `_only` features to verify all bugs caught.
```

### What this establishes for the cumulative proof

The matching/, matching-pino/, matching-diff/, amm-diff/, refresh-diff/,
vault-diff/, and oracle-diff/ harnesses' silence on clean code is now
*meaningful*: it isn't the harnesses being mis-wired and missing things,
it's the production code actually satisfying the invariants. The
planted-bug acceptance establishes the floor — no false negatives on
these four representative bug shapes — that gives the cumulative
0-divergence result above its weight on the W4 surface.

The same discipline applied to W8 AMM and W9 refresh surfaces appears
below.

## Planted-bug acceptance — W8 AMM (`programs/anchor-w8-buggy/` + `fuzz/amm-buggy/`)

Two bugs planted in the W8 swap path. Both permanent in source; both
designed so the plants don't interact (Bug A only affects the
output-side reserves; Bug B inflates reserve_in by a constant +1, small
enough not to mask Bug A's k-drop).

### The two planted bugs (`programs/anchor-w8-buggy/src/lib.rs`)

| Bug | Plant                                                                | Targets                                |
| --- | -------------------------------------------------------------------- | -------------------------------------- |
| A   | `amount_out` doubled (`reserve_out * fee_in * 2 / denom`)             | constant-product k non-decreasing      |
| B   | `pool.reserve_in = reserve_in + amount_in + 1` (constant +1 inflation) | reserve ↔ vault delta consistency      |

### Acceptance results (2026-06-07)

| Variant feature                                  | Catches | Hits  | Example finding                                                                  |
| ------------------------------------------------ | ------- | ----: | -------------------------------------------------------------------------------- |
| `invariant_k_non_decreasing_only`                | Bug A   | 2,304 | `k_pre=2×10¹² → k_post=1.999×10¹² (reserve_in_post=1000439, reserve_out_post=1998257)` |
| `invariant_reserve_vault_consistent_only`        | Bug B   | 5,945 | `reserve_in/vault_in drift: Δreserve=103 vs Δvault=102` (the +1 inflation surfaced cleanly) |

Both ran ~7–9 second wall-clock smoke campaigns at ~467 / ~814 exec/sec.

### Plant-design lesson learned

The first attempt planted Bug B as `reserve_in + 2 × amount_in` (double-credit).
That interacted with Bug A: the inflated reserve_in compensated for the
doubled amount_out drop in `k = reserve_in × reserve_out`, and k often
*increased* across the buggy swap rather than decreased. Bug A's invariant
silently passed.

Re-planted Bug B as a constant `+ 1` so its reserve_in inflation can't mask
Bug A's k-drop while still producing a 1-unit delta the reserve-vault
check picks up on every call. This is the same lesson the W4 plants
flushed (Monotonic only fires on actual decrease, tick-sort only fires
on multi-tick non-monotonic state) — **AMM-class plants need explicit
non-interaction reasoning across the planted bugs**.

## Planted-bug acceptance — W9 refresh (`programs/anchor-w9-buggy/` + `fuzz/refresh-buggy/`)

Two bugs planted in the W9 lending refresh. The plants target independent
fields (one touches reserve_a, the other touches obligation) so no
interaction reasoning is needed.

### The two planted bugs (`programs/anchor-w9-buggy/src/lib.rs`)

| Bug | Plant                                                | Targets                                       |
| --- | ---------------------------------------------------- | --------------------------------------------- |
| A   | `reserve_a.last_update_slot = current_slot` skipped  | reserve slot tracks the passed `current_slot` |
| B   | `obligation.last_health = 0` forced                  | health positive when collateral + debt > 0    |

### Acceptance results (2026-06-07)

| Variant feature                            | Catches | Hits  | Example finding                                                                                  |
| ------------------------------------------ | ------- | ----: | ------------------------------------------------------------------------------------------------ |
| `invariant_reserve_slot_tracks_only`       | Bug A   | 9,660 | `reserve_a.last_update_slot stale: passed current_slot=421215 but reserve_a.last_update_slot=0`  |
| `invariant_health_positive_only`           | Bug B   | 9,632 | `obligation.last_health = 0 despite deposit_amount=1000000 > 0 and oracle_a price > 0`           |

Both ran ~7 second smoke campaigns at **~1,300 exec/sec** — the W9 surface
has no SPL CPI, so the harness loops far faster than W8.

## Planted-bug acceptance — W10 vault (`programs/anchor-w10-buggy/` + `fuzz/vault-buggy/`)

Two bugs planted in the W10 NAV-weighted deposit path. Plants target
independent field families (shares vs. assets) so they don't interact.
Bug B uses the same constant-`+1` pattern as W8's reserve-vault drift,
applied here to vault.total_assets so it can't mask Bug A's
share-supply consistency check.

### The two planted bugs (`programs/anchor-w10-buggy/src/lib.rs`)

| Bug | Plant                                                       | Targets                            |
| --- | ----------------------------------------------------------- | ---------------------------------- |
| A   | `user_position.share_amount += shares` skipped              | share supply consistency           |
| B   | `vault.total_assets += deposit_amount + 1` (constant +1)    | assets ↔ vault delta consistency   |

### Acceptance results (2026-06-08)

| Variant feature                              | Catches | Hits  | Example finding                                                                                                       |
| -------------------------------------------- | ------- | ----: | --------------------------------------------------------------------------------------------------------------------- |
| `invariant_share_supply_consistent_only`     | Bug A   | 8,380 | `share-supply drift: Δvault.total_shares=65537 vs Δuser_position.share_amount=0`                                       |
| `invariant_assets_vault_consistent_only`     | Bug B   | 7,948 | `assets/vault drift: Δvault.total_assets=2 vs Δvault_underlying.amount=1` (the +1 inflation surfaced cleanly)          |

Both ran ~7 second smoke campaigns at **~1,100 exec/sec** — between W8
(SPL-CPI-bound, ~470-810/sec) and W9 (no CPI, ~1,300/sec), as expected
for a single SPL transfer per call.

## Planted-bug acceptance — W11 oracle (`programs/anchor-w11-buggy/` + `fuzz/oracle-buggy/`)

Two bugs planted in the W11 EMA price-publish path. Plants target
independent fields (`feed.last_slot` vs `feed.publish_count`) so no
interaction reasoning is needed. Bug B uses the same flip-flop pattern
as W4 Bug C — the bug must produce a strict decrement to fire a
strictly-increases check, not merely "fail to bump."

### The two planted bugs (`programs/anchor-w11-buggy/src/lib.rs`)

| Bug | Plant                                                | Targets                                          |
| --- | ---------------------------------------------------- | ------------------------------------------------ |
| A   | `feed.last_slot = new_slot` skipped                  | last_slot tracks the passed `new_slot`           |
| B   | `feed.publish_count` flip-flops 0 ↔ 1 across calls   | publish_count strictly increases per successful publish |

### Acceptance results (2026-06-08)

| Variant feature                                       | Catches | Hits  | Example finding                                                                  |
| ----------------------------------------------------- | ------- | ----: | -------------------------------------------------------------------------------- |
| `invariant_last_slot_tracks_only`                     | Bug A   | 9,182 | `feed.last_slot stale: passed new_slot=1 but feed.last_slot=0 after publish_price` |
| `invariant_publish_count_strictly_increases_only`     | Bug B   | 9,863 | `feed.publish_count failed to strictly increase: pre=1 post=0`                    |

Both ran ~6-7 second campaigns at **~1,450 exec/sec** — the fastest
acceptance surface in the suite. PriceFeed is a single account, no CPI,
no large state body, no complex math. Each invariant fires on the very
first call (Bug A) or the second call (Bug B's flip-flop down-step).

### Cumulative acceptance floor

| Surface | Planted bugs | Hits to first violation         | Total hits across all variants in ~7-14s |
| ------- | -----------: | ------------------------------- | ---------------------------------------: |
| W4      |            4 | sub-second on all 4             |                                   26,224 |
| W8      |            2 | sub-second on both              |                                    8,249 |
| W9      |            2 | sub-second on both              |                                   19,292 |
| W10     |            2 | sub-second on both              |                                   16,328 |
| W11     |            2 | sub-second on both              |                                   19,045 |
| **Σ**   |       **12** |                                 |                              **89,138**  |

Twelve distinct invariant variants across **five** of the highest-value
Solana DeFi hot-path shapes (matching, AMM, lending, vault, oracle),
each catching its target bug in thousands-of-hits volumes in under 15
seconds. The acceptance floor now spans the same surfaces that the
W4 + W8 + W9 + W10 + W11 differentials cover, so every 0-divergence
cumulative claim has a corresponding "and the harness would have caught
a real divergence too" floor for the same surface.

Remaining cumulative-proof gaps to close:
- **W12 perp** acceptance harness — same discipline, perp-shaped bugs
  (position-size accounting, funding rate accumulation, liquidation
  threshold). The perp-diff harness already exists; only the buggy
  variant + acceptance fixture remain.
- **Lifting acceptance into `solinv-fuzz`.** Seven buggy harnesses now
  share the same shape: `pre_*` snapshot fields + `last_*_succeeded`
  gate + inline pre/post delta checks. Could abstract into a
  `BuggyFixture` trait companion to `DifferentialFixture`. Pure
  maintenance simplification.

## Pinocchio-side planted-bug acceptance — W4 + W11

The W4-W11 buggy programs above are all Anchor-side: they're modified
copies of the `anchor-w*` source. Useful for proving the harnesses fire
on Anchor-shaped logic bugs, but they don't exercise the bug class the
[[project-pinocchio-rewrite-service]] wedge actually promises to catch
on a paid engagement — the **rewrite-class** bugs introduced when an
Anchor program is migrated to Pinocchio.

The two new programs `programs/pinocchio-w4-buggy/` and
`programs/pinocchio-w11-buggy/` close that gap. Their plants are
derived from the public `pinocchio-w*` sources (not the Anchor ones)
and include at least one bug per surface that is **specific to the
manual safety obligations a Pinocchio rewriter takes on** — checks
Anchor enforced for free that the rewriter must remember to write by
hand. Paired acceptance harnesses live at
`fuzz/matching-pino-buggy/` and `fuzz/oracle-pino-buggy/`.

### `programs/pinocchio-w4-buggy/`

| Bug | Plant                                                        | Targets                                              |
| --- | ------------------------------------------------------------ | ---------------------------------------------------- |
| A   | `if !signer.is_signer() { return Err(...); }` removed         | rewrite-class: solinv-core `signer_skip` invariant    |
| B   | Insert at `count` ignoring binary-search `lo`                | structural: inline tick-sort monotonicity            |

Bug A is the modal Pinocchio-rewrite bug — the rewriter forgets the
manual signer check that Anchor's `Signer<'info>` extractor would have
enforced for free. solinv-core's `signer_skip` fuzzer-driven invariant
catches it by sending a duplicate of `place_order` with the
`is_signer` flag cleared on the declared signer AccountMeta and
asserting that the program rejects the call.

### Acceptance results (2026-06-08)

| Variant feature                          | Catches | Hits  | Example finding                                                                                                |
| ---------------------------------------- | ------- | ----: | -------------------------------------------------------------------------------------------------------------- |
| `invariant_signer_skip_only`             | Bug A   | 8,913 | `ix place_order succeeded with is_signer=false on account 0 ... state hash 5024…830 → 11501…161`               |
| `invariant_tick_sort_only`               | Bug B   | 9,518 | `tick-sort violated at tick[1]: prices 866452775 -> 65537 not strictly increasing`                              |

Both ran ~6-7 second campaigns at **~1,400-1,550 exec/sec** — the
Pinocchio binary's smaller code surface (30/276 edges vs the Anchor
buggy's 109/1946) keeps the fuzzer's coverage explorer in the
program's hot loop instead of in framework boilerplate.

### `programs/pinocchio-w11-buggy/`

| Bug | Plant                                                  | Targets                                              |
| --- | ------------------------------------------------------ | ---------------------------------------------------- |
| A   | `if !publisher.is_signer() { return Err(...); }` removed | rewrite-class: solinv-core `signer_skip` invariant    |
| B   | `feed.last_slot = new_slot` skipped                    | structural: inline last_slot tracks `new_slot`       |

### Acceptance results (2026-06-08)

| Variant feature                          | Catches | Hits  | Example finding                                                                          |
| ---------------------------------------- | ------- | ----: | ---------------------------------------------------------------------------------------- |
| `invariant_signer_skip_only`             | Bug A   | 9,058 | `ix publish_price succeeded with is_signer=false on account 0`                            |
| `invariant_last_slot_tracks_only`        | Bug B   | 9,216 | `feed.last_slot stale: passed new_slot=1 but feed.last_slot=0 after publish_price`        |

Both ran ~6 second campaigns at **~1,400 exec/sec**.

### What this establishes for the wedge

Bugs A on both surfaces are the *exact* bug class the rewrite-and-prove
service exists to catch: an Anchor invariant (the implicit `Signer<>`
check) that the rewriter must remember to re-implement by hand. The
solinv-core `signer_skip` invariant catches it deterministically in
sub-second TTFF on both surfaces.

This closes the most-defensible gap in the cumulative proof. The pitch
story now reads end-to-end *for Pinocchio rewrites specifically*:

1. Public bench measures the CU savings (W4: 1,177 CU; W11: lighter still).
2. Per-side invariants pass on the rewrite (`matching-pino/`).
3. Differential proves byte-equivalence with the Anchor original
   (`matching-diff/` + four siblings, ~541K actions / 0 divergence).
4. Acceptance floor proves the harnesses *would* fire on real bugs —
   on **both** Anchor source patterns AND on Pinocchio-rewrite source
   patterns. The same invariants catch the same modal bug shapes
   regardless of which side of the rewrite line the bug landed on.

Extended cumulative acceptance floor across both bug-source families:

| Source family   | Surfaces | Planted bugs | Total hits in 6-14s |
| --------------- | -------: | -----------: | ------------------: |
| Anchor-side     |        5 |           12 |              89,138 |
| Pinocchio-side  |        2 |            4 |              36,705 |
| **Σ**           |    **7** |       **16** |         **125,843** |
