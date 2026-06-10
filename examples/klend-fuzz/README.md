# klend-fuzz — Anchor zero-copy infrastructure example

Kamino klend (Anchor 0.29 zero-copy lending) harness covering all five
Critical invariants. Phase 2 Days 22-27 built the infrastructure —
fixture, mirror structs, `init_reserve` raw_call, post-init byte-poke —
across one of five planned ix (`deposit_reserve_liquidity`).

**Honest framing**: this is **not** "klend has no bugs". This is
"klend infrastructure proven, fuzz depth gated by `ReserveConfig`
setup". The baseline `deposit_reserve_liquidity` fails at
`ok: 0/79,278 (0%)` even after `init_reserve` + `status=Active` +
`deposit_limit=100M`. The next layer of blockers (LTV, liquidation
thresholds, borrow factor, oracle config, fees) was acknowledged as
diminishing-returns at Day 27.

See the Day 22-27 implementation logs (`docs/phase2-day2{2..7}-klend-*.md`)
for the build trajectory.

## Why this example exists

Two reasons:

1. **Reusable patterns**. Days 22-27 produced five
   reusable patterns documented in the retrospective: harness
   scaffold, `#[repr(C)]` mirror + `offset_of!`, Anchor zero-copy
   discriminator handling, `init_*` raw_call pattern, post-init
   byte-modify. Future Anchor zero-copy protocols (lending, perps)
   reuse these directly.
2. **Cost-of-entry documentation**. For any contributor considering a
   complex Anchor zero-copy lending program, this harness is a
   realistic 5-7-day-of-work reference point.

## License + non-production posture

klend is **BUSL-1.1** (Kamino-Finance/klend). Solinv local fuzz
research = non-production = compliant. The harness does **not**
redistribute klend source; klend is cloned separately by the user.
Change Date 2027-11-17 converts klend to GPL-2.0.

## External program dependency

Clone klend separately:

```bash
git clone https://github.com/Kamino-Finance/klend.git ~/src/klend
```

Build the SBF program. **Specific toolchain workaround required** —
`solana-frozen-abi 1.17.18` pins `ahash =0.8.5` which is broken on
Rust 1.78+:

```bash
cd ~/src/klend/programs/klend
SDKROOT=$(xcrun --show-sdk-path) \
CFLAGS="-isysroot $(xcrun --show-sdk-path)" \
cargo build-sbf --tools-version v1.39
```

Produces `~/src/klend/target/deploy/kamino_lending.so`. The harness
loads it via absolute path — see `KLEND_SO_PATH` in
`fuzz/klend/src/main.rs`.

## Layout

```
klend-fuzz/
└── fuzz/klend/
    ├── Cargo.toml          # opt-out of solinv workspace
    └── src/main.rs         # KlendFixture + 4 mirror structs + InstructionSpec
```

Mirror structs declared with `#[repr(C)]` and compile-time
`size_of::<...>()` assertions matching upstream's
`static_assertions::const_assert_eq!`:

| Mirror | Upstream size | Verified at |
|---|---|---|
| `LendingMarketMirror` | 4,664 bytes | compile time |
| `ReserveLiquidityMirror` | 1,232 bytes | compile time |
| `ReserveCollateralMirror` | 1,096 bytes | compile time |
| `ReserveMirror` | 8,616 bytes | compile time |
| `ReserveConfigMirror` | 944 bytes | compile time |

Field offsets via `std::mem::offset_of!()`. Compile-time-verified, no
manual byte counting.

## Wire format

Standard Anchor 0.29:

- ix discriminator: `data[0..8] = sha256("global:<ix_name>")[..8]`
  (snake_case)
- args: Borsh-encoded after discriminator
- account discriminator: `account.data[0..8] = sha256("account:<TypeName>")[..8]`
  (PascalCase)

Solinv's Day 15 `ix_sighash` helper and `raw_call` pattern apply
directly without modification. This is the canonical use case the
Day 15 refactor was designed for.

## Run

```bash
cd ~/src/solinv/examples/klend-fuzz

crucible run klend invariant_account_swap_only --release --timeout 30 -j 2
```

Expected behavior: **baseline `ok` ratio near 0%**. The infrastructure
is correct (no panics across 977 init_reserve iterations Day 26, 801
byte-poke iterations Day 27), but the handler rejects the call before
reaching the surface solinv's invariants would attack. Closing this
gap requires either:

- Full `ReserveConfig` defaults (LTV, liquidation thresholds, borrow
  factor, fees) — ~2-3 days of mechanical work
- Or oracle setup (Scope / Pyth) — variable effort

Neither was completed in Phase 2.

## What this is good for today

- **Pattern reference** — copy the mirror-struct + `offset_of!`
  pattern for any other Anchor zero-copy program.
- **`init_*` raw_call template** — see
  [`docs/harness-pattern-raw-call.md`](../../docs/harness-pattern-raw-call.md).
- **Cost calibration** — if you're planning a new Anchor zero-copy
  protocol harness, budget 5-7 days; Native is more like 4.

## What this is **not** good for today

- Submitting bug bounty reports — fuzz did not reach the
  account-validation surface at depth.
- Demonstrating klend security posture — the absence of detections is
  a coverage limit, not a security claim.
