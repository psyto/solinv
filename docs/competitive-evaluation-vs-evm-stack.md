# solinv vs EVM Fuzzer/Invariant Stack — Competitive Evaluation

Date: 2026-05-25 (Phase 1 Day 13, end of session arc)
Status: Honest assessment of solinv (Critical 5/5 detecting) vs full
EVM tooling stack (Echidna / Medusa / Foundry / Halmos / Certora /
ItyFuzz / Diligence) and Solana peers (Crucible / Trident / Fidesium /
sol-azy).

## TL;DR

solinv is **"Echidna 2020 class + Medusa engine + Solana-specific
auto-invariants"** — a rare combination. Engine performance reaches
Medusa parity via Crucible inheritance. Symbolic execution and formal
verification (Halmos / Certora territory) is **completely absent**.

Cannot match 5-8 years of EVM ecosystem accumulation, but the
**Solana-specific auto-detection wedge does not exist in any EVM
tool** — placing solinv as a parallel-axis competitor rather than
direct successor.

For Phase 2: focus on real-bug-hunt revenue from the auto-detection
wedge. Symbolic execution / FV are Phase 3+ separate products.

## Tools compared

### EVM stack

| Tool | Vintage | Position |
|---|---|---|
| **Echidna** | 2019 (5+ yrs) | De facto property-based fuzzer (Trail of Bits, AGPL, Haskell). Manual invariants |
| **Medusa** | 2023 (3 yrs) | Coverage-guided next-gen Echidna successor (ToB, AGPL, Go) |
| **Foundry invariant** | 2022 (4 yrs) | Stateful invariant testing integrated into Foundry dev workflow (Paradigm, MIT/Apache) |
| **Halmos** | 2023 (3 yrs) | Symbolic execution / bounded model checker (a16z, AGPL, Python) |
| **Certora** | 2018 (8 yrs) | Commercial formal verification platform (Aave, MakerDAO, Compound use it) |
| **ItyFuzz** | 2023 | Research hybrid concolic + dataflow fuzzer |
| **Diligence Fuzzing** | 2020 | Commercial cloud fuzzer (ConsenSys) |

### Solana stack

| Tool | Vintage | Position |
|---|---|---|
| **Trident** | 2022-2026 (4 yrs) | Ackee Blockchain Security, MIT, Anchor-centric, manual `#[flow]` invariants |
| **Crucible** | 2026-04-30 (1 mo) | Asymmetric Research, MIT, LibAFL + LiteSVM + sBPF coverage |
| **Fidesium** | 2026 Q1 (5 mo) | Commercial closed SaaS, "5x faster LiteSVM fuzzer" |
| **sol-azy** | 2025 (1 yr) | FuzzingLabs, static analyzer (different category) |
| **solinv** | 2026-05-25 (13 days) | Auto-invariant catalog plugin on Crucible, this project |

## Feature comparison matrix

Legend: ✅ full / 🟡 partial / ❌ absent / — N/A for category

| Capability | Echidna | Medusa | Foundry inv | Halmos | Certora | Crucible | Trident | **solinv** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Coverage-guided fuzz | 🟡 | ✅ | ✅ | — | — | ✅ | 🟡 | ✅ (via Crucible) |
| LibAFL-class mutation | ❌ | ✅ | ✅ | — | — | ✅ | ❌ | ✅ |
| Property-based invariants | ✅ | ✅ | ✅ | — | ✅ | ✅ (manual) | ✅ (manual) | ✅ (manual + auto) |
| **Auto-detected invariants** | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | **✅ 5 Critical** |
| Stateful sequence fuzzing | 🟡 | ✅ | ✅ | — | — | ✅ | ✅ | ✅ |
| Shrinker / minimization | ✅ | ✅ | ✅ | — | — | ✅ | 🟡 | ✅ (via Crucible) |
| Coverage reporting (LCOV) | 🟡 | ✅ | ✅ | — | — | ✅ | 🟡 | ✅ (via Crucible) |
| Cheatcodes (warp / impersonate) | ❌ | 🟡 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (via Crucible) |
| Mainnet fork seeding | ❌ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | 🟡 (corpus crate skeleton) |
| Multi-worker scaling | ✅ | ✅ | ✅ | — | — | ✅ | 🟡 | ✅ (validated -j 2 = 1.7x) |
| **Symbolic execution** | ❌ | ❌ | 🟡 | **✅** | **✅** | ❌ | ❌ | ❌ |
| **Formal verification** | ❌ | ❌ | ❌ | 🟡 | **✅** | ❌ | ❌ | ❌ |
| Differential fuzz (multi-client) | ❌ | ❌ | ❌ | — | — | ❌ | ❌ | ❌ |
| Bug-bounty disclosure formatter | ❌ | ❌ | ❌ | — | — | ❌ | ❌ | 🟡 (skeleton crate) |
| MEV-aware fuzzing | ❌ | ❌ | 🟡 | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Vintage / accumulation** | 5+ yrs | 3 yrs | 4 yrs | 3 yrs | 8 yrs | 1 mo | 4 yrs | **13 days** |
| **Production adoption** | high | medium | high | medium | enterprise | early | medium | **0** |

## Where solinv leads

### 1. Solana-specific bug class auto-detection (decisive moat)

**NO EVM fuzzer auto-detects bug classes** — all require manual
invariant authoring:

| Tool | Manual API |
|---|---|
| Echidna | `function echidna_property_*()` |
| Medusa | `assert*` / `property_*` |
| Foundry | `function invariant_*()` |
| Halmos | `check_*` symbolic functions |
| Certora | CVL spec files |

**solinv catches 5 bug classes with zero user authoring**:
- signer-skip, owner-skip, discriminator-skip, pda-forge, account-swap

These are "Solana programs should universally check this" patterns
that audit firms manually review. Auto-detection at zero marginal
cost per check.

This is not a feature EVM tools deliberately skipped — it's a feature
that EVM's model (no account/owner distinction, no PDA derivation, no
discriminator convention) makes inapplicable. solinv competes on a
**parallel axis** EVM tools cannot enter.

### 2. Crucible plugin pattern (smaller surface)

EVM tools (Echidna/Medusa/Foundry) bundle engine + DSL + reporting in
heavy artifacts. solinv is a **lightweight invariant library on top of
Crucible** — smaller maintenance surface, easier adoption, easier
integration with future engine improvements.

### 3. Detection latency (empirically observed)

Day 13 measurements across 5 isolated test campaigns:

| Invariant | exec/sec | Violation rate | First-detect latency |
|---|---|---|---|
| signer-skip | ~500 | high | seconds |
| owner-skip | 924 | ~100% | seconds |
| discriminator-skip | ~530 | high | seconds |
| pda-forge | 1512 | ~20% | seconds |
| account-swap | 1267 | ~100% | seconds |

For comparison: typical Echidna campaigns require 10-60 min to find
specific bugs. solinv's auto-detection makes the time-to-first-find
near-instant for the bug classes it knows about.

## Where solinv lags

### 1. Symbolic execution (Halmos / Certora)

- **Halmos**: bounded model checking. Proves properties hold for all
  inputs within bounded ranges
- **Certora**: full formal verification with proof certificates. Used
  by Aave, Compound, MakerDAO for production-grade assurance
- **solinv: completely absent**

EVM-side high-value protocols stack **fuzz + symbolic + FV** as
defense in depth. solinv only delivers 1/3 of this stack.

### 2. Ecosystem accumulation (5-8 years)

- Echidna: 5 years, hundreds of production bug discoveries
- Foundry invariant: 4 years, de facto standard in Solidity dev
- Certora: 8 years, institutional adoption (banks, large protocols)
- **solinv: 13 days, track record zero**

Time-based gap; only closeable with time + adoption + real bug finds.

### 3. Ecosystem integration

- Foundry: forge / cast / anvil integrated workflow
- Echidna / Medusa: Slither (static) + Crytic-compile pipeline
- Certora: CI/CD integration, incident response workflows
- **solinv: runs only via Crucible CLI, no standalone dev tooling**

### 4. Mutation strategy sophistication

- Foundry: dictionary mutation, value mining from past transactions
- Medusa: handler-based stateful narrowing
- ItyFuzz: concolic execution with dataflow analysis
- **solinv: LibAFL defaults inherited via Crucible, not optimized**

### 5. MEV-aware / cross-chain primitives

- Some EVM tools have MEV-aware modes (`vm.txGasPrice` etc.)
- **solinv: Jito bundle / MEV completely unimplemented**

### 6. Enterprise audit reporting

- Echidna / Medusa: detailed call traces + reproduction artifacts
- Certora: formal proof certificates for compliance
- **solinv: Crucible output + custom violation message; no enterprise
  report format**

## 4-dimensional strategic positioning

### A. EVM-parallel axis (same niche, different ecosystem)

**solinv ≈ Echidna 2020 + Medusa engine + Solana-specific auto-invariants**

- Feature count: lower than Echidna (partial auto-invariants offset)
- Maturity: vastly lower (13 days vs 5+ years)
- **Judgment**: Reaching full Echidna feature parity in Solana would
  take 3-5 years. For now, solinv is a targeted niche tool

### B. Solana-internal competition (the real fight)

- **Crucible** (engine, 1 month): solinv is plugin layer, not a competitor
- **Trident** (4 years, Anchor-centric): solinv has auto-invariants + Crucible engine = **functionally ahead**
- **Fidesium** (closed): no market comparison possible
- **Judgment**: In Solana OSS fuzzer market, solinv has **immediate
  competitive position** via the auto-invariants wedge

### C. Investment efficiency (this session)

- 13 days → Critical 5/5 auto-detecting end-to-end
- EVM equivalent: "Echidna achieved basic property fuzzing in 5 years;
  solinv achieved 5-class auto-detection in 13 days"
- Caveat: solinv detection range is limited to 5 Solana-specific
  classes vs Echidna's universal property fuzzing
- **Judgment**: Investment efficiency is excellent because scope was
  deliberately narrow

### D. Future ceiling

- Auto-invariant catalog: 5 → 17 (baseline) → 20 (stretch) feasible
- Symbolic execution: post-Phase 3+ separate product ("Halmos for
  Solana"). 6-12 months for usable prototype
- Accumulation gap: 5-7 year horizon for Echidna/Medusa parity
- Certora-level FV: out of scope (one-person project can't reach this)
- **Judgment**: 5-7 year horizon viable for non-FV parity; FV territory
  belongs to different organization scale

## Phase 2 implications

> **Update 2026-05-25 (post-landscape verification)**: Original "Drift / Marginfi / Kamino / Jupiter" target list invalidated by Drift hack (Apr 2026) + Marginfi rebrand to Project 0 + Adrena maintenance mode. See [phase2-target-ranking.md](phase2-target-ranking.md) for current Phase 2 ranking (Kamino #1 → Raydium #2 → Save #3 → ...).

| Strategy | Recommendation |
|---|---|
| **Track B: production bug hunt** | ✅ **STRONG GO**. Auto-invariant wedge only generates revenue when run on real protocols. Current target ranking: Kamino → Raydium → Save → Wormhole → Meteora → Jito (see phase2-target-ranking.md) |
| **Track C: High tier catalog expansion** | 🟡 Run in parallel. Real-hunt feedback will tell us which High invariants are highest-value (cpi-reentrancy? cu-dos? unchecked-math?) |
| **Symbolic execution work** | ❌ NOT YET. Phase 3+ separate product. Estimated 6-12 months. Read Halmos source + design Solana sBPF symbolic interp |
| **Formal verification (Certora-level)** | ❌ NEVER for one-person team. Belongs to organization with 5-10 specialized engineers + customer commitments |
| **MEV-aware extension** | ❌ Deferred. Market demand unclear |
| **Foundry-grade CLI ergonomics** | 🟡 Deferred. Crucible CLI is sufficient for Phase 1 |
| **Audit firm partnership** | 🟡 Phase 2 audit consulting branch consideration (per project_solinv.md) |
| **Standardization push** | ❌ Premature. Need adoption first |

## Honest verdict

**solinv is "a lightweight Echidna-class fuzzer with a Solana-specific
auto-invariant wedge that does not exist anywhere in the EVM stack,
built as a plugin on Crucible v0.1.0".**

The 13-day implementation density is exceptional; the absolute
maturity gap vs EVM 5-8 year stack is genuine. Symbolic execution
and formal verification belong to different product categories
(Halmos / Certora) and should not be conflated with what solinv
delivers or aspires to.

For Phase 2 revenue: focus the wedge on real bug-hunt income. For
Phase 3+ technical ambition: symbolic execution for Solana would be
a separate product entirely (not solinv v2). For long-term
ecosystem positioning: the auto-invariants pattern, if proven via
real bug finds, becomes the basis for "the way Solana invariants are
done", whether under solinv brand or via OSS adoption by Crucible/Trident.

## Methodology

This evaluation was conducted by:
- Direct knowledge of solinv current state (Day 13, this session)
- Prior research on EVM fuzzers (docs/research-medusa-patterns.md)
- Direct knowledge of Solana ecosystem (docs/research-summary.md,
  docs/research-crucible-integration.md, docs/research-trident-ux-baseline.md)
- Public information on Halmos, Certora, ItyFuzz (general industry knowledge)

Limitations:
- No empirical solinv adoption data (it's private, Day 13)
- No direct Halmos/Certora hands-on (relies on documented behavior)
- 2026-05-25 snapshot; tools evolve weekly

This evaluation should be re-run every 6-12 months as both EVM tools
and solinv evolve.

## Related documents

- `docs/research-summary.md` — Week 1-2 validation findings
- `docs/research-crucible-integration.md` — Crucible API + integration design
- `docs/research-medusa-patterns.md` — Medusa portability assessment
- `docs/research-trident-ux-baseline.md` — Trident UX comparison
- `docs/implementation-day13-owner-skip-unmask-CRITICAL-COMPLETE.md` — current solinv state
- `docs/invariants/README.md` — invariant catalog (17 baseline + 3 stretch)
- `~/.claude/projects/-Users-hiroyusai-src/memory/project_solinv.md` — strategy memory
