# Phase 2 Target Ranking — Solana DeFi Bug-Hunt Candidates

Date: 2026-05-25 (post-landscape verification)
Source: Mirrors `~/.claude/projects/-Users-hiroyusai-src/memory/reference_solana_defi_landscape_2026.md`
Status: Active reference for Phase 2 target selection

> **STALENESS WARNING**: Protocol landscape changes rapidly (hacks, sunsets,
> rebrands, bounty terms). Re-verify all status claims before strategic
> decisions, especially monthly. The 2026 timeline alone has Drift hack
> (April), Step Finance hack (January), Adrena maintenance mode (November
> 2025), Marginfi → Project 0 rebrand, Mango v4 + Lifinity wind-downs.

## 2026 Solana DeFi incident timeline (impacting Phase 2 targets)

| Date | Protocol | Loss | Mechanism | Status |
|---|---|---|---|---|
| 2026-01-31 | Step Finance | $29M | Treasury wallet compromise (executive device, NOT contract bug) | Wound down 2026-02-23 |
| 2026-04-01 | **Drift Protocol** | **$285M-$295M** | DPRK-linked UNC4736 social engineering via durable nonces + Security Council pre-signed admin tx + zero-timelock migration. **NOT smart-contract bug** | Paused since 4/1, relaunch May-June 2026, no firm date |

Notably, both major 2026 hacks were **NOT on-chain code bugs**.
solinv (code-level invariant detector) would NOT have prevented either.
solinv's scope is account-validation bugs, not governance / admin-key
social engineering.

## Drift downstream impact (20 protocols affected)

Per SolanaFloor exposure tracker, expanded from initial 11:
Drift, PiggyBank, Perena, Vectis, Valeo, Amp Pay, **Loopscale**,
**Prime Numbers Fi** (>$10M loss), **Gauntlet** (~$6.4M), Exponent,
**Project 0 (Marginfi rebrand)**, Carrot, **Ranger Finance** (~$900K),
Reflect, Elemental, Neutral Trade, Pyra, Fuse, XPlace.

## Final Phase 2 target ranking (2026-05-25)

| Rank | Protocol | Bounty (Critical max) | Last update | solinv-fit | Notes |
|---|---|---|---|---|---|
| **1** | **Kamino** | **$1.5M** (Solana's largest) | 2026-04-28 | ⚪⚪ 高 | $3.2B TVL, unaffected by Drift, freshest bounty page, largest attack surface ROI |
| **2** | **Raydium** | $505K | **2026-05-24** (most recent) | ⚪⚪ 高 | 74 assets in scope (AMM + CLMM), complex account graphs |
| 3 | **Save (ex-Solend)** | $1M self-hosted | active | ⚪⚪ 高 | Mature codebase, ~$300M TVL, lower competition |
| 4 | **Wormhole** | $1M | 2026-05-18 | ⚪ 中 | Bridge surface = signature/consensus 中心、solinv 部分 fit、battle-tested |
| 5 | **Meteora** | $500K | active | ⚪⚪ 高 | DLMM novel surface (Zellic + Bramah audited only) |
| 6 | **Jito** | $250K | 2025-02-17 (stale-ish) | ⚪⚪ 高 | Re-Staking / Vault / Interceptor Anchor programs in scope |
| 7 | **Marinade** | $250K | 2024-11 (stale) | ⚪ 中 | Classic LST, listed live |
| 8 | **Project 0 (Marginfi)** | unclear post-rebrand | rebrand churn | ⚪ 中 | Post-Drift defensive, re-engage after TGE |
| 9 | **Jupiter Perps** | terms unverified | — | ⚪⚪ 高 | High-fit unverified, setup 後に bounty 確認 (Phase 2 OSS で direct contact) |
| 10 | **Reserve (Flipcash)** | $250K | 2026-03-05 | ⚪ 中 | Single-contract narrow scope, one-shot spot-check |

## Operationalization in solinv CLI (2026-05-26)

Day 1 scoring CLI is now available:

```bash
solinv score --config examples/targets.phase4.toml --top 10
solinv score --config examples/targets.phase4.toml --top 5 --json
```

Scoring model:

```text
score =
  tvl * W_tvl
  + change_velocity * W_change_velocity
  + permissionless_surface * W_permissionless_surface
  + complexity * W_complexity
  - audit_maturity * W_audit_maturity
```

Input normalization contract:
- Each target metric is normalized to `[0.0, 1.0]`
- Higher is better for: `tvl`, `change_velocity`, `permissionless_surface`, `complexity`
- Higher is worse for: `audit_maturity` (subtracted term)
- Weights are strategy-tunable and should be revisited weekly

Phase 4 immediate use:
- Use scoring output only as a prioritization front door
- Keep hard gates unchanged: bounty terms validity, private-posture fit, setup cost
- Re-rank when major incidents/rebrands occur; do not treat scores as static truth

## Day 2 metric bridge (state-transition coverage signal)

To complement edge-coverage saturation, High-tier detectors now record
unique semantic transition fingerprints. Enable milestone logging with:

```bash
SOLINV_TRANSITION_METRICS=1 crucible run <target> <invariant> --release --timeout 30
```

Observed logs are low-noise powers-of-two milestones:
`unique_fingerprints=1,2,4,8,16,...`

This is the direct numerator feed for Day 3's `new_signal/hour`
allocation logic.

## Phase 1 DROPPED (unverified bounty + private posture mismatch)

| Protocol | Why dropped | Phase 2 OSS reconsider? |
|---|---|---|
| Phoenix (Spot) | Unverified Immunefi listing + direct outreach matches OSS posture, not Phase 1 private | ✅ Yes, when OSS branch chosen |
| Sanctum | Same as Phoenix + LST infra specialized (Marinade serves as LST representative) | ✅ Yes, when OSS branch chosen |

**Rule (Phase 1 drop rubric)**: Unconfirmed bounty + solinv-fit medium or below → DROP. Exception: high-fit + unconfirmed = KEEP (verify bounty post-setup, like Jupiter Perps).

## Avoided protocols

| Protocol | Reason |
|---|---|
| ~~Drift~~ | Hacked 2026-04-01, paused, bounty page 404. Defer until **July 2026+ post-relaunch + 30 days** |
| ~~Adrena~~ | Maintenance mode since 2025-11-12 (fundraising failure, NOT Drift-related). No team to triage. AVOID |
| ~~Mango v4~~ | Wound down 2025-01-13 (post-Eisenberg 2022). Dead |
| ~~Lifinity~~ | Shut down 2025-12-18 ($42M USDC paid out to LFNTY holders). Dead |
| ~~Step Finance~~ | Wound down 2026-02-23 (post-hack). Dead |
| ~~SolanaFloor / Remora Markets~~ | Shut down 2026-02 (Step Finance ecosystem). Dead |
| ~~Pyth Network~~ | Oracle program scope, narrow attack surface, low solinv ROI |
| ~~Squads v4~~ | Over-audited (4 audits + formal verification, immutable since Nov 2024). Tarpit |
| ~~Light Protocol~~ | Compressed-account model breaks solinv's standard invariant assumptions |

## Yogi business impact (separate from solinv strategy)

Yogi vault deployed via Voltr/Ranger on Drift. Ranger Finance is on
Drift-affected list (~$900K loss). Double-frozen risk (Drift + Ranger).
This is an independent business concern from solinv Phase 2 ranking —
Yogi vault recovery status should be tracked separately.

## Phase 2 first action

1. **Kamino repo clone** (`Kamino-Finance/audits` for context + identify main code repo)
2. **Cargo.toml deps check**: Anchor 1.0.1 / Solana 3.0 compat with solinv workspace
3. **Immunefi bounty terms read**: automated tooling exclusions? KYC requirements?
4. **Code complexity assessment**: estimate harness setup cost
5. **Pivot rule**: if Kamino setup >5 days, switch MVP target to **Raydium (#2)** — most recently updated bounty + active development

## Strategic shifts vs session-internal ranking (Day 13)

Day 13 session ranking: Marginfi → Drift → Kamino → Jupiter
2026-05-25 verified ranking: Kamino → Raydium → Save → Wormhole → Meteora → Jito → ...

Key changes:
- **Marginfi: was #1 → now #8** (Project 0 rebrand + post-Drift defensive)
- **Drift: was #2 → defer** (Apr 2026 $285M hack, paused)
- **Kamino: was #3 → #1** (only viable top-tier target after eliminations)
- **Raydium: NEW #2** (2026-05-24 freshest update + complex AMM/CLMM = good solinv-fit)
- **Wormhole, Save, Meteora, Jito, Reserve: NEW entries** filling expanded surface
- **Phoenix, Sanctum: DROPPED** (Phase 1 private posture)

## Meta-lesson for solinv Phase 2 (codified)

Protocol landscape changes monthly through hacks, sunsets, rebrands.
**Phase 2 ranking has built-in staleness**. Before each strategic
decision (target selection, pivot, expansion), re-verify:
- Hack incidents (last 90 days)
- Bounty program changes
- Protocol operational status
- Rebrands / governance changes

Session-internal context is insufficient for Phase 2 strategy. Always
combine with fresh external verification (agent research or direct
protocol checks).

Day 13 session ranking missed all of:
- Drift Apr 2026 hack
- Marginfi → Project 0 rebrand
- Adrena maintenance mode (Nov 2025)
- Mango v4 wind-down (Jan 2025)
- Lifinity shutdown (Dec 2025)
- Step Finance hack (Jan 2026)

This is the kind of blind spot session-internal context produces.
Mitigate via periodic external verification.

## Sources for re-verification

### Bounty / scope verification
- https://immunefi.com/bug-bounty/kamino/information/ (Kamino $1.5M)
- https://immunefi.com/bug-bounty/raydium/information/ (Raydium $505K, 2026-05-24)
- https://docs.save.finance/protocol/bug-bounty (Save $1M self-hosted)
- https://immunefi.com/bug-bounty/wormhole/scope/ (Wormhole $1M, 2026-05-18)
- https://immunefi.com/bug-bounty/meteora/ (Meteora $500K)
- https://immunefi.com/bug-bounty/jito/information/ (Jito $250K)
- https://immunefi.com/bug-bounty/marinade/information/ (Marinade $250K)
- https://www.flipcash.com/blog/reserve-contract-bug-bounty (Reserve $250K)

### Hack / incident timeline
- https://www.helius.dev/blog/solana-hacks (general timeline)
- https://www.tekedia.com/12-protocols-on-solana-currently-impacted-by-the-drift-protocol-hack/ (Drift downstream 12)
- https://coinpedia.org/news/drift-protocol-exploit-impact-spreads-to-20-solana-projects/ (expanded 20)
- https://decrypt.co/358970/solana-defi-project-step-finance-to-wind-down-weeks-after-29m-hack
- https://x.com/AdrenaProtocol/status/1988506424150720580 (Adrena maintenance Nov 2025)
- https://www.drift.trade/updates/incident-recovery-update-april-16-2026-now
- https://blog.asymmetric.re/threat-contained-marginfi-flash-loan-vulnerability/

### Educational / invariant catalog sources
- https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security (Bump Seed Canonicalization, Account Reload after CPI, PDA Sharing, Arbitrary CPI patterns → solinv High tier expansion)
- https://github.com/otter-sec/anchor/blob/master/SECURITY.md (OtterSec validates Critical 5 = 118-1176 SOL tier)

### Out-of-scope (validator/runtime)
- https://github.com/anza-xyz/agave/security
- https://github.com/JumpCrypto/solana/security
- https://immunefi.com/bug-bounty/firedancer/information/
