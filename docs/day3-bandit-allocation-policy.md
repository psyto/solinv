# Day 3 Bandit Allocation Policy (Operational)

Date: 2026-05-26  
Status: Active (Phase 4 onward)

## Purpose

Convert `solinv` High-tier campaign logs into a deterministic time-allocation
decision between `unchecked-math` and `cu-dos`:

- `decision=70/30`
- `decision=50/50`
- `decision=early-stop`

This policy operationalizes the Day 3 metric bridge (`delta_fp / dt_sec`) and
is designed to avoid hand-wavy continuation when signal is flat.

## Inputs

Bandit log lines emitted by:

```bash
SOLINV_BANDIT_METRICS=1 crucible run <target> <invariant> --release --timeout <sec>
```

Expected line shape:

```text
[solinv][bandit] invariant=<name> dt_sec=<float> delta_fp=<int> fp_per_sec=<float>
```

## Decision Procedure

Run:

```bash
./scripts/recommend_bandit_allocation.sh run1.log run2.log ...
```

Default thresholds:

- `MIN_SAMPLES_PER_INV=10`
- `MIN_TOTAL_DT_SEC=30`
- `EPSILON_RATE=0.05`
- `STRONG_RATIO=1.5`

Interpretation:

- If data is insufficient → `50/50`
- If both weighted rates are near zero (`<= EPSILON_RATE`) → `early-stop`
- If winner/loser weighted-rate ratio `>= STRONG_RATIO` → `70/30`
- Otherwise → `50/50`

## Tie-back to current evidence

Day 34 and Day 38 both produced zero findings on Raydium SwapV2 and saturated
edge coverage (4.3%). Under this policy shape, comparable zero-signal runs
naturally converge to `early-stop` instead of open-ended continuation.

References:

- [phase3-day34-unchecked-math-gate2.md](~/src/solinv/docs/phase3-day34-unchecked-math-gate2.md)
- [phase3-day38-cu-dos-gate2.md](~/src/solinv/docs/phase3-day38-cu-dos-gate2.md)

## Weekly review rule

Revisit thresholds only weekly (not per run), and only with a short change log:

- old threshold
- new threshold
- reason
- before/after decision impact on the latest 3 campaigns

This prevents post-hoc threshold tuning to justify continuation.

## Measurement snapshot template

Copy this block after each allocation checkpoint:

```md
### Snapshot: YYYY-MM-DD

- Target set: <e.g., raydium swapv2>
- Logs used: <log1>, <log2>, ...
- Command: `./scripts/bandit_decide.sh logs/*.log`

Aggregate:
- samples: <n>
- sum_dt_sec: <float>
- sum_delta: <int>
- global_weighted_fp_per_sec: <float>

Per-invariant weighted rates:
- unchecked-math: <float>
- cu-dos: <float>

Decision:
- `decision=<70/30|50/50|early-stop>`
- reason: <tool output reason>

Action:
- If `early-stop`: stop High-tier continuation on this target class.
- If `70/30`: allocate next window 70% winner / 30% loser.
- If `50/50`: keep equal split until next checkpoint.
```

### Snapshot: 2026-05-26

- Target set: raydium swapv2
- Logs used: logs/2026-05-26_raydium_amm_unchecked-math_run1.log logs/2026-05-26_raydium_amm_cu-dos_run1.log
- Command: `./scripts/bandit_decide.sh logs/2026-05-26_raydium_amm_unchecked-math_run1.log logs/2026-05-26_raydium_amm_cu-dos_run1.log`

Aggregate:
- samples: 125768
- sum_dt_sec: 174.359
- sum_delta: 2
- global_weighted_fp_per_sec: 0.011

Per-invariant weighted rates:
- unchecked-math: 0.011
- cu-dos: 0.012

Decision:
- `decision=early-stop`
- reason: reason=both-rates-near-zero eps=0.050

Action:
- If `early-stop`: stop High-tier continuation on this target class.
- If `70/30`: allocate next window 70% winner / 30% loser.
- If `50/50`: keep equal split until next checkpoint.
