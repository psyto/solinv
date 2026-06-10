# Security Policy

solinv is a Solana-aware invariant fuzzing framework. The
maintainers take security reports seriously — a real vulnerability
in solinv's detectors, helpers, or harness scaffolding could mask
bugs in downstream protocols that rely on the catalog.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead:

1. **Preferred**: open a [private security advisory](https://github.com/psyto/solinv/security/advisories/new) on this repo. GitHub will notify the maintainers.
2. **Fallback**: email `saito.hiroyuki@gmail.com` with subject `[solinv security] <one-line summary>`.

Please include:

- A clear description of the vulnerability and its impact.
- Steps to reproduce — ideally a minimal `crucible run` invocation,
  a test case, or a patched harness diff.
- Your suggested fix, if you have one.
- Your name + affiliation (if any), and whether you want public
  attribution after the fix lands.

## Scope

**In scope** (vulnerabilities welcomed and acknowledged):

- `crates/solinv-core/` — invariant detectors. False negatives (a
  detector that should fire but doesn't on a real bug shape) and
  high-rate false positives both qualify.
- `crates/solinv-fuzz/` — capability traits + `InstructionSpec` +
  `bytepoke` helpers. Memory-safety issues, panic on adversarial
  input, soundness gaps.
- `crates/solinv-cli/`, `crates/solinv-cheat/`, `crates/solinv-corpus/`,
  `crates/solinv-disclose/` — CLI + cheat wrappers + corpus
  ingestion + disclosure formatter.

**Out of scope** (intentional design, not bugs):

- The planted bugs in `examples/escrow-demo/programs/escrow/`. These
  are deliberately vulnerable for detector self-validation. Each
  `unsafe_*` ix is documented as such; finding a way to "exploit"
  the planted bug is the detector's job.
- The buggy Pinocchio/Anchor program variants in
  `examples/pinocchio-bench-fuzz/programs/*-buggy/`. Same: planted
  for differential validation.
- Performance issues that don't affect correctness (slow campaigns,
  high memory use) — open a regular issue.
- Issues in the [Crucible](https://github.com/asymmetric-research/crucible)
  upstream — report those to Asymmetric Research directly.
- Issues in the Solana runtime, Anchor, or any external program
  whose `.so` solinv harnesses load — report to the respective
  upstream.

## Response timeline

| Stage | Target |
|---|---|
| Acknowledgment of report | 3 business days |
| Initial triage / severity assessment | 7 business days |
| Fix in private branch | depends on severity (see below) |
| Coordinated disclosure | mutually agreed, target ≤90 days |

Severity bands (mirroring CVSS but informally applied):

- **Critical** (silent false negative on a real-world bug class
  that's also in the catalog as detectable): fix target 14 days.
- **High** (false negative on a real-world bug class not in the
  catalog; soundness gap in `solinv-fuzz`): fix target 30 days.
- **Medium** (false positive rate >25% on hardened production
  targets; non-exploitable panic on adversarial harness input):
  fix target 60 days.
- **Low** (documentation gap, methodology improvement, false
  positive only on synthetic non-realistic inputs): merged on the
  next regular release cycle.

## Disclosure

After a fix lands in `main`:

1. We open a public security advisory with the vulnerability
   description, affected versions, fix commit, and reporter
   attribution (if requested).
2. We tag a patch release.
3. We add a row to the "Acknowledgments" section below.

If you find a real bug via solinv in a **downstream protocol** (not
solinv itself), please report it to that protocol's security team —
solinv's own SECURITY.md is not the venue. The disclosure templates
in [`docs/disclosure-template-*.md`](docs/) are designed for this
case.

## Acknowledgments

_None yet — be the first._

## What this policy does NOT cover

- Vulnerabilities in protocols that solinv detects bugs in. solinv
  is a tool; if you find a real bug in (say) Kamino via solinv, you
  report it to Kamino under their bounty / disclosure process, not
  here.
- Methodology disagreements (e.g., "your §9 framing is too lax / too
  strict"). Those are issues, not security reports. Open a regular
  issue and tag `methodology`.
- Disagreements with the calibration dataset (e.g., "0 violations on
  Raydium doesn't prove anything"). Those are valid — see the
  "honest framing" sections (§10) of each invariant spec — but they
  are not security reports.
