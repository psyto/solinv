# sBPF Coverage Feasibility — Research Notes

Date: 2026-05-24
Status: Week 1 validation item #1

## Verdict

**FEASIBLE in 3-5 days** (not 1-2 weeks) by depending on Crucible's existing coverage stack. Building our own from scratch would be 4-6 weeks. Patching the SBPF VM ourselves would be 8-12 weeks.

**Recommended architecture: layer solinv on Crucible, inherit its edge + source-level coverage as-is, only add solinv-specific feedback metrics (invariant-distance, state-novelty) on top.**

## Key facts

1. **LimeChain's `sbpf-coverage` is a postprocessor**, not instrumentation. v0.2.12, AGPL-3.0 (license blocker for private use).
2. **The actual instrumentation lives upstream in anza-xyz/svm**: `program-runtime/src/invoke_context.rs::iterate_vm_traces` + `RegisterTrace`, populated by `sbpf/src/vm.rs`.
3. **LiteSVM 0.9.0+ exposes it** via `register-tracing` cargo feature → `crates/litesvm/src/register_tracing.rs::DefaultRegisterTracingCallback`. Writes `.regs` / `.insns` / `.exec.sha256` to `$SBF_TRACE_DIR`.
4. **`asymmetric-research/litesvm-tracing` is obsolete** — was 0.7.1 fork pre-merge. Mainline LiteSVM 0.9+ has it now.
5. **Crucible already consumes this end-to-end**:
   - Cargo: `litesvm = { version = "0.9.0", features = ["register-tracing"] }`
   - Macro: `crates/crucible-fuzz-macro/src/coverage.rs` — LibAFL-style 256KB edge bitmap, AFL hitcount buckets, branch tracking, source-level LCOV
   - CLI: `crucible run … --coverage [--symbols debug.so] [--lcov-out path]`
   - Docs: `crucible/docs/coverage.md` (3-binary recipe)

## Required platform-tools version

**MUST pin v1.51+** — pre-v1.51 LLD has the `R_SBF_64_64` relocation bug (anza-xyz/llvm-project#159) that corrupts DWARF → silent zero coverage. Bake into solinv CI.

## JIT vs interpreter

`RegisterTrace` only populated in tracing mode (`LiteSVM::new_debuggable` or `SBF_TRACE_DIR` set), which forces interpreter execution. Expect ~5-20x slowdown vs JIT.

**Crucible's pattern** (which solinv should inherit): fuzz without coverage at full JIT speed, then **replay corpus with coverage as separate pass**. Don't run them in the same loop.

## sBPF version drift

- Crucible pins `solana-sbpf = "0.13"`
- sbpf-coverage pins `solana-sbpf = "0.14.4"`
- Both work because `regs[11] = PC` invariant is stable
- **solinv should pin transitively via Crucible** (avoid independent pin)

## License consideration

**LimeChain/sbpf-coverage is AGPL-3.0** — cannot link as library in private solinv code. Mitigation: use Crucible's own LCOV writer (MIT) directly. No dependency on sbpf-coverage required.

## Day 1 actions

1. Clone `asymmetric-research/crucible`
2. Install platform-tools v1.51+ via `cargo build-sbf --tools-version v1.51`
3. Run `crucible/examples/escrow/` with `--coverage --symbols`
4. Confirm LCOV output renders correctly
5. Read `crucible/docs/coverage.md` end-to-end
6. Stamp a `solinv-plugin` crate that wraps `#[crucible_fuzz]` and adds invariant DSL

## Code pointers (sorted by priority)

| File | Purpose |
|------|---------|
| `asymmetric-research/crucible/docs/coverage.md` | 3-binary recipe, start here |
| `crucible/crates/crucible-fuzz-macro/src/coverage.rs` | `coverage_state_code()`, `MAP_SIZE`, `SHARED_EDGE_BITMAP_SIZE` — feedback signal contract |
| `crucible/examples/escrow/` | Working harness to fork as solinv's first test target |
| `LiteSVM/litesvm/crates/litesvm/src/register_tracing.rs::DefaultRegisterTracingCallback::handler` | Exact format of `.regs`/`.insns`/`.exec.sha256` files |
| `anza-xyz/svm/program-runtime/src/invoke_context.rs::iterate_vm_traces` | Lowest-level hook (only touch if outgrowing LiteSVM wrapper) |
| `anza-xyz/svm/sbpf/src/vm.rs` | Where interpreter writes trace |
| `LimeChain/sbpf-coverage/src/lib.rs::run()` | Reference DWARF→LCOV impl (already mirrored in Crucible) |

## Strategic implication for solinv

The entire sBPF coverage problem is **solved-and-shipping**. solinv does NOT need to build coverage; it inherits Crucible's. This frees Week 1-2 to focus on:
- Invariant catalog design (the actual wedge)
- Mainnet corpus seeder architecture
- Disclosure formatter UX

Original Phase 1 timeline can compress: instead of 1-2 weeks for coverage MVP, we get 3-5 days for Crucible integration, leaving ~10 days for invariant library design — which is the actual moat.

## Sources

- https://limechain.tech/blog/inspecting-the-engine-of-internet-capital-markets-how-to-achieve-line-level-visibility-in-solana-programs
- https://github.com/LimeChain/sbpf-coverage
- https://github.com/asymmetric-research/crucible
- https://github.com/LiteSVM/litesvm
- https://github.com/anza-xyz/svm
- https://github.com/anza-xyz/llvm-project/pull/159
- https://inversive.xyz/blog/Solaris/ (Inversive Solaris, described but not OSS)
