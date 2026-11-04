# Try solinv on your Anchor program

2026-11-04

## What we're asking

Please point solinv at one Anchor program you know well, time each step, and tell us where you got stuck. Step 1–2 take about 10 minutes and need only Rust; step 3 is optional and needs the Solana toolchain.

- **What you get:** a map of which instructions in your program have hand-checked accounts (`UncheckedAccount` / `AccountInfo`) and which write state with no signer at all — the places an account-validation review starts.
- **What we learn:** how long a first result takes for someone who did not build solinv. Our own numbers (6–11 minutes on three production programs) are the author's, not yours.
- **Nothing leaves your machine.** solinv reads your IDL and source locally; nothing is uploaded.

## Before you start

| Step | You need |
| --- | --- |
| 1–2 (map) | Rust (`cargo`); an Anchor program's source and its IDL, Anchor 0.30 or later |
| 3 (fuzz, optional) | the above, plus the Solana toolchain (`cargo build-sbf`) and the [Crucible](https://github.com/asymmetric-research/crucible) CLI |

An older (pre-0.30) IDL works after `anchor idl convert <path> -p <program id> -o <out>`. Native and Shank programs are not supported yet — telling us that you have one is useful too.

Keep a clock running: note the time you start each step.

## Step 1 — install (about 1–2 minutes)

```bash
cargo install --git https://github.com/psyto/solinv --rev 4a800dc3fb1c solinv-cli
solinv --help
```

The commit is pinned so we all run the same code. On our machine the install took about 90 seconds.

## Step 2 — map your program (about 5 minutes)

In your Anchor workspace:

```bash
anchor build      # writes target/idl/<program>.json
solinv idl target/idl/<program>.json --src programs/<program>/src
```

If you would rather not build, an IDL already in the repo works too, but it may lack PDA seeds and fixed addresses if it was generated without resolution.

On Anchor 0.30, building the IDL with current Rust fails in `anchor-syn` with `no method named source_file found for struct proc_macro2::Span` ([anchor#3661](https://github.com/otter-sec/anchor/issues/3661); fixed in 0.31.1). What worked for us on 0.30.1, from the workspace root:

```bash
cargo update -p proc-macro2 --precise 1.0.94
cd programs/<program> && RUSTUP_TOOLCHAIN=nightly-2025-04-15 anchor idl build -o ../../target/idl/<program>.json
```

If the program uses token accounts, its `idl-build` feature also needs `anchor-spl/idl-build`.

How to read it (an excerpt from solinv's own planted-bug demo):

```
unsafe_withdraw   ! no signer, writes an unconstrained slot
   0 vault            W   U
   1 depositor        W   U
```

| Mark | Meaning |
| --- | --- |
| `S` `W` `P` `A` | signer, writable, PDA seeds, fixed address — as the IDL declares them; Anchor enforces these |
| `U` | `UncheckedAccount` / `AccountInfo` in your source: owner and type checks are hand-written |
| `T` | a typed account (`Account<'info, T>` and friends): Anchor checks owner and type |
| `t` | a typed account whose identity no declared constraint fixes (no `seeds`, `address`, `has_one`, `associated_token::*` or `.key()` comparison): Anchor checks it is *an* account of the type, not *which* one. Fine for the caller's own token account; a hole for a vault or escrow the program owns, unless the handler compares its key |
| `·` | declares nothing, and the source reader could not place it (an alias, a multi-line type) |
| `! no signer, …` | the instruction has no signer and writes a slot the IDL leaves unconstrained — either meant to be permissionless, or a missing authority check |

For each flagged instruction, note whether it is meant to be callable by anyone. For each writable `t`, note whether the caller is meant to choose it. On the audited programs we tried, every one was — that is a fine answer.

Also try the pull-request check on two commits of your own history (a minute, no build):

```bash
git worktree add /tmp/before <an older commit>
solinv diff --base-src /tmp/before/programs/<program>/src --head-src programs/<program>/src
```

It names any account check removed between them. Note what it reported, and whether any of it was noise.

## Step 3 (optional) — fuzz one instruction (15–45 minutes)

Pick one instruction from step 2, ideally one with a `U` slot. Most of the time goes into setup: creating the accounts that must exist before the instruction can run.

1. Install the Crucible CLI and build your program:

   ```bash
   git clone https://github.com/asymmetric-research/crucible ~/src/crucible
   cargo install --path ~/src/crucible/crates/crucible-fuzz-cli
   cargo build-sbf          # writes target/deploy/<program>.so
   ```

   If the program is already deployed, fuzzing the deployed binary is usually better: `solana program dump -u m <program id> <program>.so`. Rebuilding a program whose Cargo.lock has solana-program below 1.16 (check it) with current platform-tools broke, in our tests, the one kind of CPI we tried (`init` calling System Program `create_account`), failing with "Access violation … 0xffffffffffffffff", on a real validator too ([why](https://github.com/psyto/solinv/blob/main/docs/phase5-day61-h1-was-the-build.md)).
2. Start the harness from solinv's template: copy `Cargo.toml` and `src/main.rs` from [examples/escrow-demo/fuzz/escrow_clean](https://github.com/psyto/solinv/tree/4a800dc3fb1c/examples/escrow-demo/fuzz/escrow_clean) into `fuzz/<program>/`. Delete its `escrow-clean` dependency and the `use escrow_clean::ID;` line, and point the `solinv-fuzz` / `solinv-core` path dependencies at `{ git = "https://github.com/psyto/solinv", rev = "4a800dc3fb1c" }`.
3. Print the spec stub and paste it into `instructions()`:

   ```bash
   solinv idl target/idl/<program>.json --rust <instruction>
   ```
4. In `setup()`, load your `.so` and create the accounts the instruction reads; fill the stub's `todo!`s with their keys.
5. Run for a minute:

   ```bash
   cargo build --release --features invariant_all
   crucible run <program> invariant_all --binary-in target/release/invariant_test --timeout 60
   ```

`crucible run` exits 0 even when it reports a finding ([crucible#26](https://github.com/asymmetric-research/crucible/issues/26)), so look for lines starting `[FUZZ_FINDING] [` — solinv's detectors start their message with `[<detector>:…]` — rather than at the exit code. It also checks `--timeout` only every 1000 iterations, so a slow harness can run well past it ([crucible#25](https://github.com/asymmetric-research/crucible/issues/25)); `timeout 90 crucible run …` stops it from outside.

Reading the result: 0 findings is the usual answer for audited code, but only counts if the untampered instruction succeeds — send it once from `setup()` and check. Lines starting `[SOLINV_CANDIDATES]` name checks solinv inferred from your fixture's state; a finding on one of those is a lead to confirm against what the program intends, not a confirmed bug. The [README](https://github.com/psyto/solinv#start-from-your-idl) walks through each piece.

## What to send back

Fill in what applies and send it to whoever shared this page; a step you skipped or abandoned is as useful as one you finished.

| Question | Your answer |
| --- | --- |
| Program (name or kind), Anchor version, number of instructions |  |
| Step 1: minutes, and any error |  |
| Step 2: minutes; how many `U` slots; which instructions were flagged |  |
| Step 2: were the flagged instructions meant to be callable by anyone? |  |
| `solinv diff` on your history: anything reported, and was any of it noise? |  |
| Step 3: minutes to a first result, or where you stopped and why (paste the error) |  |
| Step 3: findings or `[SOLINV_CANDIDATES]` lines worth a second look |  |
| What took longest, or confused you |  |
| Would you run this in CI on every PR? What would it take? |  |
