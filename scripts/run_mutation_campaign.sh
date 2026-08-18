#!/usr/bin/env bash
set -euo pipefail

# Drive a solinv mutation campaign end to end.
#
# For each mutant in a plan: patch the source, rebuild the SBF program,
# run the invariant harness, and classify the outcome. Emits a results
# JSON that `solinv mutate score` turns into a report.
#
# The classification is the load-bearing part, so it is spelled out:
#
#   build fails                       -> build_failed  (excluded)
#   harness reports violation         -> killed        (by the named invariant)
#   run emitted no [reached] at all   -> harness_error (excluded)
#   enclosing ix never executed       -> not_reached   (excluded)
#   otherwise                         -> survived
#
# `harness_error` is third in that list on purpose, ahead of both
# reachability and the survived fallback. A harness that never started
# is silent in exactly the way a harness that found nothing is silent,
# so "no evidence" has to be tested for before either of them, and it
# has to be its own outcome. Letting it fall through to `survived` is
# not a conservative default — it invents a detector blind spot out of
# a configuration mistake.
#
# "Never reached" cannot be inferred from a silent run: a detector that
# was never asked and one that was asked and said nothing look identical
# from outside. The two halves that make the distinction possible are
#
#   - `solinv mutate plan` records each mutant's `enclosing_fn`
#   - solinv emits `[solinv][reached] ix=<name>` under
#     SOLINV_REACHABILITY=1 when a canonical instruction executes
#
# and this script joins them by name. The join is sound in one
# direction only: if the enclosing function's ix never ran, the mutation
# certainly did not. The converse does not hold — the ix may have run
# without taking the mutated branch — so a mutant whose ix *did* run is
# classified `survived`, never promoted on that evidence alone. That
# errs against the detector, which is the direction to err in.
#
# A mutant with no `enclosing_fn`, or whose name matches no instruction,
# is also treated as `survived` for the same reason.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 5 ]]; then
  cat <<'EOF'
Usage:
  run_mutation_campaign.sh <plan.json> <manifest-path> <invariant-target> \
                           <harness-dir> <results.json>

Arguments:
  plan.json         campaign produced by `solinv mutate plan`
  manifest-path     Cargo.toml of the program to rebuild per mutant
  invariant-target  crucible target name to run (e.g. escrow)
  harness-dir       crucible harness directory (e.g.
                    examples/escrow-demo/fuzz/escrow). Required: crucible
                    defaults to ./fuzz/<program>/ relative to the working
                    directory, which is not where a harness lives when the
                    campaign is driven from the repo root.
  results.json      where to write the results array

Environment:
  SOLINV_TIMEOUT    per-mutant fuzz timeout in seconds (default 30)
  SOLINV_BIN        path to the solinv binary (default ./target/release/solinv)

Per-mutant build and run logs are kept next to results.json, in
<results>-logs/. They are the only way to tell a detector blind spot
from a broken harness after the fact, so they outlive the run.
EOF
  exit 0
fi

PLAN="$1"
MANIFEST="$2"
TARGET="$3"
HARNESS="$4"
RESULTS="$5"
TIMEOUT="${SOLINV_TIMEOUT:-30}"
SOLINV="${SOLINV_BIN:-./target/release/solinv}"
LOGDIR="${RESULTS%.json}-logs"

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }
command -v crucible >/dev/null || { echo "error: crucible is required" >&2; exit 1; }
cargo build-sbf --version >/dev/null 2>&1 || {
  echo "error: cargo build-sbf is required" >&2; exit 1; }
[[ -x "$SOLINV" ]] || { echo "error: solinv binary not found at $SOLINV" >&2; exit 1; }
[[ -d "$HARNESS" ]] || { echo "error: no harness directory at $HARNESS" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$LOGDIR"

# Read ids with a `while read` loop, not `mapfile`: macOS ships bash 3.2,
# where `mapfile` does not exist.
IDS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && IDS+=("$line")
done < <(jq -r '.mutants[].id' "$PLAN")

if [[ "${#IDS[@]}" -eq 0 ]]; then
  echo "error: no mutants in $PLAN" >&2
  exit 1
fi

echo "campaign: ${#IDS[@]} mutants against $TARGET"

# Baseline: build and run the *unmutated* program once, and require it
# to emit at least one `[solinv][reached]` line.
#
# Every per-mutant classification below is read off this harness's
# output, so a harness that cannot speak makes the entire campaign
# unfalsifiable — and it fails silently, because its silence is shaped
# like a clean run. One build and one run up front is the cheapest
# possible calibration, and it is the difference between finding out now
# and finding out after every mutant has been built.
echo "baseline: building and running the unmutated program"
if ! cargo build-sbf --tools-version v1.52 --manifest-path "$MANIFEST" \
      >"$LOGDIR/baseline-build.log" 2>&1; then
  echo "error: the unmutated program does not build; see $LOGDIR/baseline-build.log" >&2
  exit 1
fi

SOLINV_REACHABILITY=1 crucible run "$TARGET" "invariant_all" \
  -C "$HARNESS" --release --timeout "$TIMEOUT" \
  >"$LOGDIR/baseline-run.log" 2>&1 || true

if ! grep -q '\[solinv\]\[reached\]' "$LOGDIR/baseline-run.log"; then
  echo "error: the baseline run emitted no [solinv][reached] lines." >&2
  echo "       Every mutant would be classified from this same silence," >&2
  echo "       so the campaign would report a broken harness as detector" >&2
  echo "       blind spots. Refusing to run. See $LOGDIR/baseline-run.log" >&2
  exit 1
fi

echo "baseline: $(grep -c '\[solinv\]\[reached\]' "$LOGDIR/baseline-run.log") \
instruction(s) reached"

echo "[" > "$RESULTS"
FIRST=1

for id in "${IDS[@]}"; do
  file=$(jq -r --arg id "$id" '.mutants[] | select(.id==$id) | .file' "$PLAN")
  killer=$(jq -r --arg id "$id" '.mutants[] | select(.id==$id) | .expected_killer' "$PLAN")
  encl=$(jq -r --arg id "$id" \
    '.mutants[] | select(.id==$id) | .enclosing_fn // ""' "$PLAN")

  cp "$file" "$WORK/orig.rs"
  # Restore the pristine source no matter how this iteration exits.
  restore() { cp "$WORK/orig.rs" "$file"; }

  if ! "$SOLINV" mutate apply --plan "$PLAN" --mutant "$id" --out "$file" >/dev/null 2>&1; then
    restore
    outcome='{"outcome":"build_failed","reason":"apply failed (stale plan?)"}'
  elif ! cargo build-sbf --tools-version v1.52 --manifest-path "$MANIFEST" \
        >"$WORK/build.log" 2>&1; then
    restore
    outcome=$(jq -n --arg r "$(tail -c 400 "$WORK/build.log")" \
      '{outcome:"build_failed", reason:$r}')
  else
    restore
    rc=0
    SOLINV_REACHABILITY=1 SOLINV_MUTANT_ID="$id" \
      crucible run "$TARGET" "invariant_all" \
      -C "$HARNESS" --release --timeout "$TIMEOUT" \
      >"$WORK/run.log" 2>&1 || rc=$?
    cp "$WORK/run.log" "$LOGDIR/$(echo "$id" | tr '/:@#' '____').log"

    # The invariant name is taken from solinv's own violation prefix,
    # e.g. "[unchecked-math:<pid>] ...". Attribution matters: a mutant
    # killed by an unexpected detector is still dead, but the report
    # separates the two.
    by=$(grep -oE '\[(signer-skip|owner-skip|discriminator-skip|pda-forge|account-swap|unchecked-math|cu-dos|cpi-reentrancy|realloc-race|bump-seed-canonicalization):' \
      "$WORK/run.log" | head -1 | tr -d '[:' || true)

    if [[ -n "$by" ]]; then
      # A violation is positive evidence that the harness ran, so it is
      # read before the exit code: crucible exits non-zero *because* it
      # found the crash we were hoping for.
      outcome=$(jq -n --arg by "$by" '{outcome:"killed", by:$by}')
    elif ! grep -q '\[solinv\]\[reached\]' "$WORK/run.log"; then
      # No violation and no evidence of execution. The baseline check
      # established the harness can speak, so silence here is a fault in
      # this run, not a finding about the detectors.
      outcome=$(jq -n --arg r "exit $rc, no [reached] output: $(tail -c 300 "$WORK/run.log")" \
        '{outcome:"harness_error", reason:$r}')
    elif [[ -n "$encl" ]] \
         && ! grep -qE "\[solinv\]\[reached\] ix=${encl}( |$)" "$WORK/run.log"; then
      # The ledger reported *some* instruction as reached but not this
      # mutant's, so this code did not execute. The harness_error branch
      # above has already ruled out the case where the ledger said
      # nothing at all, which is what makes this negative meaningful.
      outcome='{"outcome":"not_reached"}'
    else
      outcome='{"outcome":"survived"}'
    fi
  fi

  [[ $FIRST -eq 1 ]] || echo "," >> "$RESULTS"
  FIRST=0
  jq -n --arg id "$id" --arg k "$killer" --argjson o "$outcome" \
    '{mutant_id:$id, expected_killer:$k} + $o' >> "$RESULTS"
  echo "  $id -> $(echo "$outcome" | jq -r .outcome)"
done

echo "]" >> "$RESULTS"
echo
echo "results written to $RESULTS"
echo "score it with:"
echo "  $SOLINV mutate score --plan $PLAN --results $RESULTS"
