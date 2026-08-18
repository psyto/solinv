#!/usr/bin/env bash
set -euo pipefail

# Drive a solinv mutation campaign end to end.
#
# For each mutant in a plan: patch the source, rebuild the SBF program,
# run the invariant harness twice, and classify the outcome. Emits a
# results JSON that `solinv mutate score` turns into a report.
#
# The classification is the load-bearing part, so it is spelled out:
#
#   build fails                       -> build_failed  (excluded)
#   harness reports violation         -> killed        (by the named invariant)
#   neither run emitted any [reached] -> harness_error (excluded)
#   enclosing ix never executed       -> not_reached   (excluded)
#   otherwise                         -> survived
#
# `harness_error` sits ahead of both reachability and the survived
# fallback on purpose. A harness that never started is silent in exactly
# the way a harness that found nothing is silent, so "no evidence" has to
# be tested for before either of them, and it has to be its own outcome.
# Letting it fall through to `survived` is not a conservative default —
# it invents a detector blind spot out of a configuration mistake.
#
# WHY TWO RUNS PER MUTANT
#
# Killing and reaching cannot be measured in the same run. The fuzzer
# stops an iteration at its first violation, and on a target planted with
# bugs that is the first action — so state never accumulates, and every
# instruction that needs a funded vault fails and reads as unreachable.
# Measured on escrow-demo: a scoring run reaches 4 of 9 instructions, an
# assertion-free run reaches all 9.
#
# So: SOLINV_TEST is the scoring run, SOLINV_REACH_TEST is an
# assertion-free run whose only job is to drive actions. Reachability is
# the union of both ledgers. Both are re-run per mutant, because a
# mutation can change what the program will accept.
#
# THE JOIN
#
#   - `solinv mutate plan` records each mutant's `enclosing_fn`
#   - solinv emits `[solinv][reached] ix=<name>` under
#     SOLINV_REACHABILITY=1 when an action's instruction succeeds
#
# and this script joins them by name. The join is sound in one direction
# only: if the enclosing function's ix never ran, the mutation certainly
# did not. The converse does not hold — the ix may have run without
# taking the mutated branch — so a mutant whose ix *did* run is
# classified `survived`, never promoted on that evidence alone. That errs
# against the detector, which is the direction to err in.
#
# A mutant with no `enclosing_fn`, or whose name matches no instruction,
# is also treated as `survived` for the same reason.

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "$#" -lt 5 ]]; then
  cat <<'EOF'
Usage:
  run_mutation_campaign.sh <plan.json> <manifest-path> <invariant-target> \
                           <crucible-dir> <results.json>

Arguments:
  plan.json         campaign produced by `solinv mutate plan`
  manifest-path     Cargo.toml of the program to rebuild per mutant
  invariant-target  crucible target name to run (e.g. escrow)
  crucible-dir      directory CONTAINING fuzz/<target>/ (e.g.
                    examples/escrow-demo). Required, and it must be a
                    working directory rather than a --harness-dir: -C is
                    honoured when building the harness but not when
                    locating the built binary, so crucible must be run
                    from here.
  results.json      where to write the results array

Environment:
  SOLINV_TIMEOUT    per-run fuzz timeout in seconds (default 30)
  SOLINV_BIN        path to the solinv binary (default ./target/release/solinv)
  SOLINV_TEST       scoring test name (default invariant_all)
  SOLINV_REACH_TEST reachability test name (default invariant_reachability)

Budget for two fuzz runs plus one SBF rebuild per mutant.

Per-mutant build and run logs are kept next to results.json, in
<results>-logs/. They are the only way to tell a detector blind spot
from a broken harness after the fact, so they outlive the run.
EOF
  exit 0
fi

# Absolute, because runs happen with the working directory moved to
# CRUCIBLE_DIR and every one of these would otherwise resolve against it.
# `abspath` handles a path whose file does not exist yet, and leaves an
# already-absolute one alone — prefixing $PWD unconditionally builds
# paths like /repo//tmp/out.json, which then get created inside the repo.
abspath() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)  printf '%s\n' "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")" ;;
  esac
}

PLAN="$(abspath "$1")"
MANIFEST="$(abspath "$2")"
TARGET="$3"
CRUCIBLE_DIR="$4"
RESULTS="$(abspath "$5")"
TIMEOUT="${SOLINV_TIMEOUT:-30}"
SOLINV="${SOLINV_BIN:-./target/release/solinv}"
TEST="${SOLINV_TEST:-invariant_all}"
REACH_TEST="${SOLINV_REACH_TEST:-invariant_reachability}"
LOGDIR="${RESULTS%.json}-logs"

command -v jq >/dev/null || { echo "error: jq is required" >&2; exit 1; }
command -v crucible >/dev/null || { echo "error: crucible is required" >&2; exit 1; }
cargo build-sbf --version >/dev/null 2>&1 || {
  echo "error: cargo build-sbf is required" >&2; exit 1; }
[[ -x "$SOLINV" ]] || { echo "error: solinv binary not found at $SOLINV" >&2; exit 1; }
SOLINV="$(abspath "$SOLINV")"
[[ -d "$CRUCIBLE_DIR/fuzz/$TARGET" ]] || {
  echo "error: no harness at $CRUCIBLE_DIR/fuzz/$TARGET" >&2; exit 1; }
CRUCIBLE_DIR="$(cd "$CRUCIBLE_DIR" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$LOGDIR"

# Run one crucible test from CRUCIBLE_DIR. Exit code is returned, not
# swallowed: a non-zero exit with no violation in the log is the shape a
# harness failure takes, and the caller has to be able to see it.
run_test() {
  local test_name="$1" log="$2" rc=0
  ( cd "$CRUCIBLE_DIR" && SOLINV_REACHABILITY=1 SOLINV_MUTANT_ID="${SOLINV_MUTANT_ID:-}" \
      crucible run "$TARGET" "$test_name" --release --timeout "$TIMEOUT" ) \
    >"$log" 2>&1 || rc=$?
  return $rc
}

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

echo "campaign: ${#IDS[@]} mutants against $TARGET ($TEST + $REACH_TEST)"

# Baseline: build and run the *unmutated* program once, and require the
# reachability pass to emit at least one `[solinv][reached]` line.
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

run_test "$REACH_TEST" "$LOGDIR/baseline-reach.log" || true

if ! grep -q '\[solinv\]\[reached\]' "$LOGDIR/baseline-reach.log"; then
  echo "error: the baseline run emitted no [solinv][reached] lines." >&2
  echo "       Every mutant would be classified from this same silence," >&2
  echo "       so the campaign would report a broken harness as detector" >&2
  echo "       blind spots. Refusing to run. See $LOGDIR/baseline-reach.log" >&2
  exit 1
fi

echo "baseline reaches:"
grep -o '\[solinv\]\[reached\] ix=[A-Za-z0-9_]*' "$LOGDIR/baseline-reach.log" \
  | sort -u | sed 's/^/  /'

# Instructions the plan needs but the baseline never reaches are dead
# weight: they will be excluded per-mutant, one rebuild at a time. Say so
# now, while the number still means something to a reader deciding
# whether to spend the build time.
for fn in $(jq -r '.mutants[].enclosing_fn // empty' "$PLAN" | sort -u); do
  if ! grep -qE "\[solinv\]\[reached\] ix=${fn}( |$)" "$LOGDIR/baseline-reach.log"; then
    n=$(jq -r --arg f "$fn" '[.mutants[] | select(.enclosing_fn==$f)] | length' "$PLAN")
    echo "  warning: $n mutant(s) in '$fn', which the baseline never reaches"
  fi
done

echo "[" > "$RESULTS"
FIRST=1

for id in "${IDS[@]}"; do
  file=$(jq -r --arg id "$id" '.mutants[] | select(.id==$id) | .file' "$PLAN")
  killer=$(jq -r --arg id "$id" '.mutants[] | select(.id==$id) | .expected_killer' "$PLAN")
  encl=$(jq -r --arg id "$id" \
    '.mutants[] | select(.id==$id) | .enclosing_fn // ""' "$PLAN")
  slug=$(echo "$id" | tr '/:@#' '____')

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
    SOLINV_MUTANT_ID="$id" run_test "$TEST" "$LOGDIR/$slug.score.log" || rc=$?
    SOLINV_MUTANT_ID="$id" run_test "$REACH_TEST" "$LOGDIR/$slug.reach.log" || true

    # The invariant name is taken from solinv's own violation prefix,
    # e.g. "[unchecked-math:<pid>] ...". Attribution matters: a mutant
    # killed by an unexpected detector is still dead, but the report
    # separates the two.
    by=$(grep -oE '\[(signer-skip|owner-skip|discriminator-skip|pda-forge|account-swap|unchecked-math|cu-dos|cpi-reentrancy|realloc-race|bump-seed-canonicalization):' \
      "$LOGDIR/$slug.score.log" | head -1 | tr -d '[:' || true)

    cat "$LOGDIR/$slug.score.log" "$LOGDIR/$slug.reach.log" > "$WORK/both.log"

    if [[ -n "$by" ]]; then
      # A violation is positive evidence that the harness ran, so it is
      # read before the exit code: crucible exits non-zero *because* it
      # found the crash we were hoping for.
      outcome=$(jq -n --arg by "$by" '{outcome:"killed", by:$by}')
    elif ! grep -q '\[solinv\]\[reached\]' "$WORK/both.log"; then
      # No violation and no evidence of execution in either run. The
      # baseline check established the harness can speak, so silence here
      # is a fault in this run, not a finding about the detectors.
      outcome=$(jq -n --arg r "exit $rc, no [reached] output: $(tail -c 300 "$LOGDIR/$slug.score.log")" \
        '{outcome:"harness_error", reason:$r}')
    elif [[ -n "$encl" ]] \
         && ! grep -qE "\[solinv\]\[reached\] ix=${encl}( |$)" "$WORK/both.log"; then
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
echo "logs kept in $LOGDIR"
echo "score it with:"
echo "  $SOLINV mutate score --plan $PLAN --results $RESULTS"
