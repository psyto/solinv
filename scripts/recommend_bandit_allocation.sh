#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  recommend_bandit_allocation.sh <log_file> [more_logs...]
  cat bandit.log | recommend_bandit_allocation.sh

Reads [solinv][bandit] lines and recommends one of:
  - early-stop
  - 70/30 (winner/loser)
  - 50/50

Environment overrides:
  MIN_SAMPLES_PER_INV   default: 10
  MIN_TOTAL_DT_SEC      default: 30
  EPSILON_RATE          default: 0.05
  STRONG_RATIO          default: 1.5
EOF
  exit 0
fi

awk_program='
  /\[solinv\]\[bandit\]/ {
    inv=""; dt=0; delta=0;
    for (i=1; i<=NF; i++) {
      if ($i ~ /^invariant=/) {
        split($i, a, "="); inv=a[2];
      } else if ($i ~ /^dt_sec=/) {
        split($i, a, "="); dt=a[2]+0;
      } else if ($i ~ /^delta_fp=/) {
        split($i, a, "="); delta=a[2]+0;
      }
    }
    if (inv != "") {
      count[inv] += 1;
      sum_dt[inv] += dt;
      sum_delta[inv] += delta;
      total_dt += dt;
      total_delta += delta;
      inv_seen[inv] = 1;
    }
  }
  END {
    min_samples = (ENVIRON["MIN_SAMPLES_PER_INV"] != "" ? ENVIRON["MIN_SAMPLES_PER_INV"]+0 : 10);
    min_total_dt = (ENVIRON["MIN_TOTAL_DT_SEC"] != "" ? ENVIRON["MIN_TOTAL_DT_SEC"]+0 : 30);
    eps = (ENVIRON["EPSILON_RATE"] != "" ? ENVIRON["EPSILON_RATE"]+0 : 0.05);
    strong = (ENVIRON["STRONG_RATIO"] != "" ? ENVIRON["STRONG_RATIO"]+0 : 1.5);

    n_inv = 0;
    for (k in inv_seen) { names[n_inv++] = k; }
    if (n_inv == 0) {
      print "decision=insufficient-data reason=no bandit lines";
      exit 0;
    }

    print "== Rates ==";
    printf("%-20s %8s %12s %12s %14s\n", "invariant", "samples", "sum_dt_sec", "sum_delta", "weighted_rate");
    for (i=0; i<n_inv; i++) {
      inv = names[i];
      rate[inv] = (sum_dt[inv] > 0 ? sum_delta[inv] / sum_dt[inv] : 0);
      printf("%-20s %8d %12.3f %12d %14.3f\n", inv, count[inv], sum_dt[inv], sum_delta[inv], rate[inv]);
    }
    global_rate = (total_dt > 0 ? total_delta / total_dt : 0);
    printf("global_weighted_rate=%.3f total_dt_sec=%.3f total_delta=%d\n", global_rate, total_dt, total_delta);
    print "";

    # Only robust for 2-way competition (unchecked-math vs cu-dos).
    if (n_inv != 2) {
      print "decision=50/50 reason=non-binary invariant set";
      exit 0;
    }

    inv_a = names[0]; inv_b = names[1];
    ra = rate[inv_a]; rb = rate[inv_b];
    if (ra >= rb) { win=inv_a; lose=inv_b; rw=ra; rl=rb; }
    else { win=inv_b; lose=inv_a; rw=rb; rl=ra; }

    # Data sufficiency gate.
    if (count[inv_a] < min_samples || count[inv_b] < min_samples || total_dt < min_total_dt) {
      printf("decision=50/50 reason=insufficient-data min_samples=%d min_total_dt=%.0f\n", min_samples, min_total_dt);
      exit 0;
    }

    # If both near-zero => early-stop.
    if (rw <= eps && rl <= eps) {
      printf("decision=early-stop reason=both-rates-near-zero eps=%.3f\n", eps);
      exit 0;
    }

    ratio = (rl > 0 ? rw / rl : 999999);
    if (ratio >= strong) {
      printf("decision=70/30 winner=%s loser=%s reason=strong-separation ratio=%.3f threshold=%.3f\n", win, lose, ratio, strong);
    } else {
      printf("decision=50/50 reason=weak-separation ratio=%.3f threshold=%.3f\n", ratio, strong);
    }
  }
'

if [[ "$#" -gt 0 ]]; then
  awk "$awk_program" "$@"
else
  awk "$awk_program"
fi
