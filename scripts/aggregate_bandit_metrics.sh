#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  aggregate_bandit_metrics.sh <log_file> [more_logs...]
  cat log.txt | aggregate_bandit_metrics.sh

Parses lines like:
  [solinv][bandit] invariant=unchecked-math dt_sec=0.120 delta_fp=3 fp_per_sec=25.000

Outputs:
  - per-invariant totals/averages
  - global totals and weighted fp/sec
EOF
  exit 0
fi

if [[ "$#" -gt 0 ]]; then
  awk '
    /\[solinv\]\[bandit\]/ {
      inv=""; dt=0; delta=0; rate=0;
      for (i=1; i<=NF; i++) {
        if ($i ~ /^invariant=/) {
          split($i, a, "="); inv=a[2];
        } else if ($i ~ /^dt_sec=/) {
          split($i, a, "="); dt=a[2]+0;
        } else if ($i ~ /^delta_fp=/) {
          split($i, a, "="); delta=a[2]+0;
        } else if ($i ~ /^fp_per_sec=/) {
          split($i, a, "="); rate=a[2]+0;
        }
      }
      if (inv != "") {
        count[inv] += 1;
        sum_dt[inv] += dt;
        sum_delta[inv] += delta;
        sum_rate[inv] += rate;
        total_count += 1;
        total_dt += dt;
        total_delta += delta;
      }
    }
    END {
      printf("== Per Invariant ==\n");
      printf("%-20s %8s %12s %12s %12s %14s\n",
        "invariant", "samples", "sum_dt_sec", "sum_delta", "avg_rate", "weighted_rate");
      for (inv in count) {
        avg_rate = (count[inv] > 0) ? (sum_rate[inv] / count[inv]) : 0;
        weighted_rate = (sum_dt[inv] > 0) ? (sum_delta[inv] / sum_dt[inv]) : 0;
        printf("%-20s %8d %12.3f %12d %12.3f %14.3f\n",
          inv, count[inv], sum_dt[inv], sum_delta[inv], avg_rate, weighted_rate);
      }
      printf("\n== Global ==\n");
      global_weighted = (total_dt > 0) ? (total_delta / total_dt) : 0;
      printf("samples=%d sum_dt_sec=%.3f sum_delta=%d weighted_fp_per_sec=%.3f\n",
        total_count, total_dt, total_delta, global_weighted);
    }
  ' "$@"
else
  awk '
    /\[solinv\]\[bandit\]/ {
      inv=""; dt=0; delta=0; rate=0;
      for (i=1; i<=NF; i++) {
        if ($i ~ /^invariant=/) {
          split($i, a, "="); inv=a[2];
        } else if ($i ~ /^dt_sec=/) {
          split($i, a, "="); dt=a[2]+0;
        } else if ($i ~ /^delta_fp=/) {
          split($i, a, "="); delta=a[2]+0;
        } else if ($i ~ /^fp_per_sec=/) {
          split($i, a, "="); rate=a[2]+0;
        }
      }
      if (inv != "") {
        count[inv] += 1;
        sum_dt[inv] += dt;
        sum_delta[inv] += delta;
        sum_rate[inv] += rate;
        total_count += 1;
        total_dt += dt;
        total_delta += delta;
      }
    }
    END {
      printf("== Per Invariant ==\n");
      printf("%-20s %8s %12s %12s %12s %14s\n",
        "invariant", "samples", "sum_dt_sec", "sum_delta", "avg_rate", "weighted_rate");
      for (inv in count) {
        avg_rate = (count[inv] > 0) ? (sum_rate[inv] / count[inv]) : 0;
        weighted_rate = (sum_dt[inv] > 0) ? (sum_delta[inv] / sum_dt[inv]) : 0;
        printf("%-20s %8d %12.3f %12d %12.3f %14.3f\n",
          inv, count[inv], sum_dt[inv], sum_delta[inv], avg_rate, weighted_rate);
      }
      printf("\n== Global ==\n");
      global_weighted = (total_dt > 0) ? (total_delta / total_dt) : 0;
      printf("samples=%d sum_dt_sec=%.3f sum_delta=%d weighted_fp_per_sec=%.3f\n",
        total_count, total_dt, total_delta, global_weighted);
    }
  '
fi
