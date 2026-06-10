#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF'
Usage:
  render_bandit_snapshot.sh <log_file> [more_logs...]

Outputs a Markdown snapshot block for:
  docs/day3-bandit-allocation-policy.md
EOF
  exit 0
fi

if [[ "$#" -lt 1 ]]; then
  echo "error: provide at least one log file" >&2
  exit 1
fi

decision_line="$(./scripts/recommend_bandit_allocation.sh "$@" | rg '^decision=' -m 1 || true)"
if [[ -z "${decision_line}" ]]; then
  decision_line="decision=insufficient-data reason=no-decision-line"
fi

awk -v today="$(date +%F)" -v files="$*" -v decision_line="$decision_line" '
  /\[solinv\]\[bandit\]/ {
    inv=""; dt=0; delta=0;
    for (i=1; i<=NF; i++) {
      if ($i ~ /^invariant=/) { split($i, a, "="); inv=a[2]; }
      else if ($i ~ /^dt_sec=/) { split($i, a, "="); dt=a[2]+0; }
      else if ($i ~ /^delta_fp=/) { split($i, a, "="); delta=a[2]+0; }
    }
    if (inv != "") {
      count[inv] += 1;
      sum_dt[inv] += dt;
      sum_delta[inv] += delta;
      total_count += 1;
      total_dt += dt;
      total_delta += delta;
    }
  }
  END {
    uw = (sum_dt["unchecked-math"] > 0 ? sum_delta["unchecked-math"] / sum_dt["unchecked-math"] : 0);
    cd = (sum_dt["cu-dos"] > 0 ? sum_delta["cu-dos"] / sum_dt["cu-dos"] : 0);
    global = (total_dt > 0 ? total_delta / total_dt : 0);

    decision = decision_line;
    sub(/ .*/, "", decision);
    sub(/^decision=/, "", decision);
    reason = decision_line;
    sub(/^decision=[^ ]+ /, "", reason);

    printf("### Snapshot: %s\n\n", today);
    printf("- Target set: <fill target class>\n");
    printf("- Logs used: %s\n", files);
    printf("- Command: `./scripts/bandit_decide.sh %s`\n\n", files);
    printf("Aggregate:\n");
    printf("- samples: %d\n", total_count);
    printf("- sum_dt_sec: %.3f\n", total_dt);
    printf("- sum_delta: %d\n", total_delta);
    printf("- global_weighted_fp_per_sec: %.3f\n\n", global);
    printf("Per-invariant weighted rates:\n");
    printf("- unchecked-math: %.3f\n", uw);
    printf("- cu-dos: %.3f\n\n", cd);
    printf("Decision:\n");
    printf("- `decision=%s`\n", decision);
    printf("- reason: %s\n\n", reason);
    printf("Action:\n");
    printf("- If `early-stop`: stop High-tier continuation on this target class.\n");
    printf("- If `70/30`: allocate next window 70%% winner / 30%% loser.\n");
    printf("- If `50/50`: keep equal split until next checkpoint.\n");
  }
' "$@"
