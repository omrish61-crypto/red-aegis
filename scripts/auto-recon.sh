#!/bin/bash
# RedAegis 6-hourly auto-recon + report generation + QA verification
# Runs recon against ALL targets in scope, updates evidence, facts, grade,
# and runs a QA smoke-test to verify the full flow.
set -euo pipefail

PROJ=/c/Users/onris/INTECTED
STATEDIR=/c/Users/onris/.intected
TOK=$(cat "$STATEDIR"/dashboard.token)
LOG="$STATEDIR/logs/auto-recon-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$STATEDIR"/logs

exec >> "$LOG" 2>&1
echo "=== RedAegis auto-recon started at $(date -u) ==="

# 1. Get all targets from mission 8 scope
TARGETS=$(cd "$PROJ" && uv run python - <<'EOF'
import sqlite3, json
conn = sqlite3.connect('C:/Users/onris/.intected/intected.db')
scope = json.loads(conn.execute(
    'SELECT allowed_hosts_json FROM missions WHERE id=8').fetchone()[0])
conn.close()
print(" ".join(scope))
EOF
)

echo "TARGETS: $TARGETS"

# 2. Run recon against EACH target in scope
for TARGET in $TARGETS; do
    echo "=== recon against $TARGET ==="
    cd "$PROJ" && uv run intected recon --mission 8 --target "$TARGET" --force \
        --operator-approved 2>&1 || echo "WARNING: recon failed for $TARGET (exit $?)"
    echo ""
done

# 3. Regenerate report (refreshes the grade)
echo "=== report refresh ==="
cd "$PROJ" && uv run python - <<'EOF'
import sqlite3, json
conn = sqlite3.connect('C:/Users/onris/.intected/intected.db')
from intected.evidence import _default_target
from intected.grading import compute_grade
target = _default_target(conn, 8) or "unknown"
grade = compute_grade(conn, 8, target)
print(f"TARGET: {target}  |  GRADE: {grade.letter} ({grade.score}/100)")
print(f"  deductions: {len(grade.deductions)} | facts: {grade.fact_count}")
for d in grade.deductions[:5]:
    print(f"    - {d['points']}pts: {d['reason']}")
conn.close()
EOF

echo ""
echo "=== QA smoke test ==="

# 4. QA: verify the full flow works
FAILURES=0

# 4a. Dashboard responds
HTTP=$(curl -s -m 5 -o /dev/null -w "%{http_code}" \
      "http://127.0.0.1:8765/api/missions?token=$TOK")
if [ "$HTTP" = "200" ]; then
    echo "PASS dashboard missions ($HTTP)"
else
    echo "FAIL dashboard missions ($HTTP)"
    FAILURES=$((FAILURES+1))
fi

# 4b. Plan endpoint
PLAN=$(curl -s -m 10 "http://127.0.0.1:8765/api/missions/8/plan?token=$TOK")
if echo "$PLAN" | grep -q '"plan"'; then
    echo "PASS plan endpoint"
else
    echo "FAIL plan endpoint"
    FAILURES=$((FAILURES+1))
fi

# 4c. Report page
REPORT=$(curl -s -m 10 -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:8765/api/missions/8/report?token=$TOK")
if [ "$REPORT" = "200" ]; then
    echo "PASS report page ($REPORT)"
else
    echo "FAIL report page ($REPORT)"
    FAILURES=$((FAILURES+1))
fi

# 4d. Suite (smoke)
cd "$PROJ" && uv run pytest -q 2>&1 | tail -1

echo ""
if [ "$FAILURES" -eq 0 ]; then
    echo "QA ALL PASSED"
else
    echo "QA FAILURES: $FAILURES"
fi
echo "=== auto-recon completed at $(date -u) ==="
