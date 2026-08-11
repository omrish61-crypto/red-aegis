#!/bin/bash
# RedAegis tool-verification driver: ONE test per fresh dashboard instance.
# After every test the dashboard is restarted clean (better performance,
# no accumulated state, no single-threaded server blocking).
cd /c/Users/onris/INTECTED || exit 1
TOK=$(cat /c/Users/onris/.intected/dashboard.token)
LOG=/tmp/dashtest.log
: > "$LOG"
for cid in 27 28 29 30 31 32 33 34 35 36; do
  # --- stop the dashboard cleanly ---
  P=$(netstat -ano 2>/dev/null | grep ":8765" | grep -i listen | awk '{print $NF}' | head -1)
  [ -n "$P" ] && taskkill -F -PID "$P" >/dev/null 2>&1
  sleep 2
  # --- start a fresh instance ---
  (cd /c/Users/onris/INTECTED && uv run intected dashboard --port 8765 >> "$LOG" 2>&1 &)
  sleep 8
  UP=$(curl -s -m 4 -o /dev/null -w "%{http_code}" "http://127.0.0.1:8765/api/missions?token=$TOK")
  echo "=== cmd $cid (dashboard $UP) ===" >> "$LOG"
  # --- run exactly ONE test through the dashboard API ---
  curl -s -m 700 -X POST "http://127.0.0.1:8765/api/commands/$cid/run?token=$TOK" \
       -o "/tmp/res_$cid.json"
  python -c "
import json
try:
    d = json.load(open('/tmp/res_$cid.json'))
    print('cmd $cid -> state=%s exit=%s facts=%s elapsed=%s' % (
        d.get('state'), d.get('exit_code'), d.get('facts_added'), d.get('elapsed_s')))
    head = (d.get('output_head') or '').replace(chr(10),' ')[:70]
    if head: print('   output:', head)
except Exception as e:
    print('cmd $cid -> NO RESULT:', e)
" | tee -a "$LOG"
done
echo "ALL TOOL TESTS DONE" | tee -a "$LOG"
