#!/usr/bin/env bash
# INTECTED Docker entrypoint
#   - Initialises the SQLite DB if missing
#   - Starts the FastAPI dashboard on the configured host:port
#
# Env vars honoured:
#   DASHBOARD_HOST   default 0.0.0.0
#   DASHBOARD_PORT   default 8765
#   INTECTED_STATE   default /home/intected/.intected
set -euo pipefail

echo "=== INTECTED Dashboard (Docker) ==="
echo "State dir:  ${INTECTED_STATE:-/home/intected/.intected}"
echo "Bridge URL: ${REDAEGIS_BRIDGE_URL:-http://bridge:4000/v1}"

# --- Ensure state directories exist ------------------------------------------
STATE_DIR="${INTECTED_STATE:-/home/intected/.intected}"
EVIDENCE_DIR="${STATE_DIR}/evidence"
mkdir -p "$STATE_DIR" "$EVIDENCE_DIR"

# --- Init DB if missing ------------------------------------------------------
DB_FILE="${STATE_DIR}/intected.db"
if [ ! -f "$DB_FILE" ]; then
    echo "DB not found — initialising: $DB_FILE"
    python -c "
import sqlite3
from intected import db, config
conn = db.connect(config.db_path())
db.init_db(conn)
conn.close()
print('DB initialised.')
"
else
    echo "DB exists: $DB_FILE"
fi

# --- Start dashboard ---------------------------------------------------------
HOST="${DASHBOARD_HOST:-0.0.0.0}"
PORT="${DASHBOARD_PORT:-8765}"

echo "Starting FastAPI dashboard on ${HOST}:${PORT} ..."
exec python -m uvicorn intected.dashboard:create_app \
    --factory \
    --host "$HOST" \
    --port "$PORT" \
    --log-level warning
