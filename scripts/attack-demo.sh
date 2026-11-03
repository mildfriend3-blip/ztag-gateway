#!/usr/bin/env bash
# Replays the three attack shapes from the threat model against a running
# gateway and prints the numbers used in the evaluation chapter.
#
#   ./scripts/attack-demo.sh [base-url]
set -euo pipefail

# Local development: `make env` writes .env with random secrets.
if [ -f .env ]; then set -a; . ./.env; set +a; fi

BASE="${1:-http://127.0.0.1:8443}"
SECRET="${ZTAG_JWT_SECRET:?set ZTAG_JWT_SECRET (run: make env)}"
BIN=./bin/ztag-loadgen
DEVICE="id=d-7712;os=macos;managed=1;posture=compliant"

TOKEN=$("${BIN%loadgen}tokengen" -secret "$SECRET" -sub user-3001 -svc web -did d-7712 \
        -scope orders.read -amr pwd,otp -ttl 10m)

hr() { printf '\n\033[1m%s\033[0m\n' "$1"; }

hr "1. Baseline: legitimate traffic (throughput and latency ceiling)"
$BIN -url "$BASE/api/orders" -token "$TOKEN" -mode legit -c 50 -n 5000 -device "$DEVICE"

hr "2. Bot flood: same identity, no pacing (sliding-window limiter)"
$BIN -url "$BASE/api/login" -token "$TOKEN" -mode flood -c 100 -n 5000 -device "$DEVICE"

hr "3. Credential stuffing: rotating usernames and source IPs"
$BIN -url "$BASE/api/login" -token "$TOKEN" -mode stuffing -c 50 -n 3000 -device "$DEVICE" -spoof-ip

hr "4. Stolen token replayed from an unknown device"
$BIN -url "$BASE/api/orders" -token "$TOKEN" -mode legit -c 20 -n 200 \
     -device "id=d-0000;os=linux;managed=0;posture=unknown"

hr "5. Forged token (bad signature)"
$BIN -url "$BASE/api/orders" -token "$TOKEN" -mode badtoken -c 20 -n 200 -device "$DEVICE"

hr "Gateway counters"
curl -s "$BASE/metrics" | grep -E '^ztag_(requests_total|decisions_total|audit_events_total|inflight_requests)' || true
