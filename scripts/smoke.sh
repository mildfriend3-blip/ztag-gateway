#!/usr/bin/env bash
# End-to-end checks against a running gateway.
#
# Usage: ./scripts/smoke.sh [base-url]
# Expects the topology from `make up` (or the same services started locally).
set -uo pipefail

# Local development: `make env` writes .env with random secrets.
if [ -f .env ]; then set -a; . ./.env; set +a; fi

BASE="${1:-http://127.0.0.1:8443}"
SECRET="${ZTAG_JWT_SECRET:?set ZTAG_JWT_SECRET (run: make env)}"
ADMIN="${ZTAG_ADMIN_TOKEN:?set ZTAG_ADMIN_TOKEN (run: make env)}"
DEVICE="id=d-7712;os=macos;managed=1;posture=compliant"
PASS=0
FAIL=0

if [[ -x ./bin/ztag-tokengen ]]; then
  TOKENGEN=./bin/ztag-tokengen
elif command -v ztag-tokengen >/dev/null 2>&1; then
  TOKENGEN=ztag-tokengen
else
  echo "ztag-tokengen not found; run 'make build' first" >&2
  exit 1
fi

check() { # name expected actual
  local name="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then
    printf '  \033[32mPASS\033[0m %-46s %s\n' "$name" "$got"
    PASS=$((PASS+1))
  else
    printf '  \033[31mFAIL\033[0m %-46s want=%s got=%s\n' "$name" "$want" "$got"
    FAIL=$((FAIL+1))
  fi
}

status() { # url, extra curl args...
  local url="$1"; shift
  curl -s -o /dev/null -w '%{http_code}' "$@" "$url"
}

echo "target: $BASE"

# --- a healthy, fully authorised request ------------------------------------
TOKEN=$("$TOKENGEN" -secret "$SECRET" -sub user-1001 -svc web -did d-7712 \
        -scope orders.read -amr pwd,otp -ttl 5m)
check "valid token, bound device" 200 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $TOKEN" -H "X-Ztag-Device: $DEVICE")"

# --- identity failures ------------------------------------------------------
check "no token" 401 "$(status "$BASE/api/orders" -H "X-Ztag-Device: $DEVICE")"
check "garbage token" 401 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer not.a.token" -H "X-Ztag-Device: $DEVICE")"

FORGED=$(curl -s -X POST "$BASE/api/orders" -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer ${TOKEN%?}X" -H "X-Ztag-Device: $DEVICE")
check "tampered signature" 401 "$FORGED"

# --- session takeover: same token, different device -------------------------
check "token replayed from another device" 401 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $TOKEN" \
      -H "X-Ztag-Device: id=d-9999;os=linux;managed=0;posture=unknown")"

check "no device fingerprint" 401 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $TOKEN")"

# --- authorisation failures -------------------------------------------------
NOSCOPE=$("$TOKENGEN" -secret "$SECRET" -sub user-1002 -svc web -did d-7712 -scope reports.read -ttl 5m)
check "token without the route scope" 403 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $NOSCOPE" -H "X-Ztag-Device: $DEVICE")"

LATERAL=$("$TOKENGEN" -secret "$SECRET" -sub svc-reporting -svc reporting -did d-7712 -scope orders.read -ttl 5m)
check "lateral movement (wrong service identity)" 403 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $LATERAL" -H "X-Ztag-Device: $DEVICE")"

NOMFA=$("$TOKENGEN" -secret "$SECRET" -sub user-1003 -svc web -did d-7712 \
        -scope payments.write -amr pwd -ttl 5m)
check "payments without a second factor" 403 \
  "$(status "$BASE/api/payments" -X POST -H "Authorization: Bearer $NOMFA" -H "X-Ztag-Device: $DEVICE")"

# --- long-lived token rejected even if correctly signed ---------------------
LONG=$("$TOKENGEN" -secret "$SECRET" -sub user-1004 -svc web -did d-7712 -scope orders.read -ttl 24h)
check "24h token rejected (TTL ceiling)" 401 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $LONG" -H "X-Ztag-Device: $DEVICE")"

# --- revocation -------------------------------------------------------------
REV=$("$TOKENGEN" -secret "$SECRET" -sub user-2001 -svc web -did d-7712 -scope orders.read -ttl 5m -jti revoke-me-1)
check "token valid before revocation" 200 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $REV" -H "X-Ztag-Device: $DEVICE")"

curl -s -o /dev/null -X POST "$BASE/admin/revoke" \
  -H "X-Ztag-Admin-Token: $ADMIN" -H 'Content-Type: application/json' \
  -d '{"jti":"revoke-me-1","ttl_seconds":600}'
sleep 0.2
check "token rejected after revocation" 401 \
  "$(status "$BASE/api/orders" -H "Authorization: Bearer $REV" -H "X-Ztag-Device: $DEVICE")"

# --- rate limiting ----------------------------------------------------------
codes=""
for _ in $(seq 1 80); do
  codes+=$(status "$BASE/api/login" -X POST \
    -H "Authorization: Bearer $TOKEN" -H "X-Ztag-Device: $DEVICE")$'\n'
done
limited=$(grep -c '^429$' <<<"$codes" || true)
if [[ "$limited" -gt 0 ]]; then
  printf '  \033[32mPASS\033[0m %-46s %s\n' "flood is throttled (429s seen)" "$limited"
  PASS=$((PASS+1))
else
  printf '  \033[31mFAIL\033[0m %-46s\n' "flood is throttled (no 429)"
  FAIL=$((FAIL+1))
fi

# --- identity headers reach the upstream, token does not --------------------
body=$(curl -s "$BASE/api/orders" -H "Authorization: Bearer $TOKEN" -H "X-Ztag-Device: $DEVICE")
if grep -q 'X-Ztag-Subject' <<<"$body" && ! grep -q 'Authorization' <<<"$body"; then
  printf '  \033[32mPASS\033[0m %-46s\n' "identity forwarded, token stripped"
  PASS=$((PASS+1))
else
  printf '  \033[31mFAIL\033[0m %-46s %s\n' "identity forwarded, token stripped" "$body"
  FAIL=$((FAIL+1))
fi

echo
echo "passed: $PASS   failed: $FAIL"
[[ "$FAIL" -eq 0 ]]
