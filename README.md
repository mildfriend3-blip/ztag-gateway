# Distributed Zero-Trust Access Gateway

A cloud-native data plane proxy that sits in front of internal microservices and
admits a request only after it has proved **who** the caller is, **which device**
they are on, that their credential has **not been revoked**, that they are
**within their rate budget**, and that the **policy engine** allows this identity
to reach this route from this service. Everything it decides is streamed to a
decoupled audit pipeline that can never slow the request path.

Final-year capstone project. Written in Go with **zero third-party
dependencies**: the entire data plane — HTTP proxy, JWT verification, Redis
client, rate limiter, policy client, metrics and audit pipeline — is standard
library plus about 3,000 lines of application code.

```
                        ┌──────────────────────────────────────┐
   Incoming             │            CONTROL PLANE             │
   requests             │  OPA (Rego): identity, service,      │
      │                 │  route, device posture, MFA, TTL     │
      ▼                 └───────────────▲──────────────────────┘
┌───────────────┐      decision (JSON)  │
│  Go Data      │◄──────────────────────┘
│  Plane Proxy  │
│               │──────► Redis  (revocation list + sliding-window limiter)
│  verify →     │
│  bind →       │──────► Redis Stream  ──► Log worker ──► audit store
│  revoke →     │        (async queue)
│  throttle →   │
│  policy →     │
│  forward      │──────► Internal services (orders, payments, admin, auth)
└───────────────┘
```

## Documents

Two things a reviewer usually wants before the code: the deck and the manual.
Both are published as pages on this repository, so they open in a browser
instead of downloading.

| Document | Read it | In the repository |
|---|---|---|
| Review deck (15 slides) | [Open the deck](https://mildfriend3-blip.github.io/ztag-gateway/review-deck.html) | `docs/review-deck.html` |
| Installation and user manual (12 pages) | [Open the manual](https://mildfriend3-blip.github.io/ztag-gateway/user-manual.pdf) | `docs/user-manual.pdf` |
| Design, threat model, evaluation | [docs index](https://mildfriend3-blip.github.io/ztag-gateway/) | `docs/DESIGN.md`, `docs/THREAT_MODEL.md`, `docs/EVALUATION.md` |

On a laptop the deck advances with the arrow keys (`F` for full screen). On a
phone, tap the right half of the screen to advance and the left half to go
back; landscape reads better. GitHub does not render HTML files from the repository view, which
is why the deck is served from the pages site rather than linked from the file
tree.

## Why this design

A gateway that checks a static API key or a long-lived session cookie is a
single stolen string away from compromise. This project replaces static checks
with continuous verification:

| Attack | Naive defence | What this gateway does |
|---|---|---|
| Stolen session token | Nothing until expiry | Token is short-lived, bound to a device fingerprint, and checked against a global revocation list on every request |
| Credential stuffing | Per-account lockout after the damage | Atomic sliding-window limiter in front of the login route, keyed by identity *and* source address |
| Lateral movement | Flat network, service trusts service | OPA decides service→route reachability; Kubernetes NetworkPolicy blocks everything else at the packet level |
| Audit evasion by flooding | Synchronous logging becomes the bottleneck | Bounded queue with shed-and-count semantics; audit never blocks a request |

## Quick start

```bash
make env              # writes .env with random local secrets (gitignored)
make build            # builds bin/ztag-{proxy,echo,tokengen,loadgen,logworker}
make test             # Go unit tests
make policy-test      # OPA policy unit tests (needs the opa binary)
make check            # everything CI runs

make up               # docker compose: redis, opa, gateway, services, logworker
make token            # prints a demo token
make smoke            # end-to-end behaviour checks (bash scripts/smoke.sh) against localhost:8443
make attack           # replays the three attack shapes and prints numbers
make down
```

A single authorised request, by hand:

```bash
TOKEN=$(./bin/ztag-tokengen -sub user-1001 -svc web -did d-7712 \
        -scope orders.read -amr pwd,otp -ttl 5m)

curl -s http://localhost:8443/api/orders \
  -H "Authorization: Bearer $TOKEN" \
  -H 'X-Ztag-Device: id=d-7712;os=macos;managed=1;posture=compliant'
```

The upstream receives `X-Ztag-Subject`, `X-Ztag-Service`, `X-Ztag-Device`,
`X-Ztag-Trust` and `X-Ztag-Request-Id`, and **never** receives the bearer token.

## Repository layout

```
cmd/
  proxy/        the data plane
  logworker/    stream consumer that persists audit events
  tokengen/     demo issuer (stands in for the IdP)
  loadgen/      load and attack generator (legit, flood, stuffing, badtoken)
  echo/         stand-in internal service that reports forwarded headers
internal/
  proxysrv/     request pipeline, reverse proxy, admin API, metrics endpoints
  jwt/          HS256/RS256 verification with pinned algorithm and TTL ceiling
  redisclient/  minimal RESP2 client: pool, pipelining, EVALSHA, streams
  revocation/   two-level revocation cache (in-process L1 + Redis L2)
  ratelimit/    atomic sliding window (Lua) + degraded in-process fallback
  policy/       OPA decision client with hand-built JSON input
  audit/        bounded queue, worker pool, sinks (Redis Stream, JSONL, Kafka)
  device/       device fingerprint parsing and trust scoring
  metrics/      Prometheus text exposition, no client library
  config/       environment configuration and validation
policies/       authz.rego, data.json, authz_test.rego
deploy/k8s/     namespace, redis, opa, gateway (HPA/PDB), upstreams, NetworkPolicies
scripts/        smoke.sh, attack-demo.sh
docs/           DESIGN.md, THREAT_MODEL.md, EVALUATION.md
```

## The request pipeline

Every request walks the same seven stages, and each stage is timed into the
audit record (`stages_us`):

1. **Route match** — longest-prefix lookup against the configured route table.
2. **Token verify** — signature (pinned algorithm), `exp`/`nbf`, issuer,
   audience, and a hard ceiling on `exp - iat`.
3. **Device binding** — the fingerprint must be present and, when the token
   carries a `did` claim, must match it.
4. **Revocation** — `jti` and `sub` looked up in the L1 cache, then Redis.
5. **Rate limit** — identity window, plus a per-source window on sensitive
   routes.
6. **Authorisation** — local scope check, then the OPA decision.
7. **Forward + audit** — reverse proxy with identity headers, then a
   non-blocking hand-off to the audit engine.

Failure policy is explicit: revocation, rate limiting and policy **fail closed**
for routes flagged `sensitive` and fail open (degraded, and flagged as such in
the audit record) elsewhere. Every degraded request is marked
`"degraded": true`.

## Endpoints

| Path | Purpose |
|---|---|
| `/api/*` | Proxied routes (see `ZTAG_ROUTES`) |
| `/healthz` | Liveness; never touches a dependency |
| `/readyz` | Readiness; pings Redis |
| `/metrics` | Prometheus text exposition |
| `POST /admin/revoke` | Revoke a `jti` and/or a `sub`; needs `X-Ztag-Admin-Token` |
| `GET /admin/stats` | Counters plus revocation cache statistics |

```bash
curl -X POST localhost:8443/admin/revoke \
  -H "X-Ztag-Admin-Token: $ZTAG_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"sub":"user-1001","ttl_seconds":900}'
```

## Configuration

All configuration is environment driven and validated at startup; the process
refuses to boot with an unusable security setting (short HS256 secret, `alg=none`,
empty route table, malformed upstream).

| Variable | Default | Meaning |
|---|---|---|
| `ZTAG_LISTEN` | `:8443` | Listen address |
| `ZTAG_REDIS_ADDR` | `127.0.0.1:6379` | Redis endpoint |
| `ZTAG_REDIS_POOL` / `ZTAG_REDIS_TIMEOUT` | `64` / `300ms` | Connection pool, per-command deadline |
| `ZTAG_OPA_URL` | `http://127.0.0.1:8181/v1/data/ztag/authz/decision` | Decision endpoint |
| `ZTAG_POLICY_TIMEOUT` | `25ms` | Budget for the policy call |
| `ZTAG_POLICY_FAIL_OPEN` | `false` | Deny when OPA is unreachable (recommended) |
| `ZTAG_JWT_ALG` | `HS256` | `HS256` or `RS256` |
| `ZTAG_JWT_SECRET` | **required** | HS256 key, minimum 16 bytes. No default: the gateway refuses to start without it |
| `ZTAG_JWT_PUBLIC_KEY_FILE` | — | PEM public key for RS256 |
| `ZTAG_JWT_ISSUER` / `ZTAG_JWT_AUDIENCE` | `ztag-idp` / `ztag-api` | Claim expectations |
| `ZTAG_MAX_TOKEN_TTL` | `15m` | Reject tokens living longer than this |
| `ZTAG_CLOCK_LEEWAY` | `5s` | Clock-skew tolerance |
| `ZTAG_RATE_LIMIT` / `ZTAG_RATE_WINDOW` | `60` / `1m` | Sliding-window budget |
| `ZTAG_RATELIMIT_FAIL_OPEN` | `false` | Fall back to the in-process limiter |
| `ZTAG_REVOCATION_NEG_TTL` | `2s` | How long "not revoked" is cached locally |
| `ZTAG_REQUIRE_DEVICE` | `true` | Reject requests without a fingerprint |
| `ZTAG_AUDIT_SINKS` | `redis` | `redis`, `jsonl`, `none` |
| `ZTAG_AUDIT_STREAM` | `ztag:audit:stream` | Stream key |
| `ZTAG_AUDIT_QUEUE` / `ZTAG_AUDIT_WORKERS` | `8192` / `2` | Queue depth and flush workers |
| `ZTAG_ADMIN_TOKEN` | — | Enables the admin API; empty disables it |
| `ZTAG_ROUTES` | `/api/=http://127.0.0.1:9000\|` | `prefix=upstream\|scope\|flags`, `;` separated, flag `sensitive` |

## Secrets

Nothing usable is committed to this repository. There is no default signing key
and no default admin token, because a gateway that ships with a known key is a
gateway whose tokens anyone can forge.

| Where | How the secret arrives |
|---|---|
| Local (Compose) | `make env` generates `.env` with `openssl rand`; `.env` is gitignored |
| Local (binaries) | `export ZTAG_JWT_SECRET=$(openssl rand -hex 32)` |
| Kubernetes | `deploy/k8s/02-secret.yaml` holds placeholders only; create the Secret out of band (SealedSecrets, External Secrets, Vault, or `kubectl create secret`) |
| CI | Nothing to supply: the tests generate their own throwaway keys |

`docker-compose.yml` uses `${ZTAG_JWT_SECRET:?...}`, so `docker compose up`
fails immediately with a clear message instead of starting with a weak key. The
helper scripts (`smoke.sh`, `attack-demo.sh`) do the same, and source `.env`
automatically when it exists.

An empty `ZTAG_ADMIN_TOKEN` disables the admin API entirely rather than exposing
it unauthenticated.

## Redis data model

| Key | Type | TTL | Purpose |
|---|---|---|---|
| `ztag:revoked:jti:<jti>` | string | token lifetime | Revoke one token |
| `ztag:revoked:sub:<sub>` | string | window | Revoke every session of a user |
| `ztag:rl:<route>\|<subject>` | zset | window | Sliding window per identity |
| `ztag:rl:src\|<ip>\|<route>` | zset | window | Sliding window per source on sensitive routes |
| `ztag:audit:stream` | stream | trimmed ~200k | Audit queue with consumer groups |

## Testing

```bash
make test          # unit tests: JWT, device, config, limiter, audit engine,
                   # policy client, metrics
make race          # same, under the race detector
make policy-test   # 10 Rego tests, one per attack the policy must refuse
make bench         # micro-benchmarks (token verification, allocations)
make smoke         # 20+ end-to-end checks against a live gateway
```

The unit tests encode the security properties, not just the happy path: expired,
forged, `alg=none`, wrong-audience and over-long tokens are all rejected by
`internal/jwt`; the audit engine has a test that proves `Emit` cannot block the
caller when the queue is full; the policy tests assert that a valid token from
the wrong service, without MFA, or on an untrusted device is denied.

## Measured behaviour

On a 2 vCPU development container, single-client, request admitted end to end
(`docs/EVALUATION.md` has the methodology and the caveats):

| Stage | p50 | p95 |
|---|---|---|
| Token verification | 33 µs | 58 µs |
| Revocation lookup (L1 hit) | 1 µs | 1 µs |
| Sliding-window limiter | 1.4 ms | 5.9 ms |
| OPA decision | 1.2 ms | 2.5 ms |
| Upstream | 0.7 ms | 1.3 ms |
| **Total** | **3.5 ms** | **59 ms** |

These are container numbers with an in-memory Redis stand-in; run
`scripts/attack-demo.sh` on your own hardware for the numbers in your report.

## Design decisions worth defending in a viva

- **No third-party modules.** Every dependency is code you can be asked to
  explain. It also makes the image small and the supply chain trivial.
- **Redis Streams instead of Kafka by default.** Same consumer-group semantics,
  one less cluster to operate for a capstone; `docs/kafka-sink.go.txt` is the
  identical `Sink` interface implemented over Kafka behind a `kafka` build tag,
  kept out of the module so `go mod tidy` stays dependency-free.
- **The token never reaches the upstream.** The proxy converts a bearer
  credential into signed-off identity headers, so an internal service cannot
  replay a user credential.
- **Revocation is a cache, not a lookup.** Two levels, with a bounded negative
  TTL, so the common case never touches the network — and the staleness window
  is a documented number, not an accident.
- **Audit drops rather than blocks.** An attacker who floods the gateway must
  not be able to turn logging into a denial of service.

## Limitations and next steps

- Revocation is checked per request but the L1 negative cache means a revoked
  token can survive up to `ZTAG_REVOCATION_NEG_TTL` (default 2 s) on a replica
  that already cached it. Set it to `0` for strict consistency at the cost of
  one Redis round trip per request.
- Rate limits are per route prefix and identity; a global per-tenant budget
  would need a second key dimension.
- The policy input carries device *asserted* posture. Trusting that assertion
  requires an endpoint agent or a device certificate — the natural next step is
  mTLS with SPIFFE identities between gateway and upstream.
- `cmd/echo` is a stand-in; wiring real services means changing `ZTAG_ROUTES`
  and the Rego route table only.

## Licence

MIT. See `docs/` for the full design, threat model and evaluation plan.
