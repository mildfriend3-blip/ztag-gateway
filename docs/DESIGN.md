# Design

This document explains how the gateway is built, why each component exists, and
what happens when a dependency fails. It is the technical reference behind the
README and the companion to `THREAT_MODEL.md` (what we defend against) and
`EVALUATION.md` (how we prove it).

## 1. Problem statement

Internal microservices are usually protected by network position, not identity.
Once an attacker is inside — through a stolen session, a phished credential or
one compromised pod — every service trusts them. Three consequences matter:

1. **Sessions outlive compromise.** A bearer token is valid until it expires, no
   matter who is holding it.
2. **Authentication endpoints are cheap to attack.** Nothing in front of the
   login route distinguishes a human from a script, so credential stuffing
   reaches the password check itself.
3. **The network is flat.** Service A can call service B directly; a single
   foothold becomes a walk.

The project answers all three with one control point: a data plane that verifies
continuously, throttles cheaply, and decides centrally.

## 2. Goals and non-goals

**Goals**

- Sub-millisecond steady-state overhead on top of the upstream call for the
  identity stages (verification, revocation cache hit).
- No single dependency can take the whole gateway down without an explicit,
  documented policy choice per route.
- Every decision, allow or deny, is auditable, with stage-level timings.
- Horizontally scalable: N gateway replicas share one Redis and one OPA, with no
  coordination beyond those services.
- Deployable as a plain binary, a container, and a Kubernetes workload with
  restrictive network policy.

**Non-goals**

- Being an ingress controller, WAF or TLS terminator for the whole cluster. It
  sits behind an L7 load balancer and does one thing.
- Storing or issuing credentials. Token issuance belongs to the IdP; `tokengen`
  exists only so the project can be demonstrated.
- General-purpose policy authoring UI.

## 3. Component responsibilities

| Component | Owns | Must never |
|---|---|---|
| `cmd/proxy` (`internal/proxysrv`) | Request pipeline, reverse proxy, admin API, metrics | Write audit synchronously, hold user credentials after the request |
| `internal/jwt` | Proof of identity | Accept an algorithm it was not configured for, or a token longer-lived than the TTL ceiling |
| `internal/revocation` | "Is this identity still allowed?" | Become a per-request network dependency on the hot path |
| `internal/ratelimit` | Admission rate per identity/source | Give an attacker a way to bypass by rotating identities |
| `internal/policy` | Ask OPA, parse the verdict | Interpret an undefined decision as allow |
| `internal/audit` | Durable record of decisions | Block, or apply back pressure to, the request path |
| OPA (`policies/`) | Authorisation semantics | Contain transport or caching logic |
| `cmd/logworker` | Persist the stream | Be required for the gateway to serve traffic |

## 4. Request lifecycle

```
handleProxy
  ├─ route match (longest prefix)                       ~50 ns
  ├─ bearer parse + jwt.Verify                          ~33 µs
  │    header.alg must equal the pinned algorithm
  │    HMAC/RSA verify → exp/nbf (±leeway) → iss → aud → exp-iat ≤ ceiling
  ├─ device.Parse + binding check                       ~2 µs
  ├─ revocation.Revoked(jti, sub)                       ~1 µs (L1) / ~0.3 ms (L2)
  ├─ ratelimit.Allow(route|subject)                     ~1 ms (one Lua round trip)
  │    + ratelimit.Allow(src|ip|route) for sensitive routes
  ├─ scope check (local, cheap)                         ~0.1 µs
  ├─ policy.Decide(input)                               ~1.2 ms (one HTTP round trip)
  ├─ ReverseProxy.ServeHTTP → upstream                  ~0.7 ms in the demo topology
  └─ audit.Emit(event)                                  ~200 ns (channel send or drop)
```

Every stage writes its own duration into `reqCtx.stage`, which becomes
`stages_us` in the audit record. That is what makes the evaluation chapter
possible without a profiler: the gateway times itself.

### Why the order is what it is

Cheapest and most decisive first. Signature verification rejects the vast
majority of hostile traffic for tens of microseconds. Revocation is next because
it is nearly free when cached and catastrophic to skip. Rate limiting precedes
authorisation so that a flood cannot consume OPA capacity — the policy engine is
the most expensive shared dependency, and protecting it is the point. Scope is
checked locally before the round trip because a missing scope is knowable
without the policy engine.

## 5. Identity model

A token is an HS256 or RS256 JWT with the following claims:

```json
{
  "sub": "user-1001",
  "iss": "ztag-idp",
  "aud": ["ztag-api"],
  "iat": 1767225600,
  "exp": 1767225900,
  "jti": "5ccd2f82388e6a04198d746d",
  "svc": "web",
  "did": "d-7712",
  "scope": ["orders.read"],
  "amr": ["pwd", "otp"]
}
```

- `svc` is the **calling service identity**, not a user role. It is what makes
  service-to-service segmentation possible: a token minted for `reporting` cannot
  be replayed against `/api/payments`.
- `did` binds the token to a device. The client must present a matching
  fingerprint; a replayed token on another machine fails at stage 3.
- `amr` records how the user authenticated, so a route can demand a second
  factor without a second token.
- `jti` makes single-token revocation possible; `sub` makes "log this user out
  everywhere" possible.

Verification pins the algorithm. The `alg` header is compared against the
configured algorithm for a precise error message, but dispatch never depends on
it, so `alg: none` and HMAC/RSA confusion are structurally impossible.

## 6. Revocation

Two levels, because the answer is almost always "not revoked" and it must be
cheap:

- **L1** — in-process map of `key → {revoked, until}` guarded by an `RWMutex`.
  Positive entries live 30 s; negative entries live `ZTAG_REVOCATION_NEG_TTL`
  (default 2 s). Bounded at 200k entries, garbage-collected opportunistically;
  on overflow the map is reset rather than maintaining an LRU on the hot path.
- **L2** — one `MGET` over `ztag:revoked:jti:<jti>` and `ztag:revoked:sub:<sub>`.
  Present and non-empty means revoked.

**Trade-off, stated plainly:** the negative cache means a token revoked at time
*T* can still be admitted on a replica that cached "not revoked" at *T-ε* for up
to the negative TTL. Setting `ZTAG_REVOCATION_NEG_TTL=0` gives strict
consistency at one Redis round trip per request (~0.3 ms locally). The default
is a deliberate 2 s window.

Revocation is written by `POST /admin/revoke`, which sets both keys with a TTL
and also primes the local cache, so the replica that served the admin call
applies it immediately.

## 7. Rate limiting

The limiter is a sorted set per key with millisecond scores:

```lua
ZREMRANGEBYSCORE key -inf now-window   -- drop the expired tail
count = ZCARD key
if count >= limit then return {0, count, retry_after} end
ZADD key now member                    -- member = "<now>:<seq>"
PEXPIRE key window
return {1, count+1, 0}
```

Properties that matter:

- **Atomic.** Trim, count and insert happen inside one Lua invocation, so 100
  replicas cannot each admit the same last slot.
- **Sliding, not fixed.** A fixed window lets an attacker send 2× the limit
  across a boundary; a sliding window bounds the rate at every instant.
- **Two dimensions.** `route|subject` stops one identity flooding; on routes
  flagged `sensitive`, `src|ip|route` stops credential stuffing that rotates
  usernames from one host. Neither alone is sufficient.
- **Unique members.** `<now>:<process-wide sequence>` guarantees distinct
  members even for requests inside the same millisecond, so a burst is never
  under-counted.

When Redis is unreachable the proxy either denies (`ZTAG_RATELIMIT_FAIL_OPEN=false`,
the default) or falls back to a per-replica fixed-window limiter. The fallback is
weaker by construction — N replicas admit N × limit — so it is marked
`degraded: true` in the audit record rather than presented as equivalent.

## 8. Policy

OPA receives a compact JSON document and returns a decision object:

```json
{"input": {
  "subject": "user-1001", "service": "web", "scopes": ["orders.read"],
  "amr": ["pwd","otp"], "jti": "...", "method": "GET", "path": "/api/orders",
  "route": "/api/orders", "source_ip": "203.0.113.9", "token_ttl_s": 300,
  "request_id": "11gfr03-1",
  "device": {"id": "d-7712", "hash": "d4d1ed5f6eac5324", "trust": 100, "bound": true}
}}
```

```json
{"result": {"allow": true, "reason": "admitted", "step_up": false}}
```

The input is serialised by hand into a pooled buffer (`appendJSONString`) rather
than via reflection, which keeps the call to roughly one allocation and makes
the exact document reviewable in a single screen. Escaping follows RFC 8259 for
control characters, quotes and backslashes, so a crafted header cannot inject
JSON into the policy input.

Deny reasons are a **set**, and the decision reports the first in sorted order,
so a request that fails several checks always produces the same explanation.
`default allow := false` makes the verdict total: an unmatched rule set denies
rather than returning `undefined`.

**Failure mode.** `ZTAG_POLICY_FAIL_OPEN=false` (default) means an OPA timeout or
transport error yields `503 policy_unavailable`. The 25 ms default budget is
deliberately tight: it is a latency guarantee to the caller, and the operator can
raise it when OPA is co-located.

## 9. Audit pipeline

```
request path ──Emit (non-blocking)──► bounded channel (8192)
                                          │
                              worker pool (2) ──batch 64 / 5 ms──► Sink
                                                                     ├─ Redis Stream (default)
                                                                     ├─ JSONL (local/demo)
                                                                     └─ Kafka (build tag)
                                                                              │
                                                                     logworker ──► audit store
```

Design rules:

- `Emit` is a `select` with a `default` branch. If the queue is full the event
  is dropped and counted (`ztag_audit_events_total{state="dropped"}`). Logging
  must never be an availability lever an attacker can pull.
- Workers batch up to 64 events or 5 ms, then write once. The Redis sink
  pipelines one `XADD` per event in a single write, so the cost is one syscall
  per batch.
- The consumer group (`audit-writers`) makes the log worker horizontally
  scalable and at-least-once: a crashed worker's pending entries are re-delivered
  because it never `XACK`ed them.
- Sinks are an interface. `docs/kafka-sink.go.txt` is a ready-made Kafka sink
  implementing the same three methods behind `//go:build kafka`; drop it into
  `internal/audit/` when the deployment already runs Kafka. The queue backend is
  a build tag, not a rewrite.

Event schema (JSONL, one object per line):

```json
{"ts":1793729137081,"rid":"11gfr03-1","sub":"bench","jti":"5ccd…","svc":"web",
 "did":"d-7712","dhk":"d4d1ed5f6eac5324","trust":100,"method":"GET",
 "path":"/api/orders","route":"/api/orders","status":200,"decision":"allow",
 "reason":"admitted","src_ip":"127.0.0.1","lat_us":3484,
 "stages_us":{"auth_us":33,"revocation_us":1,"ratelimit_us":1406,
              "policy_us":1222,"upstream_us":712}}
```

The device is identified by a **hash**, not the raw fingerprint, so the audit
store never holds a high-entropy identifier that could be replayed.

## 10. Failure modes

| Failure | Default behaviour | Control |
|---|---|---|
| Redis unreachable | Sensitive routes `503`; others admit in degraded mode with a per-replica limiter and a 2 s-cached revocation view | `ZTAG_RATELIMIT_FAIL_OPEN`, route `sensitive` flag |
| OPA unreachable or slow | `503 policy_unavailable` (fail closed) | `ZTAG_POLICY_FAIL_OPEN`, `ZTAG_POLICY_TIMEOUT` |
| Upstream unreachable | `502 upstream_unreachable`, audited as `decision: "error"` | Upstream timeout, retry at the client |
| Audit sink down | Events queue, then drop and count; requests unaffected | Queue depth, `ztag_audit_events_total` |
| Clock skew | ±5 s tolerance on `exp`/`nbf` | `ZTAG_CLOCK_LEEWAY` |
| Malformed request | Denied with a specific reason code before any dependency is touched | — |

Note the asymmetry: **authorisation fails closed, telemetry fails open.** Denying
traffic because logging is down would hand an attacker a trivial outage; allowing
traffic because policy is down would hand them the whole system.

## 11. Performance design

- Zero third-party dependencies, so the binary is a static ~9 MB image with no
  init cost beyond process start.
- Connection pooling everywhere: the Redis client keeps a fixed pool with
  dead-connection discard; the OPA client uses a transport with
  `MaxIdleConnsPerHost=256`; the upstream transport keeps 1024 idle connections
  per host.
- Buffer reuse: the Redis command buffer lives on the connection, the policy
  input lives in a `sync.Pool`, the audit sink reuses its line buffer.
- No per-request goroutines. The only goroutines are the audit workers, the HTTP
  server's own, and whatever the runtime adds.
- Timers are avoided on the hot path; deadlines are absolute and computed once
  per stage.
- The response writer is wrapped once (`statusWriter`) to capture status for the
  audit record, and the wrapper forwards `Flush` so streaming still works.

## 12. Deployment topology

- **Container:** multi-stage build, distroless runtime, non-root, read-only root
  filesystem, all capabilities dropped.
- **Kubernetes:** three replicas behind a `ClusterIP` service, HPA on CPU and on
  `ztag_inflight_requests`, PDB `minAvailable: 2`, zone-spread constraints,
  `preStop` sleep so the load balancer drains before the process exits.
- **Network:** default-deny ingress and egress in the namespace. The gateway may
  reach Redis, OPA and the upstreams; upstreams may reach DNS only; Redis and OPA
  accept traffic from the gateway (and Redis from the log worker) and nothing
  else. This is the packet-level half of microsegmentation, and OPA is the
  identity-level half; both must agree, which is why the route table exists in
  both places.

## 13. Extension points

- **RS256 / JWKS.** `ZTAG_JWT_ALG=RS256` plus a PEM public key; a JWKS fetcher
  with key rotation is the natural next increment (`internal/jwt` already keeps
  the algorithm pinned per verifier).
- **Kafka.** Copy `docs/kafka-sink.go.txt` to `internal/audit/sink_kafka.go`,
  `go get github.com/segmentio/kafka-go`, then `go build -tags kafka ./cmd/proxy`.
  It is kept out of the module so that `go mod tidy` stays dependency-free.
- **mTLS between gateway and upstream.** Terminate client certs, map SPIFFE IDs
  into the policy input's `service` field, and the Rego table needs no change.
- **Per-tenant budgets.** Add a tenant dimension to the limiter key and to
  `data.ztag.routes`.
