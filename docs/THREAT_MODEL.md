# Threat model

Structured with STRIDE-style categories but organised around the three attack
classes the project claims to stop, because those are what the evaluation and
the viva will test. Every control listed here has an executable check: a unit
test, a Rego test, or a line in `scripts/smoke.sh`. The mapping is at the end.

## 1. Assets

| Asset | Why it matters | Where it lives |
|---|---|---|
| User session / bearer token | Grants a user's authority to anyone holding it | Client, in flight |
| Service identity | Grants a service's reachability | Token claim `svc` |
| Internal service availability | A flood of the login route is an outage | Upstream pods |
| Audit record | The only evidence after an incident | Redis stream → store |
| Policy | The authorisation semantics of the whole estate | OPA data |
| Redis revocation list | The kill switch for compromised identity | Redis |

## 2. Actors

- **Remote unauthenticated attacker** — no token; scans, floods, tries forged
  tokens.
- **Attacker with a stolen token** — has a valid credential, not the device.
- **Insider or compromised service** — has a legitimately issued token for one
  service and tries to reach others.
- **Malicious client on a compromised endpoint** — presents a managed-device
  fingerprint that is no longer true.

Out of scope: physical access to nodes, compromise of the IdP signing key, and
supply-chain attacks on the container base image (mitigated, not solved, by the
distroless non-root runtime).

## 3. Threat A — session takeover and token leakage

**Scenario.** The token is captured from a proxy log, a browser extension, a
shoulder-surfed screen or a leaked HAR file. The attacker replays it from their
own machine.

**Naive defences and why they fail.** Static API keys never expire. Long-lived
JWTs cannot be withdrawn. Parameter checks (`user_id` matches `session.user_id`)
prove nothing when the attacker simply uses the victim's own values.

**Controls, in the order they fire**

1. **Short lifetime with a ceiling.** `exp - iat` must be ≤ `ZTAG_MAX_TOKEN_TTL`
   (15 min). A correctly signed 24-hour token is rejected — the issuer cannot
   quietly hand out a long-lived credential (`ErrTTL`).
2. **Device binding.** The token carries `did`; the request must present a
   fingerprint whose `id` matches, or the request is denied at stage 3. This is
   the control that specifically defeats replay: the string is useless on
   another machine.
3. **Device posture.** The fingerprint's asserted posture feeds a 0–100 trust
   score; the policy refuses below `min_trust` (50). A compliant managed laptop
   scores 90–100; an unknown device scores ≤ 20.
4. **Revocation.** `jti` (one token) and `sub` (all sessions) keys in Redis, with
   an in-process cache in front. One admin call kills a session cluster-wide,
   with a documented staleness window of `ZTAG_REVOCATION_NEG_TTL` (2 s default).
5. **Token never forwarded.** The upstream receives identity headers, never the
   bearer token, so a compromised internal service has nothing to replay.
6. **No credential in logs.** Audit records carry `sub`, `jti` and a device
   *hash*, never the token or the raw fingerprint.

**Residual risk.** An attacker who also steals the device fingerprint string and
whose device scores above the trust floor will pass — fingerprint headers are
asserted, not attested. The real fix is an endpoint certificate or a device-bound
key (WebAuthn / DPoP); the project documents this rather than pretending
otherwise.

## 4. Threat B — credential stuffing and bot flooding

**Scenario.** A botnet submits millions of username/password pairs against
`/api/login`, or simply floods the gateway to exhaust it.

**Controls**

1. **Sliding window before the upstream.** The limiter runs inside the proxy,
   ahead of the login route, so the password check is never reached by a flood.
   Atomic in Lua, therefore correct across replicas.
2. **Two dimensions.** `route|subject` bounds one identity; `src|ip|route` on
   sensitive routes bounds one source. Rotating usernames does not help against
   the second; rotating source addresses does not help against the first.
3. **Cheap rejection ordering.** Signature verification and the local scope check
   happen before the two network calls, so garbage traffic costs tens of
   microseconds.
4. **`Retry-After` and `X-RateLimit-Remaining`.** Well-behaved clients back off
   instead of retrying into the wall.
5. **Audit under load.** The audit queue sheds and counts rather than blocking,
   so a flood cannot convert logging into a bottleneck — the failure mode most
   naive gateways exhibit.
6. **Distributed denial of service** is *not* solved here. The project is honest
   about the boundary: volumetric attacks belong to an upstream scrubbing service
   or the cloud provider; this gateway protects the application layer.

## 5. Threat C — lateral movement

**Scenario.** One service (or one pod) is compromised. The attacker uses its
valid token to call other services, escalating from a low-value reporting job to
payments and admin.

**Controls**

1. **Service identity in the token.** `svc` names the calling service. It is a
   claim of the issuer, not a header the caller can set — and the proxy strips
   every inbound `X-Ztag-*` header before setting its own, so spoofing the
   identity header is impossible.
2. **Service→route table in OPA.** A route lists `allowed_services`; a token
   minted for `reporting` calling `/api/orders` is denied with
   `service_not_allowed` even though every other check passes.
3. **Route-scoped permissions.** Scope, HTTP method and MFA requirements are per
   route in `policies/data.json`. `/api/admin` additionally requires
   `ops-console` as the service identity and a second factor.
4. **Network segmentation.** Kubernetes default-deny ingress and egress; the
   gateway is the only pod allowed to reach the upstreams, and the upstreams may
   reach DNS only. Even a compromised upstream cannot scan the namespace, so the
   policy layer is not the only obstacle.
5. **No direct service-to-service path.** There is no sidecar bypass: services
   are reachable only through the gateway service, and the NetworkPolicy
   enforces it at the packet level.

**Residual risk.** Anything with `kubectl` in the namespace can change the
policy or the NetworkPolicy. Cluster RBAC and policy-change auditing are the
correct answer and are outside this project's scope.

## 6. Other threats considered

| Threat | Control |
|---|---|
| Forged token | Signature verification with a pinned algorithm; `alg: none` and confusion attacks rejected by construction |
| Token for another audience | `aud` must contain `ztag-api` |
| Token from another issuer | `iss` must match |
| Replay of an expired token | `exp` with ±5 s leeway only |
| Header injection into policy input | RFC 8259 escaping in the hand-built JSON; control characters stripped from echoed headers |
| Log injection | Response header echoes are sanitised to printable ASCII and truncated |
| Admin API abuse | Constant-time token comparison; empty `ZTAG_ADMIN_TOKEN` disables the API entirely |
| Policy engine compromise | An undefined decision is a deny (`default allow := false`); transport errors fail closed |
| Dependency outage as a bypass | Sensitive routes fail closed; degraded admits are marked `degraded: true` in the audit stream |
| Audit tampering | Events leave the process immediately over a queue; the sink is append-only, and the consumer group's `XACK` discipline prevents silent loss |
| Resource exhaustion via audit | Bounded queue, drop-and-count, no blocking |

## 7. Control → test mapping

| Control | Where it is proved |
|---|---|
| Signature, algorithm, expiry, audience, issuer, TTL ceiling | `internal/jwt/jwt_test.go` — `TestVerifyRejects` |
| Device binding and posture scoring | `internal/device/device_test.go`, `TestDeniesStolenTokenOnUnmanagedDevice` (Rego) |
| Revocation on every request | `scripts/smoke.sh` (valid → revoke → 401), end-to-end harness |
| Sliding window, atomicity, degraded fallback | `internal/ratelimit/ratelimit_test.go` |
| Service→route segmentation | `TestDeniesLateralMovement` (Rego) |
| MFA requirement on payments | `TestDeniesPaymentsWithoutMFA` (Rego) |
| Method restriction | `TestDeniesWrongMethod` (Rego) |
| Unknown route denied | `TestDeniesUnknownRoute` (Rego) |
| Audit never blocks the request path | `internal/audit/engine_test.go` — `TestEngineDropsInsteadOfBlocking` |
| Policy failure fails closed | `internal/policy/policy_test.go` — `TestDecideTimeout` |
| Token stripped, identity forwarded | `scripts/smoke.sh`, `cmd/echo` response |
| Admin API authentication | `scripts/smoke.sh`, `/admin/stats` without a token → 401 |

## 8. What this project deliberately does not claim

- It does not stop volumetric DDoS.
- It does not attest device health; it consumes an assertion.
- It does not protect against a compromised IdP signing key.
- It does not make a flat network safe on its own; the NetworkPolicy is half of
  the answer, and the other half is RBAC on the cluster.
- The 2 s revocation staleness window is a real window. It is configurable, and
  the strict setting costs one Redis round trip per request.
