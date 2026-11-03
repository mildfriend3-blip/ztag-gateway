# Evaluation

The project claims three things: it stops the three attack classes, it stays out
of the latency budget, and its audit path cannot be used against it. This
document says how each claim is measured, reports a reference run, and lists the
threats to the validity of those numbers.

## 1. What is measured

| Claim | Metric | Instrument |
|---|---|---|
| Verification is cheap | `ns/op`, allocations per verification | `go test -bench -benchmem` |
| Each stage is cheap | `p50`/`p95` per stage in µs | `stages_us` in the audit record |
| End-to-end overhead is acceptable | Total p50/p95/p99 and throughput | `cmd/loadgen` |
| Attacks are stopped | Status-code mix per attack shape | `cmd/loadgen` + `scripts/attack-demo.sh` |
| Audit never blocks | Drops under back pressure, request latency unchanged | `internal/audit` unit test + `ztag_audit_events_total` |
| Revocation is fast and effective | L1 hit ratio, time-to-deny after revoke | `/admin/stats`, `scripts/smoke.sh` |
| Policy is not a bottleneck | `policy_us`, `ztag_dependency_errors_total{dependency="opa"}` | audit + `/metrics` |

Everything the gateway measures about itself is exposed twice: as a counter on
`/metrics` and as a per-request record in the audit stream. A number in this
document can therefore be recomputed from raw records.

## 2. Method

```bash
make build
make up                     # redis, opa, gateway, orders, auth, logworker
make token                  # a valid token for user-1001 on device d-7712
make attack                 # five load runs: baseline, flood, stuffing,
                            # stolen token, forged token
curl -s localhost:8443/metrics
docker compose exec logworker tail -f /var/log/ztag/audit.jsonl
```

`cmd/loadgen` reports, per run: mode, workers, wall time, requests sent,
successful responses, transport errors, requests per second, and p50/p90/p99/max
latency, plus the status-code histogram. Because it reports the histogram, an
attack run is self-documenting: 429s mean the limiter held, 401s mean identity
was rejected, and a spike of 200s during a "stolen token" run would be a finding.

### Reading the audit stream

```bash
jq -r '[.stages_us.auth_us, .stages_us.revocation_us, .stages_us.ratelimit_us,
        .stages_us.policy_us, .stages_us.upstream_us, .lat_us] | @tsv' \
   audit.jsonl | sort -n -k6 | tail -5
```

Because every stage is timed individually, a regression can be attributed
without a profiler: if `policy_us` grows, the policy engine or the network to it
changed; if `revocation_us` grows, the L1 hit rate fell.

## 3. Reference run

Hardware: 2 vCPU (AMD EPYC 7571), 2 GB RAM, single container, everything
co-located: gateway, OPA 1.0.0, an in-memory Redis stand-in, and the upstream
echo service. **These are not production numbers** — see §5.

### 3.1 Token verification (micro-benchmark)

```
BenchmarkVerifyHS256-2   100334   12246 ns/op   1768 B/op   30 allocs/op
```

12.2 µs per verification, 30 allocations. The allocations come from base64
decoding and `json.Unmarshal` into the claims struct; both are candidates for a
pooled-buffer rewrite. This is why the design document says
*allocation-conscious*, not zero-allocation.

### 3.2 Per-stage latency, admitted requests (n = 496, single client)

| Stage | p50 | p95 |
|---|---|---|
| Token verification (`auth_us`) | 33 µs | 58 µs |
| Revocation, L1 hit (`revocation_us`) | 1 µs | 1 µs |
| Sliding-window limiter (`ratelimit_us`) | 1406 µs | 5909 µs |
| OPA decision (`policy_us`) | 1222 µs | 2495 µs |
| Upstream (`upstream_us`) | 712 µs | 1336 µs |
| **Total (`lat_us`)** | **3484 µs** | **58830 µs** |

Load generator view of the same run: p50 4.1 ms, p90 9.7 ms, p99 62.8 ms, 70
requests/second at concurrency 1.

Interpretation:

- The identity stages the project is responsible for — verification, revocation,
  device binding — cost **tens of microseconds**. The 2 ms "sub-2ms token lookup"
  target is met by the L1 cache and by the Redis lookup when it is missed.
- The two network round trips (limiter, policy) dominate. Both are one call each,
  and both are on the critical path by design: a sliding window that is not
  atomic is not a rate limiter, and a decision that is not made centrally is not
  a policy.
- p95 total is much larger than p50 because of scheduling noise on 2 vCPUs shared
  by five processes, including a garbage collector.

### 3.3 Saturation behaviour

At concurrency 50–200 on this hardware, throughput plateaued at ~130–190 req/s
and a growing share of responses were `503 policy_unavailable`: with 2 vCPUs and
five processes competing, the 25 ms policy budget was exceeded under load.
`ztag_dependency_errors_total{dependency="opa"}` tracked it exactly, which is the
point of the metric — the failure was attributed to the right dependency in one
query.

This is an environment limit, not a gateway limit. On a machine with one core
per concurrent proxy worker and a co-located OPA, the same run should be limited
by OPA throughput, not by CPU contention. Re-run §3.2 and §3.3 on your own
hardware and use those numbers; the method is what transfers.

## 4. Attack runs

Expected and observed behaviour per mode (verified with the end-to-end harness;
reproduce with `make attack`):

| Mode | Expected status mix | What it proves |
|---|---|---|
| `legit` | 200 | The happy path works under load |
| `flood` (same identity, `/api/login`) | first `limit` responses admitted, then 429 with `Retry-After` | The sliding window holds and is not bypassable by concurrency |
| `stuffing` (rotating usernames, rotating `X-Forwarded-For`) | 429 once either the identity or the source budget is spent | Two dimensions are required; one is not enough |
| stolen token (`-device` swapped) | 401 `device_binding_mismatch` | Replay from another machine fails at stage 3 |
| `badtoken` | 401 `invalid_token:bad_signature` | Forged credentials never reach a dependency |
| no token | 401 `missing_bearer_token` | — |
| revoked token | 401 `token_revoked` within the negative-cache window | The kill switch works cluster-wide |
| long-lived token (24 h) | 401 `invalid_token:ttl_too_long` | The issuer cannot bypass the TTL ceiling |
| valid token, wrong `svc` | 403 `policy_denied:service_not_allowed` | Lateral movement is stopped with a valid credential |

Record the histogram, not just the throughput: a run that returns 429 for 95% of
requests has a very different meaning from one that returns 200.

## 5. Threats to validity

Be explicit about these in the report; an examiner will ask.

1. **Shared 2 vCPU container.** The proxy, OPA, Redis, the load generator and the
   upstream competed for two cores. Absolute latency is inflated and the
   saturation point is meaningless as a capacity figure. Relative stage costs and
   the attack behaviour are still informative.
2. **In-memory Redis stand-in for the reference run.** The container had no Redis
   server, so the measurements used a minimal local RESP server implementing the
   same commands. It is not as fast as Redis 7 and does not model persistence.
   `make up` uses the real image; re-measure there.
3. **Single client host.** The load generator shares a kernel and a NIC with the
   gateway, so per-request overhead is understated at low concurrency and
   overstated at high concurrency.
4. **Synthetic upstream.** `cmd/echo` returns a small JSON body in microseconds;
   a real service would dominate the total, which is the desired outcome but
   changes the percentages.
5. **Warm caches.** Revocation and rate-limit numbers assume a warm L1 cache and
   an existing Redis connection; the first request after a deploy is slower.
6. **No adversarial network conditions.** Packet loss, TLS handshakes and real
   internet RTT are absent; the policy and limiter calls are loopback.

## 6. Reproducing and reporting

For the report, capture:

```bash
# 1. correctness
make test && make policy-test && make smoke        # record pass counts

# 2. micro
make bench                                          # ns/op, B/op, allocs/op

# 3. per stage
#    run a single-client load, then compute p50/p95 from the audit stream
#    (jq one-liner in §2)

# 4. saturation
for c in 1 10 50 100 200; do
  ./bin/ztag-loadgen -url http://localhost:8443/api/orders -token "$TOKEN" \
    -mode legit -c $c -n 5000 -device "$DEVICE"
done

# 5. attacks
make attack

# 6. dependency failure drills
docker compose stop opa     && make smoke   # expect 503 on sensitive routes
docker compose start opa
docker compose stop redis   && make smoke   # expect 503 + degraded audit records
docker compose start redis
```

The dependency drills are worth a paragraph each in the evaluation chapter: they
demonstrate that the failure mode is the designed one, not an accident.

## 7. Results to fill in

| Experiment | p50 | p95 | p99 | Throughput | Notes |
|---|---|---|---|---|---|
| legit, c=1 | | | | | |
| legit, c=10 | | | | | |
| legit, c=50 | | | | | |
| legit, c=200 | | | | | |
| flood, c=100 | | | | | 429 share: |
| stuffing, c=50 | | | | | 429 share: |
| stolen token | | | | | 401 share: |
| OPA stopped | | | | | 503 share: |
| Redis stopped | | | | | 503 share, degraded: |
