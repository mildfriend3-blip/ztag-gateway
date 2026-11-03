// Package proxysrv is the data plane. Every request walks a fixed pipeline:
//
//	route match -> token verify -> device binding -> revocation -> rate limit
//	-> scope + policy decision -> upstream -> audit
//
// Each stage is timed, each denial is audited, and no stage can block the
// request path on logging. Dependencies fail closed for routes marked
// sensitive and fail open (in degraded mode) elsewhere.
package proxysrv

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ztag/gateway/internal/audit"
	"github.com/ztag/gateway/internal/config"
	"github.com/ztag/gateway/internal/device"
	"github.com/ztag/gateway/internal/jwt"
	"github.com/ztag/gateway/internal/metrics"
	"github.com/ztag/gateway/internal/policy"
	"github.com/ztag/gateway/internal/ratelimit"
	"github.com/ztag/gateway/internal/redisclient"
	"github.com/ztag/gateway/internal/revocation"
)

// Deps are the collaborators the data plane needs. Any nil optional dependency
// simply disables its stage, which keeps unit tests small.
type Deps struct {
	Verifier   *jwt.Verifier
	Redis      *redisclient.Client
	Revocation *revocation.Cache
	Limiter    *ratelimit.Limiter
	Policy     *policy.Client
	Audit      *audit.Engine
	Metrics    *metrics.Metrics
}

// Server is the gateway handler.
type Server struct {
	cfg       *config.Config
	deps      Deps
	routes    []*route
	mux       http.Handler
	memLimits *ratelimit.MemoryLimiter
	seq       atomic.Uint64
	now       func() time.Time
}

type route struct {
	cfg config.Route
	rp  *httputil.ReverseProxy
}

type ctxKey struct{}

// Decision values recorded on every request.
const (
	decisionPending = "pending"
	decisionAllow   = "allow"
	decisionDeny    = "deny"
	decisionError   = "error"
)

type reqCtx struct {
	rid      string
	start    time.Time
	route    *route
	claims   *jwt.Claims
	dev      device.Profile
	method   string
	path     string
	srcIP    string
	decision string
	reason   string
	stage    audit.Stage
	degraded bool
	bytes    int64
}

// New wires the server and its reverse proxies.
func New(cfg *config.Config, deps Deps) (*Server, error) {
	if deps.Metrics == nil {
		deps.Metrics = &metrics.Metrics{}
	}
	s := &Server{
		cfg:       cfg,
		deps:      deps,
		memLimits: ratelimit.NewMemory(cfg.RateLimit, cfg.RateWindow),
		now:       time.Now,
	}
	for _, rc := range cfg.Routes {
		u, err := url.Parse(rc.Upstream)
		if err != nil {
			return nil, err
		}
		s.routes = append(s.routes, &route{cfg: rc, rp: s.newProxy(u)})
	}
	// Longest prefix wins so /api/orders/admin beats /api/.
	sort.SliceStable(s.routes, func(i, j int) bool {
		return len(s.routes[i].cfg.Prefix) > len(s.routes[j].cfg.Prefix)
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/admin/revoke", s.handleRevoke)
	mux.HandleFunc("/admin/stats", s.handleStats)
	mux.HandleFunc("/", s.handleProxy)
	s.mux = mux
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) newProxy(u *url.URL) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   500 * time.Millisecond,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          4096,
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: s.cfg.UpstreamTimeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}

	return &httputil.ReverseProxy{
		Transport: transport,
		ErrorLog:  log.New(io.Discard, "", 0),
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = u.Scheme
			pr.Out.URL.Host = u.Host
			pr.Out.Host = u.Host
			pr.SetXForwarded()

			// The bearer token never crosses the trust boundary: the
			// upstream gets a signed-off identity, not a replayable secret.
			pr.Out.Header.Del("Authorization")
			pr.Out.Header.Del("Cookie")

			// Strip every client-supplied identity header before the proxy
			// sets its own, so a caller cannot spoof who it is.
			for h := range pr.Out.Header {
				if strings.HasPrefix(http.CanonicalHeaderKey(h), "X-Ztag-") {
					pr.Out.Header.Del(h)
				}
			}

			rc, _ := pr.In.Context().Value(ctxKey{}).(*reqCtx)
			if rc == nil || rc.claims == nil {
				return
			}
			pr.Out.Header.Set("X-Ztag-Subject", rc.claims.Subject)
			pr.Out.Header.Set("X-Ztag-Jti", rc.claims.JTI)
			pr.Out.Header.Set("X-Ztag-Service", rc.claims.Service)
			pr.Out.Header.Set("X-Ztag-Device", rc.dev.Hash)
			pr.Out.Header.Set("X-Ztag-Trust", rc.dev.TrustHeader())
			pr.Out.Header.Set("X-Ztag-Request-Id", rc.rid)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.deps.Metrics.UpstreamErr.Add(1)
			if rc, ok := r.Context().Value(ctxKey{}).(*reqCtx); ok {
				rc.decision = decisionError
				rc.reason = "upstream_unreachable"
			}
			writeJSON(w, http.StatusBadGateway, "upstream_unreachable", "", "")
		},
	}
}

func (s *Server) match(path string) *route {
	for _, rt := range s.routes {
		if strings.HasPrefix(path, rt.cfg.Prefix) {
			return rt
		}
	}
	return nil
}

// handleProxy is the hot path.
func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: w}
	rc := &reqCtx{
		rid:      requestID(r, &s.seq),
		start:    s.now(),
		route:    s.match(r.URL.Path),
		method:   r.Method,
		path:     r.URL.Path,
		srcIP:    clientIP(r),
		decision: decisionPending,
	}
	sw.Header().Set("X-Ztag-Request-Id", rc.rid)
	defer s.finish(sw, rc)

	m := s.deps.Metrics
	m.Requests.Add(1)
	m.InFlight.Add(1)
	defer m.InFlight.Add(-1)

	if rc.route == nil {
		s.deny(sw, rc, http.StatusNotFound, "no_route")
		return
	}
	if r.Method == http.MethodOptions {
		// Preflight is answered at the edge; it carries no credentials.
		sw.WriteHeader(http.StatusNoContent)
		rc.decision = decisionAllow
		rc.reason = "preflight"
		return
	}

	// ---- 1. token ------------------------------------------------------
	tok, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		s.deny(sw, rc, http.StatusUnauthorized, "missing_bearer_token")
		return
	}
	t := s.now()
	claims, err := s.deps.Verifier.Verify(tok, t)
	rc.stage.Auth = s.now().Sub(t).Microseconds()
	if err != nil {
		s.deny(sw, rc, http.StatusUnauthorized, "invalid_token:"+tokenReason(err))
		return
	}
	rc.claims = claims

	// ---- 2. device binding --------------------------------------------
	rc.dev = device.Parse(r.Header.Get(device.HeaderFingerprint), r.Header.Get(device.HeaderPosture))
	if s.cfg.RequireDevice && !rc.dev.Present {
		s.deny(sw, rc, http.StatusUnauthorized, "device_fingerprint_required")
		return
	}
	deviceBound := rc.dev.ID != "" && claims.DeviceID != "" && rc.dev.ID == claims.DeviceID
	if claims.DeviceID != "" && !deviceBound {
		s.deny(sw, rc, http.StatusUnauthorized, "device_binding_mismatch")
		return
	}

	// ---- 3. revocation -------------------------------------------------
	t = s.now()
	revoked, revErr := s.deps.Revocation.Revoked(claims.JTI, claims.Subject)
	rc.stage.Revocation = s.now().Sub(t).Microseconds()
	if revErr != nil {
		m.RedisErrors.Add(1)
		rc.degraded = true
		if rc.route.cfg.Sensitive {
			s.deny(sw, rc, http.StatusServiceUnavailable, "revocation_unavailable")
			return
		}
	}
	if revoked {
		m.Revoked.Add(1)
		s.deny(sw, rc, http.StatusUnauthorized, "token_revoked")
		return
	}

	// ---- 4. rate limit -------------------------------------------------
	t = s.now()
	if !s.admit(sw, rc, r) {
		rc.stage.RateLimit = s.now().Sub(t).Microseconds()
		return
	}
	rc.stage.RateLimit = s.now().Sub(t).Microseconds()

	// ---- 5. scope + policy --------------------------------------------
	if sc := rc.route.cfg.Scope; sc != "" && !claims.HasScope(sc) {
		s.deny(sw, rc, http.StatusForbidden, "insufficient_scope")
		return
	}

	t = s.now()
	dec, perr := s.deps.Policy.Decide(r.Context(), &policy.Input{
		Subject:      claims.Subject,
		Service:      claims.Service,
		Scopes:       claims.Scopes,
		AMR:          claims.AMR,
		JTI:          claims.JTI,
		Method:       r.Method,
		Path:         r.URL.Path,
		Route:        rc.route.cfg.Prefix,
		DeviceID:     rc.dev.ID,
		DeviceHash:   rc.dev.Hash,
		DeviceTrust:  rc.dev.Score,
		DeviceBound:  deviceBound,
		SourceIP:     clientIP(r),
		TokenTTLSecs: claims.Expiry - s.now().Unix(),
		RequestID:    rc.rid,
	})
	rc.stage.Policy = s.now().Sub(t).Microseconds()
	switch {
	case perr != nil:
		m.PolicyErrors.Add(1)
		rc.degraded = true
		if !s.cfg.PolicyFailOpen {
			s.deny(sw, rc, http.StatusServiceUnavailable, "policy_unavailable")
			return
		}
	case !dec.Allow:
		m.PolicyDenies.Add(1)
		s.deny(sw, rc, http.StatusForbidden, "policy_denied:"+dec.Reason)
		return
	}

	// ---- 6. upstream ---------------------------------------------------
	t = s.now()
	ctx := context.WithValue(r.Context(), ctxKey{}, rc)
	rc.route.rp.ServeHTTP(sw, r.WithContext(ctx))
	rc.stage.Upstream = s.now().Sub(t).Microseconds()
	if rc.decision != decisionPending {
		return // a deny or an upstream error already recorded the outcome
	}
	rc.decision = decisionAllow
	rc.reason = "admitted"
}

// admit applies the identity window and, for sensitive routes, a second
// per-source window so credential stuffing cannot rotate identities to escape
// the first one.
func (s *Server) admit(w *statusWriter, rc *reqCtx, r *http.Request) bool {
	m := s.deps.Metrics
	identityKey := rc.route.cfg.Prefix + "|" + rc.claims.Subject

	res, err := s.deps.Limiter.Allow(identityKey)
	if err != nil {
		m.RedisErrors.Add(1)
		rc.degraded = true
		if !s.cfg.RateLimitFailOpen {
			s.deny(w, rc, http.StatusServiceUnavailable, "ratelimit_unavailable")
			return false
		}
		res = s.memLimits.Allow(identityKey)
	}
	if !res.Allowed {
		m.RateLimited.Add(1)
		w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())+1))
		w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(res.Limit, 10))
		s.deny(w, rc, http.StatusTooManyRequests, "rate_limited")
		return false
	}
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(res.Limit-res.Count, 10))

	if rc.route.cfg.Sensitive {
		ipKey := "src|" + clientIP(r) + "|" + rc.route.cfg.Prefix
		ipRes, ipErr := s.deps.Limiter.Allow(ipKey)
		if ipErr != nil {
			m.RedisErrors.Add(1)
			rc.degraded = true
			if !s.cfg.RateLimitFailOpen {
				s.deny(w, rc, http.StatusServiceUnavailable, "ratelimit_unavailable")
				return false
			}
			ipRes = s.memLimits.Allow(ipKey)
		}
		if !ipRes.Allowed {
			m.RateLimited.Add(1)
			w.Header().Set("Retry-After", strconv.Itoa(int(ipRes.RetryAfter.Seconds())+1))
			s.deny(w, rc, http.StatusTooManyRequests, "source_rate_limited")
			return false
		}
	}
	return true
}

func (s *Server) deny(w *statusWriter, rc *reqCtx, status int, reason string) {
	rc.decision = decisionDeny
	rc.reason = reason
	s.deps.Metrics.Denied.Add(1)
	w.Header().Set("X-Ztag-Decision", "deny")
	w.Header().Set("X-Ztag-Reason", sanitizeHeader(reason))
	writeJSON(w, status, reason, rc.rid, "")
}

func (s *Server) finish(w *statusWriter, rc *reqCtx) {
	lat := s.now().Sub(rc.start)
	s.deps.Metrics.Observe(lat)
	if rc.decision == decisionPending {
		// No stage resolved the request: treat it as an error, never an allow.
		rc.decision = decisionError
		rc.reason = "unresolved"
	}
	if rc.decision == decisionAllow {
		s.deps.Metrics.Allowed.Add(1)
	}

	if s.deps.Audit == nil {
		return
	}
	ev := &audit.Event{
		TS:        rc.start.UnixMilli(),
		RequestID: rc.rid,
		Method:    rc.method,
		Status:    w.status,
		Decision:  rc.decision,
		Reason:    rc.reason,
		Path:      rc.path,
		SourceIP:  rc.srcIP,
		Trust:     rc.dev.Score,
		DeviceID:  rc.dev.ID,
		DeviceHK:  rc.dev.Hash,
		LatencyUS: lat.Microseconds(),
		Stage:     rc.stage,
		Degraded:  rc.degraded,
	}
	if rc.route != nil {
		ev.Route = rc.route.cfg.Prefix
	}
	if rc.claims != nil {
		ev.Subject = rc.claims.Subject
		ev.JTI = rc.claims.JTI
		ev.Service = rc.claims.Service
	}
	if s.deps.Audit.Emit(ev) {
		s.deps.Metrics.AuditEmitted.Add(1)
	} else {
		s.deps.Metrics.AuditDropped.Add(1)
	}
}

// ---- infrastructure endpoints -----------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, "ok", "", "")
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if s.deps.Redis == nil {
		writeJSON(w, http.StatusOK, "ready", "", "")
		return
	}
	if err := s.deps.Redis.Ping(); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, "redis_unavailable", "", "")
		return
	}
	writeJSON(w, http.StatusOK, "ready", "", "")
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.deps.Metrics.WriteProm(w)
}

type revokeRequest struct {
	JTI        string `json:"jti"`
	Subject    string `json:"sub"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, "admin_unauthorized", "", "")
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, "method_not_allowed", "", "")
		return
	}
	var req revokeRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, "bad_request", "", "")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = s.cfg.MaxTokenTTL
	}
	if err := s.deps.Revocation.RevokeToken(req.JTI, ttl); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, "redis_unavailable", "", "")
		return
	}
	if err := s.deps.Revocation.RevokeSubject(req.Subject, ttl); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, "redis_unavailable", "", "")
		return
	}
	writeJSON(w, http.StatusOK, "revoked", "", "")
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if !s.adminOK(r) {
		writeJSON(w, http.StatusUnauthorized, "admin_unauthorized", "", "")
		return
	}
	rs := s.deps.Revocation.Stats()
	body := map[string]any{
		"requests":      s.deps.Metrics.Requests.Load(),
		"allowed":       s.deps.Metrics.Allowed.Load(),
		"denied":        s.deps.Metrics.Denied.Load(),
		"rate_limited":  s.deps.Metrics.RateLimited.Load(),
		"revoked":       s.deps.Metrics.Revoked.Load(),
		"audit_emitted": s.deps.Metrics.AuditEmitted.Load(),
		"audit_dropped": s.deps.Metrics.AuditDropped.Load(),
		"revocation_l1": rs,
		"policy_errors": s.deps.Metrics.PolicyErrors.Load(),
		"redis_errors":  s.deps.Metrics.RedisErrors.Load(),
	}
	if s.deps.Audit != nil {
		body["audit_queue_depth"] = s.deps.Audit.Depth()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func (s *Server) adminOK(r *http.Request) bool {
	if s.cfg.AdminToken == "" {
		return false
	}
	got := r.Header.Get("X-Ztag-Admin-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.AdminToken)) == 1
}

// ---- helpers -----------------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if w.wrote {
		return
	}
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

// Flush keeps streaming responses working through the wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSON(w http.ResponseWriter, status int, reason, rid, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	body := struct {
		Error     string `json:"error"`
		Detail    string `json:"detail,omitempty"`
		RequestID string `json:"request_id,omitempty"`
	}{Error: reason, Detail: detail, RequestID: rid}
	_ = json.NewEncoder(w).Encode(body)
}

func bearer(h string) (string, bool) {
	const prefix = "bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(h[len(prefix):])
	return tok, tok != ""
}

func clientIP(r *http.Request) string {
	// The data plane sits behind exactly one L7 load balancer; X-Forwarded-For
	// is appended by that hop, so the last entry is the closest trustworthy
	// source address.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func requestID(r *http.Request, seq *atomic.Uint64) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 64 {
		return sanitizeHeader(id)
	}
	n := seq.Add(1)
	return strconv.FormatInt(time.Now().UnixNano()&0xffffffff, 36) + "-" + strconv.FormatUint(n, 36)
}

// sanitizeHeader strips control characters before a value is echoed into a
// response header (log/header injection defence).
func sanitizeHeader(s string) string {
	if len(s) > 128 {
		s = s[:128]
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 0x20 && c < 0x7f {
			b = append(b, c)
		}
	}
	return string(b)
}

func tokenReason(err error) string {
	switch {
	case errors.Is(err, jwt.ErrExpired):
		return "expired"
	case errors.Is(err, jwt.ErrSignature):
		return "bad_signature"
	case errors.Is(err, jwt.ErrAlgorithm):
		return "bad_algorithm"
	case errors.Is(err, jwt.ErrAudience):
		return "bad_audience"
	case errors.Is(err, jwt.ErrIssuer):
		return "bad_issuer"
	case errors.Is(err, jwt.ErrTTL):
		return "ttl_too_long"
	case errors.Is(err, jwt.ErrNotYet):
		return "not_yet_valid"
	case errors.Is(err, jwt.ErrMissing):
		return "missing_claim"
	default:
		return "malformed"
	}
}
