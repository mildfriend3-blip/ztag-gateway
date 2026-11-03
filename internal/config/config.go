// Package config loads the data plane configuration from the environment. Every
// value has a safe default, and every security-relevant knob is explicit so it
// can be reviewed in one place.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Route maps a path prefix onto an upstream and the scope it requires.
type Route struct {
	// Prefix is the incoming path prefix, for example /api/orders.
	Prefix string
	// Upstream is the base URL of the internal service.
	Upstream string
	// Scope is the OAuth-style scope the token must carry ("" means any).
	Scope string
	// Sensitive marks routes that must fail closed when a dependency is down.
	Sensitive bool
}

// Config is the full runtime configuration.
type Config struct {
	ListenAddr        string
	RedisAddr         string
	RedisPool         int
	RedisTimeout      time.Duration
	OPAURL            string
	PolicyTimeout     time.Duration
	PolicyFailOpen    bool
	JWTAlg            string
	JWTSecret         []byte
	JWTPublicKeyPEM   string
	JWTIssuer         string
	JWTAudience       string
	MaxTokenTTL       time.Duration
	ClockLeeway       time.Duration
	RateLimit         int64
	RateWindow        time.Duration
	RateLimitFailOpen bool
	RevocationNegTTL  time.Duration
	RequireDevice     bool
	AuditQueue        int
	AuditWorkers      int
	AuditStream       string
	AuditSinks        []string
	AuditFile         string
	AdminToken        string
	UpstreamTimeout   time.Duration
	ShutdownTimeout   time.Duration
	Routes            []Route
}

// Load reads and validates the environment.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:        env("ZTAG_LISTEN", ":8443"),
		RedisAddr:         env("ZTAG_REDIS_ADDR", "127.0.0.1:6379"),
		RedisPool:         envInt("ZTAG_REDIS_POOL", 64),
		RedisTimeout:      envDur("ZTAG_REDIS_TIMEOUT", 300*time.Millisecond),
		OPAURL:            env("ZTAG_OPA_URL", "http://127.0.0.1:8181/v1/data/ztag/authz/decision"),
		PolicyTimeout:     envDur("ZTAG_POLICY_TIMEOUT", 25*time.Millisecond),
		PolicyFailOpen:    envBool("ZTAG_POLICY_FAIL_OPEN", false),
		JWTAlg:            strings.ToUpper(env("ZTAG_JWT_ALG", "HS256")),
		JWTSecret:         []byte(os.Getenv("ZTAG_JWT_SECRET")),
		JWTPublicKeyPEM:   env("ZTAG_JWT_PUBLIC_KEY_FILE", ""),
		JWTIssuer:         env("ZTAG_JWT_ISSUER", "ztag-idp"),
		JWTAudience:       env("ZTAG_JWT_AUDIENCE", "ztag-api"),
		MaxTokenTTL:       envDur("ZTAG_MAX_TOKEN_TTL", 15*time.Minute),
		ClockLeeway:       envDur("ZTAG_CLOCK_LEEWAY", 5*time.Second),
		RateLimit:         int64(envInt("ZTAG_RATE_LIMIT", 60)),
		RateWindow:        envDur("ZTAG_RATE_WINDOW", time.Minute),
		RateLimitFailOpen: envBool("ZTAG_RATELIMIT_FAIL_OPEN", false),
		RevocationNegTTL:  envDur("ZTAG_REVOCATION_NEG_TTL", 2*time.Second),
		RequireDevice:     envBool("ZTAG_REQUIRE_DEVICE", true),
		AuditQueue:        envInt("ZTAG_AUDIT_QUEUE", 8192),
		AuditWorkers:      envInt("ZTAG_AUDIT_WORKERS", 2),
		AuditStream:       env("ZTAG_AUDIT_STREAM", "ztag:audit:stream"),
		AuditSinks:        splitCSV(env("ZTAG_AUDIT_SINKS", "redis")),
		AuditFile:         env("ZTAG_AUDIT_FILE", ""),
		AdminToken:        env("ZTAG_ADMIN_TOKEN", ""),
		UpstreamTimeout:   envDur("ZTAG_UPSTREAM_TIMEOUT", 5*time.Second),
		ShutdownTimeout:   envDur("ZTAG_SHUTDOWN_TIMEOUT", 10*time.Second),
	}

	routes, err := parseRoutes(env("ZTAG_ROUTES", "/api/=http://127.0.0.1:9000|"))
	if err != nil {
		return nil, err
	}
	c.Routes = routes

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	switch c.JWTAlg {
	case "HS256":
		// There is deliberately no default signing secret: a gateway that
		// ships with a known key is a gateway anyone can forge tokens for.
		if len(c.JWTSecret) == 0 {
			return errors.New("config: ZTAG_JWT_SECRET is required (16+ random bytes); no default is provided")
		}
		if len(c.JWTSecret) < 16 {
			return errors.New("config: ZTAG_JWT_SECRET must be at least 16 bytes")
		}
	case "RS256":
		if c.JWTPublicKeyPEM == "" {
			return errors.New("config: ZTAG_JWT_PUBLIC_KEY_FILE is required for RS256")
		}
	default:
		return fmt.Errorf("config: unsupported ZTAG_JWT_ALG %q (use HS256 or RS256)", c.JWTAlg)
	}
	if c.RateLimit <= 0 {
		return errors.New("config: ZTAG_RATE_LIMIT must be positive")
	}
	if len(c.Routes) == 0 {
		return errors.New("config: ZTAG_ROUTES is empty")
	}
	for _, r := range c.Routes {
		u, err := url.Parse(r.Upstream)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return fmt.Errorf("config: route %q has an invalid upstream %q", r.Prefix, r.Upstream)
		}
	}
	if c.AdminToken == "" {
		// An empty admin token disables the admin API; say so loudly at startup
		// rather than silently accepting unauthenticated revocation.
		fmt.Fprintln(os.Stderr, "config: ZTAG_ADMIN_TOKEN is empty, admin API disabled")
	}
	return nil
}

// parseRoutes reads "prefix=upstream|scope|flags" entries separated by ';'.
// The only recognised flag is "sensitive".
func parseRoutes(spec string) ([]Route, error) {
	var out []Route
	for _, entry := range strings.Split(spec, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		left, right, ok := strings.Cut(entry, "=")
		if !ok {
			return nil, fmt.Errorf("config: malformed route %q (want prefix=upstream|scope|flags)", entry)
		}
		parts := strings.Split(right, "|")
		r := Route{Prefix: strings.TrimSpace(left), Upstream: strings.TrimSpace(parts[0])}
		if len(parts) > 1 {
			r.Scope = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			for _, f := range strings.Split(parts[2], ",") {
				if strings.EqualFold(strings.TrimSpace(f), "sensitive") {
					r.Sensitive = true
				}
			}
		}
		if !strings.HasPrefix(r.Prefix, "/") {
			return nil, fmt.Errorf("config: route prefix %q must start with /", r.Prefix)
		}
		out = append(out, r)
	}
	return out, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
