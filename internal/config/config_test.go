package config

import (
	"os"
	"testing"
	"time"
)

func TestParseRoutes(t *testing.T) {
	got, err := parseRoutes("/api/orders=http://orders:9000|orders.read|;/api/payments=http://pay:9000|payments.write|sensitive")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 routes, got %d", len(got))
	}
	if got[0].Prefix != "/api/orders" || got[0].Scope != "orders.read" || got[0].Sensitive {
		t.Fatalf("route 0: %+v", got[0])
	}
	if !got[1].Sensitive || got[1].Upstream != "http://pay:9000" {
		t.Fatalf("route 1: %+v", got[1])
	}
}

func TestParseRoutesRejectsBadPrefix(t *testing.T) {
	if _, err := parseRoutes("api/orders=http://x:1"); err == nil {
		t.Fatal("expected an error for a prefix without a leading slash")
	}
	if _, err := parseRoutes("/api/orders"); err == nil {
		t.Fatal("expected an error for a route without an upstream")
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("ZTAG_JWT_SECRET", "0123456789abcdef0123456789abcdef")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ListenAddr != ":8443" || cfg.RateLimit != 60 || cfg.MaxTokenTTL != 15*time.Minute {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if len(cfg.Routes) != 1 {
		t.Fatalf("expected the default route, got %d", len(cfg.Routes))
	}
}

func TestLoadRequiresSecret(t *testing.T) {
	// No default signing secret exists: an unset ZTAG_JWT_SECRET must fail.
	t.Setenv("ZTAG_JWT_SECRET", "")
	os.Unsetenv("ZTAG_JWT_SECRET")
	if _, err := Load(); err == nil {
		t.Fatal("expected a validation error when ZTAG_JWT_SECRET is unset")
	}
}

func TestLoadRejectsShortSecret(t *testing.T) {
	t.Setenv("ZTAG_JWT_SECRET", "short")
	if _, err := Load(); err == nil {
		t.Fatal("expected a validation error for a short HS256 secret")
	}
}

func TestLoadRejectsUnsupportedAlgorithm(t *testing.T) {
	t.Setenv("ZTAG_JWT_ALG", "none")
	if _, err := Load(); err == nil {
		t.Fatal(`"none" must never be an accepted algorithm`)
	}
}
