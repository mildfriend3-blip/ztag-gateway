// Command proxy is the zero-trust data plane. It terminates client requests,
// verifies identity, asks the policy engine, and forwards only what survives.
package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ztag/gateway/internal/audit"
	"github.com/ztag/gateway/internal/config"
	"github.com/ztag/gateway/internal/jwt"
	"github.com/ztag/gateway/internal/metrics"
	"github.com/ztag/gateway/internal/policy"
	"github.com/ztag/gateway/internal/proxysrv"
	"github.com/ztag/gateway/internal/ratelimit"
	"github.com/ztag/gateway/internal/redisclient"
	"github.com/ztag/gateway/internal/revocation"
)

func main() {
	logger := log.New(os.Stdout, "ztag-proxy ", log.LstdFlags|log.LUTC)

	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("%v", err)
	}

	rdb := redisclient.New(cfg.RedisAddr, cfg.RedisPool, cfg.RedisTimeout)
	defer rdb.Close()
	if err := rdb.Ping(); err != nil {
		logger.Printf("warning: redis not reachable at startup: %v (degraded mode)", err)
	}

	verifier, err := buildVerifier(cfg)
	if err != nil {
		logger.Fatalf("jwt: %v", err)
	}

	rev := revocation.New(rdb, cfg.RevocationNegTTL)
	limiter := ratelimit.New(rdb, "ztag:rl:", cfg.RateLimit, cfg.RateWindow)
	pol := policy.New(cfg.OPAURL, cfg.PolicyTimeout)

	engine, err := buildAudit(cfg, rdb, logger)
	if err != nil {
		logger.Fatalf("audit: %v", err)
	}
	defer engine.Close()

	srv, err := proxysrv.New(cfg, proxysrv.Deps{
		Verifier:   verifier,
		Redis:      rdb,
		Revocation: rev,
		Limiter:    limiter,
		Policy:     pol,
		Audit:      engine,
		Metrics:    &metrics.Metrics{},
	})
	if err != nil {
		logger.Fatalf("proxy: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// No WriteTimeout: streaming responses must be able to outlive it.
	}

	for _, rt := range cfg.Routes {
		logger.Printf("route %s -> %s scope=%q sensitive=%v", rt.Prefix, rt.Upstream, rt.Scope, rt.Sensitive)
	}
	logger.Printf("listening on %s alg=%s ratelimit=%d/%s audit_sinks=%s",
		cfg.ListenAddr, verifier.Algorithm(), cfg.RateLimit, cfg.RateWindow, strings.Join(cfg.AuditSinks, ","))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		logger.Fatalf("server: %v", err)
	case sig := <-stop:
		logger.Printf("received %s, draining for %s", sig, cfg.ShutdownTimeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Printf("shutdown: %v", err)
	}
}

func buildVerifier(cfg *config.Config) (*jwt.Verifier, error) {
	opts := []jwt.Option{
		jwt.WithLeeway(cfg.ClockLeeway),
		jwt.WithMaxTTL(cfg.MaxTokenTTL),
	}
	switch cfg.JWTAlg {
	case "HS256":
		return jwt.NewHMACVerifier(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, opts...), nil
	case "RS256":
		pub, err := loadPublicKey(cfg.JWTPublicKeyPEM)
		if err != nil {
			return nil, err
		}
		return jwt.NewRSAVerifier(pub, cfg.JWTIssuer, cfg.JWTAudience, opts...), nil
	default:
		return nil, errors.New("unsupported algorithm " + cfg.JWTAlg)
	}
}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("no PEM block in public key file")
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaPub, ok := pub.(*rsa.PublicKey); ok {
			return rsaPub, nil
		}
		return nil, errors.New("public key is not RSA")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func buildAudit(cfg *config.Config, rdb *redisclient.Client, logger *log.Logger) (*audit.Engine, error) {
	var sinks []audit.Sink
	for _, name := range cfg.AuditSinks {
		switch strings.ToLower(name) {
		case "redis", "redis-stream", "stream":
			sinks = append(sinks, audit.NewStreamSink(rdb, cfg.AuditStream, 200_000))
		case "jsonl", "file":
			s, err := audit.NewJSONLSink(cfg.AuditFile)
			if err != nil {
				return nil, err
			}
			sinks = append(sinks, s)
		case "none":
			logger.Printf("audit: no sink configured")
		default:
			logger.Printf("audit: unknown sink %q ignored", name)
		}
	}
	return audit.NewEngine(cfg.AuditQueue, cfg.AuditWorkers, sinks...), nil
}
