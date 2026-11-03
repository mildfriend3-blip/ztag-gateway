// Command tokengen issues short-lived demo tokens. In a real deployment this
// role belongs to the identity provider; here it lets the whole pipeline be
// exercised locally without standing one up.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ztag/gateway/internal/jwt"
)

func main() {
	var (
		secret   = flag.String("secret", os.Getenv("ZTAG_JWT_SECRET"), "HS256 secret (or ZTAG_JWT_SECRET); required")
		issuer   = flag.String("iss", env("ZTAG_JWT_ISSUER", "ztag-idp"), "issuer")
		audience = flag.String("aud", env("ZTAG_JWT_AUDIENCE", "ztag-api"), "audience")
		subject  = flag.String("sub", "user-1001", "subject")
		service  = flag.String("svc", "web", "calling service identity")
		scopes   = flag.String("scope", "orders.read,orders.write", "comma separated scopes")
		device   = flag.String("did", "d-7712", "device id the token is bound to")
		amr      = flag.String("amr", "pwd,otp", "authentication methods")
		ttl      = flag.Duration("ttl", 5*time.Minute, "token lifetime")
		jti      = flag.String("jti", "", "token id (random if empty)")
	)
	flag.Parse()

	if len(*secret) < 16 {
		fmt.Fprintln(os.Stderr, "error: no signing secret. Pass -secret or set ZTAG_JWT_SECRET (16+ bytes).")
		os.Exit(2)
	}

	id := *jti
	if id == "" {
		var b [12]byte
		if _, err := rand.Read(b[:]); err != nil {
			fmt.Fprintln(os.Stderr, "rand:", err)
			os.Exit(1)
		}
		id = hex.EncodeToString(b[:])
	}

	now := time.Now()
	c := &jwt.Claims{
		Subject:  *subject,
		Issuer:   *issuer,
		Audience: jwt.Audience{*audience},
		IssuedAt: now.Unix(),
		Expiry:   now.Add(*ttl).Unix(),
		JTI:      id,
		Scopes:   split(*scopes),
		Service:  *service,
		DeviceID: *device,
		AMR:      split(*amr),
	}
	token, err := jwt.SignHS256(c, []byte(*secret))
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
	fmt.Println(token)
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
