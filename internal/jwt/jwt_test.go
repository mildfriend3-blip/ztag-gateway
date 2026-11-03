package jwt

import (
	"strings"
	"testing"
	"time"
)

func tok(secret []byte, c *Claims) string {
	s, err := SignHS256(c, secret)
	if err != nil {
		panic(err)
	}
	return s
}

func TestVerifyHappyPath(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Unix(1_700_000_000, 0)
	v := NewHMACVerifier(secret, "ztag-idp", "ztag-api", WithMaxTTL(15*time.Minute))

	c := &Claims{
		Subject: "user-1", Issuer: "ztag-idp", Audience: Audience{"ztag-api"},
		IssuedAt: now.Unix(), Expiry: now.Add(10 * time.Minute).Unix(),
		JTI: "j1", Service: "web",
	}

	got, err := v.Verify(tok(secret, c), now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Subject != "user-1" || got.JTI != "j1" {
		t.Fatalf("claims mismatch: %+v", got)
	}
}

func TestVerifyRejects(t *testing.T) {
	secret := []byte("s3cr3t")
	now := time.Unix(1_700_000_000, 0)
	v := NewHMACVerifier(secret, "ztag-idp", "ztag-api", WithLeeway(0), WithMaxTTL(15*time.Minute))

	base := func() *Claims {
		return &Claims{
			Subject: "u", Issuer: "ztag-idp", Audience: Audience{"ztag-api"},
			IssuedAt: now.Unix(), Expiry: now.Add(time.Minute).Unix(),
		}
	}

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"expired", tok(secret, func() *Claims { c := base(); c.Expiry = now.Add(-time.Second).Unix(); return c }()), ErrExpired},
		{"wrong-key", tok([]byte("other"), base()), ErrSignature},
		{"wrong-issuer", tok(secret, func() *Claims { c := base(); c.Issuer = "evil"; return c }()), ErrIssuer},
		{"wrong-aud", tok(secret, func() *Claims { c := base(); c.Audience = Audience{"other"}; return c }()), ErrAudience},
		{"long-ttl", tok(secret, func() *Claims { c := base(); c.Expiry = now.Add(2 * time.Hour).Unix(); return c }()), ErrTTL},
		{"alg-none", "eyJhbGciOiJub25lIn0." + strings.Split(tok(secret, base()), ".")[1] + ".x", ErrAlgorithm},
		{"garbage", "not.a.token", ErrMalformed},
	}
	for _, tc := range cases {
		if _, err := v.Verify(tc.token, now); err != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestAudienceForms(t *testing.T) {
	var a Audience
	if err := a.UnmarshalJSON([]byte(`"svc"`)); err != nil || !a.Has("svc") {
		t.Fatalf("string aud: %v %v", a, err)
	}
	if err := a.UnmarshalJSON([]byte(`["a","b"]`)); err != nil || !a.Has("b") {
		t.Fatalf("array aud: %v %v", a, err)
	}
}

func BenchmarkVerifyHS256(b *testing.B) {
	secret := []byte("s3cr3t")
	now := time.Now()
	v := NewHMACVerifier(secret, "ztag-idp", "ztag-api")
	c := &Claims{
		Subject: "user-1", Issuer: "ztag-idp", Audience: Audience{"ztag-api"},
		IssuedAt: now.Unix(), Expiry: now.Add(5 * time.Minute).Unix(), JTI: "j1",
	}
	token := tok(secret, c)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := v.Verify(token, now); err != nil {
			b.Fatal(err)
		}
	}
}
