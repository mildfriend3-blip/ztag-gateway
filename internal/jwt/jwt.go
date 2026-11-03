// Package jwt implements the minimal, allocation-conscious JWT verification
// path used by the zero-trust data plane. Only HS256 and RS256 are accepted.
// "none" and algorithm-confusion attacks are structurally impossible because
// the algorithm is pinned by the verifier and never used for dispatch.
package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Algorithm is the pinned signing algorithm of a Verifier.
type Algorithm int

const (
	// HS256 is HMAC-SHA256, used for the local demo issuer.
	HS256 Algorithm = iota
	// RS256 is RSA PKCS#1 v1.5 with SHA-256, used with an IdP public key.
	RS256
)

// String returns the JWA name of the algorithm.
func (a Algorithm) String() string {
	if a == RS256 {
		return "RS256"
	}
	return "HS256"
}

var (
	// ErrMalformed means the compact serialization could not be parsed.
	ErrMalformed = errors.New("jwt: malformed token")
	// ErrAlgorithm means the token header names an algorithm the verifier does not accept.
	ErrAlgorithm = errors.New("jwt: algorithm not accepted")
	// ErrSignature means the cryptographic signature did not verify.
	ErrSignature = errors.New("jwt: signature mismatch")
	// ErrExpired means exp is in the past (beyond leeway).
	ErrExpired = errors.New("jwt: token expired")
	// ErrNotYet means nbf is in the future (beyond leeway).
	ErrNotYet = errors.New("jwt: token not yet valid")
	// ErrAudience means aud does not contain the configured audience.
	ErrAudience = errors.New("jwt: audience mismatch")
	// ErrIssuer means iss does not match the configured issuer.
	ErrIssuer = errors.New("jwt: issuer mismatch")
	// ErrTTL means the token lifetime exceeds the configured maximum.
	ErrTTL = errors.New("jwt: token lifetime exceeds policy")
	// ErrMissing means a required claim is absent.
	ErrMissing = errors.New("jwt: required claim missing")
)

// Audience decodes the "aud" claim, which RFC 7519 allows to be a string or an
// array of strings.
type Audience []string

// UnmarshalJSON accepts both encodings of "aud".
func (a *Audience) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*a = Audience{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return err
	}
	*a = Audience(ss)
	return nil
}

// Has reports whether v is present in the audience list.
func (a Audience) Has(v string) bool {
	for _, s := range a {
		if s == v {
			return true
		}
	}
	return false
}

// Claims is the verified payload handed to the policy engine and audit stream.
type Claims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss,omitempty"`
	Audience  Audience `json:"aud,omitempty"`
	Expiry    int64    `json:"exp"`
	NotBefore int64    `json:"nbf,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	JTI       string   `json:"jti,omitempty"`
	Scopes    []string `json:"scope,omitempty"`
	Service   string   `json:"svc,omitempty"`
	DeviceID  string   `json:"did,omitempty"`
	AMR       []string `json:"amr,omitempty"`

	// Raw is the decoded payload, kept so the audit sink can forward it
	// without re-encoding every field.
	Raw []byte `json:"-"`
}

// ExpiresAt returns the expiry as a time.
func (c *Claims) ExpiresAt() time.Time { return time.Unix(c.Expiry, 0) }

// HasScope reports whether the token carries a scope ("*" matches anything).
func (c *Claims) HasScope(want string) bool {
	for _, s := range c.Scopes {
		if s == want || s == "*" {
			return true
		}
	}
	return false
}

// Verifier pins the algorithm, key material and claim expectations for one
// issuer. It is safe for concurrent use.
type Verifier struct {
	alg      Algorithm
	secret   []byte
	pub      *rsa.PublicKey
	issuer   string
	audience string
	leeway   time.Duration
	maxTTL   time.Duration
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithLeeway tolerates small clock skew on exp and nbf.
func WithLeeway(d time.Duration) Option { return func(v *Verifier) { v.leeway = d } }

// WithMaxTTL rejects tokens whose exp-iat exceeds d. This keeps access tokens
// short-lived even if the issuer misbehaves.
func WithMaxTTL(d time.Duration) Option { return func(v *Verifier) { v.maxTTL = d } }

// NewHMACVerifier returns a verifier for HS256 tokens.
func NewHMACVerifier(secret []byte, issuer, audience string, opts ...Option) *Verifier {
	v := &Verifier{alg: HS256, secret: secret, issuer: issuer, audience: audience, leeway: 30 * time.Second}
	for _, o := range opts {
		o(v)
	}
	return v
}

// NewRSAVerifier returns a verifier for RS256 tokens.
func NewRSAVerifier(pub *rsa.PublicKey, issuer, audience string, opts ...Option) *Verifier {
	v := &Verifier{alg: RS256, pub: pub, issuer: issuer, audience: audience, leeway: 30 * time.Second}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Algorithm reports the pinned algorithm.
func (v *Verifier) Algorithm() Algorithm { return v.alg }

var rawURL = base64.RawURLEncoding

// Verify checks structure, signature, algorithm, lifetime and audience.
func (v *Verifier) Verify(token string, now time.Time) (*Claims, error) {
	if len(token) < 16 {
		return nil, ErrMalformed
	}
	first := strings.IndexByte(token, '.')
	if first <= 0 {
		return nil, ErrMalformed
	}
	last := strings.LastIndexByte(token, '.')
	if last <= first || last == len(token)-1 {
		return nil, ErrMalformed
	}
	signingInput := token[:last]

	// The header is decoded only to produce a precise error message; the
	// verification path itself is pinned by the verifier's algorithm.
	if hdr, err := rawURL.DecodeString(token[:first]); err == nil {
		var h struct {
			Alg string `json:"alg"`
		}
		if json.Unmarshal(hdr, &h) == nil && h.Alg != v.alg.String() {
			return nil, ErrAlgorithm
		}
	}

	sig, err := decodeSegment(token[last+1:])
	if err != nil {
		return nil, ErrMalformed
	}
	if err := v.checkSignature(signingInput, sig); err != nil {
		return nil, err
	}

	payload, err := decodeSegment(token[first+1 : last])
	if err != nil {
		return nil, ErrMalformed
	}
	c := &Claims{}
	if err := json.Unmarshal(payload, c); err != nil {
		return nil, ErrMalformed
	}
	c.Raw = payload

	if c.Subject == "" || c.Expiry == 0 {
		return nil, ErrMissing
	}
	if now.After(time.Unix(c.Expiry, 0).Add(v.leeway)) {
		return nil, ErrExpired
	}
	if c.NotBefore != 0 && now.Add(v.leeway).Before(time.Unix(c.NotBefore, 0)) {
		return nil, ErrNotYet
	}
	if v.issuer != "" && c.Issuer != v.issuer {
		return nil, ErrIssuer
	}
	if v.audience != "" && !c.Audience.Has(v.audience) {
		return nil, ErrAudience
	}
	if v.maxTTL > 0 && c.IssuedAt > 0 {
		if time.Duration(c.Expiry-c.IssuedAt)*time.Second > v.maxTTL {
			return nil, ErrTTL
		}
	}
	return c, nil
}

func (v *Verifier) checkSignature(signingInput string, sig []byte) error {
	switch v.alg {
	case HS256:
		mac := hmac.New(sha256.New, v.secret)
		mac.Write([]byte(signingInput))
		if !hmac.Equal(mac.Sum(nil), sig) {
			return ErrSignature
		}
		return nil
	case RS256:
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(v.pub, crypto.SHA256, digest[:], sig); err != nil {
			return ErrSignature
		}
		return nil
	default:
		return ErrAlgorithm
	}
}

// decodeSegment accepts both padded and unpadded base64url segments.
func decodeSegment(s string) ([]byte, error) {
	if b, err := rawURL.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// SignHS256 issues an HS256 token. Used by the demo issuer (cmd/tokengen) and
// tests; the data plane itself never signs.
func SignHS256(c *Claims, secret []byte) (string, error) {
	hdr := []byte(`{"alg":"HS256","typ":"JWT"}`)
	body, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	signingInput := rawURL.EncodeToString(hdr) + "." + rawURL.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + rawURL.EncodeToString(mac.Sum(nil)), nil
}
