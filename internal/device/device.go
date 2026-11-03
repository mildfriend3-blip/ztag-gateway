// Package device parses the structural device profile that clients present
// alongside a token. Binding a token to a device fingerprint turns a stolen
// bearer token into a useless string on any other machine, which is the
// cheapest defence against session takeover.
package device

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// Header names understood by the data plane.
const (
	HeaderFingerprint = "X-Ztag-Device"
	HeaderPosture     = "X-Ztag-Posture"
)

// Profile is the parsed device context.
type Profile struct {
	// ID is the client-asserted stable device identifier.
	ID string
	// Hash is a short digest of the whole fingerprint, safe for audit logs.
	Hash string
	// Platform is the asserted OS family.
	Platform string
	// Managed reports whether the endpoint agent says it is managed.
	Managed bool
	// Posture is the endpoint compliance verdict: compliant, stale or unknown.
	Posture string
	// Score is a 0-100 trust score derived from the posture signals.
	Score int
	// Present is false when the client sent no fingerprint at all.
	Present bool
}

// Posture values.
const (
	PostureCompliant = "compliant"
	PostureStale     = "stale"
	PostureUnknown   = "unknown"
)

// Parse reads a fingerprint of the form
//
//	id=d-7712;os=macos;managed=1;posture=compliant
//
// Unknown keys are ignored, order does not matter, and a malformed field
// degrades the score instead of rejecting the request: the policy engine owns
// the accept/deny decision, this package only describes the endpoint.
func Parse(fingerprint, postureHeader string) Profile {
	p := Profile{Posture: PostureUnknown, Hash: hashOf(fingerprint + "|" + postureHeader)}
	if fingerprint == "" && postureHeader == "" {
		return p
	}
	p.Present = true

	for _, field := range strings.Split(fingerprint, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "id":
			p.ID = v
		case "os":
			p.Platform = v
		case "managed":
			p.Managed = v == "1" || strings.EqualFold(v, "true")
		case "posture":
			p.Posture = strings.ToLower(v)
		}
	}
	if postureHeader != "" {
		p.Posture = strings.ToLower(strings.TrimSpace(postureHeader))
	}

	switch p.Posture {
	case PostureCompliant:
		p.Score = 90
	case PostureStale:
		p.Score = 45
	default:
		p.Score = 20
	}
	if p.Managed && p.Score < 100 {
		p.Score += 10
	}
	if p.ID == "" {
		p.Score -= 20
	}
	if p.Score < 0 {
		p.Score = 0
	}
	return p
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}

// TrustHeader renders the score for the upstream service, so an application can
// apply its own step-up rules without re-parsing the fingerprint.
func (p Profile) TrustHeader() string { return strconv.Itoa(p.Score) }
