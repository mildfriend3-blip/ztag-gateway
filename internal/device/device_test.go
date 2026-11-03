package device

import "testing"

func TestParse(t *testing.T) {
	p := Parse("id=d-7712;os=macos;managed=1;posture=compliant", "")
	if !p.Present || p.ID != "d-7712" || p.Platform != "macos" || !p.Managed {
		t.Fatalf("unexpected profile: %+v", p)
	}
	if p.Posture != PostureCompliant || p.Score < 90 {
		t.Fatalf("compliant managed device should score high: %+v", p)
	}
	if p.Hash == "" || len(p.Hash) != 16 {
		t.Fatalf("expected 16-char fingerprint hash, got %q", p.Hash)
	}
}

func TestParseHeaderOverridesPosture(t *testing.T) {
	p := Parse("id=d-1;os=windows;posture=compliant", "stale")
	if p.Posture != PostureStale {
		t.Fatalf("posture header must win: %+v", p)
	}
	if p.Score >= 90 {
		t.Fatalf("stale posture must lower the score: %+v", p)
	}
}

func TestParseAbsent(t *testing.T) {
	p := Parse("", "")
	if p.Present {
		t.Fatalf("empty fingerprint must report Present=false")
	}
	if p.Score != 0 {
		t.Fatalf("absent device should score 0, got %d", p.Score)
	}
}

func TestUnknownDeviceScoresLow(t *testing.T) {
	p := Parse("os=linux", "")
	if p.ID != "" {
		t.Fatalf("expected no id")
	}
	if p.Score > 25 {
		t.Fatalf("anonymous device must score low, got %d", p.Score)
	}
}
