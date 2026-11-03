package policy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDecideAllow(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("gateway sent invalid JSON: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"result":{"allow":true,"reason":"admitted","step_up":false}}`)
	}))
	defer srv.Close()

	c := New(srv.URL, 200*time.Millisecond)
	dec, err := c.Decide(context.Background(), &Input{
		Subject: `user-"1"`, Service: "web", Scopes: []string{"orders.read"},
		Method: "GET", Path: "/api/orders", Route: "/api/orders",
		DeviceID: "d-1", DeviceHash: "abc", DeviceTrust: 90, DeviceBound: true,
		SourceIP: "203.0.113.9", TokenTTLSecs: 300, RequestID: "rid-1",
	})
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if !dec.Allow || dec.Reason != "admitted" {
		t.Fatalf("unexpected decision: %+v", dec)
	}

	// The hand-built JSON must survive a quote in the subject.
	input, _ := got["input"].(map[string]any)
	if input["subject"] != `user-"1"` {
		t.Fatalf("subject was mangled: %v", input["subject"])
	}
	dev, _ := input["device"].(map[string]any)
	if dev["bound"] != true || dev["trust"] != float64(90) {
		t.Fatalf("device block wrong: %v", dev)
	}
}

func TestDecideDenyAndUndefined(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"deny", `{"result":{"allow":false,"reason":"service_not_allowed"}}`, "service_not_allowed"},
		{"undefined", `{}`, "policy_undefined"},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, tc.body)
		}))
		c := New(srv.URL, 200*time.Millisecond)
		dec, err := c.Decide(context.Background(), &Input{Subject: "u"})
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if dec.Allow || dec.Reason != tc.want {
			t.Fatalf("%s: got %+v, want reason %q", tc.name, dec, tc.want)
		}
	}
}

func TestDecideTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(150 * time.Millisecond)
		io.WriteString(w, `{"result":{"allow":true}}`)
	}))
	defer srv.Close()

	c := New(srv.URL, 20*time.Millisecond)
	if _, err := c.Decide(context.Background(), &Input{Subject: "u"}); err == nil {
		t.Fatal("a slow policy engine must surface an error so the caller can fail closed")
	}
}
