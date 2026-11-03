// Package policy talks to the control plane: an Open Policy Agent instance that
// receives a compact JSON document describing the request and answers allow or
// deny. Serialising the input by hand (instead of reflection-based encoding)
// keeps the call to roughly one allocation per request and makes the exact
// document the gateway sends auditable in one screen of code.
package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Input is the request context evaluated by OPA.
type Input struct {
	Subject      string
	Service      string
	Scopes       []string
	AMR          []string
	JTI          string
	Method       string
	Path         string
	Route        string
	DeviceID     string
	DeviceHash   string
	DeviceTrust  int
	DeviceBound  bool
	SourceIP     string
	TokenTTLSecs int64
	RequestID    string
}

// Decision is OPA's answer.
type Decision struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	StepUp bool   `json:"step_up"`
}

// ErrDenied is returned when OPA answers with an explicit deny document.
var ErrDenied = errors.New("policy: denied")

// Client is a small, pooled HTTP client for the OPA decision endpoint.
type Client struct {
	url     string
	hc      *http.Client
	timeout time.Duration
	bufs    sync.Pool
}

// New builds a policy client for decisionPath (for example
// http://opa:8181/v1/data/ztag/authz/decision).
func New(decisionPath string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 25 * time.Millisecond
	}
	transport := &http.Transport{
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 256,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   false,
	}
	return &Client{
		url:     decisionPath,
		timeout: timeout,
		hc:      &http.Client{Transport: transport, Timeout: timeout},
		bufs:    sync.Pool{New: func() any { b := make([]byte, 0, 1024); return &b }},
	}
}

// Decide evaluates the input. Any transport error, timeout or malformed answer
// is returned as an error; the caller applies its configured failure mode
// (the proxy fails closed).
func (c *Client) Decide(ctx context.Context, in *Input) (Decision, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	bp := c.bufs.Get().(*[]byte)
	defer c.bufs.Put(bp)

	body := (*bp)[:0]
	body = append(body, `{"input":{"subject":`...)
	body = appendJSONString(body, in.Subject)
	body = append(body, `,"service":`...)
	body = appendJSONString(body, in.Service)
	body = append(body, `,"scopes":`...)
	body = appendJSONStrings(body, in.Scopes)
	body = append(body, `,"amr":`...)
	body = appendJSONStrings(body, in.AMR)
	body = append(body, `,"jti":`...)
	body = appendJSONString(body, in.JTI)
	body = append(body, `,"method":`...)
	body = appendJSONString(body, in.Method)
	body = append(body, `,"path":`...)
	body = appendJSONString(body, in.Path)
	body = append(body, `,"route":`...)
	body = appendJSONString(body, in.Route)
	body = append(body, `,"device":{"id":`...)
	body = appendJSONString(body, in.DeviceID)
	body = append(body, `,"hash":`...)
	body = appendJSONString(body, in.DeviceHash)
	body = append(body, `,"trust":`...)
	body = strconv.AppendInt(body, int64(in.DeviceTrust), 10)
	body = append(body, `,"bound":`...)
	body = strconv.AppendBool(body, in.DeviceBound)
	body = append(body, '}')
	body = append(body, `,"source_ip":`...)
	body = appendJSONString(body, in.SourceIP)
	body = append(body, `,"token_ttl_s":`...)
	body = strconv.AppendInt(body, in.TokenTTLSecs, 10)
	body = append(body, `,"request_id":`...)
	body = appendJSONString(body, in.RequestID)
	body = append(body, `}}`...)
	*bp = body

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return Decision{}, err
	}
	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return Decision{}, errors.New("policy: unexpected status " + resp.Status)
	}

	var out struct {
		Result *Decision `json:"result"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, 1<<16))
	if err := dec.Decode(&out); err != nil {
		return Decision{}, err
	}
	if out.Result == nil {
		// An undefined decision (no matching rule) is a deny.
		return Decision{Allow: false, Reason: "policy_undefined"}, nil
	}
	if out.Result.Reason == "" && !out.Result.Allow {
		out.Result.Reason = "policy_denied"
	}
	return *out.Result, nil
}

func appendJSONStrings(dst []byte, ss []string) []byte {
	dst = append(dst, '[')
	for i, s := range ss {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, s)
	}
	return append(dst, ']')
}

// appendJSONString writes a JSON string literal with the escaping required by
// RFC 8259 for the characters an attacker can put in a header value.
func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch ch {
		case '"', '\\':
			dst = append(dst, '\\', ch)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if ch < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', hexDigits[ch>>4], hexDigits[ch&0xf])
				continue
			}
			dst = append(dst, ch)
		}
	}
	return append(dst, '"')
}

const hexDigits = "0123456789abcdef"
