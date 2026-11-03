// Package redisclient is a minimal, dependency-free Redis client implementing
// just enough RESP2 to serve the data plane: GET/MGET/EXISTS/DEL/SET with TTL,
// EVALSHA script execution with EVAL fallback, XADD for the audit stream, and
// pipelining for batched writes.
//
// It exists so the gateway binary has zero third-party dependencies: the
// critical path stays auditable, the container image stays tiny, and the
// hot path allocates only what the caller asks for.
package redisclient

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Error is a Redis error reply (for example NOSCRIPT or WRONGTYPE).
type Error string

// Error implements the error interface.
func (e Error) Error() string { return "redis: " + string(e) }

// ErrClosed is returned once Close has been called.
var ErrClosed = errors.New("redisclient: client closed")

// Client is a fixed-size connection pool. It is safe for concurrent use.
type Client struct {
	addr    string
	timeout time.Duration
	idle    chan *conn
	closed  atomic.Bool
}

type conn struct {
	nc  net.Conn
	r   *bufio.Reader
	buf []byte
}

// New creates a pool of at most poolSize idle connections to addr.
func New(addr string, poolSize int, timeout time.Duration) *Client {
	if poolSize <= 0 {
		poolSize = 32
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	return &Client{addr: addr, timeout: timeout, idle: make(chan *conn, poolSize)}
}

// Addr returns the configured address.
func (c *Client) Addr() string { return c.addr }

func (c *Client) get() (*conn, error) {
	if c.closed.Load() {
		return nil, ErrClosed
	}
	select {
	case cn := <-c.idle:
		return cn, nil
	default:
	}
	nc, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return nil, err
	}
	return &conn{nc: nc, r: bufio.NewReaderSize(nc, 4096), buf: make([]byte, 0, 512)}, nil
}

func (c *Client) put(cn *conn) {
	select {
	case c.idle <- cn:
	default:
		cn.nc.Close()
	}
}

// Close drains the pool and marks the client closed.
func (c *Client) Close() error {
	c.closed.Store(true)
	for {
		select {
		case cn := <-c.idle:
			cn.nc.Close()
		default:
			return nil
		}
	}
}

// Do sends one command and returns its reply as string, int64, nil, []any or
// Error.
func (c *Client) Do(args ...string) (any, error) {
	cn, err := c.get()
	if err != nil {
		return nil, err
	}
	if err := cn.nc.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		cn.nc.Close()
		return nil, err
	}
	cn.buf = AppendCommand(cn.buf[:0], args)
	if _, err := cn.nc.Write(cn.buf); err != nil {
		cn.nc.Close()
		return nil, err
	}
	v, err := readReply(cn.r, 0)
	if err != nil {
		cn.nc.Close()
		return nil, err
	}
	c.put(cn)
	return v, nil
}

// DoWithTimeout is Do with an explicit deadline, for blocking commands such as
// XREADGROUP where the server-side BLOCK must be shorter than the client
// deadline.
func (c *Client) DoWithTimeout(timeout time.Duration, args ...string) (any, error) {
	cn, err := c.get()
	if err != nil {
		return nil, err
	}
	if err := cn.nc.SetDeadline(time.Now().Add(timeout)); err != nil {
		cn.nc.Close()
		return nil, err
	}
	cn.buf = AppendCommand(cn.buf[:0], args)
	if _, err := cn.nc.Write(cn.buf); err != nil {
		cn.nc.Close()
		return nil, err
	}
	v, err := readReply(cn.r, 0)
	if err != nil {
		cn.nc.Close()
		return nil, err
	}
	c.put(cn)
	return v, nil
}

// Pipeline sends every command in cmds in a single write and reads every reply
// in order. It is the batch path used by the audit sink.
func (c *Client) Pipeline(cmds [][]string) ([]any, error) {
	if len(cmds) == 0 {
		return nil, nil
	}
	cn, err := c.get()
	if err != nil {
		return nil, err
	}
	if err := cn.nc.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		cn.nc.Close()
		return nil, err
	}
	buf := cn.buf[:0]
	for _, cmd := range cmds {
		buf = AppendCommand(buf, cmd)
	}
	cn.buf = buf
	if _, err := cn.nc.Write(buf); err != nil {
		cn.nc.Close()
		return nil, err
	}
	out := make([]any, len(cmds))
	for i := range cmds {
		v, err := readReply(cn.r, 0)
		if err != nil {
			cn.nc.Close()
			return nil, err
		}
		out[i] = v
	}
	c.put(cn)
	return out, nil
}

// Ping checks liveness of the server.
func (c *Client) Ping() error {
	v, err := c.Do("PING")
	if err != nil {
		return err
	}
	if s, ok := v.(string); !ok || s != "PONG" {
		return errors.New("redisclient: unexpected ping reply")
	}
	return nil
}

// AppendCommand appends a RESP2 array-of-bulk-strings command to dst.
func AppendCommand(dst []byte, args []string) []byte {
	dst = append(dst, '*')
	dst = strconv.AppendInt(dst, int64(len(args)), 10)
	dst = append(dst, '\r', '\n')
	for _, a := range args {
		dst = append(dst, '$')
		dst = strconv.AppendInt(dst, int64(len(a)), 10)
		dst = append(dst, '\r', '\n')
		dst = append(dst, a...)
		dst = append(dst, '\r', '\n')
	}
	return dst
}

func readReply(r *bufio.Reader, depth int) (any, error) {
	if depth > 8 {
		return nil, errors.New("redisclient: reply nesting too deep")
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if len(line) < 3 || line[len(line)-2] != '\r' {
		return nil, errors.New("redisclient: truncated reply")
	}
	payload := line[1 : len(line)-2]
	switch line[0] {
	case '+':
		return payload, nil
	case '-':
		return nil, Error(payload)
	case ':':
		return strconv.ParseInt(payload, 10, 64)
	case '$':
		n, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		n, err := strconv.Atoi(payload)
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			v, err := readReply(r, depth+1)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	default:
		return nil, errors.New("redisclient: unknown reply type")
	}
}

// Script is a server-side Lua script addressed by SHA1, so the steady state
// sends only the hash instead of the source.
type Script struct {
	src string
	sha string
}

// NewScript compiles (locally) a Lua script and computes its SHA1.
func NewScript(src string) *Script {
	sum := sha1.Sum([]byte(src))
	return &Script{src: src, sha: hex.EncodeToString(sum[:])}
}

// SHA returns the script hash.
func (s *Script) SHA() string { return s.sha }

// Run executes the script with EVALSHA, falling back to EVAL once if the server
// has not cached it (NOSCRIPT).
func (s *Script) Run(c *Client, keys []string, args ...string) (any, error) {
	cmd := make([]string, 0, 3+len(keys)+len(args))
	cmd = append(cmd, "EVALSHA", s.sha, strconv.Itoa(len(keys)))
	cmd = append(cmd, keys...)
	cmd = append(cmd, args...)

	v, err := c.Do(cmd...)
	if err == nil {
		return v, nil
	}
	var re Error
	if errors.As(err, &re) && strings.HasPrefix(string(re), "NOSCRIPT") {
		cmd[0], cmd[1] = "EVAL", s.src
		return c.Do(cmd...)
	}
	return nil, err
}

// Int64 coerces a reply to int64 (missing keys and non-integers become 0).
func Int64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case string:
		n, _ := strconv.ParseInt(t, 10, 64)
		return n
	default:
		return 0
	}
}

// Strings coerces an array reply to []string.
func Strings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
