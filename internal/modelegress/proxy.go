package modelegress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	maxHeaderBytes  = 8 << 10
	maxHelloBytes   = 64 << 10
	ioDeadline      = 10 * time.Second
	preAuthDeadline = 2 * time.Second
)

type Resolver interface {
	Resolve(ctx context.Context, host string) ([]net.IP, error)
}
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var ErrCapacity = fmt.Errorf("model egress connection limit reached")

type ConnectionLimiter struct{ slots chan struct{} }

func NewConnectionLimiter(max int) *ConnectionLimiter {
	if max < 1 {
		return nil
	}
	return &ConnectionLimiter{slots: make(chan struct{}, max)}
}
func (l *ConnectionLimiter) acquire() bool {
	if l == nil {
		return false
	}
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}
func (l *ConnectionLimiter) release() {
	if l != nil {
		<-l.slots
	}
}

type Proxy struct {
	Policy     Policy
	Capability ProductionCapability
	// TokenVerifier permits a bounded egress-owned session registry. It avoids
	// replacing an existing runtime's token whenever another broker session
	// authenticates.
	TokenVerifier func(string) bool
	Resolver      Resolver
	Dialer        Dialer
	Clock         func() time.Time
	// Admission bounds unauthenticated local connections before they consume
	// goroutines or file descriptors. It is deliberately distinct from the
	// outbound model connection limiter below.
	Admission *ConnectionLimiter
	Limiter   *ConnectionLimiter
}

func (p Proxy) ServeConn(ctx context.Context, client net.Conn) error {
	if client == nil {
		return ErrDenied
	}
	_ = client.SetDeadline(time.Now().Add(ioDeadline))
	defer client.Close()
	if p.Resolver == nil || p.Dialer == nil || p.Limiter == nil {
		return ErrDenied
	}
	admitted := false
	if p.Admission != nil {
		if !p.Admission.acquire() {
			return ErrCapacity
		}
		admitted = true
		defer func() {
			if admitted {
				p.Admission.release()
			}
		}()
		_ = client.SetDeadline(time.Now().Add(preAuthDeadline))
	}
	if err := p.Policy.Validate(); err != nil || (p.TokenVerifier == nil && verifyCapability(p.Policy, p.Capability) != nil) {
		return ErrDenied
	}
	var accepted func(string) bool
	if p.TokenVerifier != nil {
		accepted = p.TokenVerifier
	} else {
		token, err := proxyToken(p.Capability)
		if err != nil {
			return ErrDenied
		}
		accepted = func(got string) bool { return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 }
	}
	r := bufio.NewReaderSize(client, maxHeaderBytes+1)
	host, err := readCONNECTAuthorized(r, accepted)
	if err != nil || !allowedHost(p.Policy, host) {
		writeStatus(client, 403)
		return ErrDenied
	}
	if admitted {
		p.Admission.release()
		admitted = false
	}
	_ = client.SetDeadline(time.Now().Add(ioDeadline))
	// Authentication and the bounded CONNECT header are processed before a
	// shared outbound slot is acquired. A local unauthenticated peer therefore
	// cannot exhaust model egress capacity by holding a TCP connection open.
	if !p.Limiter.acquire() {
		return ErrCapacity
	}
	defer p.Limiter.release()
	ips, err := p.Resolver.Resolve(ctx, host)
	if err != nil {
		writeStatus(client, 502)
		return err
	}
	ip := selectPublicIP(ips)
	if ip == nil {
		writeStatus(client, 403)
		return ErrDenied
	}
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	peek, sni, err := readClientHello(r)
	if err != nil || sni != host {
		return ErrDenied
	}
	upstream, err := p.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(p.Policy.Port))))
	if err != nil {
		return err
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(ioDeadline))
	if _, err = upstream.Write(peek); err != nil {
		return err
	}
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, r); errCh <- e }()
	go func() { _, e := io.Copy(client, upstream); errCh <- e }()
	return <-errCh
}

func readCONNECT(r *bufio.Reader, token string) (string, error) {
	return readCONNECTAuthorized(r, func(got string) bool { return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1 })
}

func readCONNECTAuthorized(r *bufio.Reader, accepted func(string) bool) (string, error) {
	if accepted == nil {
		return "", ErrDenied
	}
	var b bytes.Buffer
	for b.Len() <= maxHeaderBytes {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", ErrDenied
		}
		if err != nil {
			return "", err
		}
		_, _ = b.Write(line)
		if b.Len() > maxHeaderBytes {
			return "", ErrDenied
		}
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	lines := strings.Split(b.String(), "\r\n")
	if len(lines) < 2 {
		return "", ErrDenied
	}
	parts := strings.Split(lines[0], " ")
	if len(parts) != 3 || parts[0] != "CONNECT" || parts[2] != "HTTP/1.1" {
		return "", ErrDenied
	}
	if strings.Contains(parts[1], "/") || strings.ContainsAny(parts[1], "?#") {
		return "", ErrDenied
	}
	host, port, err := net.SplitHostPort(parts[1])
	if err != nil || port != "443" || !validFQDN(host) {
		return "", ErrDenied
	}
	seenHost, seenAuth := false, false
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return "", ErrDenied
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "host":
			if seenHost || strings.TrimSpace(v) != parts[1] {
				return "", ErrDenied
			}
			seenHost = true
		case "proxy-authorization":
			const prefix = "Basic "
			value := strings.TrimSpace(v)
			if seenAuth || !strings.HasPrefix(value, prefix) {
				return "", ErrDenied
			}
			raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, prefix))
			user, token, ok := strings.Cut(string(raw), ":")
			if err != nil || !ok || user != "openduck" || !accepted(token) {
				return "", ErrDenied
			}
			seenAuth = true
		default:
			return "", ErrDenied
		}
	}
	if !seenHost || !seenAuth {
		return "", ErrDenied
	}
	return strings.ToLower(host), nil
}

func proxyAuthorization(token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("openduck:"+token))
}

func readClientHello(r *bufio.Reader) ([]byte, string, error) {
	h := make([]byte, 5)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, "", err
	}
	if h[0] != 22 || h[1] != 3 || h[2] < 1 {
		return nil, "", ErrDenied
	}
	n := int(binary.BigEndian.Uint16(h[3:]))
	if n < 4 || n > maxHelloBytes {
		return nil, "", ErrDenied
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, "", err
	}
	if body[0] != 1 || len(body) < 4 || int(body[1])<<16|int(body[2])<<8|int(body[3]) != len(body)-4 {
		return nil, "", ErrDenied
	}
	name, err := parseHello(body[4:])
	if err != nil {
		return nil, "", err
	}
	return append(h, body...), name, nil
}

func parseHello(b []byte) (string, error) {
	if len(b) < 34 {
		return "", ErrDenied
	}
	pos := 2 + 32
	if pos+1 > len(b) {
		return "", ErrDenied
	}
	sl := int(b[pos])
	pos++
	if pos+sl+1 > len(b) {
		return "", ErrDenied
	}
	pos += sl
	if pos+2 > len(b) {
		return "", ErrDenied
	}
	cl := int(binary.BigEndian.Uint16(b[pos:]))
	pos += 2
	if pos+cl+1 > len(b) {
		return "", ErrDenied
	}
	pos += cl
	comp := int(b[pos])
	pos++
	if pos+comp+2 > len(b) {
		return "", ErrDenied
	}
	pos += comp
	if pos+2 > len(b) {
		return "", ErrDenied
	}
	extLen := int(binary.BigEndian.Uint16(b[pos:]))
	pos += 2
	if pos+extLen != len(b) {
		return "", ErrDenied
	}
	var sni string
	for end := pos + extLen; pos < end; {
		if pos+4 > end {
			return "", ErrDenied
		}
		typ := binary.BigEndian.Uint16(b[pos:])
		ln := int(binary.BigEndian.Uint16(b[pos+2:]))
		pos += 4
		if pos+ln > end {
			return "", ErrDenied
		}
		ext := b[pos : pos+ln]
		pos += ln
		if typ == 0xfe0d {
			return "", ErrDenied
		}
		if typ != 0 {
			continue
		}
		if len(ext) < 5 {
			return "", ErrDenied
		}
		list := int(binary.BigEndian.Uint16(ext))
		if list+2 != len(ext) || ext[2] != 0 {
			return "", ErrDenied
		}
		n := int(binary.BigEndian.Uint16(ext[3:5]))
		if n == 0 || n+5 != len(ext) {
			return "", ErrDenied
		}
		sni = string(ext[5:])
	}
	if sni == "" || !validFQDN(sni) {
		return "", ErrDenied
	}
	return strings.ToLower(sni), nil
}

func selectPublicIP(ips []net.IP) net.IP {
	for _, ip := range ips {
		if publicIP(ip) {
			return ip
		}
	}
	return nil
}
func publicIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if inSpecialRange(ip) {
		return false
	}
	return true
}

var specialRanges = func() []*net.IPNet {
	var out []*net.IPNet
	for _, cidr := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "100::/64", "2001:0::/32", "2001:1::/32", "2001:2::/48", "2001:3::/32", "2001:4:112::/48", "2001:10::/28", "2001:20::/28", "2001:db8::/32", "2002::/16", "3fff::/20", "64:ff9b:1::/48", "fc00::/7", "fe80::/10"} {
		_, n, _ := net.ParseCIDR(cidr)
		out = append(out, n)
	}
	return out
}()

func inSpecialRange(ip net.IP) bool {
	for _, n := range specialRanges {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func writeStatus(w io.Writer, code int) {
	_, _ = fmt.Fprintf(w, "HTTP/1.1 %d Denied\r\nContent-Length: 0\r\n\r\n", code)
}
