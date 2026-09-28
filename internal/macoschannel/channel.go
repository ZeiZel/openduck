package macoschannel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxHandshake             = 16 << 10
	maxBindingCanonical      = 1 << 20
	maxBindingDomain         = 128
	defaultHandshakeDeadline = 5 * time.Second
)

type hello struct {
	Version   string     `json:"version"`
	Channel   string     `json:"channel"`
	LocalRole string     `json:"local_role"`
	PeerRole  string     `json:"peer_role"`
	UID       uint32     `json:"uid"`
	GID       uint32     `json:"gid"`
	KeyEpoch  uint64     `json:"key_epoch"`
	Release   ReleasePin `json:"release"`
	Nonce     string     `json:"nonce"`
	MAC       string     `json:"mac"`
}
type ack struct {
	Version string `json:"version"`
	Nonce   string `json:"nonce"`
	MAC     string `json:"mac"`
}
type authenticatedConn struct {
	net.Conn
	once     sync.Once
	mu       sync.Mutex
	ev       Evidence
	binding  []byte
	closed   bool
	closeErr error
}

type authentication struct {
	evidence Evidence
	binding  []byte
}

func (c *authenticatedConn) evidence() {}
func (c *authenticatedConn) Evidence() Evidence {
	if c == nil {
		return Evidence{}
	}
	return c.ev
}

type socketState struct {
	dev, ino uint64
	digest   string
}

func Dial(ctx context.Context, cfg Config) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	before, err := verifySocketPath(cfg)
	if err != nil {
		return nil, err
	}
	if before.digest != cfg.PeerRelease.SocketDigest {
		return nil, ErrRelease
	}
	d := net.Dialer{}
	c, err := d.DialContext(ctx, "unix", filepath.Join(cfg.Contract.SocketRoot, cfg.Contract.SocketPath))
	if err != nil {
		return nil, err
	}
	// A path cannot be connected relative to a directory FD on Darwin. We make
	// no stronger TOCTOU claim: detect a replacement before and after connect
	// and fail closed if it changed while the pathname operation was in flight.
	after, err := verifySocketPath(cfg)
	if err != nil || after != before {
		_ = c.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrUnavailable
	}
	if after.digest != cfg.PeerRelease.SocketDigest {
		_ = c.Close()
		return nil, ErrRelease
	}
	stopHandshake, err := startHandshakeDeadline(c, ctx)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	auth, err := authenticateContext(ctx, c, cfg)
	stopHandshake()
	if err == nil {
		err = c.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return newAuthenticatedConn(c, auth), nil
}

// Listener intentionally exposes no raw Accept method. A caller can only get
// a Conn after both kernel credential and transcript validation have completed.
type Listener struct {
	ln    net.Listener
	cfg   Config
	state socketState
	mu    sync.Mutex
}

func Listen(cfg Config) (*Listener, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if _, err := verifySocketRoot(cfg.Contract, cfg.SocketRootFD); err != nil {
		return nil, err
	}
	path := filepath.Join(cfg.Contract.SocketRoot, cfg.Contract.SocketPath)
	if st, err := os.Lstat(path); err == nil {
		// Listen is never allowed to unlink an existing path. Callers that own
		// stale-socket cleanup must prove liveness and perform inode-safe cleanup
		// before this boundary; any appearance here is a split-brain race.
		_ = st
		return nil, ErrUnavailable
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrUnavailable
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// net.Listen honors the process umask. Set the declared mode then capture
	// immutable identity; any concurrent replacement is detected below.
	if err := os.Chmod(path, cfg.Contract.ExpectedSocketMode); err != nil {
		_ = l.Close()
		return nil, ErrUnavailable
	}
	state, err := verifySocketPath(cfg)
	if err != nil {
		_ = l.Close()
		return nil, err
	}
	if state.digest != cfg.LocalRelease.SocketDigest {
		_ = l.Close()
		return nil, ErrRelease
	}
	return &Listener{ln: l, cfg: cfg, state: state}, nil
}

func (l *Listener) AcceptAuthenticated(ctx context.Context) (Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if l == nil || l.ln == nil {
		return nil, ErrUnavailable
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if state, err := verifySocketPath(l.cfg); err != nil || state != l.state {
		if err != nil {
			return nil, err
		}
		return nil, ErrUnavailable
	}
	if l.state.digest != l.cfg.LocalRelease.SocketDigest {
		return nil, ErrRelease
	}
	ul, ok := l.ln.(*net.UnixListener)
	if !ok {
		return nil, ErrUnavailable
	}
	stop := interruptOnContext(ul, ctx)
	c, err := ul.Accept()
	stop()
	_ = ul.SetDeadline(time.Time{})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	var stopHandshake func()
	if stopHandshake, err = startHandshakeDeadline(c, ctx); err == nil {
		var state socketState
		state, err = verifySocketPath(l.cfg)
		if err == nil && state != l.state {
			err = ErrUnavailable
		}
	}
	var auth authentication
	if err == nil {
		auth, err = authenticateContext(ctx, c, l.cfg)
	}
	if stopHandshake != nil {
		stopHandshake()
	}
	if err == nil {
		err = c.SetDeadline(time.Time{})
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return newAuthenticatedConn(c, auth), nil
}
func (l *Listener) Close() error {
	if l == nil || l.ln == nil {
		return ErrUnavailable
	}
	return l.ln.Close()
}
func (l *Listener) Addr() net.Addr {
	if l == nil || l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}
func (c *authenticatedConn) Close() error {
	if c == nil {
		return ErrUnavailable
	}
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		zero(c.binding)
		c.binding = nil
		c.mu.Unlock()
		if c.Conn == nil {
			c.closeErr = ErrUnavailable
		} else {
			c.closeErr = c.Conn.Close()
		}
	})
	return c.closeErr
}

func newAuthenticatedConn(conn net.Conn, auth authentication) *authenticatedConn {
	return &authenticatedConn{Conn: conn, ev: auth.evidence, binding: auth.binding}
}

func (c *authenticatedConn) Seal(domain string, canonical []byte) (string, error) {
	if c == nil {
		return "", ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.binding) != sha256.Size {
		return "", ErrUnavailable
	}
	if !validBindingInput(domain, canonical) {
		return "", ErrBinding
	}
	return bindingTag(c.binding, c.ev, domain, canonical, c.ev.LocalRole, c.ev.PeerRole), nil
}

func (c *authenticatedConn) Verify(domain string, canonical []byte, tag string) error {
	if c == nil {
		return ErrUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || len(c.binding) != sha256.Size {
		return ErrUnavailable
	}
	if !validBindingInput(domain, canonical) || !validBindingTag(tag) {
		return ErrBinding
	}
	want := bindingTag(c.binding, c.ev, domain, canonical, c.ev.PeerRole, c.ev.LocalRole)
	if !hmac.Equal([]byte(tag), []byte(want)) {
		return ErrBinding
	}
	return nil
}

func (cfg Config) validate() error {
	if !platformAvailable() || cfg.Contract.validate() != nil || cfg.SocketRootFD == nil || cfg.KeySource == nil ||
		cfg.ReleaseRoot == nil || cfg.BinaryName == "" || !validImmutableMode(cfg.ExpectedReleaseRootMode, true) ||
		!validImmutableMode(cfg.ExpectedManifestMode, false) || !validImmutableMode(cfg.ExpectedBinaryMode, false) {
		return ErrUnavailable
	}
	if cfg.LocalRelease.validate() != nil || cfg.PeerRelease.validate() != nil {
		return ErrRelease
	}
	if err := verifyReleaseRoot(cfg); err != nil {
		return err
	}
	if err := verifyRelease(cfg.ReleaseRoot, cfg.LocalRelease, cfg.BinaryName, cfg.ExpectedReleaseRootUID, cfg.ExpectedReleaseRootGID, cfg.ExpectedManifestMode, cfg.ExpectedBinaryMode, cfg.ExpectedReleaseRootMode); err != nil {
		return err
	}
	if cfg.MaxHandshakeBytes != 0 && (cfg.MaxHandshakeBytes < 1024 || cfg.MaxHandshakeBytes > maxHandshake) {
		return ErrUnavailable
	}
	return nil
}

// ValidateConfig performs the complete non-mutating production validation.
// Composition uses it before creating state or binding a listener.
func ValidateConfig(cfg Config) error { return cfg.validate() }

func startHandshakeDeadline(c net.Conn, ctx context.Context) (func(), error) {
	d := time.Now().Add(defaultHandshakeDeadline)
	if cd, ok := ctx.Deadline(); ok && cd.Before(d) {
		d = cd
	}
	if err := c.SetDeadline(d); err != nil {
		return nil, err
	}
	return interruptOnContext(c, ctx), nil
}

type deadlineSetter interface{ SetDeadline(time.Time) error }

func interruptOnContext(c deadlineSetter, ctx context.Context) func() {
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
			_ = c.SetDeadline(time.Now())
		case <-stop:
		}
	}()
	return func() { close(stop); <-done }
}

func authenticate(c net.Conn, cfg Config) (authentication, error) {
	return authenticateContext(context.Background(), c, cfg)
}
func authenticateContext(ctx context.Context, c net.Conn, cfg Config) (authentication, error) {
	max := cfg.MaxHandshakeBytes
	if max == 0 {
		max = maxHandshake
	}
	p, err := peerCredentials(c)
	if err != nil {
		return authentication{}, err
	}
	if p.UID != *cfg.Contract.ExpectedPeerUID || p.GID != *cfg.Contract.ExpectedPeerGID {
		return authentication{}, ErrPeer
	}
	key, epoch, err := loadKeyContext(ctx, cfg.KeySource, cfg.Contract.Channel)
	if err != nil {
		return authentication{}, err
	}
	defer zero(key)
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return authentication{}, ErrUnavailable
	}
	h := hello{Version: ProtocolVersion, Channel: cfg.Contract.Channel, LocalRole: cfg.Contract.LocalRole, PeerRole: cfg.Contract.PeerRole, UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), KeyEpoch: epoch, Release: cfg.LocalRelease, Nonce: hex.EncodeToString(nonce[:])}
	h.MAC = macHello(key, h)
	if err = write(c, h, max); err != nil {
		return authentication{}, err
	}
	var peerH hello
	if err = readHello(c, &peerH, max); err != nil {
		return authentication{}, err
	}
	if err = validatePeerHello(cfg, h, peerH, p, epoch, key); err != nil {
		return authentication{}, err
	}
	a := ack{Version: ProtocolVersion, Nonce: peerH.Nonce}
	a.MAC = macAck(key, h, peerH, a.Nonce)
	if err = write(c, a, max); err != nil {
		return authentication{}, err
	}
	var peerA ack
	if err = readAck(c, &peerA, max); err != nil {
		return authentication{}, err
	}
	if peerA.Version != ProtocolVersion || peerA.Nonce != h.Nonce || !hmac.Equal([]byte(peerA.MAC), []byte(macAck(key, h, peerH, peerA.Nonce))) {
		return authentication{}, ErrPeer
	}
	binding := deriveBindingKey(key, h, peerH)
	if len(binding) != sha256.Size {
		return authentication{}, ErrUnavailable
	}
	ev := Evidence{Local: Peer{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, Peer: p, KeyEpoch: epoch, LocalRelease: cfg.LocalRelease, PeerRelease: cfg.PeerRelease, Channel: cfg.Contract.Channel, LocalRole: cfg.Contract.LocalRole, PeerRole: cfg.Contract.PeerRole}
	ev.BindingDigest = bindingDigest(binding, h, peerH)
	return authentication{evidence: ev, binding: binding}, nil
}

func validatePeerHello(cfg Config, local, peer hello, kernel Peer, epoch uint64, key []byte) error {
	if peer.Nonce == local.Nonce {
		return ErrReplay
	}
	if peer.Version != ProtocolVersion || peer.Channel != cfg.Contract.Channel || peer.LocalRole != cfg.Contract.PeerRole || peer.PeerRole != cfg.Contract.LocalRole || peer.KeyEpoch != epoch || peer.Release != cfg.PeerRelease || !validHexNonce(peer.Nonce) || !hmac.Equal([]byte(peer.MAC), []byte(macHello(key, peer))) || peer.UID != kernel.UID || peer.GID != kernel.GID {
		return ErrPeer
	}
	return nil
}

func loadKeyContext(ctx context.Context, src ContextServiceKeySource, channel string) ([]byte, uint64, error) {
	if src == nil {
		return nil, 0, ErrUnavailable
	}
	provided, epoch, err := src.LoadContext(ctx, channel)
	defer zero(provided)
	if err != nil || epoch == 0 || len(provided) < 32 {
		return nil, 0, ErrUnavailable
	}
	key := append([]byte(nil), provided...)
	return key, epoch, nil
}
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Every MAC is over a canonical unsigned transcript. In particular, a hello's
// MAC field is never recursively included in its own authenticated bytes.
func macHello(key []byte, h hello) string { h.MAC = ""; return mac(key, "hello", h) }
func macAck(key []byte, a, b hello, nonce string) string {
	a.MAC, b.MAC = "", ""
	pair := []hello{a, b}
	sort.Slice(pair, func(i, j int) bool {
		x, _ := json.Marshal(pair[i])
		y, _ := json.Marshal(pair[j])
		return bytes.Compare(x, y) < 0
	})
	return mac(key, "ack", struct {
		Version string  `json:"version"`
		Hellos  []hello `json:"hellos"`
		Nonce   string  `json:"nonce"`
	}{ProtocolVersion, pair, nonce})
}
func mac(key []byte, label string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(label))
	_, _ = m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

func deriveBindingKey(serviceKey []byte, a, b hello) []byte {
	a.MAC, b.MAC = "", ""
	pair := []hello{a, b}
	sort.Slice(pair, func(i, j int) bool {
		x, _ := json.Marshal(pair[i])
		y, _ := json.Marshal(pair[j])
		return bytes.Compare(x, y) < 0
	})
	data, err := json.Marshal(struct {
		Version string  `json:"version"`
		Purpose string  `json:"purpose"`
		Hellos  []hello `json:"hellos"`
	}{ProtocolVersion, "transcript-binding-v1", pair})
	if err != nil {
		return nil
	}
	m := hmac.New(sha256.New, serviceKey)
	_, _ = m.Write(data)
	return m.Sum(nil)
}

func bindingDigest(key []byte, a, b hello) string {
	a.MAC, b.MAC = "", ""
	pair := []hello{a, b}
	sort.Slice(pair, func(i, j int) bool {
		x, _ := json.Marshal(pair[i])
		y, _ := json.Marshal(pair[j])
		return bytes.Compare(x, y) < 0
	})
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte("binding-digest-v1"))
	data, _ := json.Marshal(pair)
	_, _ = m.Write(data)
	return "sha256:" + hex.EncodeToString(m.Sum(nil))
}

func bindingTag(key []byte, ev Evidence, domain string, canonical []byte, from, to string) string {
	m := hmac.New(sha256.New, key)
	writeBindingPart(m, "openduck-binding-v1")
	writeBindingPart(m, ev.BindingDigest)
	writeBindingPart(m, ev.Channel)
	writeBindingPart(m, from)
	writeBindingPart(m, to)
	writeBindingPart(m, domain)
	writeBindingPart(m, string(canonical))
	return hex.EncodeToString(m.Sum(nil))
}

func writeBindingPart(w io.Writer, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	_, _ = w.Write(n[:])
	_, _ = io.WriteString(w, s)
}

func validBindingInput(domain string, canonical []byte) bool {
	if len(domain) == 0 || len(domain) > maxBindingDomain || len(canonical) == 0 || len(canonical) > maxBindingCanonical {
		return false
	}
	previousWasAtom := false
	for i, b := range []byte(domain) {
		atom := b >= 'a' && b <= 'z' || i > 0 && b >= '0' && b <= '9'
		separator := i > 0 && (b == '.' || b == '-' || b == '_' || b == ':' || b == '/')
		if !atom && (!separator || !previousWasAtom) {
			return false
		}
		previousWasAtom = atom
	}
	return previousWasAtom
}

func validBindingTag(tag string) bool {
	if len(tag) != sha256.Size*2 {
		return false
	}
	b, err := hex.DecodeString(tag)
	return err == nil && tag == hex.EncodeToString(b)
}
func validHexNonce(s string) bool {
	return len(s) == 64 && func() bool { _, err := hex.DecodeString(s); return err == nil }()
}

func write(w io.Writer, v any, max int) error {
	b, err := json.Marshal(v)
	if err != nil || len(b) > max {
		return ErrProtocol
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err = writeFull(w, n[:]); err != nil {
		return err
	}
	_, err = writeFull(w, b)
	return err
}
func readHello(r io.Reader, out *hello, max int) error {
	return readExact(r, out, max, []string{"version", "channel", "local_role", "peer_role", "uid", "gid", "key_epoch", "release", "nonce", "mac"})
}
func readAck(r io.Reader, out *ack, max int) error {
	return readExact(r, out, max, []string{"version", "nonce", "mac"})
}
func readExact(r io.Reader, out any, max int, fields []string) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	sz := binary.BigEndian.Uint32(n[:])
	if sz == 0 || sz > uint32(max) {
		return ErrProtocol
	}
	b := make([]byte, sz)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	tok, err := dec.Token()
	if err != nil {
		return ErrProtocol
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ErrProtocol
	}
	want, got := make(map[string]struct{}, len(fields)), make(map[string]struct{}, len(fields))
	for _, f := range fields {
		want[f] = struct{}{}
	}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return ErrProtocol
		}
		name, ok := t.(string)
		if !ok {
			return ErrProtocol
		}
		if _, ok = want[name]; !ok {
			return ErrProtocol
		}
		if _, ok = got[name]; ok {
			return ErrProtocol
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil || bytes.Equal(raw, []byte("null")) {
			return ErrProtocol
		}
		got[name] = struct{}{}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') || len(got) != len(want) {
		return ErrProtocol
	}
	if dec.More() {
		return ErrProtocol
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	// A second strict decode preserves type/range validation after duplicate and
	// missing-field checks above.
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrProtocol
	}
	return nil
}
func writeFull(w io.Writer, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := w.Write(b[n:])
		n += k
		if err != nil {
			return n, err
		}
		if k == 0 {
			return n, io.ErrShortWrite
		}
	}
	return n, nil
}

func verifySocketRoot(c SocketContract, fdRoot *os.Root) (socketState, error) {
	if fdRoot == nil {
		return socketState{}, ErrUnavailable
	}
	// Walk the physical path rather than trusting lexical cleaning alone.
	root, err := os.OpenRoot("/")
	if err != nil {
		return socketState{}, ErrUnavailable
	}
	for _, part := range strings.Split(strings.TrimPrefix(filepath.Clean(c.SocketRoot), "/"), "/") {
		if part == "" {
			continue
		}
		fi, err := root.Lstat(part)
		if err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return socketState{}, ErrUnavailable
		}
		next, err := root.OpenRoot(part)
		if err != nil {
			_ = root.Close()
			return socketState{}, ErrUnavailable
		}
		_ = root.Close()
		root = next
	}
	fi, err := root.Lstat(".")
	_ = root.Close()
	if err != nil || !fi.IsDir() || !matchesFile(fi, c.ExpectedSocketRootUID, c.ExpectedSocketRootGID, c.ExpectedSocketRootMode) {
		return socketState{}, ErrUnavailable
	}
	fdInfo, err := fdRoot.Lstat(".")
	if err != nil || !fdInfo.IsDir() || !matchesFile(fdInfo, c.ExpectedSocketRootUID, c.ExpectedSocketRootGID, c.ExpectedSocketRootMode) || !sameFile(fi, fdInfo) {
		return socketState{}, ErrUnavailable
	}
	return statState(fi, ""), nil
}
func verifySocketPath(cfg Config) (socketState, error) {
	c := cfg.Contract
	if _, err := verifySocketRoot(c, cfg.SocketRootFD); err != nil {
		return socketState{}, err
	}
	fi, err := os.Lstat(filepath.Join(c.SocketRoot, c.SocketPath))
	if err != nil || fi.Mode()&os.ModeSocket == 0 || !matchesFile(fi, c.ExpectedSocketUID, c.ExpectedSocketGID, c.ExpectedSocketMode) {
		return socketState{}, ErrUnavailable
	}
	d, err := SocketMetadataDigestFromInfo(fi, c.SocketPath)
	if err != nil {
		return socketState{}, ErrUnavailable
	}
	state := statState(fi, d)
	return state, nil
}
func statState(fi os.FileInfo, digest string) socketState {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return socketState{}
	}
	return socketState{uint64(st.Dev), uint64(st.Ino), digest}
}
func sameFile(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	return ok && x.Dev == y.Dev && x.Ino == y.Ino
}
func matchesFile(fi os.FileInfo, uid, gid uint32, mode os.FileMode) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && !hasSecurityModeBits(fi.Mode()) && uint32(st.Uid) == uid && uint32(st.Gid) == gid && fi.Mode().Perm() == mode.Perm()
}
