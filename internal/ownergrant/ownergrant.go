// Package ownergrant is the narrow, descriptor-anchored hand-off between the
// root-only owner operator and the unprivileged Controller. The Controller
// only ever receives an Ed25519 public key; it cannot create an approval.
package ownergrant

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	SchemaV1           = "openduck-owner-pending-order.v1"
	CapabilityV1       = "openduck-owner-capability.v1"
	CapabilityPurpose  = "owner-chat-canary"
	MaxPendingBytes    = 4096
	MaxPendingLifetime = 60 * time.Second
	MaxCapabilityLife  = 10 * time.Minute
)

var (
	ErrApprovalRequired = errors.New("owner approval required")
	ErrInvalidPending   = errors.New("invalid owner pending order")
	ErrAlreadyPending   = errors.New("owner approval already pending")
	ErrExpired          = errors.New("owner approval expired")
	ErrRejected         = errors.New("owner approval rejected")
)

type ApprovalRequiredError struct {
	RequestID   string
	OrderDigest string
	ExpiresAt   time.Time
}

func (e ApprovalRequiredError) Error() string { return "owner approval required" }
func (e ApprovalRequiredError) Unwrap() error { return ErrApprovalRequired }

type PendingOrder struct {
	Version     string    `json:"version"`
	RequestID   string    `json:"request_id"`
	OrderDigest string    `json:"order_digest"`
	ChatID      string    `json:"chat_id"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Capability is canonical and self-contained; only its public verification key
// enters the Controller process.
type Capability struct {
	Version     string    `json:"version"`
	Purpose     string    `json:"purpose"`
	RequestID   string    `json:"request_id"`
	Nonce       string    `json:"nonce"`
	OrderDigest string    `json:"order_digest"`
	ChatID      string    `json:"chat_id"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   string    `json:"signature"`
}

type Store struct {
	root       *os.Root
	uid, gid   int
	dev, inode uint64
}

func OpenStore(path string, uid, gid int) (*Store, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || uid < 0 || gid < 0 {
		return nil, ErrInvalidPending
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrInvalidPending
	}
	st, err := r.Lstat(".")
	if err != nil || !validDir(st, uid, gid, 0700) {
		_ = r.Close()
		return nil, ErrInvalidPending
	}
	dev, ino, ok := identity(st)
	if !ok {
		_ = r.Close()
		return nil, ErrInvalidPending
	}
	return &Store{root: r, uid: uid, gid: gid, dev: dev, inode: ino}, nil
}
func OpenCurrentStore(path string) (*Store, error) {
	return OpenStore(path, os.Geteuid(), os.Getegid())
}
func (s *Store) Close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.Close()
}

func (p PendingOrder) Validate(now time.Time) error {
	if p.Version != SchemaV1 || !safeRequestID(p.RequestID) || !digest(p.OrderDigest) || !opaque(p.ChatID, 256) || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(now.UTC()) || p.ExpiresAt.Sub(now.UTC()) > MaxPendingLifetime {
		return ErrInvalidPending
	}
	return nil
}
func safeRequestID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func opaque(s string, n int) bool {
	return s != "" && len(s) <= n && !strings.ContainsAny(s, "\r\n/\\")
}
func digest(s string) bool {
	if len(s) != 71 || !strings.HasPrefix(s, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(s[7:])
	return err == nil
}
func safeLeaf(s string) bool {
	return s != "" && filepath.Base(s) == s && !strings.ContainsAny(s, "\\/")
}

func Request(queue, orderDigest, chatID string, now time.Time) (PendingOrder, error) {
	s, err := OpenCurrentStore(queue)
	if err != nil {
		return PendingOrder{}, err
	}
	defer s.Close()
	return s.Request(orderDigest, chatID, now)
}

// Request creates a fresh request id for every later attempt. Only one pending
// prompt is shown at once, but equal orders can be approved again after use.
func (s *Store) Request(orderDigest, chatID string, now time.Time) (PendingOrder, error) {
	if s == nil || !digest(orderDigest) || !opaque(chatID, 256) {
		return PendingOrder{}, ErrInvalidPending
	}
	return s.withLock(func() (PendingOrder, error) {
		active, err := s.active(now)
		if err != nil {
			return PendingOrder{}, err
		}
		if active.RequestID != "" {
			if active.OrderDigest != orderDigest || active.ChatID != chatID {
				return PendingOrder{}, ErrAlreadyPending
			}
			return active, ApprovalRequiredError{active.RequestID, active.OrderDigest, active.ExpiresAt}
		}
		id, err := randomHex(16)
		if err != nil {
			return PendingOrder{}, ErrInvalidPending
		}
		p := PendingOrder{SchemaV1, id, orderDigest, chatID, now.UTC().Add(MaxPendingLifetime)}
		raw, err := canonicalPending(p)
		if err != nil || s.writeAtomic("pending."+id, raw, s.uid, s.gid) != nil {
			return PendingOrder{}, ErrInvalidPending
		}
		return p, ApprovalRequiredError{p.RequestID, p.OrderDigest, p.ExpiresAt}
	})
}
func (s *Store) Active(now time.Time) (PendingOrder, error) {
	return s.withLock(func() (PendingOrder, error) { return s.active(now) })
}
func (s *Store) active(now time.Time) (PendingOrder, error) {
	if s.validRoot() != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	d, err := s.root.Open(".")
	if err != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	defer d.Close()
	entries, err := d.ReadDir(-1)
	if err != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	var found PendingOrder
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "pending.") {
			continue
		}
		if !safeRequestID(strings.TrimPrefix(name, "pending.")) {
			return PendingOrder{}, ErrInvalidPending
		}
		p, err := s.readPending(name, now)
		if err == nil {
			if found.RequestID != "" {
				return PendingOrder{}, ErrAlreadyPending
			}
			found = p
			continue
		}
		if errors.Is(err, ErrExpired) {
			_ = s.root.Remove(name)
			continue
		}
		return PendingOrder{}, err
	}
	return found, nil
}
func (s *Store) Read(requestID string, now time.Time) (PendingOrder, error) {
	if s == nil || !safeRequestID(requestID) {
		return PendingOrder{}, ErrInvalidPending
	}
	return s.readPending("pending."+requestID, now)
}
func (s *Store) readPending(name string, now time.Time) (PendingOrder, error) {
	raw, err := s.readExact(name, s.uid, s.gid, 0600, MaxPendingBytes)
	if err != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	p, err := parsePending(raw)
	if err != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	if err = p.Validate(now); err != nil {
		if !p.ExpiresAt.IsZero() && !p.ExpiresAt.After(now.UTC()) {
			return PendingOrder{}, ErrExpired
		}
		return PendingOrder{}, err
	}
	return p, nil
}

func Phrase(p PendingOrder) string {
	return "APPROVE " + p.RequestID + " " + p.OrderDigest + " " + p.ChatID
}
func CapabilityLeaf(prefix, requestID string) (string, error) {
	if !safeLeaf(prefix) || !safeRequestID(requestID) {
		return "", ErrInvalidPending
	}
	return prefix + "." + requestID, nil
}

func Issue(private ed25519.PrivateKey, p PendingOrder, now time.Time) ([]byte, Capability, error) {
	if len(private) != ed25519.PrivateKeySize || p.Validate(now) != nil {
		return nil, Capability{}, ErrInvalidPending
	}
	nonce, err := randomHex(16)
	if err != nil {
		return nil, Capability{}, ErrInvalidPending
	}
	c := Capability{Version: CapabilityV1, Purpose: CapabilityPurpose, RequestID: p.RequestID, Nonce: nonce, OrderDigest: p.OrderDigest, ChatID: p.ChatID, IssuedAt: now.UTC(), ExpiresAt: now.UTC().Add(MaxCapabilityLife)}
	signed, err := canonicalCapability(c, false)
	if err != nil {
		return nil, Capability{}, ErrInvalidPending
	}
	c.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(private, signed))
	raw, err := canonicalCapability(c, true)
	if err != nil {
		return nil, Capability{}, ErrInvalidPending
	}
	return raw, c, nil
}

// Consume is root-helper-only. It writes a controller-owned exact request leaf
// then removes the corresponding pending leaf under the same store lock.
func (s *Store) Consume(requestID, capabilityRoot, prefix string, private ed25519.PrivateKey, controllerUID, controllerGID int, now time.Time) error {
	if s == nil || !safeRequestID(requestID) || controllerUID < 0 || controllerGID < 0 {
		return ErrInvalidPending
	}
	leaf, err := CapabilityLeaf(prefix, requestID)
	if err != nil {
		return err
	}
	_, err = s.withLock(func() (PendingOrder, error) {
		p, err := s.Read(requestID, now)
		if err != nil {
			return PendingOrder{}, err
		}
		raw, _, err := Issue(private, p, now)
		if err != nil {
			return PendingOrder{}, err
		}
		root, err := os.OpenRoot(capabilityRoot)
		if err != nil {
			return PendingOrder{}, ErrInvalidPending
		}
		defer root.Close()
		if err := writeAtomicRoot(root, leaf, raw, controllerUID, controllerGID); err != nil {
			return PendingOrder{}, err
		}
		if err := s.root.Remove("pending." + requestID); err != nil {
			return PendingOrder{}, ErrInvalidPending
		}
		return PendingOrder{}, nil
	})
	return err
}

// VerifyAndConsume is Controller-side. It takes only a public key. Mismatches
// are validated before the replay rename, so they cannot consume a valid grant.
func VerifyAndConsume(capabilityRoot, prefix, requestID string, public ed25519.PublicKey, orderDigest, chatID string, now time.Time) error {
	if len(public) != ed25519.PublicKeySize || !safeRequestID(requestID) || !digest(orderDigest) || !opaque(chatID, 256) {
		return ErrRejected
	}
	leaf, err := CapabilityLeaf(prefix, requestID)
	if err != nil {
		return ErrRejected
	}
	r, err := os.OpenRoot(capabilityRoot)
	if err != nil {
		return ErrRejected
	}
	defer r.Close()
	raw, err := readExactRoot(r, leaf, os.Geteuid(), os.Getegid(), 0600, MaxPendingBytes)
	if err != nil {
		return ErrRejected
	}
	c, err := parseCapability(raw)
	if err != nil || c.Version != CapabilityV1 || c.Purpose != CapabilityPurpose || c.RequestID != requestID || c.OrderDigest != orderDigest || c.ChatID != chatID || !safeRequestID(c.Nonce) || !c.IssuedAt.Before(c.ExpiresAt) || !c.ExpiresAt.After(now.UTC()) || c.ExpiresAt.Sub(c.IssuedAt) > MaxCapabilityLife || c.IssuedAt.After(now.UTC().Add(time.Minute)) {
		return ErrRejected
	}
	sig, err := base64.RawStdEncoding.DecodeString(c.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return ErrRejected
	}
	signed, err := canonicalCapability(c, false)
	if err != nil || !ed25519.Verify(public, signed, sig) {
		return ErrRejected
	}
	if _, err := r.Lstat(leaf + ".consumed"); err == nil || !os.IsNotExist(err) {
		return ErrRejected
	}
	if err := r.Rename(leaf, leaf+".consumed"); err != nil {
		return ErrRejected
	}
	return nil
}

func (s *Store) withLock(fn func() (PendingOrder, error)) (PendingOrder, error) {
	if s == nil || s.root == nil || s.validRoot() != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	f, err := s.root.OpenFile(".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !validFile(st, s.uid, s.gid, 0600) {
		return PendingOrder{}, ErrInvalidPending
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func (s *Store) validRoot() error {
	st, err := s.root.Lstat(".")
	if err != nil || !validDir(st, s.uid, s.gid, 0700) {
		return ErrInvalidPending
	}
	d, i, ok := identity(st)
	if !ok || d != s.dev || i != s.inode {
		return ErrInvalidPending
	}
	return nil
}
func (s *Store) readExact(name string, uid, gid int, mode os.FileMode, max int64) ([]byte, error) {
	return readExactRoot(s.root, name, uid, gid, mode, max)
}
func (s *Store) writeAtomic(name string, raw []byte, uid, gid int) error {
	return writeAtomicRoot(s.root, name, raw, uid, gid)
}
func readExactRoot(root *os.Root, name string, uid, gid int, mode os.FileMode, max int64) ([]byte, error) {
	if root == nil || !safeLeaf(name) {
		return nil, ErrInvalidPending
	}
	before, err := root.Lstat(name)
	if err != nil || !validFile(before, uid, gid, mode) {
		return nil, ErrInvalidPending
	}
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidPending
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !validFile(after, uid, gid, mode) || !sameFile(before, after) {
		return nil, ErrInvalidPending
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		return nil, ErrInvalidPending
	}
	return raw, nil
}

// LoadPublicKey reads the Controller's raw Ed25519 verification key from an
// already-open trusted root. Public keys are not service-key records and do
// not carry a channel epoch.
func LoadPublicKey(root *os.Root, name string, uid, gid int) (ed25519.PublicKey, error) {
	raw, err := readExactRoot(root, name, uid, gid, 0600, ed25519.PublicKeySize)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidPending
	}
	return append(ed25519.PublicKey(nil), raw...), nil
}
func writeAtomicRoot(root *os.Root, name string, raw []byte, uid, gid int) error {
	if root == nil || !safeLeaf(name) || len(raw) == 0 || len(raw) > MaxPendingBytes {
		return ErrInvalidPending
	}
	if _, err := root.Lstat(name); err == nil || !os.IsNotExist(err) {
		return ErrRejected
	}
	tmp, err := randomHex(16)
	if err != nil {
		return ErrInvalidPending
	}
	tmp = ".tmp-" + tmp
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return ErrInvalidPending
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = root.Remove(tmp)
		}
	}()
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = f.Chown(uid, gid)
	}
	if err == nil {
		err = f.Chmod(0600)
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return ErrInvalidPending
	}
	if err = root.Rename(tmp, name); err != nil {
		return ErrInvalidPending
	}
	cleanup = false
	return nil
}
func canonicalPending(p PendingOrder) ([]byte, error) { return json.Marshal(p) }
func parsePending(raw []byte) (PendingOrder, error) {
	var p PendingOrder
	if json.Unmarshal(raw, &p) != nil {
		return PendingOrder{}, ErrInvalidPending
	}
	canonical, err := canonicalPending(p)
	if err != nil || !bytes.Equal(raw, canonical) {
		return PendingOrder{}, ErrInvalidPending
	}
	return p, nil
}
func canonicalCapability(c Capability, signature bool) ([]byte, error) {
	if signature {
		return json.Marshal(c)
	}
	return json.Marshal(struct {
		Version     string    `json:"version"`
		Purpose     string    `json:"purpose"`
		RequestID   string    `json:"request_id"`
		Nonce       string    `json:"nonce"`
		OrderDigest string    `json:"order_digest"`
		ChatID      string    `json:"chat_id"`
		IssuedAt    time.Time `json:"issued_at"`
		ExpiresAt   time.Time `json:"expires_at"`
	}{c.Version, c.Purpose, c.RequestID, c.Nonce, c.OrderDigest, c.ChatID, c.IssuedAt, c.ExpiresAt})
}
func parseCapability(raw []byte) (Capability, error) {
	var c Capability
	if json.Unmarshal(raw, &c) != nil {
		return Capability{}, ErrInvalidPending
	}
	canonical, err := canonicalCapability(c, true)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Capability{}, ErrInvalidPending
	}
	return c, nil
}
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func validDir(i os.FileInfo, uid, gid int, mode os.FileMode) bool {
	return i != nil && i.IsDir() && i.Mode()&os.ModeSymlink == 0 && i.Mode().Perm() == mode && owned(i, uid, gid)
}
func validFile(i os.FileInfo, uid, gid int, mode os.FileMode) bool {
	if i == nil {
		return false
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	return ok && i.Mode().IsRegular() && i.Mode()&os.ModeSymlink == 0 && i.Mode().Perm() == mode && int(st.Uid) == uid && int(st.Gid) == gid && st.Nlink == 1
}
func owned(i os.FileInfo, uid, gid int) bool {
	if i == nil {
		return false
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == uid && int(st.Gid) == gid
}
func identity(i os.FileInfo) (uint64, uint64, bool) {
	if i == nil {
		return 0, 0, false
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return uint64(st.Dev), st.Ino, true
}
func sameFile(a, b os.FileInfo) bool {
	ad, ai, aok := identity(a)
	bd, bi, bok := identity(b)
	return aok && bok && ad == bd && ai == bi
}
