package codexruntime

// The owner canary has deliberately small concrete local gates.  They are not
// HTTP/session checks: a browser on loopback is only a presentation client.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const ownerHomeName = "codex-owner-chat"

type sealedCapability struct {
	Version     string `json:"version"`
	Purpose     string `json:"purpose"`
	Expires     string `json:"expires_at"`
	OrderDigest string `json:"order_digest,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	MAC         string `json:"mac"`
}

// SealedStartupCapability validates a single, short-lived, Keychain-sealed
// startup grant and consumes it on the first authorization. The controller
// never accepts an origin, IP address, or cookie as proof of ownership.
type SealedStartupCapability struct {
	mu             sync.Mutex
	active         bool
	capabilityPath string
}

func NewSealedStartupCapability(publicKey ed25519.PublicKey, capabilityPath string, now time.Time) (*SealedStartupCapability, error) {
	return newSealedStartupCapability(publicKey, capabilityPath, now, "", "")
}

// NewBoundSealedStartupCapability additionally requires the provisioned
// capability to name the exact GeneralChatOrder digest and chat session.
func NewBoundSealedStartupCapability(publicKey ed25519.PublicKey, capabilityPath string, now time.Time, orderDigest, sessionID string) (*SealedStartupCapability, error) {
	if orderDigest == "" || sessionID == "" {
		return nil, ErrOwnerAuthorization
	}
	return newSealedStartupCapability(publicKey, capabilityPath, now, orderDigest, sessionID)
}

func newSealedStartupCapability(publicKey ed25519.PublicKey, capabilityPath string, now time.Time, orderDigest, sessionID string) (*SealedStartupCapability, error) {
	if len(publicKey) != ed25519.PublicKeySize || capabilityPath == "" || !filepath.IsAbs(capabilityPath) || filepath.Clean(capabilityPath) != capabilityPath {
		return nil, ErrOwnerAuthorization
	}
	info, err := os.Lstat(capabilityPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ownedByCurrentUser(info) {
		return nil, ErrOwnerAuthorization
	}
	raw, err := os.ReadFile(capabilityPath)
	if err != nil || len(raw) > 4096 {
		return nil, ErrOwnerAuthorization
	}
	var cap sealedCapability
	if json.Unmarshal(raw, &cap) != nil || cap.Version != "openduck-owner-canary-capability.v1" || cap.Purpose != "owner-chat-canary" || cap.MAC == "" || (orderDigest != "" && (cap.OrderDigest != orderDigest || cap.SessionID != sessionID)) {
		return nil, ErrOwnerAuthorization
	}
	expires, err := time.Parse(time.RFC3339, cap.Expires)
	if err != nil || !expires.After(now.UTC()) || expires.Sub(now.UTC()) > 10*time.Minute {
		return nil, ErrOwnerAuthorization
	}
	mac, err := hex.DecodeString(cap.MAC)
	if err != nil || len(mac) != ed25519.SignatureSize {
		return nil, ErrOwnerAuthorization
	}
	macInput := cap.Version + "\n" + cap.Purpose + "\n" + cap.Expires
	if orderDigest != "" {
		macInput += "\n" + cap.OrderDigest + "\n" + cap.SessionID
	}
	if !ed25519.Verify(publicKey, []byte(macInput), mac) {
		return nil, ErrOwnerAuthorization
	}
	return &SealedStartupCapability{active: true, capabilityPath: capabilityPath}, nil
}
func (a *SealedStartupCapability) Authorize(context.Context) error {
	if a == nil {
		return ErrOwnerAuthorization
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.active {
		return ErrOwnerAuthorization
	}
	// Persist the one-use transition before allowing the run to proceed. An
	// atomic rename leaves the original leaf absent across process restarts.
	consumed := a.capabilityPath + ".consumed"
	if _, err := os.Lstat(consumed); err == nil || !os.IsNotExist(err) {
		return ErrOwnerAuthorization
	}
	if err := os.Rename(a.capabilityPath, consumed); err != nil {
		return ErrOwnerAuthorization
	}
	a.active = false // one winning canary run; concurrent callers lose the CAS
	return nil
}

// LocalProcessGate makes the mutually-exclusive canary posture observable.
// It rejects rather than attempting to stop another runtime.
type LocalProcessGate struct{ command string }

func NewLocalProcessGate() *LocalProcessGate { return &LocalProcessGate{command: "/bin/ps"} }
func (g *LocalProcessGate) Check(ctx context.Context) error {
	if g == nil || g.command == "" {
		return ErrProcessGate
	}
	out, err := exec.CommandContext(ctx, g.command, "-axo", "comm=").Output()
	if err != nil {
		return ErrProcessGate
	}
	for _, line := range strings.Split(strings.ToLower(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "openclaw") || strings.Contains(line, "ollama") || strings.Contains(line, "deepseek-harness") || strings.Contains(line, "/dsh") {
			return ErrProcessGate
		}
	}
	return nil
}

// LocalExecutableObserver pins the exact executable bytes before launch.
type LocalExecutableObserver struct{}

func (LocalExecutableObserver) Observe(_ context.Context, binary, interpreter string) (string, string, error) {
	paths := []string{binary}
	if interpreter != "" {
		paths = []string{interpreter, binary}
	}
	h := sha256.New()
	names := make([]string, 0, len(paths))
	for _, target := range paths {
		info, err := os.Lstat(target)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !ownedByCurrentUser(info) {
			return "", "", ErrUnsafeRuntime
		}
		raw, err := os.ReadFile(target)
		if err != nil || len(raw) == 0 {
			return "", "", ErrUnsafeRuntime
		}
		stat := info.Sys().(*syscall.Stat_t)
		_, _ = h.Write([]byte(target + "\n" + strconv.FormatUint(uint64(stat.Ino), 10) + "\n" + strconv.FormatInt(info.ModTime().UnixNano(), 10) + "\n"))
		_, _ = h.Write(raw)
		names = append(names, filepath.Base(target))
	}
	return strings.Join(names, "+"), "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid()
}

var _ OwnerAuthenticator = (*SealedStartupCapability)(nil)
var _ ProcessGate = (*LocalProcessGate)(nil)
var _ ExecutableObserver = LocalExecutableObserver{}
