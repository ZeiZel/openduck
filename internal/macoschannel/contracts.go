// Package macoschannel implements a deliberately narrow, fail-closed local
// Unix-domain channel. Kernel peer credentials authenticate the account, not
// the peer executable: callers must not treat Evidence as code-signing proof.
package macoschannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrUnavailable = errors.New("macoschannel: unavailable")
	ErrProtocol    = errors.New("macoschannel: protocol violation")
	ErrPeer        = errors.New("macoschannel: peer credentials rejected")
	ErrRelease     = errors.New("macoschannel: release pin rejected")
	ErrReplay      = errors.New("macoschannel: handshake replay")
	ErrBinding     = errors.New("macoschannel: transcript binding rejected")
)

const ProtocolVersion = "openduck-channel-v1"

const securityModeBits = os.ModeSetuid | os.ModeSetgid | os.ModeSticky

// SocketContract is intentionally explicit. Nil peer identities are never a
// wildcard: UID/GID 0 are represented by pointers to zero.
type SocketContract struct {
	Channel, LocalRole, PeerRole                 string
	SocketPath                                   string // one basename, relative to SocketRoot
	SocketRoot                                   string // absolute, clean, physical directory
	ExpectedPeerUID, ExpectedPeerGID             *uint32
	ExpectedSocketRootUID, ExpectedSocketRootGID uint32
	ExpectedSocketRootMode                       os.FileMode
	ExpectedSocketUID, ExpectedSocketGID         uint32
	ExpectedSocketMode                           os.FileMode
}

type ReleasePin struct {
	ReleaseID      string `json:"release_id"`
	BinaryDigest   string `json:"binary_digest"`
	SocketDigest   string `json:"socket_digest"`
	ManifestDigest string `json:"manifest_digest"`
}

type ContextServiceKeySource interface {
	LoadContext(ctx context.Context, channel string) (key []byte, epoch uint64, err error)
}

type Config struct {
	Contract     SocketContract
	LocalRelease ReleasePin
	PeerRelease  ReleasePin
	ReleaseRoot  *os.Root // an already-open root FD, never a pathname
	SocketRootFD *os.Root // must refer to Contract.SocketRoot's physical directory
	BinaryName   string
	KeySource    ContextServiceKeySource

	// Release ownership and modes are explicit instead of relying on a
	// process-wide umask or a permissive deployment convention.
	ExpectedReleaseRootUID, ExpectedReleaseRootGID uint32
	ExpectedReleaseRootMode                        os.FileMode
	ExpectedManifestMode                           os.FileMode
	ExpectedBinaryMode                             os.FileMode
	MaxHandshakeBytes                              int
}

// Conn is sealed. Evidence is exported for consumers, while the unexported
// marker prevents a foreign implementation from manufacturing a trusted Conn.
type Conn interface {
	net.Conn
	Evidence() Evidence
	Seal(domain string, canonical []byte) (tag string, err error)
	Verify(domain string, canonical []byte, tag string) error
	evidence()
}

type Evidence struct {
	Local, Peer                  Peer
	KeyEpoch                     uint64
	LocalRelease, PeerRelease    ReleasePin
	Channel, LocalRole, PeerRole string
	// BindingDigest is a non-secret identifier for this exact authenticated
	// connection. It is safe to compare and log, but cannot create tags.
	BindingDigest string
}

type Peer struct{ UID, GID uint32 }

func (c SocketContract) validate() error {
	if c.Channel == "" || c.LocalRole == "" || c.PeerRole == "" || c.LocalRole == c.PeerRole ||
		c.ExpectedPeerUID == nil || c.ExpectedPeerGID == nil ||
		c.SocketRoot == "" || !filepath.IsAbs(c.SocketRoot) || filepath.Clean(c.SocketRoot) != c.SocketRoot ||
		c.SocketPath == "" || filepath.Base(c.SocketPath) != c.SocketPath || strings.Contains(c.SocketPath, string(filepath.Separator)) ||
		!validImmutableMode(c.ExpectedSocketRootMode, true) || !validMode(c.ExpectedSocketMode, false) {
		return ErrUnavailable
	}
	return nil
}

func validMode(mode os.FileMode, dir bool) bool {
	if mode == 0 || mode&^os.FileMode(0777) != 0 || mode.Perm()&0007 != 0 {
		return false
	}
	if dir && (mode.Perm()&0300) != 0300 {
		return false
	}
	return true
}
func validImmutableMode(mode os.FileMode, dir bool) bool {
	return validMode(mode, dir) && mode.Perm()&0022 == 0
}
func hasSecurityModeBits(mode os.FileMode) bool { return mode&securityModeBits != 0 }

func (p ReleasePin) validate() error {
	if p.ReleaseID == "" {
		return ErrRelease
	}
	for _, s := range []string{p.BinaryDigest, p.SocketDigest, p.ManifestDigest} {
		if len(s) != sha256.Size*2 {
			return ErrRelease
		}
		if _, e := hex.DecodeString(s); e != nil {
			return ErrRelease
		}
	}
	return nil
}

func hexDigest(b []byte) string { d := sha256.Sum256(b); return hex.EncodeToString(d[:]) }
func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrProtocol, fmt.Sprintf(format, args...))
}
