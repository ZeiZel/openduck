// Package ownerauth runs the local, native owner-authentication helper.
// It is deliberately not wired to the controller: callers must provide the
// controller-issued opaque proof reference and an already authenticated
// challenge. The helper never receives credentials or network access.
package ownerauth

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	maxLine  = 64 << 10
	maxText  = 8 << 10
	maxField = 2 << 10
)

var (
	ErrInvalidHelper = errors.New("invalid owner-auth helper")
	ErrProtocol      = errors.New("owner-auth helper protocol error")
)

type Request struct {
	SessionID         string
	DisplayInstance   string
	ActionType        string
	Title             string
	PreviewText       string
	Destination       string
	Risk              string
	ExpiresAt         string
	PreviewDigest     string
	DestinationDigest string
	Challenge         string
	ProofRef          string // controller-generated opaque reference; never interpreted
}

type Result struct {
	Decision        string    `json:"decision"`
	Approver        string    `json:"approver,omitempty"`
	Challenge       string    `json:"challenge"`
	SessionID       string    `json:"session_id"`
	DisplayInstance string    `json:"display_instance_id"`
	Timestamp       time.Time `json:"timestamp"`
	ProofRef        string    `json:"proof_ref,omitempty"`
}

// Dossier is the immutable preview sent to the native helper. It deliberately
// contains no challenge or controller capability handle.
type Dossier struct {
	SessionID         string
	DisplayInstance   string
	ActionType        string
	Title             string
	PreviewText       string
	Destination       string
	Risk              string
	ExpiresAt         string
	PreviewDigest     string
	DestinationDigest string
}

// DecisionAuthority is the local controller-owned boundary. The helper's
// decision is an observation only; this authority supplies the approver and a
// fresh, controller-generated proof reference.
type DecisionAuthority interface {
	Authorize(context.Context, string, string) (approver, proofRef string, err error)
}

// Session is the two-phase process session used by nativeconfirm's adapter.
type Session interface {
	Render(context.Context) (RenderAck, error)
	Authenticate(context.Context, string) (Result, error)
	Cancel()
}

type RenderAck struct {
	SessionID         string
	DisplayNonce      string
	PreviewDigest     string
	DestinationDigest string
}

type Config struct {
	Path      string
	SHA256    string
	Timeout   time.Duration
	Authority DecisionAuthority
}

func (c Config) validate() error {
	if filepath.IsAbs(c.Path) == false || c.Path == "" || strings.TrimSpace(c.SHA256) == "" {
		return ErrInvalidHelper
	}
	if len(c.SHA256) != sha256.Size*2 {
		return ErrInvalidHelper
	}
	if _, err := hex.DecodeString(c.SHA256); err != nil {
		return ErrInvalidHelper
	}
	return nil
}

func verifyExecutable(path, want string) error {
	v, err := openVerifiedExecutable(path, want)
	if err != nil {
		return err
	}
	v.cleanup()
	return v.file.Close()
}

// verifiedHook is a test seam used to exercise replacement races between
// verification and exec. Production code leaves it nil.
var verifiedHook func()

// beforeLinkHook is test-only and lets security tests force a pathname swap
// between opening the verified descriptor and creating its private hard link.
var beforeLinkHook func()

type verifiedExecutable struct {
	file    *os.File
	path    string
	cleanup func()
}

func openVerifiedExecutable(path, want string) (*verifiedExecutable, error) {
	if err := validateParentDirectory(path); err != nil {
		return nil, err
	}
	// O_NOFOLLOW makes the final pathname component non-followable. The file
	// descriptor returned here is the object that is hashed and later exec'd.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalidHelper
	}
	if beforeLinkHook != nil {
		beforeLinkHook()
	}
	execPath, cleanup, err := linkExecutable(path)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	linkedInfo, err := os.Stat(execPath)
	if err != nil || !sameInode(f, linkedInfo) {
		return nil, ErrInvalidHelper
	}
	closeOnErr := true
	defer func() {
		if closeOnErr {
			_ = f.Close()
			cleanup()
		}
	}()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0700 {
		return nil, ErrInvalidHelper
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uint32(os.Getuid()) {
		return nil, ErrInvalidHelper
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 32<<20+1)); err != nil {
		return nil, ErrInvalidHelper
	}
	if hex.EncodeToString(h.Sum(nil)) != strings.ToLower(want) {
		return nil, ErrInvalidHelper
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, ErrInvalidHelper
	}
	closeOnErr = false
	return &verifiedExecutable{file: f, path: execPath, cleanup: cleanup}, nil
}

func sameInode(f *os.File, info os.FileInfo) bool {
	a, err := f.Stat()
	if err != nil || info == nil {
		return false
	}
	x, ok1 := a.Sys().(*syscall.Stat_t)
	y, ok2 := info.Sys().(*syscall.Stat_t)
	return ok1 && ok2 && x.Dev == y.Dev && x.Ino == y.Ino
}

// linkExecutable creates a private hard link to the already-open object
// object. A hard link is an inode reference, so replacing the configured
// pathname after this point cannot change the bytes that will be executed.
// The descriptor remains open and is inherited as an additional defense and
// audit evidence; macOS rejects execve(/dev/fd/N) for ordinary descriptors.
func linkExecutable(path string) (string, func(), error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".openduck-helper-*")
	if err != nil {
		return "", nil, ErrInvalidHelper
	}
	runPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(runPath)
		return "", nil, ErrInvalidHelper
	}
	if err := os.Remove(runPath); err != nil {
		return "", nil, ErrInvalidHelper
	}
	if err := os.Link(path, runPath); err != nil {
		return "", nil, ErrInvalidHelper
	}
	// Cleanup is inode-aware: never remove a replacement that appeared at the
	// temporary pathname after this exact helper was linked.
	info, err := os.Stat(runPath)
	if err != nil {
		_ = os.Remove(runPath)
		return "", nil, ErrInvalidHelper
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		_ = os.Remove(runPath)
		return "", nil, ErrInvalidHelper
	}
	return runPath, func() {
		current, err := os.Stat(runPath)
		if err != nil {
			return
		}
		cur, ok := current.Sys().(*syscall.Stat_t)
		if ok && cur.Dev == st.Dev && cur.Ino == st.Ino {
			_ = os.Remove(runPath)
		}
	}, nil
}

func validateParentDirectory(path string) error {
	dir := filepath.Dir(path)
	if !filepath.IsAbs(dir) || dir == "/" {
		return ErrInvalidHelper
	}
	// Walk every component and reject symlinked ancestors. Resolving an
	// ancestor through a symlink could redirect the helper into an untrusted
	// tree between validation and linking.
	cur := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(dir, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return ErrInvalidHelper
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			return ErrInvalidHelper
		}
		// macOS exposes the protected temporary hierarchy through /var ->
		// /private/var. This system-owned, non-writable alias is the sole
		// accepted symlink ancestor; all user-controlled symlink ancestors are
		// rejected.
		if fi.Mode()&os.ModeSymlink != 0 {
			if cur != "/var" {
				return ErrInvalidHelper
			}
			target, e := filepath.EvalSymlinks(cur)
			if e != nil || target != "/private/var" {
				return ErrInvalidHelper
			}
			fi, e = os.Stat(cur)
			if e != nil {
				return ErrInvalidHelper
			}
		}
		if !fi.IsDir() {
			return ErrInvalidHelper
		}
	}
	fi, err := os.Lstat(dir)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() || fi.Mode().Perm() != 0700 {
		return ErrInvalidHelper
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uint32(os.Getuid()) {
		return ErrInvalidHelper
	}
	return nil
}

func (c Config) Run(ctx context.Context, req Request) (Result, error) {
	if err := c.validate(); err != nil {
		return Result{}, err
	}
	if req.SessionID == "" || req.DisplayInstance == "" || req.ActionType == "" || req.Title == "" || req.Challenge == "" || req.ProofRef == "" || len(req.PreviewText) == 0 || len(req.PreviewText) > maxText || len(req.ActionType) > maxField || len(req.Title) > maxField || len(req.Destination) == 0 || len(req.Destination) > maxField || len(req.Risk) == 0 || len(req.Risk) > maxField || len(req.ExpiresAt) == 0 || len(req.ExpiresAt) > maxField || !validDigest(req.PreviewDigest) || !validDigest(req.DestinationDigest) {
		return Result{}, ErrProtocol
	}
	verified, err := openVerifiedExecutable(c.Path, c.SHA256)
	if err != nil {
		return Result{}, err
	}
	defer verified.file.Close()
	defer verified.cleanup()
	if verifiedHook != nil {
		verifiedHook()
	}
	if c.Timeout <= 0 || c.Timeout > 5*time.Minute {
		c.Timeout = 90 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	// The private hard link refers to the exact inode that was verified.
	// ExtraFiles also maps the verified descriptor to fd 3 and keeps it alive
	// through exec for auditability; macOS does not permit execve(/dev/fd/N).
	cmd := exec.CommandContext(ctx, verified.path)
	cmd.Args = []string{verified.path}
	cmd.ExtraFiles = []*os.File{verified.file}
	cmd.Dir = "/"
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/var/empty", "LANG=C"}
	in, err := cmd.StdinPipe()
	if err != nil {
		return Result{}, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return Result{}, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return Result{}, err
	}
	defer func() { _ = in.Close(); _ = cmd.Process.Kill() }()
	enc := json.NewEncoder(in)
	if err := enc.Encode(map[string]any{"type": "preview", "session_id": req.SessionID, "display_instance_id": req.DisplayInstance, "action_type": req.ActionType, "title": req.Title, "text": req.PreviewText, "destination": req.Destination, "risk": req.Risk, "expires_at": req.ExpiresAt, "preview_digest": req.PreviewDigest, "destination_digest": req.DestinationDigest}); err != nil {
		return Result{}, ErrProtocol
	}
	r := bufio.NewReaderSize(out, maxLine+1)
	line, err := boundedLine(r)
	if err != nil {
		return Result{}, ErrProtocol
	}
	var rendered struct {
		Type              string `json:"type"`
		SessionID         string `json:"session_id"`
		DisplayInstance   string `json:"display_instance_id"`
		DisplayNonce      string `json:"display_nonce"`
		PreviewDigest     string `json:"preview_digest"`
		DestinationDigest string `json:"destination_digest"`
	}
	if err := json.Unmarshal(line, &rendered); err != nil {
		return Result{}, fmt.Errorf("%w: rendered json: %v", ErrProtocol, err)
	}
	if rendered.Type != "rendered" || rendered.SessionID != req.SessionID || rendered.DisplayInstance != req.DisplayInstance || rendered.DisplayNonce == "" || !validDigest(rendered.PreviewDigest) || rendered.PreviewDigest != req.PreviewDigest || !validDigest(rendered.DestinationDigest) || rendered.DestinationDigest != req.DestinationDigest {
		return Result{}, fmt.Errorf("%w: rendered mismatch", ErrProtocol)
	}
	if err := enc.Encode(map[string]any{"type": "challenge", "session_id": req.SessionID, "challenge": req.Challenge}); err != nil {
		return Result{}, ErrProtocol
	}
	line, err = boundedLine(r)
	if err != nil {
		return Result{}, ErrProtocol
	}
	var result Result
	var envelope struct {
		Type   string `json:"type"`
		Result Result `json:"result"`
	}
	if err := json.Unmarshal(line, &envelope); err != nil {
		return Result{}, fmt.Errorf("%w: decision json: %v", ErrProtocol, err)
	}
	if envelope.Type != "decision" {
		return Result{}, fmt.Errorf("%w: decision type", ErrProtocol)
	}
	result = envelope.Result
	if result.SessionID != req.SessionID || result.DisplayInstance != req.DisplayInstance || result.Challenge != req.Challenge || (result.Decision != "approve" && result.Decision != "reject") || result.Timestamp.IsZero() {
		return Result{}, ErrProtocol
	}
	result.ProofRef = req.ProofRef
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		return Result{}, ErrProtocol
	}
	return result, nil
}

func validDigest(s string) bool {
	if strings.HasPrefix(s, "sha256:") {
		s = strings.TrimPrefix(s, "sha256:")
	}
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func boundedLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		part, err := r.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > maxLine {
			return nil, fmt.Errorf("line too large")
		}
		if err == nil {
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
	}
}
