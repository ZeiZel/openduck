package codexruntime

// This file is the broker-owned production isolation seam.  It is intentionally
// in this package because the lifecycle methods on ProductionRuntimeIsolation
// are sealed from command packages.  The command can therefore only compose a
// validated value; it cannot manufacture a process or capability itself.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"openduck/internal/codexbroker"
	"openduck/internal/macoschannel"
	"openduck/internal/verifiedroot"
)

var ErrProductionIsolationConfig = errors.New("invalid production isolation configuration")

type ProductionIsolationConfig struct {
	Binary         string
	SandboxExec    string
	SandboxProfile string
	Arguments      []string
	CodexHome      string
	PrivateCWD     string
	Model          string
	ProxyAddress   string
	// ProxyGrantExpiresAt is checked by codexruntimewire before this isolation
	// is composed. After that one-time channel-bound consumption, child restart
	// liveness is governed by the broker-renewed egress session registry; the
	// runtime has no renewal endpoint or egress credential.
	ProxyGrantExpiresAt time.Time
	Identity            codexbroker.ExpectedRuntimeIdentity
	// ProxyAddress comes only from a verified broker-runtime ProxyGrant. The
	// runtime never receives an egress capability or egress service key.
	Attestation     codexbroker.BoundaryAttestation
	HomeRoot        *verifiedroot.Root
	CWDRoot         *verifiedroot.Root
	ReleaseRoot     *verifiedroot.Root
	BinaryName      string
	BinaryDigest    string
	ArtifactRelease macoschannel.ReleasePin
	Sandbox         ProductionSandbox
}

// ProductionSandbox is an independently attested OS boundary. HTTPS_PROXY
// alone is never accepted as sandbox proof.
type ProductionSandbox interface {
	Attested() bool
	revalidate() error
	productionSandbox()
}

type darwinSandbox struct {
	pf, seatbelt bool
	verify       func() error
}

func (darwinSandbox) productionSandbox() {}
func (s darwinSandbox) Attested() bool   { return s.pf && s.seatbelt }
func (s darwinSandbox) revalidate() error {
	if !s.Attested() || s.verify == nil {
		return ErrProductionIsolationConfig
	}
	return s.verify()
}

const (
	pfAnchor           = "com.openduck"
	PFEvidenceV1       = "openduck.pf-evidence.v2"
	maxPFEvidenceBytes = 4096
	pfEvidenceFileMode = 0644
)

// PFEvidence is root-produced during activation. The runtime only verifies
// this canonical record; it never opens /dev/pf or shells out to pfctl. Root
// state changes are the trust boundary: root must rewrite this evidence after
// changing PF, and a reboot is rejected by the exact BootID binding.
type PFEvidence struct {
	SchemaVersion string `json:"schema_version"`
	BootID        string `json:"boot_id"`
	Anchor        string `json:"anchor"`
	Enabled       bool   `json:"enabled"`
	PolicyDigest  string `json:"policy_digest"`
	RulesDigest   string `json:"rules_digest"`
	RootUID       uint32 `json:"root_uid"`
	RootGID       uint32 `json:"root_gid"`
	RootMode      uint32 `json:"root_mode"`
	RootDigest    string `json:"root_digest"`
}

func (p PFEvidence) Canonical() ([]byte, error) {
	if p.SchemaVersion != PFEvidenceV1 || p.BootID == "" || strings.ContainsAny(p.BootID, "\r\n\x00") || p.Anchor != pfAnchor || !p.Enabled || len(p.PolicyDigest) != 64 || len(p.RulesDigest) != 64 || p.RootUID != 0 || p.RootGID != 0 || p.RootMode != 0755 || len(p.RootDigest) != 64 {
		return nil, ErrProductionIsolationConfig
	}
	if _, err := hex.DecodeString(p.PolicyDigest); err != nil {
		return nil, ErrProductionIsolationConfig
	}
	if _, err := hex.DecodeString(p.RulesDigest); err != nil {
		return nil, ErrProductionIsolationConfig
	}
	if _, err := hex.DecodeString(p.RootDigest); err != nil {
		return nil, ErrProductionIsolationConfig
	}
	return json.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		BootID        string `json:"boot_id"`
		Anchor        string `json:"anchor"`
		Enabled       bool   `json:"enabled"`
		PolicyDigest  string `json:"policy_digest"`
		RulesDigest   string `json:"rules_digest"`
		RootUID       uint32 `json:"root_uid"`
		RootGID       uint32 `json:"root_gid"`
		RootMode      uint32 `json:"root_mode"`
		RootDigest    string `json:"root_digest"`
	}{p.SchemaVersion, p.BootID, p.Anchor, p.Enabled, p.PolicyDigest, p.RulesDigest, p.RootUID, p.RootGID, p.RootMode, p.RootDigest})
}

// NewDarwinSandbox is the only production sandbox constructor. It verifies
// root-owned policy files and a root-produced canonical PF evidence record.
func NewDarwinSandbox(root *verifiedroot.Root, pfStateFile, seatbeltProfile, expectedPFPolicy, expectedSeatbelt, evidenceFile, evidenceDigest, expectedRulesDigest, bootID string) (ProductionSandbox, error) {
	return newDarwinSandbox(root, pfStateFile, seatbeltProfile, expectedPFPolicy, expectedSeatbelt, evidenceFile, evidenceDigest, expectedRulesDigest, bootID, time.Now().UTC())
}

func newDarwinSandbox(root *verifiedroot.Root, pfStateFile, seatbeltProfile, expectedPFPolicy, expectedSeatbelt, evidenceFile, evidenceDigest, expectedRulesDigest, bootID string, now time.Time) (ProductionSandbox, error) {
	verify := func(at time.Time) error {
		return verifyDarwinSandbox(root, pfStateFile, seatbeltProfile, expectedPFPolicy, expectedSeatbelt, evidenceFile, evidenceDigest, expectedRulesDigest, bootID, at)
	}
	if verify(now) != nil {
		return nil, ErrProductionIsolationConfig
	}
	return darwinSandbox{pf: true, seatbelt: true, verify: func() error { return verify(time.Now().UTC()) }}, nil
}

func verifyDarwinSandbox(root *verifiedroot.Root, pfStateFile, seatbeltProfile, expectedPFPolicy, expectedSeatbelt, evidenceFile, evidenceDigest, expectedRulesDigest, bootID string, now time.Time) error {
	if runtime.GOOS != "darwin" || root == nil || pfStateFile == "" || seatbeltProfile == "" || evidenceFile == "" || bootID == "" || len(expectedPFPolicy) != 64 || len(expectedSeatbelt) != 64 || len(evidenceDigest) != 64 || len(expectedRulesDigest) != 64 || root.Revalidate() != nil {
		return ErrProductionIsolationConfig
	}
	pf, err := digestRootFile(root, pfStateFile)
	if err != nil || pf != expectedPFPolicy {
		return ErrProductionIsolationConfig
	}
	seat, err := digestRootFile(root, seatbeltProfile)
	if err != nil || seat != expectedSeatbelt {
		return ErrProductionIsolationConfig
	}
	return verifyPFEvidence(root, evidenceFile, evidenceDigest, expectedPFPolicy, expectedRulesDigest, bootID, now)
}

// RevalidateProductionSandbox verifies fresh root-produced PF evidence at the
// session boundary. Command packages cannot manufacture this sealed check.
func RevalidateProductionSandbox(s ProductionSandbox) error {
	if s == nil {
		return ErrProductionIsolationConfig
	}
	return s.revalidate()
}

func digestBytes(v []byte) string { sum := sha256.Sum256(v); return hex.EncodeToString(sum[:]) }

func verifyPFEvidence(root *verifiedroot.Root, name, expectedDigest, expectedPolicy, expectedRules, bootID string, now time.Time) error {
	if root == nil || filepath.Base(name) != name || len(expectedDigest) != 64 || len(expectedPolicy) != 64 || len(expectedRules) != 64 || bootID == "" {
		return ErrProductionIsolationConfig
	}
	info, err := root.Handle().Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm() != pfEvidenceFileMode {
		return ErrProductionIsolationConfig
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || st.Gid != 0 {
		return ErrProductionIsolationConfig
	}
	f, err := root.Handle().Open(name)
	if err != nil {
		return ErrProductionIsolationConfig
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxPFEvidenceBytes+1))
	if err != nil || len(b) == 0 || len(b) > maxPFEvidenceBytes || digestBytes(b) != expectedDigest {
		return ErrProductionIsolationConfig
	}
	var evidence PFEvidence
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if dec.Decode(&evidence) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return ErrProductionIsolationConfig
	}
	rootInfo, rootErr := root.Handle().Lstat(".")
	canonical, err := evidence.Canonical()
	if err != nil || rootErr != nil || evidence.RootDigest != rootMetadataDigest(rootInfo) || string(canonical) != string(b) || validatePFEvidence(evidence, expectedPolicy, expectedRules, bootID, now) != nil {
		return ErrProductionIsolationConfig
	}
	return nil
}

func rootMetadataDigest(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return ""
	}
	return digestBytes([]byte(fmt.Sprintf("pf-root-v1|%d|%d|%d|%d|%o", st.Dev, st.Ino, st.Uid, st.Gid, info.Mode().Perm())))
}

func validatePFEvidence(evidence PFEvidence, expectedPolicy, expectedRules, bootID string, _ time.Time) error {
	if _, err := evidence.Canonical(); err != nil || evidence.BootID != bootID || evidence.PolicyDigest != expectedPolicy || evidence.RulesDigest != expectedRules {
		return ErrProductionIsolationConfig
	}
	return nil
}

func digestRootFile(root *verifiedroot.Root, name string) (string, error) {
	if root == nil || name == "" || filepath.Base(name) != name {
		return "", ErrProductionIsolationConfig
	}
	f, err := root.Handle().Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c ProductionIsolationConfig) Validate() error {
	if !absoluteClean(c.Binary) || !absoluteClean(c.SandboxExec) || !absoluteClean(c.SandboxProfile) || !absoluteClean(c.CodexHome) || !absoluteClean(c.PrivateCWD) || c.Model == "" || !validRuntimeProxy(c.ProxyAddress) || c.ProxyGrantExpiresAt.IsZero() || c.Identity.Validate() != nil || c.Attestation.Validate() != nil || c.Attestation.RuntimeID != c.Identity.RuntimeID || c.Attestation.RuntimeBinaryDigest != c.Identity.RuntimeBinaryDigest || c.Attestation.PolicyDigest != c.Identity.PolicyDigest || c.Attestation.BrokerReleaseDigest != c.Identity.BrokerReleaseDigest || c.Attestation.BrokerSocketDigest != c.Identity.BrokerSocketDigest || c.Attestation.ExpectedEgressUID != c.Identity.ExpectedEgressUID || c.Attestation.ExpectedEgressGID != c.Identity.ExpectedEgressGID || c.Attestation.ExpectedEgressReleaseDigest != c.Identity.ExpectedEgressReleaseDigest || c.Attestation.ExpectedEgressSocketDigest != c.Identity.ExpectedEgressSocketDigest || c.Attestation.Epoch != c.Identity.KeyEpoch || c.HomeRoot == nil || c.CWDRoot == nil || c.ReleaseRoot == nil || c.BinaryName == "" || c.BinaryDigest != trimDigest(c.Identity.RuntimeBinaryDigest) || c.Sandbox == nil || !c.Sandbox.Attested() || RevalidateProductionSandbox(c.Sandbox) != nil {
		return ErrProductionIsolationConfig
	}
	if c.Binary != filepath.Join(c.ReleaseRoot.Path(), c.BinaryName) {
		return ErrProductionIsolationConfig
	}
	if err := c.HomeRoot.Revalidate(); err != nil {
		return ErrProductionIsolationConfig
	}
	if err := c.CWDRoot.Revalidate(); err != nil {
		return ErrProductionIsolationConfig
	}
	if err := c.ReleaseRoot.Revalidate(); err != nil {
		return ErrProductionIsolationConfig
	}
	if err := macoschannel.VerifyReleaseOwned(c.ReleaseRoot.Handle(), c.ArtifactRelease, c.BinaryName, 0, 0, 0644, 0755, 0755); err != nil {
		return ErrProductionIsolationConfig
	}
	for _, a := range c.Arguments {
		if strings.ContainsAny(a, "\x00\r\n") {
			return ErrProductionIsolationConfig
		}
	}
	return nil
}

func trimDigest(s string) string {
	if len(s) == len("sha256:")+64 && strings.HasPrefix(s, "sha256:") {
		return s[len("sha256:"):]
	}
	return ""
}

func absoluteClean(s string) bool {
	return s != "" && filepath.IsAbs(s) && filepath.Clean(s) == s && s != string(filepath.Separator)
}

func validRuntimeProxy(v string) bool {
	if strings.ContainsAny(v, "\r\n") {
		return false
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "http" || u.Host != "127.0.0.1:8790" || u.User == nil || u.User.Username() != "openduck" {
		return false
	}
	token, ok := u.User.Password()
	if !ok || len(token) != 64 {
		return false
	}
	_, err = hex.DecodeString(token)
	return err == nil
}

type productionIsolation struct{ cfg ProductionIsolationConfig }

func NewProductionRuntimeIsolation(cfg ProductionIsolationConfig) (ProductionRuntimeIsolation, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &productionIsolation{cfg: cfg}, nil
}

// ComposeProductionServer wires the already-authenticated broker channel to
// the broker-owned backend. It performs all backend attestation and egress
// capability checks before codexbroker creates a serving object; callers must
// still obtain conn from macoschannel after the OS release/channel proofs.
func ComposeProductionServer(conn macoschannel.Conn, identity codexbroker.ExpectedRuntimeIdentity, isolation ProductionRuntimeIsolation, model string) (*codexbroker.ProductionServer, error) {
	backend, err := NewProductionBackend(identity, isolation, model)
	if err != nil {
		return nil, err
	}
	return codexbroker.NewProductionServer(conn, backend, identity)
}

func (p *productionIsolation) proxyAddress(context.Context) (string, error) {
	if p == nil || p.cfg.Validate() != nil {
		return "", ErrProductionIsolationConfig
	}
	return p.cfg.ProxyAddress, nil
}

func (p *productionIsolation) attestation(context.Context) (codexbroker.BoundaryAttestation, error) {
	if p == nil || p.cfg.Validate() != nil {
		return codexbroker.BoundaryAttestation{}, ErrProductionIsolationConfig
	}
	return p.cfg.Attestation, nil
}

func (p *productionIsolation) start(ctx context.Context) (ProductionRuntimeProcess, error) {
	if p == nil || p.cfg.Validate() != nil || ctx == nil {
		return nil, ErrProductionIsolationConfig
	}
	if err := macoschannel.VerifyReleaseOwned(p.cfg.ReleaseRoot.Handle(), p.cfg.ArtifactRelease, p.cfg.BinaryName, 0, 0, 0644, 0755, 0755); err != nil {
		return nil, ErrProductionIsolationConfig
	}
	if err := verifyPinnedBinary(p.cfg.ReleaseRoot, p.cfg.BinaryName, p.cfg.BinaryDigest); err != nil {
		return nil, ErrProductionIsolationConfig
	}
	args := append([]string{"-f", p.cfg.SandboxProfile, p.cfg.Binary}, p.cfg.Arguments...)
	cmd := exec.CommandContext(ctx, p.cfg.SandboxExec, args...)
	cmd.Dir = p.cfg.PrivateCWD
	cmd.Env = []string{"HOME=" + p.cfg.CodexHome, "CODEX_HOME=" + p.cfg.CodexHome, "HTTPS_PROXY=" + p.cfg.ProxyAddress, "NO_PROXY=localhost,127.0.0.1"}
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		_ = in.Close()
		return nil, err
	}
	// This is deliberately after command construction and both pipe setup: it
	// is the final instruction before cmd.Start. The grant itself was consumed
	// at channel admission; this fresh PF check prevents a post-admission root
	// policy change from authorizing another child.
	if RevalidateProductionSandbox(p.cfg.Sandbox) != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, ErrProductionIsolationConfig
	}
	if err := cmd.Start(); err != nil {
		_ = in.Close()
		_ = out.Close()
		return nil, err
	}
	return &productionProcess{cmd: cmd, in: in, out: out}, nil
}

func verifyPinnedBinary(root *verifiedroot.Root, name, want string) error {
	if root == nil || name == "" || len(want) != 64 {
		return ErrProductionIsolationConfig
	}
	if _, err := hex.DecodeString(want); err != nil {
		return ErrProductionIsolationConfig
	}
	if err := root.Revalidate(); err != nil {
		return err
	}
	f, err := root.Handle().Open(name)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrProductionIsolationConfig
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return ErrProductionIsolationConfig
	}
	return nil
}

type productionProcess struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  io.ReadCloser
	once sync.Once
}

func (p *productionProcess) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *productionProcess) Write(b []byte) (int, error) { return p.in.Write(b) }
func (p *productionProcess) Close() error {
	if p == nil {
		return nil
	}
	var err error
	p.once.Do(func() { err = errors.Join(p.in.Close(), p.out.Close()) })
	return err
}
func (p *productionProcess) terminate() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}
func (p *productionProcess) wait() error {
	if p == nil || p.cmd == nil {
		return nil
	}
	return p.cmd.Wait()
}
