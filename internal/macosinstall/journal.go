package macosinstall

// The provisioning journal is intentionally separate from callback JSONL.
// It is always a descriptor-rooted, locally durable hash chain. Protection is
// promoted explicitly only after the separately authenticated authorities run.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"openduck/internal/macoschannel"
	"openduck/internal/platformanchor"
	"openduck/internal/platformcheckpoint"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// installedJournalKeySource is intentionally rooted at the install descriptor
// passed by Installer.  It is not exported: callers cannot select a key path
// or obtain the raw key bytes.
type installedJournalKeySource struct {
	root *os.Root
	path string
	uid  uint32
	gid  uint32
}

func (s installedJournalKeySource) LoadContext(_ context.Context, channel string) ([]byte, uint64, error) {
	if s.root == nil || channel != platformcheckpoint.JournalAudience {
		return nil, 0, macoschannel.ErrUnavailable
	}
	before, err := s.root.Lstat(s.path)
	if err != nil || !safeExistingRegular(before, 0600, 116) || !ownedBy(before, s.uid, s.gid) {
		return nil, 0, macoschannel.ErrUnavailable
	}
	f, err := s.root.Open(s.path)
	if err != nil {
		return nil, 0, macoschannel.ErrUnavailable
	}
	after, statErr := f.Stat()
	b, readErr := io.ReadAll(io.LimitReader(f, 117))
	closeErr := f.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !sameFileIdentity(before, after) || !safeExistingRegular(after, 0600, 116) || !ownedBy(after, s.uid, s.gid) || !validCanonicalServiceKey(b, channel, 1) {
		for n := range b {
			b[n] = 0
		}
		return nil, 0, macoschannel.ErrUnavailable
	}
	key := append([]byte(nil), b[84:116]...)
	for n := range b {
		b[n] = 0
	}
	return key, 1, nil
}

// bindInstalledProductionJournal is the sealed composition point.  It runs
// only after Configure installed the immutable descriptors and both authority
// daemons are live.  Every path is fixed relative to the Installer root; no
// socket, role, UID/GID, release or key input is accepted from a caller.
func (i *Installer) bindInstalledProductionJournal(ctx context.Context) error {
	if i == nil || i.root == nil || i.fake {
		return errors.New("protected journal authority unavailable")
	}
	checkpointUID, checkpointGID, err := i.ops.PrincipalIDs(ctx, "_openduck_checkpoint", "_openduck_checkpoint")
	if err != nil {
		return errors.New("protected journal principal unavailable")
	}
	anchorUID, anchorGID, err := i.ops.PrincipalIDs(ctx, "_openduck_anchor", "_openduck_anchor")
	if err != nil {
		return errors.New("protected journal principal unavailable")
	}
	_, checkpointChannelGID, err := i.ops.PrincipalIDs(ctx, "_openduck_checkpoint", "_openduck_installer_checkpoint_channel")
	if err != nil {
		return errors.New("protected journal channel unavailable")
	}
	_, anchorChannelGID, err := i.ops.PrincipalIDs(ctx, "_openduck_anchor", "_openduck_installer_anchor_channel")
	if err != nil {
		return errors.New("protected journal channel unavailable")
	}
	if checkpointUID == 0 || anchorUID == 0 || checkpointUID == anchorUID || checkpointChannelGID == checkpointGID || anchorChannelGID == anchorGID || checkpointChannelGID == anchorChannelGID {
		return errors.New("protected journal principals invalid")
	}
	if err := i.verifyJournalTopology(); err != nil {
		return errors.New("protected journal topology unavailable")
	}
	// Installer is root, but the two channels have independent groups and keys.
	installerUID, installerGID := uint32(0), uint32(0)
	checkpointPin, err := i.installedJournalPin("checkpoint-installer")
	if err != nil {
		return err
	}
	anchorPin, err := i.installedJournalPin("anchor-installer")
	if err != nil {
		return err
	}
	checkpointInstallerPin, err := i.installedJournalPin("installer-checkpoint")
	if err != nil {
		return err
	}
	anchorInstallerPin, err := i.installedJournalPin("installer-anchor")
	if err != nil {
		return err
	}
	checkpoint, err := i.newInstalledCheckpointJournalClient(installerUID, installerGID, uint32(checkpointUID), uint32(checkpointGID), uint32(checkpointChannelGID), checkpointInstallerPin, checkpointPin)
	if err != nil {
		return err
	}
	anchor, err := i.newInstalledAnchorJournalClient(installerUID, installerGID, uint32(anchorUID), uint32(anchorGID), uint32(anchorChannelGID), anchorInstallerPin, anchorPin)
	if err != nil {
		return err
	}
	binding, err := NewProductionJournalBinding(checkpoint, anchor)
	if err != nil {
		return err
	}
	return i.BindProductionJournal(binding)
}

func (i *Installer) installedJournalPin(service string) (macoschannel.ReleasePin, error) {
	if service != "checkpoint-installer" && service != "anchor-installer" && service != "installer-checkpoint" && service != "installer-anchor" {
		return macoschannel.ReleasePin{}, errors.New("protected journal release unavailable")
	}
	b, err := i.root.ReadFile("releases/" + service + "/" + i.cfg.ReleaseID + "/manifest.json")
	if err != nil {
		return macoschannel.ReleasePin{}, errors.New("protected journal release unavailable")
	}
	var m struct {
		ReleaseID    string `json:"release_id"`
		BinaryDigest string `json:"binary_digest"`
		SocketDigest string `json:"socket_digest"`
		Binary       string `json:"binary"`
	}
	if json.Unmarshal(b, &m) != nil || m.ReleaseID != i.cfg.ReleaseID || !isDigest(m.BinaryDigest) || !isDigest(m.SocketDigest) || m.Binary == "" {
		return macoschannel.ReleasePin{}, errors.New("protected journal release unavailable")
	}
	return macoschannel.ReleasePin{ReleaseID: m.ReleaseID, BinaryDigest: m.BinaryDigest, SocketDigest: m.SocketDigest, ManifestDigest: Digest(b)}, nil
}

func (i *Installer) newInstalledCheckpointJournalClient(localUID, localGID, peerUID, peerGID, channelGID uint32, local, peer macoschannel.ReleasePin) (*platformcheckpoint.ProductionJournalClient, error) {
	d, err := i.installedJournalDialer("checkpoint", localUID, localGID, peerUID, peerGID, channelGID, local, peer)
	if err != nil {
		return nil, err
	}
	policy := platformcheckpoint.JournalPolicy{Audience: platformcheckpoint.JournalAudience, Policy: platformcheckpoint.Policy{Channel: platformcheckpoint.JournalAudience, LocalRole: "installer", PeerRole: "checkpoint", LocalUID: localUID, LocalGID: localGID, PeerUID: peerUID, PeerGID: peerGID, KeyEpoch: 1, LocalRelease: local, PeerRelease: peer}}
	client, err := platformcheckpoint.NewProductionJournalClient(d, policy)
	if err != nil {
		return nil, errors.New("protected journal authority unavailable")
	}
	return client, nil
}

func (i *Installer) newInstalledAnchorJournalClient(localUID, localGID, peerUID, peerGID, channelGID uint32, local, peer macoschannel.ReleasePin) (*platformanchor.JournalProductionClient, error) {
	d, err := i.installedJournalDialer("anchor", localUID, localGID, peerUID, peerGID, channelGID, local, peer)
	if err != nil {
		return nil, err
	}
	policy := platformanchor.JournalPolicy{Audience: platformanchor.JournalAudience, ProductionPolicy: platformanchor.ProductionPolicy{Channel: platformanchor.JournalAudience, LocalRole: "installer", PeerRole: "anchor", LocalRelease: local, PeerRelease: peer, ExpectedLocalUID: &localUID, ExpectedLocalGID: &localGID, ExpectedPeerUID: &peerUID, ExpectedPeerGID: &peerGID, ExpectedKeyEpoch: 1}}
	client, err := platformanchor.NewProductionJournalClient(d, policy)
	if err != nil {
		return nil, errors.New("protected journal authority unavailable")
	}
	return client, nil
}

func (i *Installer) installedJournalDialer(peer string, localUID, localGID, peerUID, peerGID, channelGID uint32, local, remote macoschannel.ReleasePin) (*macoschannel.Dialer, error) {
	if peer != "checkpoint" && peer != "anchor" || localUID != 0 || localGID != 0 || peerUID == 0 || channelGID == 0 {
		return nil, errors.New("protected journal topology invalid")
	}
	socketRoot, err := i.root.OpenRoot("channels/installer-" + peer)
	if err != nil {
		return nil, errors.New("protected journal socket unavailable")
	}
	releaseRoot, err := i.root.OpenRoot("releases/installer-" + peer + "/" + i.cfg.ReleaseID)
	if err != nil {
		_ = socketRoot.Close()
		return nil, errors.New("protected journal release unavailable")
	}
	keyPath := "keys/installer-" + peer + "/journal.key"
	keyRoot, err := i.root.OpenRoot("keys/installer-" + peer)
	if err != nil {
		_ = socketRoot.Close()
		_ = releaseRoot.Close()
		return nil, errors.New("protected journal key unavailable")
	}
	if err = keyRoot.Close(); err != nil {
		_ = socketRoot.Close()
		_ = releaseRoot.Close()
		return nil, errors.New("protected journal key unavailable")
	}
	cfg := macoschannel.Config{Contract: macoschannel.SocketContract{Channel: platformcheckpoint.JournalAudience, LocalRole: "installer", PeerRole: peer, SocketRoot: SystemRoot + "/channels/installer-" + peer, SocketPath: "journal.sock", ExpectedPeerUID: &peerUID, ExpectedPeerGID: &peerGID, ExpectedSocketRootUID: peerUID, ExpectedSocketRootGID: channelGID, ExpectedSocketRootMode: 0750, ExpectedSocketUID: peerUID, ExpectedSocketGID: channelGID, ExpectedSocketMode: 0660}, LocalRelease: local, PeerRelease: remote, ReleaseRoot: releaseRoot, SocketRootFD: socketRoot, BinaryName: "openduck-installer", KeySource: installedJournalKeySource{root: i.root, path: keyPath, uid: 0, gid: 0}, ExpectedReleaseRootUID: 0, ExpectedReleaseRootGID: 0, ExpectedReleaseRootMode: 0550, ExpectedManifestMode: 0440, ExpectedBinaryMode: 0550}
	d, err := macoschannel.NewDialer(cfg)
	if err != nil {
		_ = socketRoot.Close()
		_ = releaseRoot.Close()
		_ = keyRoot.Close()
		return nil, errors.New("protected journal topology unavailable")
	}
	return d, nil
}

const deploymentLockPath = "/private/var/run/openduck-installer.lock"

type DeploymentLock struct{ f *os.File }

func AcquireDeploymentLock() (*DeploymentLock, error) {
	return acquireDeploymentLock(deploymentLockPath)
}
func acquireDeploymentLock(path string) (*DeploymentLock, error) {
	if filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("unsafe deployment lock path")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("deployment lock held")
	}
	return &DeploymentLock{f: f}, nil
}
func (l *DeploymentLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return errors.Join(syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN), l.f.Close())
}

type JournalEntry struct {
	RunID         string `json:"run_id"`
	ReleaseDigest string `json:"release_digest"`
	Phase         string `json:"phase"`
	Event         string `json:"event"`
	PreviousHash  string `json:"previous_hash"`
	Hash          string `json:"hash"`
	Sequence      uint64 `json:"sequence"`
}
type JournalCheckpoint struct {
	RunID          string `json:"run_id"`
	ReleaseDigest  string `json:"release_digest"`
	Phase          string `json:"phase"`
	Nonce          string `json:"nonce"`
	PayloadDigest  string `json:"payload_digest"`
	LastHash       string `json:"last_hash"`
	PreviousDigest string `json:"previous_digest"`
	Signature      string `json:"signature"`
	Sequence       uint64 `json:"sequence"`
	AnchorSequence uint64 `json:"anchor_sequence"`
}

// ProductionJournalBinding can only be constructed from the concrete typed,
// authenticated platform clients. It exposes no socket or key capability.
type ProductionJournalBinding struct{ authority *productionJournalAuthority }

func NewProductionJournalBinding(checkpoint *platformcheckpoint.ProductionJournalClient, anchor *platformanchor.JournalProductionClient) (ProductionJournalBinding, error) {
	if checkpoint == nil || anchor == nil || !checkpoint.Valid() || !anchor.Valid() {
		return ProductionJournalBinding{}, errors.New("protected journal authority unavailable")
	}
	return ProductionJournalBinding{authority: &productionJournalAuthority{checkpoint: checkpoint, anchor: anchor}}, nil
}
func (b ProductionJournalBinding) valid() bool { return b.authority != nil && b.authority.valid() }

// journalAuthority is private: only tests in this package may substitute a
// deterministic fake. Production receives only ProductionJournalBinding.
type journalAuthority interface {
	valid() bool
	sign(context.Context, string, string, string, string, string, uint64) (string, error)
	verify(context.Context, string, string, string, string, string, string, uint64) error
	load(context.Context, string, string, string, string) (uint64, string, error)
	cas(context.Context, string, string, string, string, uint64, uint64, string, string) error
}
type productionJournalAuthority struct {
	checkpoint *platformcheckpoint.ProductionJournalClient
	anchor     *platformanchor.JournalProductionClient
}

func (a *productionJournalAuthority) valid() bool {
	return a != nil && a.checkpoint != nil && a.anchor != nil && a.checkpoint.Valid() && a.anchor.Valid()
}
func (a *productionJournalAuthority) sign(c context.Context, id, run, release, nonce, digest string, seq uint64) (string, error) {
	if !a.valid() {
		return "", errors.New("protected journal authority unavailable")
	}
	return a.checkpoint.Sign(c, id, run, journalAuthorityRelease(release), nonce, digest, seq)
}
func (a *productionJournalAuthority) verify(c context.Context, id, run, release, nonce, digest, sig string, seq uint64) error {
	if !a.valid() {
		return errors.New("protected journal authority unavailable")
	}
	return a.checkpoint.Verify(c, id, run, journalAuthorityRelease(release), nonce, digest, sig, seq)
}
func (a *productionJournalAuthority) load(c context.Context, id, run, release, nonce string) (uint64, string, error) {
	if !a.valid() {
		return 0, "", errors.New("protected journal authority unavailable")
	}
	return a.anchor.Load(c, id, run, journalAuthorityRelease(release), nonce)
}
func (a *productionJournalAuthority) cas(c context.Context, id, run, release, nonce string, old, next uint64, oldD, newD string) error {
	if !a.valid() {
		return errors.New("protected journal authority unavailable")
	}
	return a.anchor.CAS(c, id, run, journalAuthorityRelease(release), nonce, old, next, oldD, newD)
}
func journalAuthorityRelease(release string) string {
	if strings.HasPrefix(release, "sha256:") {
		return release
	}
	return "sha256:" + release
}

type ProvisioningJournal struct {
	root                     *os.Root
	runID, releaseDigest     string
	authority                journalAuthority
	sequence, anchorSequence uint64
	lastHash, lastCheckpoint string
	lastPhase, lastEvent     string
	protected                bool
	required                 bool
	hashes                   map[uint64]string
	fault                    func(string) error // package-test crash seam
}

// OpenProvisioningJournal permits a crash-detecting local bootstrap chain.
// Existing protected state never opens without a valid authority binding.
func OpenProvisioningJournal(root *os.Root, runID, releaseDigest string, authority journalAuthority) (*ProvisioningJournal, error) {
	if root == nil || validateRunID(runID) != nil || !isDigest(releaseDigest) {
		return nil, errors.New("invalid provisioning journal")
	}
	j := &ProvisioningJournal{root: root, runID: runID, releaseDigest: releaseDigest, authority: authority, hashes: map[uint64]string{}}
	if err := j.ensureTree(); err != nil {
		return nil, err
	}
	if err := j.loadAndVerify(); err != nil {
		return nil, err
	}
	return j, nil
}
func (j *ProvisioningJournal) dir() string { return "state/controller/provisioning/" + j.runID }
func (j *ProvisioningJournal) ensureTree() error {
	for _, x := range []struct {
		p string
		m os.FileMode
	}{{"state", 0711}, {"state/controller", 0700}, {"state/controller/provisioning", 0700}, {j.dir(), 0700}} {
		st, err := j.root.Lstat(x.p)
		if errors.Is(err, os.ErrNotExist) {
			created := false
			if err = j.root.Mkdir(x.p, x.m); err == nil {
				created = true
			} else if !errors.Is(err, os.ErrExist) {
				return err
			}
			// Mkdir is constrained by the caller's umask.  Journal metadata has
			// exact modes, so normalize a directory we just created through its
			// already-open root descriptor before trusting it.
			if created {
				if chmodErr := j.root.Chmod(x.p, x.m); chmodErr != nil {
					return chmodErr
				}
			}
			st, err = j.root.Lstat(x.p)
		}
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || st.Mode().Perm() != x.m.Perm() || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("unsafe provisioning journal tree")
		}
	}
	return nil
}
func (j *ProvisioningJournal) loadAndVerify() error {
	p := j.dir() + "/journal.jsonl"
	st, err := j.root.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return j.noCheckpoint()
	}
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1<<20 {
		return errors.New("unsafe provisioning journal")
	}
	b, err := j.root.ReadFile(p)
	if err != nil {
		return err
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		return errors.New("provisioning journal is not closed")
	}
	previous := ""
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e JournalEntry
		if json.Unmarshal([]byte(line), &e) != nil {
			return errors.New("provisioning journal chain invalid")
		}
		canonical, e2 := json.Marshal(e)
		if e2 != nil || string(canonical) != line || e.RunID != j.runID || e.ReleaseDigest != j.releaseDigest || e.Sequence != j.sequence+1 || e.PreviousHash != previous || e.Hash != journalEntryHash(e) || !validJournalField(e.Phase) || !validJournalField(e.Event) {
			return errors.New("provisioning journal chain invalid")
		}
		j.sequence, previous = e.Sequence, e.Hash
		j.lastPhase, j.lastEvent = e.Phase, e.Event
		j.hashes[e.Sequence] = e.Hash
	}
	j.lastHash = previous
	return j.loadCheckpoint()
}
func (j *ProvisioningJournal) noCheckpoint() error {
	for _, name := range []string{"checkpoint.json", ".checkpoint.pending"} {
		if _, err := j.root.Lstat(j.dir() + "/" + name); err == nil {
			return errors.New("provisioning checkpoint unavailable")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func (j *ProvisioningJournal) loadCheckpoint() error {
	checkpoint, err := j.readCheckpointFile("checkpoint.json")
	if err != nil {
		return err
	}
	pending, err := j.readCheckpointFile(".checkpoint.pending")
	if err != nil {
		return err
	}
	if checkpoint != nil {
		if j.authority == nil || !j.authority.valid() || checkpoint.Sequence > j.sequence || j.hashes[checkpoint.Sequence] != checkpoint.LastHash || verifyCheckpointSignature(context.Background(), j.authority, *checkpoint) != nil {
			return errors.New("provisioning checkpoint invalid")
		}
		j.anchorSequence, j.lastCheckpoint = checkpoint.AnchorSequence, checkpointDigest(*checkpoint)
	}
	if pending != nil {
		if j.authority == nil || !j.authority.valid() || pending.Sequence != j.sequence || pending.LastHash != j.lastHash || pending.Phase != j.lastPhase || pending.PreviousDigest != j.lastCheckpoint || verifyCheckpointSignature(context.Background(), j.authority, *pending) != nil {
			return errors.New("provisioning pending checkpoint invalid")
		}
		if err := j.syncExistingPending(); err != nil {
			return err
		}
		if err := j.completePending(*pending); err != nil {
			return err
		}
		j.protected, j.required = true, true
		return nil
	}
	if checkpoint != nil && verifyCheckpoint(context.Background(), j.authority, *checkpoint) != nil {
		return errors.New("provisioning checkpoint invalid")
	}
	if checkpoint == nil {
		if j.sequence > 0 && j.lastPhase == "protection" && j.lastEvent == "seal" && j.authority != nil && j.authority.valid() {
			j.required = true
			if err := j.seal("protection"); err != nil {
				return err
			}
			j.protected = true
		}
		return nil
	}
	if checkpoint.Sequence == j.sequence {
		j.protected, j.required = true, true
		return nil
	}
	// Resume the exact durable tail, not a newly appended event.
	if err := j.seal(j.lastPhase); err != nil {
		return err
	}
	j.protected, j.required = true, true
	return nil
}
func (j *ProvisioningJournal) readCheckpointFile(name string) (*JournalCheckpoint, error) {
	p := j.dir() + "/" + name
	st, err := j.root.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1<<16 {
		return nil, errors.New("unsafe provisioning checkpoint")
	}
	b, err := j.root.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c JournalCheckpoint
	if json.Unmarshal(b, &c) != nil {
		return nil, errors.New("provisioning checkpoint invalid")
	}
	canonical, e := json.Marshal(c)
	if e != nil || string(canonical) != string(b) || !validCheckpoint(c) || c.RunID != j.runID || c.ReleaseDigest != j.releaseDigest {
		return nil, errors.New("provisioning checkpoint invalid")
	}
	return &c, nil
}
func validJournalField(v string) bool {
	if len(v) < 1 || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func validJournalID(v string) bool {
	if len(v) < 8 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
func validHex(v string) bool { _, e := hex.DecodeString(v); return e == nil }
func validCheckpoint(c JournalCheckpoint) bool {
	return validateRunID(c.RunID) == nil && isDigest(c.ReleaseDigest) && validJournalField(c.Phase) && validJournalID(c.Nonce) && validAuthorityDigest(c.PayloadDigest) && c.Sequence > 0 && c.AnchorSequence > 0 && len(c.LastHash) == 64 && validHex(c.LastHash) && (c.PreviousDigest == "" || validAuthorityDigest(c.PreviousDigest)) && len(c.Signature) == 64 && validHex(c.Signature)
}
func validAuthorityDigest(v string) bool {
	return strings.HasPrefix(v, "sha256:") && len(v) == len("sha256:")+64 && validHex(v[len("sha256:"):])
}

// Transition always appends and fsyncs a closed local JSONL entry. Once
// protected, any checkpoint outage is a hard error rather than a downgrade.
func (j *ProvisioningJournal) Transition(phase, event string) error {
	if j == nil || !validJournalField(phase) || !validJournalField(event) {
		return errors.New("invalid provisioning journal transition")
	}
	e := JournalEntry{RunID: j.runID, ReleaseDigest: j.releaseDigest, Phase: phase, Event: event, Sequence: j.sequence + 1, PreviousHash: j.lastHash}
	e.Hash = journalEntryHash(e)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	f, err := j.root.OpenFile(j.dir()+"/journal.jsonl", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = j.syncDir(); err != nil {
		return err
	}
	j.sequence, j.lastHash = e.Sequence, e.Hash
	j.lastPhase, j.lastEvent = e.Phase, e.Event
	j.hashes[e.Sequence] = e.Hash
	if err = j.inject("append-to-sign"); err != nil {
		return err
	}
	if !j.protected && !j.required {
		return nil
	}
	if err = j.seal(phase); err != nil {
		return fmt.Errorf("journal checkpoint uncertain: %w", err)
	}
	j.protected = true
	return nil
}

// Promote seals the complete historical chain after the authorities are live.
func (j *ProvisioningJournal) Promote() error {
	if j == nil || j.authority == nil || !j.authority.valid() {
		return errors.New("protected journal authority unavailable")
	}
	if j.protected {
		return nil
	}
	j.required = true
	if err := j.Transition("protection", "seal"); err != nil {
		return err
	}
	j.protected = true
	return nil
}
func (j *ProvisioningJournal) Protected() bool { return j != nil && j.protected }
func (j *ProvisioningJournal) seal(phase string) error {
	if j.authority == nil || !j.authority.valid() || j.sequence == 0 {
		return errors.New("protected journal authority unavailable")
	}
	c := JournalCheckpoint{RunID: j.runID, ReleaseDigest: j.releaseDigest, Phase: phase, Nonce: journalToken("nonce", j.runID, j.releaseDigest, fmt.Sprint(j.sequence), j.lastHash, j.lastCheckpoint), LastHash: j.lastHash, PreviousDigest: j.lastCheckpoint, Sequence: j.sequence, AnchorSequence: j.anchorSequence + 1}
	c.PayloadDigest = digestCheckpointPayload(c)
	signID := journalToken("checkpoint-sign", c.RunID, c.ReleaseDigest, c.Nonce, c.PayloadDigest, fmt.Sprint(c.Sequence))
	sig, err := j.authority.sign(context.Background(), signID, c.RunID, c.ReleaseDigest, c.Nonce, c.PayloadDigest, c.Sequence)
	if err != nil {
		return err
	}
	if len(sig) != 64 || !validHex(sig) {
		return errors.New("invalid journal signature")
	}
	c.Signature = sig
	if err = j.persistPending(c); err != nil {
		return err
	}
	return j.completePending(c)
}
func (j *ProvisioningJournal) persistPending(c JournalCheckpoint) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := j.dir() + "/.checkpoint.pending"
	if existing, e := j.root.ReadFile(tmp); e == nil {
		if string(existing) == string(b) {
			return j.syncExistingPending()
		}
		return errors.New("conflicting provisioning pending checkpoint")
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	f, err := j.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = j.inject("sign-to-pending-fsync")
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return j.syncDir()
}
func (j *ProvisioningJournal) syncExistingPending() error {
	f, err := j.root.Open(j.dir() + "/.checkpoint.pending")
	if err != nil {
		return err
	}
	err = f.Sync()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return j.syncDir()
}
func (j *ProvisioningJournal) completePending(c JournalCheckpoint) error {
	want := checkpointDigest(c)
	loadID := journalToken("anchor-load", c.RunID, c.ReleaseDigest, c.Nonce, fmt.Sprint(j.anchorSequence), j.lastCheckpoint)
	gotSeq, gotDigest, err := j.authority.load(context.Background(), loadID, c.RunID, c.ReleaseDigest, c.Nonce)
	if err != nil {
		return err
	}
	if gotSeq == j.anchorSequence && gotDigest == j.lastCheckpoint {
		if err = j.inject("pending-to-cas"); err != nil {
			return err
		}
		casID := journalToken("anchor-cas", c.RunID, c.ReleaseDigest, c.Nonce, fmt.Sprint(j.anchorSequence), j.lastCheckpoint, want)
		if err = j.authority.cas(context.Background(), casID, c.RunID, c.ReleaseDigest, c.Nonce, j.anchorSequence, c.AnchorSequence, j.lastCheckpoint, want); err != nil {
			return err
		}
	} else if gotSeq != c.AnchorSequence || gotDigest != want {
		return errors.New("journal checkpoint anchor mismatch")
	}
	if err = j.inject("cas-to-rename"); err != nil {
		return err
	}
	if err = j.root.Rename(j.dir()+"/.checkpoint.pending", j.dir()+"/checkpoint.json"); err != nil {
		return err
	}
	if err = j.inject("rename-to-dir-fsync"); err != nil {
		return err
	}
	if err = j.syncDir(); err != nil {
		return err
	}
	j.anchorSequence, j.lastCheckpoint = c.AnchorSequence, checkpointDigest(c)
	return nil
}
func (j *ProvisioningJournal) inject(point string) error {
	if j != nil && j.fault != nil {
		return j.fault(point)
	}
	return nil
}
func (j *ProvisioningJournal) syncDir() error {
	f, err := j.root.Open(j.dir())
	if err != nil {
		return err
	}
	err = f.Sync()
	return errors.Join(err, f.Close())
}
func journalEntryHash(e JournalEntry) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("journal.v2|%s|%s|%d|%s|%s|%s", e.RunID, e.ReleaseDigest, e.Sequence, e.Phase, e.Event, e.PreviousHash)))
	return hex.EncodeToString(h[:])
}
func checkpointPayload(c JournalCheckpoint) []byte {
	return []byte(fmt.Sprintf("checkpoint.v2|%s|%s|%s|%d|%d|%s|%s|%s", c.RunID, c.ReleaseDigest, c.Nonce, c.Sequence, c.AnchorSequence, c.Phase, c.LastHash, c.PreviousDigest))
}
func digestCheckpointPayload(c JournalCheckpoint) string {
	h := sha256.Sum256(checkpointPayload(c))
	return "sha256:" + hex.EncodeToString(h[:])
}
func checkpointDigest(c JournalCheckpoint) string {
	h := sha256.Sum256(append(checkpointPayload(c), []byte("|"+c.PayloadDigest+"|"+c.Signature)...))
	return "sha256:" + hex.EncodeToString(h[:])
}
func journalToken(parts ...string) string {
	h := sha256.New()
	_, _ = io.WriteString(h, "openduck.provisioning-journal.v2\x00")
	for _, p := range parts {
		_, _ = io.WriteString(h, p+"\x00")
	}
	return hex.EncodeToString(h.Sum(nil))
}
func verifyCheckpoint(ctx context.Context, a journalAuthority, c JournalCheckpoint) error {
	if err := verifyCheckpointSignature(ctx, a, c); err != nil {
		return err
	}
	loadID := journalToken("anchor-load", c.RunID, c.ReleaseDigest, c.Nonce, fmt.Sprint(c.AnchorSequence), checkpointDigest(c))
	seq, digest, err := a.load(ctx, loadID, c.RunID, c.ReleaseDigest, c.Nonce)
	if err != nil || seq != c.AnchorSequence || digest != checkpointDigest(c) {
		return errors.New("journal checkpoint anchor mismatch")
	}
	return nil
}
func verifyCheckpointSignature(ctx context.Context, a journalAuthority, c JournalCheckpoint) error {
	if a == nil || !a.valid() || !validCheckpoint(c) || c.PayloadDigest != digestCheckpointPayload(c) {
		return errors.New("protected journal checkpoint unavailable")
	}
	signID := journalToken("checkpoint-verify", c.RunID, c.ReleaseDigest, c.Nonce, c.PayloadDigest, c.Signature, fmt.Sprint(c.Sequence))
	if err := a.verify(ctx, signID, c.RunID, c.ReleaseDigest, c.Nonce, c.PayloadDigest, c.Signature, c.Sequence); err != nil {
		return err
	}
	return nil
}

// fakeProvisioningJournalAuthority is used only by the package's descriptor
// rooted fake installer. It is not exported and never a production fallback.
type fakeProvisioningJournalAuthority struct {
	mu      sync.Mutex
	anchors map[string]fakeJournalAnchor
}
type fakeJournalAnchor struct {
	sequence uint64
	digest   string
}

func newFakeProvisioningJournalAuthority() *fakeProvisioningJournalAuthority {
	return &fakeProvisioningJournalAuthority{anchors: map[string]fakeJournalAnchor{}}
}
func (a *fakeProvisioningJournalAuthority) valid() bool { return a != nil && a.anchors != nil }
func (a *fakeProvisioningJournalAuthority) sign(_ context.Context, _ string, run, release, nonce, digest string, sequence uint64) (string, error) {
	if !a.valid() {
		return "", errors.New("authority unavailable")
	}
	return fakeJournalSignature(run, release, nonce, digest, sequence), nil
}
func (a *fakeProvisioningJournalAuthority) verify(_ context.Context, _ string, run, release, nonce, digest, sig string, sequence uint64) error {
	if !a.valid() || sig != fakeJournalSignature(run, release, nonce, digest, sequence) {
		return errors.New("signature")
	}
	return nil
}
func (a *fakeProvisioningJournalAuthority) load(_ context.Context, _ string, run, _ string, _ string) (uint64, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	x := a.anchors[run]
	return x.sequence, x.digest, nil
}
func (a *fakeProvisioningJournalAuthority) cas(_ context.Context, _ string, run, _ string, _ string, old, next uint64, oldD, newD string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	x := a.anchors[run]
	if x.sequence != old || x.digest != oldD || next != old+1 {
		return errors.New("cas")
	}
	a.anchors[run] = fakeJournalAnchor{next, newD}
	return nil
}
func fakeJournalSignature(run, release, nonce, digest string, sequence uint64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("fake-provisioning-journal|%s|%s|%s|%s|%d", run, release, nonce, digest, sequence)))
	return hex.EncodeToString(h[:])
}
