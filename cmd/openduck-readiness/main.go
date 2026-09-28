// Command openduck-readiness reports the fail-closed activation state. It
// never probes the network, reads credentials, starts jobs, or mutates state.
package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"openduck/internal/codexruntime"
	"openduck/internal/macosinstall"
	providerreadiness "openduck/internal/readiness"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type State string

const (
	Sudo     State = "SUDO_PROVISIONING_REQUIRED"
	Login    State = "SERVICE_LOGIN_REQUIRED"
	Canary   State = "LIVE_EGRESS_CANARY_REQUIRED"
	Approval State = "ACTIVATION_APPROVAL_REQUIRED"
	Ready    State = "READY"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "openduck-readiness:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	fs := flag.NewFlagSet("openduck-readiness", flag.ContinueOnError)
	root := fs.String("root", macosinstall.SystemRoot, "fixed production root (only the fixed default is accepted)")
	doctorJSON := fs.Bool("doctor-json", false, "print bounded read-only host posture as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *root != macosinstall.SystemRoot {
		return errors.New("arbitrary readiness roots are not accepted")
	}
	if *doctorJSON {
		b, err := macosinstall.DoctorJSON()
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	state, reason, next := readiness(*root)
	fmt.Printf("state=%s\nreason=%s\nnext=%s\n", state, reason, next)
	return nil
}

func readiness(root string) (State, string, State) {
	if !topologyReady(root) {
		return Sudo, "service principals, groups, keys, releases, and disabled LaunchDaemons require sudo provisioning", Approval
	}
	if !livePFReady(root) {
		return Sudo, "live PF status/rules do not match canonical current-boot evidence", Approval
	}
	if !jobsActive() {
		if !pfEvidenceFresh(root) {
			return Sudo, "canonical current-boot PF evidence requires sudo finalization before activation", Approval
		}
		return Approval, "explicit approval is required to start the PF-confined production services", Login
	}
	if !serviceLoginReady(root) {
		return Login, "dedicated runtime-owned ChatGPT/Codex service login is required", Canary
	}
	if !canaryReady(root) {
		return Canary, "operator must approve and execute the live egress canary", Approval
	}
	providerReport := providerOperationalReport(root)
	if !providerReport.Operational {
		return Approval, "provider operational evidence unavailable: " + strings.Join(providerReport.ReasonCodes, ","), Approval
	}
	return Ready, "all production services are active with verified offline topology", Ready
}

func providerOperationalReport(root string) providerreadiness.Report {
	expected, err := providerreadiness.DiscoverExpected(root)
	if err != nil {
		return providerreadiness.Report{ReasonCodes: []string{providerreadiness.ReasonTopologyInvalid}}
	}
	evidence, err := providerreadiness.LoadEvidence(root)
	if err != nil {
		return providerreadiness.Report{ReasonCodes: []string{providerreadiness.ReasonEvidenceAbsent}}
	}
	active := releaseID(root)
	activated := readReleaseSelector(root, "activated.release")
	// launchctl+ps and hashing the installed path is TOCTOU-prone: it cannot
	// bind the running image, start identity, effective credentials, or channel
	// peer credential. Until a privileged macOS attestor supplies those facts,
	// pass no live observations and remain fail-closed.
	return providerreadiness.Evaluate(expected, evidence, providerreadiness.Activation{ReleaseID: active, ActiveRelease: active, ActivatedRelease: activated, Complete: active != "" && active == activated}, nil, time.Now().UTC())
}

func readReleaseSelector(root, leaf string) string {
	b, err := os.ReadFile(filepath.Join(root, leaf))
	if err != nil {
		return ""
	}
	value := strings.TrimSpace(string(b))
	if !validReleaseID(value) || string(b) != value+"\n" {
		return ""
	}
	return value
}

func topologyReady(root string) bool {
	ids, ok := productionIDs()
	if !ok {
		return false
	}
	channelContracts := []struct{ path, owner, group string }{{"channels/platform-anchor", "_openduck_anchor", "_openduck_channel"}, {"checkpoint-channel/platform-checkpoint", "_openduck_checkpoint", "_openduck_checkpoint_channel"}, {"channels/model-egress", "_openduck_egress", "_openduck_egress_channel"}, {"channels/codex-owner", "_openduck_broker", "_openduck_broker_channel"}, {"channels/codex-runtime", "_openduck_codex", "_openduck_runtime_channel"}}
	seenGID := map[string]bool{}
	for _, pair := range channelContracts {
		g, err := user.LookupGroup(pair.group)
		if err != nil || seenGID[g.Gid] || !exactOwnedDirGroup(filepath.Join(root, pair.path), pair.owner, pair.group, 0750) {
			return false
		}
		seenGID[g.Gid] = true
	}
	for group, users := range map[string][]string{"_openduck_channel": {"_openduck", "_openduck_anchor"}, "_openduck_checkpoint_channel": {"_openduck_checkpoint", "_openduck_anchor"}, "_openduck_egress_channel": {"_openduck_egress", "_openduck_broker"}, "_openduck_broker_channel": {"_openduck_broker", "_openduck"}, "_openduck_runtime_channel": {"_openduck_codex", "_openduck_broker"}} {
		for _, name := range users {
			if !memberOf(group, name) {
				return false
			}
		}
	}
	for _, p := range []string{"state", "logs", "home", "home/runtime", "home/runtime/work", "keys", "releases", "releases/codex", "channels", "checkpoint-channel", "pf", "seatbelt", "launchd", "active.release"} {
		st, err := os.Lstat(filepath.Join(root, p))
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.IsDir() && p != "active.release" {
			return false
		}
	}
	for _, p := range []string{"pf/openduck.conf", "pf/egress-policy.json", "seatbelt/codex.sb", "seatbelt/egress.sb", "operator/owner-ed25519.key", "keys/controller-anchor/owner.public", "operator/owner-capabilities", "seatbelt/pf-evidence.json"} {
		st, err := os.Lstat(filepath.Join(root, p))
		if err != nil || st.Mode()&os.ModeSymlink != 0 || (p == "seatbelt/pf-evidence.json" && st.Size() > 2<<20) {
			return false
		}
	}
	for path, mode := range map[string]os.FileMode{"pf/openduck.conf": 0644, "pf/egress-policy.json": 0644, "seatbelt/codex.sb": 0644, "seatbelt/egress.sb": 0644, "seatbelt/state": 0644} {
		if !exactOwnedFile(filepath.Join(root, path), "root", mode, true) {
			return false
		}
	}
	if !exactOwnedFile(filepath.Join(root, "home/controller/bin/openduck-codex-login"), "_openduck", 0700, true) || !exactOwnedFile(filepath.Join(root, "operator/openduck-owner-grant"), "root", 0700, true) {
		return false
	}
	if !exactOwnedFile(filepath.Join(root, ".openduck-provider-attestor"), "root", 0700, true) || !exactOwnedFile(filepath.Join(root, ".openduck-native-mcp"), "root", 0755, true) {
		return false
	}
	if !exactOwnedFile(filepath.Join(root, "operator/codex-login.json"), "root", 0644, true) {
		return false
	}
	if !exactOwnedFile(filepath.Join(root, ".openduck-service-login"), "root", 0700, true) {
		return false
	}
	id := releaseID(root)
	if !validReleaseID(id) {
		return false
	}
	if !manifestBoundHelper(root, id, "bin/openduck-provider-attestor", ".openduck-provider-attestor") || !manifestBoundHelper(root, id, "bin/openduck-native-mcp", ".openduck-native-mcp") {
		return false
	}
	plists := map[string]struct{ service, user, binary string }{"com.openduck.checkpoint.plist": {"checkpoint", "_openduck_checkpoint", "openduck-checkpoint"}, "com.openduck.anchor.plist": {"anchor", "_openduck_anchor", "openduck-anchor"}, "com.openduck.egress.plist": {"egress", "_openduck_egress", "openduck-egress"}, "com.openduck.codex-runtime.plist": {"runtime", "_openduck_codex", "openduck-codex-runtime"}, "com.openduck.codex-broker.plist": {"broker", "_openduck_broker", "openduck-codex-broker"}, "com.openduck.controller.plist": {"controller", "_openduck", "openduck-controller"}}
	for p, contract := range plists {
		st, err := os.Lstat(filepath.Join(root, "launchd", p))
		if err != nil || st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() || !exactOwnedFile(filepath.Join(root, "launchd", p), "root", 0644, true) {
			return false
		}
		b, err := os.ReadFile(filepath.Join(root, "launchd", p))
		text := string(b)
		program := filepath.Join(root, "releases", contract.service, id, contract.binary)
		if err != nil || id == "" || !contains(text, "<key>Disabled</key><true/>") || !contains(text, "<key>RunAtLoad</key><false/>") || !contains(text, "<key>UserName</key><string>"+contract.user+"</string>") || !contains(text, "<string>"+program+"</string>") || contains(text, "<string></string>") || unresolvedPlist(text) {
			return false
		}
	}
	keyChannels := map[string]struct{ channel, owner string }{"anchor/service.key": {"platform-anchor", "_openduck_anchor"}, "controller/service.key": {"platform-anchor", "_openduck"}, "controller-anchor/service.key": {"platform-anchor", "_openduck"}, "anchor-checkpoint/checkpoint.key": {"platform-checkpoint", "_openduck_anchor"}, "checkpoint/service.key": {"platform-checkpoint", "_openduck_checkpoint"}, "egress/service.key": {"model-egress", "_openduck_egress"}, "broker-egress/service.key": {"model-egress", "_openduck_broker"}, "broker-controller/service.key": {"codex-owner", "_openduck_broker"}, "controller-broker/service.key": {"codex-owner", "_openduck"}, "broker/service.key": {"broker-private", "_openduck_broker"}, "runtime/service.key": {"codex-runtime", "_openduck_codex"}, "broker-runtime/service.key": {"codex-runtime", "_openduck_broker"}}
	for p, key := range keyChannels {
		st, err := os.Lstat(filepath.Join(root, "keys", p))
		b, readErr := os.ReadFile(filepath.Join(root, "keys", p))
		if err != nil || readErr != nil || st.Mode().Perm() != 0600 || st.Size() != 116 || st.Mode()&os.ModeSymlink != 0 || !exactOwnedFile(filepath.Join(root, "keys", p), key.owner, 0600, true) || !canonicalServiceKey(b, key.channel) {
			return false
		}
	}
	for _, copies := range [][]string{{"anchor/service.key", "controller/service.key", "controller-anchor/service.key"}, {"anchor-checkpoint/checkpoint.key", "checkpoint/service.key"}, {"egress/service.key", "broker-egress/service.key"}, {"broker-controller/service.key", "controller-broker/service.key"}, {"runtime/service.key", "broker-runtime/service.key"}} {
		var first []byte
		for n, p := range copies {
			b, err := os.ReadFile(filepath.Join(root, "keys", p))
			if err != nil || n > 0 && !bytes.Equal(first, b) {
				return false
			}
			if n == 0 {
				first = b
			}
		}
	}
	private, perr := os.ReadFile(filepath.Join(root, "operator/owner-ed25519.key"))
	public, puberr := os.ReadFile(filepath.Join(root, "keys/controller-anchor/owner.public"))
	if perr != nil || puberr != nil || len(private) != ed25519.PrivateKeySize || len(public) != ed25519.PublicKeySize || !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
		return false
	}
	for p := range plists {
		internal, e1 := os.ReadFile(filepath.Join(root, "launchd", p))
		external, e2 := os.ReadFile(filepath.Join("/Library/LaunchDaemons", p))
		if e1 != nil || e2 != nil || !bytes.Equal(internal, external) || !exactOwnedFile(filepath.Join("/Library/LaunchDaemons", p), "root", 0644, true) {
			return false
		}
	}
	// A marker is not evidence. The canonical PF evidence must be present and
	// bounded before the state machine can advance past provisioning.
	if b, err := os.ReadFile(filepath.Join(root, "seatbelt/pf-evidence.json")); err != nil || !exactOwnedFile(filepath.Join(root, "seatbelt/pf-evidence.json"), "root", 0644, true) || !canonicalPFEvidence(b, root, false) {
		return false
	}
	for service, owner := range map[string]string{"checkpoint": "_openduck_checkpoint", "anchor": "_openduck_anchor", "egress": "_openduck_egress", "runtime": "_openduck_codex", "broker": "_openduck_broker", "controller": "_openduck"} {
		if !releaseReady(root, service, owner, id) {
			return false
		}
	}
	if !releaseReadyAt(root, "releases/anchor-checkpoint/"+id, "_openduck_anchor", id, "openduck-anchor") || !releaseReadyAt(root, "releases/codex/"+id, "root", id, "codex") {
		return false
	}
	_ = ids
	return true
}

func manifestBoundHelper(root, release, source, installed string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "releases/controller", release, "release-manifest.v2.json"))
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return false
	}
	var manifest struct {
		Schema     string `json:"schema"`
		ReleaseID  string `json:"release_id"`
		TargetRoot string `json:"target_root"`
		Artifacts  []struct {
			Path   string `json:"path"`
			Type   string `json:"type"`
			Digest string `json:"digest"`
		} `json:"artifacts"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.Schema != "openduck.release-manifest.v2" || manifest.ReleaseID != release || manifest.TargetRoot != root {
		return false
	}
	want := ""
	for _, artifact := range manifest.Artifacts {
		if artifact.Path == source && artifact.Type == "helper" {
			if want != "" {
				return false
			}
			want = artifact.Digest
		}
	}
	body, readErr := os.ReadFile(filepath.Join(root, installed))
	return readErr == nil && len(want) == 64 && digest(body) == want
}

func unresolvedPlist(text string) bool {
	for _, token := range []string{"_DIGEST", "_UID", "_GID", "RELEASE_ID", "MODEL_ID", "BOOT_ID", "KEY_EPOCH", "CODEX_RUNTIME_ID"} {
		if strings.Contains(text, token) {
			return true
		}
	}
	return false
}

func productionIDs() (map[string][2]uint32, bool) {
	result := map[string][2]uint32{}
	for _, name := range []string{"_openduck", "_openduck_anchor", "_openduck_checkpoint", "_openduck_egress", "_openduck_codex", "_openduck_broker"} {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, false
		}
		uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
		gid, e2 := strconv.ParseUint(u.Gid, 10, 32)
		if e1 != nil || e2 != nil || uid == 0 || gid == 0 {
			return nil, false
		}
		result[name] = [2]uint32{uint32(uid), uint32(gid)}
	}
	return result, true
}
func memberOf(group, name string) bool {
	ok, err := macosinstall.LocalGroupMember(context.Background(), group, name)
	return err == nil && ok
}

func canonicalServiceKey(b []byte, channel string) bool {
	if len(b) != 116 || len(channel) == 0 || len(channel) > 64 || string(b[:8]) != "ODKEYFD\x01" || b[8] != 1 || int(b[9]) != len(channel) || b[10] != 0 || b[11] != 0 || string(b[12:12+len(channel)]) != channel || binary.BigEndian.Uint64(b[76:84]) != 1 {
		return false
	}
	for _, v := range b[12+len(channel) : 76] {
		if v != 0 {
			return false
		}
	}
	return true
}

func canonicalPFEvidence(raw []byte, root string, requireFresh bool) bool {
	var evidence codexruntime.PFEvidence
	if len(raw) == 0 || len(raw) > 4096 || json.Unmarshal(raw, &evidence) != nil {
		return false
	}
	canonical, err := evidence.Canonical()
	if err != nil || !bytes.Equal(raw, canonical) || evidence.BootID != currentBootID() {
		return false
	}
	policy, err := os.ReadFile(filepath.Join(root, "seatbelt", "state"))
	seatbeltInfo, statErr := os.Lstat(filepath.Join(root, "seatbelt"))
	return err == nil && statErr == nil && digest(policy) == evidence.PolicyDigest && evidence.RootDigest == readinessPFRootDigest(seatbeltInfo)
}

func readinessPFRootDigest(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return ""
	}
	return digest([]byte(fmt.Sprintf("pf-root-v1|%d|%d|%d|%d|%o", st.Dev, st.Ino, st.Uid, st.Gid, info.Mode().Perm())))
}

func pfEvidenceFresh(root string) bool {
	raw, err := os.ReadFile(filepath.Join(root, "seatbelt", "pf-evidence.json"))
	return err == nil && canonicalPFEvidence(raw, root, true)
}

func livePFReady(root string) bool {
	status, _, err := runReadinessCommand("/sbin/pfctl", "-s", "info")
	if err != nil || !bytes.Contains(status, []byte("Status: Enabled")) {
		return false
	}
	rules, _, err := runReadinessCommand("/sbin/pfctl", "-a", "com.openduck", "-sr")
	if err != nil || len(bytes.TrimSpace(rules)) == 0 {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(root, "seatbelt", "pf-evidence.json"))
	if err != nil {
		return false
	}
	var evidence codexruntime.PFEvidence
	if json.Unmarshal(raw, &evidence) != nil || !canonicalPFEvidence(raw, root, false) || digest(rules) != evidence.RulesDigest {
		return false
	}
	return true
}

var runReadinessCommand = func(bin string, args ...string) ([]byte, []byte, error) {
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func releaseReady(root, service, owner, id string) bool {
	return releaseReadyAt(root, filepath.Join("releases", service, id), owner, id, "")
}
func releaseReadyAt(root, relative, group, id, expectedBinary string) bool {
	releaseRoot := filepath.Join(root, relative)
	manifestPath := filepath.Join(root, relative, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return false
	}
	var manifest struct {
		ReleaseID    string `json:"release_id"`
		Binary       string `json:"binary"`
		BinaryDigest string `json:"binary_digest"`
	}
	if json.Unmarshal(raw, &manifest) != nil || manifest.ReleaseID != id || manifest.Binary == "" || expectedBinary != "" && manifest.Binary != expectedBinary || filepath.Base(manifest.Binary) != manifest.Binary || len(manifest.BinaryDigest) != 64 {
		return false
	}
	binaryPath := filepath.Join(root, relative, manifest.Binary)
	binaryBytes, err := os.ReadFile(binaryPath)
	if group == "root" {
		return err == nil && exactOwnedDirGroup(releaseRoot, "root", "wheel", 0755) && exactOwnedFile(manifestPath, "root", 0644, true) && exactOwnedFile(binaryPath, "root", 0755, true) && digest(binaryBytes) == manifest.BinaryDigest
	}
	return err == nil && exactOwnedDirGroup(releaseRoot, "root", group, 0550) && exactOwnedFileGroup(manifestPath, "root", group, 0440, true) && exactOwnedFileGroup(binaryPath, "root", group, 0550, true) && digest(binaryBytes) == manifest.BinaryDigest
}

func currentBootID() string {
	return readCurrentBootID()
}

var readCurrentBootID = func() string {
	out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func serviceLoginReady(root string) bool {
	if !exactOwnedFile(filepath.Join(root, "home", "runtime", "auth.json"), "_openduck_codex", 0600, true) {
		return false
	}
	id := releaseID(root)
	raw, err := os.ReadFile(filepath.Join(root, "state", "controller", "login-proof.json"))
	if err != nil || !exactOwnedFile(filepath.Join(root, "state", "controller", "login-proof.json"), "_openduck", 0600, true) {
		return false
	}
	var proof struct {
		Schema              string `json:"schema"`
		ReleaseID           string `json:"release_id"`
		RuntimeID           string `json:"runtime_id"`
		BrokerReleaseDigest string `json:"broker_release_digest"`
		Completed           bool   `json:"completed"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&proof) != nil || dec.Decode(&struct{}{}) != io.EOF || proof.Schema != "openduck-login-proof.v1" || proof.ReleaseID != id || proof.RuntimeID != "codex-runtime-"+id || !proof.Completed {
		return false
	}
	manifest, err := os.ReadFile(filepath.Join(root, "releases", "broker", id, "manifest.json"))
	return err == nil && proof.BrokerReleaseDigest == digest(manifest)
}
func canaryReady(root string) bool {
	proofPath := filepath.Join(root, "state", "controller", "canary-proof.json")
	proofRaw, err := os.ReadFile(proofPath)
	if err != nil || !exactOwnedFile(proofPath, "_openduck", 0600, true) {
		return false
	}
	path := filepath.Join(root, "state", "controller", "chat-ledger.enc")
	if !exactOwnedFile(path, "_openduck", 0600, true) {
		return false
	}
	keyRecord, err := os.ReadFile(filepath.Join(root, "keys", "controller-broker", "service.key"))
	if err != nil || len(keyRecord) != 116 {
		return false
	}
	block, err := aes.NewCipher(keyRecord[84:])
	if err != nil {
		return false
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) <= aead.NonceSize() {
		return false
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return false
	}
	return canaryEvidenceMatches(proofRaw, plain, releaseID(root), currentBootID())
}

type canaryProof struct {
	Schema        string `json:"schema"`
	ReleaseID     string `json:"release_id"`
	BootID        string `json:"boot_id"`
	RunID         string `json:"run_id"`
	ChatID        string `json:"chat_id"`
	RequestDigest string `json:"request_digest"`
	ResultDigest  string `json:"result_digest"`
}
type canaryLedgerRecord struct {
	RunID        string `json:"run_id"`
	ChatID       string `json:"chat_id"`
	State        string `json:"state"`
	Version      uint64 `json:"version"`
	ResultDigest string `json:"result_digest"`
	PendingToken string `json:"pending_token"`
}

func canaryEvidenceMatches(proofRaw, ledgerPlain []byte, releaseID, bootID string) bool {
	var proof canaryProof
	dec := json.NewDecoder(bytes.NewReader(proofRaw))
	dec.DisallowUnknownFields()
	if dec.Decode(&proof) != nil || dec.Decode(&struct{}{}) != io.EOF || proof.Schema != "openduck-canary-proof.v1" || proof.ReleaseID != releaseID || proof.BootID != bootID || proof.ChatID != "openduck-live-egress-canary" || !canonicalDigest(proof.RequestDigest) || !canonicalDigest(proof.ResultDigest) || !strings.HasPrefix(proof.RunID, "run_") {
		return false
	}
	var records []canaryLedgerRecord
	if json.Unmarshal(ledgerPlain, &records) != nil {
		return false
	}
	for _, record := range records {
		if record.RunID == proof.RunID && record.ChatID == proof.ChatID && record.State == "completed" && record.Version > 0 && record.PendingToken == "" && record.ResultDigest == proof.ResultDigest {
			return true
		}
	}
	return false
}
func canonicalDigest(s string) bool {
	return len(s) == 71 && strings.HasPrefix(s, "sha256:") && strings.Trim(s[7:], "0123456789abcdef") == ""
}
func exactOwnedFile(path, owner string, mode os.FileMode, nonempty bool) bool {
	st, err := os.Lstat(path)
	u, lookupErr := user.Lookup(owner)
	if err != nil || lookupErr != nil || !st.Mode().IsRegular() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != mode || nonempty && st.Size() == 0 {
		return false
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	x, ok := st.Sys().(*syscall.Stat_t)
	return ok && x != nil && uint64(x.Uid) == uid && x.Nlink == 1
}
func exactOwnedFileGroup(path, owner, group string, mode os.FileMode, nonempty bool) bool {
	if !exactOwnedFile(path, owner, mode, nonempty) {
		return false
	}
	st, err := os.Lstat(path)
	g, ge := user.LookupGroup(group)
	if err != nil || ge != nil {
		return false
	}
	gid, err := strconv.ParseUint(g.Gid, 10, 32)
	x, ok := st.Sys().(*syscall.Stat_t)
	return err == nil && ok && x != nil && uint64(x.Gid) == gid
}
func exactOwnedDirGroup(path, owner, group string, mode os.FileMode) bool {
	st, err := os.Lstat(path)
	u, ue := user.Lookup(owner)
	g, ge := user.LookupGroup(group)
	if err != nil || ue != nil || ge != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm() != mode {
		return false
	}
	uid, e1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, e2 := strconv.ParseUint(g.Gid, 10, 32)
	x, ok := st.Sys().(*syscall.Stat_t)
	return e1 == nil && e2 == nil && ok && x != nil && uint64(x.Uid) == uid && uint64(x.Gid) == gid
}
func jobsActive() bool {
	for _, label := range []string{"checkpoint", "anchor", "egress", "codex-runtime", "codex-broker", "controller"} {
		out, err := exec.Command("/bin/launchctl", "print", "system/com.openduck."+label).Output()
		if err != nil || !bytes.Contains(out, []byte("state = running")) || !bytes.Contains(out, []byte("pid = ")) {
			return false
		}
	}
	return true
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func contains(s, want string) bool { return strings.Contains(s, want) }

func releaseID(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "active.release"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func validReleaseID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
