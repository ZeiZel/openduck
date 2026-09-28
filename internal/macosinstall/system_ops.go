package macosinstall

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// SystemOps is the sole host mutation seam. Installer tests use fakeSystemOps;
// production uses darwinSystemOps, which invokes fixed absolute tools only.
type SystemOps interface {
	GroupExists(context.Context, string) (bool, error)
	UserExists(context.Context, string) (bool, error)
	MemberExists(context.Context, string, string) (bool, error)
	EnsureGroup(context.Context, string) error
	EnsureUser(context.Context, string, string) error
	AddGroupMember(context.Context, string, string) (bool, error)
	RemoveGroupMember(context.Context, string, string) error
	DeleteUser(context.Context, string) error
	DeleteGroup(context.Context, string) error
	Chown(context.Context, string, string, string) error
	PrepareNativeMCPBoundary(context.Context) (bool, error)
	RemoveNativeMCPBoundary(context.Context) error
	InstallPlist(context.Context, string, []byte) error
	ReadPlist(context.Context, string) ([]byte, bool, error)
	RemovePlist(context.Context, string) error
	EnableJob(context.Context, string) error
	BootstrapPlist(context.Context, string) error
	KickstartJob(context.Context, string) error
	VerifyJob(context.Context, string) error
	DisableJob(context.Context, string) error
	JobLoaded(context.Context, string) (bool, error)
	JobDisabled(context.Context, string) (bool, error)
	ExecAs(context.Context, uint32, uint32, []uint32, string, []string) error
	Bootout(context.Context, string) error
	VerifyPrincipal(context.Context, string, string) error
	VerifyMembership(context.Context, string, string) error
	PrincipalIDs(context.Context, string, string) (uint32, uint32, error)
	PFStatus(context.Context) ([]byte, error)
	PFRules(context.Context) ([]byte, error)
	PFLoad(context.Context) error
	PFEnableLease(context.Context) (string, error)
	PFReleaseLease(context.Context, string) error
	PFUnload(context.Context) error
	PFRestore(context.Context, []byte, bool) error
	BootID(context.Context) (string, error)
}

type commandRunner interface {
	Run(context.Context, []byte, string, ...string) ([]byte, []byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, stdin []byte, bin string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type commandFailure struct {
	bin    string
	args   []string
	output []byte
	err    error
}

func (e *commandFailure) Error() string {
	quoted := make([]string, len(e.args))
	for i, arg := range diagnosticArgs(e.args) {
		quoted[i] = strconv.Quote(arg)
	}
	return fmt.Sprintf("%s args=[%s] failed: %v", e.bin, strings.Join(quoted, ", "), e.err)
}

func (e *commandFailure) Unwrap() error { return e.err }

func diagnosticArgs(args []string) []string {
	result := append([]string(nil), args...)
	for index := 0; index+1 < len(result); index++ {
		switch strings.ToLower(result[index]) {
		case "-p", "--password", "--token", "--secret":
			result[index+1] = "<redacted>"
			index++
		}
	}
	return result
}

type darwinSystemOps struct {
	runner          commandRunner
	uuidSource      func() (string, error)
	healthInterval  time.Duration
	healthTimeout   time.Duration
	healthStability time.Duration
	healthNow       func() time.Time
	healthSleep     func(context.Context, time.Duration) error
}

func newDarwinSystemOps() SystemOps {
	return darwinSystemOps{runner: execCommandRunner{}, uuidSource: randomGeneratedUID}
}

// LocalGroupMember reads only the fixed local Directory Service node. It does
// not consult the host authentication search policy.
func LocalGroupMember(ctx context.Context, group, user string) (bool, error) {
	return (darwinSystemOps{runner: execCommandRunner{}}).MemberExists(ctx, group, user)
}
func (op darwinSystemOps) commandRunner() commandRunner {
	if op.runner == nil {
		return execCommandRunner{}
	}
	return op.runner
}
func (op darwinSystemOps) run(ctx context.Context, bin string, args ...string) error {
	_, err := op.output(ctx, bin, args...)
	return err
}
func (op darwinSystemOps) output(ctx context.Context, bin string, args ...string) ([]byte, error) {
	out, stderr, err := op.commandRunner().Run(ctx, nil, bin, args...)
	if err != nil {
		return nil, &commandFailure{bin: bin, args: append([]string(nil), args...), output: boundedDiagnostic(stderr), err: err}
	}
	return out, nil
}

func (op darwinSystemOps) input(ctx context.Context, stdin []byte, bin string, args ...string) error {
	_, stderr, err := op.commandRunner().Run(ctx, stdin, bin, args...)
	if err != nil {
		return &commandFailure{bin: bin, args: append([]string(nil), args...), output: boundedDiagnostic(stderr), err: err}
	}
	return nil
}

func boundedDiagnostic(raw []byte) []byte {
	const limit = 512
	if len(raw) > limit {
		raw = raw[:limit]
	}
	return append([]byte(nil), raw...)
}
func (op darwinSystemOps) EnsureGroup(ctx context.Context, name string) error {
	if ok, err := op.GroupExists(ctx, name); err != nil || ok {
		return err
	}
	id, err := op.availablePrincipalID(ctx)
	if err != nil {
		return err
	}
	if err := op.run(ctx, "/usr/sbin/dseditgroup", "-o", "create", "-n", ".", name); err != nil {
		return err
	}
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-create", "/Groups/"+name, "PrimaryGroupID", strconv.FormatUint(uint64(id), 10)); err != nil {
		_ = op.DeleteGroup(context.Background(), name)
		return err
	}
	return nil
}
func (op darwinSystemOps) GroupExists(ctx context.Context, name string) (bool, error) {
	err := op.run(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+name)
	if commandOutputContains(err, "eDSRecordNotFound") {
		return false, nil
	}
	return err == nil, err
}
func (op darwinSystemOps) UserExists(ctx context.Context, name string) (bool, error) {
	err := op.run(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+name)
	if commandOutputContains(err, "eDSRecordNotFound") {
		return false, nil
	}
	return err == nil, err
}
func (op darwinSystemOps) MemberExists(ctx context.Context, group, user string) (bool, error) {
	state, err := op.localMembership(ctx, group, user)
	if err != nil {
		return false, err
	}
	if state.byName != state.byUUID {
		return false, fmt.Errorf("local membership for %s in %s is inconsistent", user, group)
	}
	return state.byName, nil
}
func (op darwinSystemOps) EnsureUser(ctx context.Context, name, group string) error {
	exists, err := op.UserExists(ctx, name)
	if err != nil {
		return err
	}
	if exists {
		// Never repair an existing account in place: a mismatch may be a
		// pre-existing administrator object and must fail without mutation.
		return op.VerifyPrincipal(ctx, name, group)
	}
	out, err := op.output(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+group, "PrimaryGroupID")
	if err != nil {
		return err
	}
	gid, err := parseDSCLID(out, "PrimaryGroupID")
	if err != nil {
		return err
	}
	uid, err := op.availablePrincipalID(ctx)
	if err != nil {
		return err
	}
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-create", "/Users/"+name); err != nil {
		return err
	}
	created := true
	defer func() {
		if created {
			_ = op.DeleteUser(context.Background(), name)
		}
	}()
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-create", "/Users/"+name, "UniqueID", strconv.FormatUint(uint64(uid), 10)); err != nil {
		return err
	}
	generatedUID, err := op.uniqueGeneratedUID(ctx)
	if err != nil {
		return err
	}
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-create", "/Users/"+name, "GeneratedUID", generatedUID); err != nil {
		return err
	}
	for _, kv := range [][2]string{{"PrimaryGroupID", strconv.FormatUint(uint64(gid), 10)}, {"UserShell", "/usr/bin/false"}, {"NFSHomeDirectory", "/var/empty"}, {"IsHidden", "1"}, {"Password", "*"}} {
		if err := op.run(ctx, "/usr/bin/dscl", ".", "-create", "/Users/"+name, kv[0], kv[1]); err != nil {
			return err
		}
	}
	created = false
	return nil
}
func (op darwinSystemOps) AddGroupMember(ctx context.Context, group, user string) (bool, error) {
	state, err := op.localMembership(ctx, group, user)
	if err != nil {
		return false, err
	}
	if state.byName != state.byUUID {
		return false, fmt.Errorf("local membership for %s in %s is inconsistent", user, group)
	}
	if state.byName {
		return false, nil
	}
	groupRecord := "/Groups/" + group
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-append", groupRecord, "GroupMembership", user); err != nil {
		return false, err
	}
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-append", groupRecord, "GroupMembers", state.generatedUID); err != nil {
		cleanupErr := op.run(context.Background(), "/usr/bin/dscl", ".", "-delete", groupRecord, "GroupMembership", user)
		if cleanupErr != nil {
			return false, errors.Join(err, fmt.Errorf("restore local membership after failed UUID append: %w", cleanupErr))
		}
		return false, err
	}
	return true, nil
}
func (op darwinSystemOps) RemoveGroupMember(ctx context.Context, group, user string) error {
	state, err := op.localMembership(ctx, group, user)
	if err != nil {
		return err
	}
	if state.byName != state.byUUID {
		return fmt.Errorf("local membership for %s in %s is inconsistent", user, group)
	}
	if !state.byName {
		return nil
	}
	groupRecord := "/Groups/" + group
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-delete", groupRecord, "GroupMembers", state.generatedUID); err != nil {
		return err
	}
	if err := op.run(ctx, "/usr/bin/dscl", ".", "-delete", groupRecord, "GroupMembership", user); err != nil {
		restoreErr := op.run(context.Background(), "/usr/bin/dscl", ".", "-append", groupRecord, "GroupMembers", state.generatedUID)
		if restoreErr != nil {
			return errors.Join(err, fmt.Errorf("restore local membership after failed name delete: %w", restoreErr))
		}
		return err
	}
	return nil
}
func (op darwinSystemOps) DeleteUser(ctx context.Context, name string) error {
	return op.run(ctx, "/usr/bin/dscl", ".", "-delete", "/Users/"+name)
}
func (op darwinSystemOps) DeleteGroup(ctx context.Context, name string) error {
	return op.run(ctx, "/usr/bin/dscl", ".", "-delete", "/Groups/"+name)
}
func (op darwinSystemOps) Chown(ctx context.Context, path, user, group string) error {
	return op.run(ctx, "/usr/sbin/chown", user+":"+group, path)
}

func (op darwinSystemOps) PrepareNativeMCPBoundary(ctx context.Context) (bool, error) {
	const parent = "/private/var/run"
	root, err := os.OpenRoot(parent)
	if err != nil {
		return false, err
	}
	defer root.Close()
	created := false
	if err = root.Mkdir("openduck", 0770); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return false, err
	}
	info, err := root.Lstat("openduck")
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false, errors.New("native MCP boundary unsafe")
	}
	_, channelGID, idErr := op.PrincipalIDs(ctx, "root", "_openduck_channel")
	st, statOK := info.Sys().(*syscall.Stat_t)
	if idErr != nil || !statOK || st == nil {
		return created, errors.New("native MCP boundary identity unavailable")
	}
	if !created {
		if info.Mode().Perm() != 0770 || st.Uid != 0 || st.Gid != channelGID {
			return false, errors.New("native MCP boundary mismatch")
		}
		return false, nil
	}
	if err = op.Chown(ctx, parent+"/openduck", "root", "_openduck_channel"); err != nil {
		return true, err
	}
	if err = root.Chmod("openduck", 0770); err != nil {
		return true, err
	}
	info, err = root.Lstat("openduck")
	if err != nil || info.Mode().Perm() != 0770 {
		return true, errors.New("native MCP boundary unavailable")
	}
	return true, nil
}
func (darwinSystemOps) RemoveNativeMCPBoundary(context.Context) error {
	root, err := os.OpenRoot("/private/var/run")
	if err != nil {
		return err
	}
	defer root.Close()
	err = root.Remove("openduck")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func (darwinSystemOps) InstallPlist(ctx context.Context, name string, data []byte) error {
	r, err := os.OpenRoot("/Library/LaunchDaemons")
	if err != nil {
		return err
	}
	defer r.Close()
	tmp := ".openduck." + name + ".tmp"
	_ = r.Remove(tmp)
	f, err := r.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if err = f.Chmod(0644); err != nil {
		_ = f.Close()
		_ = r.Remove(tmp)
		return err
	}
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		_ = r.Remove(tmp)
		return err
	}
	if err = f.Close(); err != nil {
		_ = r.Remove(tmp)
		return err
	}
	return r.Rename(tmp, filepath.Base(name))
}
func (darwinSystemOps) ReadPlist(_ context.Context, name string) ([]byte, bool, error) {
	r, err := os.OpenRoot("/Library/LaunchDaemons")
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	name = filepath.Base(name)
	st, err := r.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !safeExistingRegular(st, 0644, st.Size()) || !ownedBy(st, 0, 0) {
		return nil, false, errors.New("unsafe external LaunchDaemon plist")
	}
	b, err := r.ReadFile(name)
	return b, true, err
}
func (darwinSystemOps) RemovePlist(_ context.Context, name string) error {
	r, err := os.OpenRoot("/Library/LaunchDaemons")
	if err != nil {
		return err
	}
	defer r.Close()
	err = r.Remove(filepath.Base(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
func (op darwinSystemOps) EnableJob(ctx context.Context, label string) error {
	return op.run(ctx, "/bin/launchctl", "enable", "system/"+label)
}
func (op darwinSystemOps) BootstrapPlist(ctx context.Context, name string) error {
	return op.run(ctx, "/bin/launchctl", "bootstrap", "system", "/Library/LaunchDaemons/"+filepath.Base(name))
}
func (op darwinSystemOps) KickstartJob(ctx context.Context, label string) error {
	return op.run(ctx, "/bin/launchctl", "kickstart", "system/"+label)
}
func (op darwinSystemOps) VerifyJob(ctx context.Context, label string) error {
	timeout, interval, stability := op.healthTimeout, op.healthInterval, op.healthStability
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	if stability <= 0 {
		stability = 5 * time.Second
	}
	now := time.Now
	if op.healthNow != nil {
		now = op.healthNow
	}
	sleep := func(ctx context.Context, d time.Duration) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
			return nil
		}
	}
	if op.healthSleep != nil {
		sleep = op.healthSleep
	}
	deadline := now().Add(timeout)
	lastPID := ""
	var stableSince time.Time
	for {
		out, err := op.output(ctx, "/bin/launchctl", "print", "system/"+label)
		pid := launchdRunningPID(out)
		if err == nil && pid != "" {
			if pid != lastPID || stableSince.IsZero() {
				lastPID, stableSince = pid, now()
			}
			if now().Sub(stableSince) >= stability {
				return nil
			}
		} else {
			lastPID, stableSince = "", time.Time{}
		}
		if !now().Before(deadline) {
			return errors.New("activated job is not stably running")
		}
		if err := sleep(ctx, interval); err != nil {
			return errors.New("activated job health cancelled")
		}
	}
}

func launchdRunningPID(out []byte) string {
	if !bytes.Contains(out, []byte("state = running")) {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 3 && fields[0] == "pid" && fields[1] == "=" && fields[2] != "0" && strings.Trim(fields[2], "0123456789") == "" {
			return fields[2]
		}
	}
	return ""
}

func (op darwinSystemOps) DisableJob(ctx context.Context, label string) error {
	return op.run(ctx, "/bin/launchctl", "disable", "system/"+label)
}
func (op darwinSystemOps) JobLoaded(ctx context.Context, label string) (bool, error) {
	out, stderr, err := op.commandRunner().Run(ctx, nil, "/bin/launchctl", "print", "system/"+label)
	return classifyLaunchctlPrint(append(boundedDiagnostic(out), boundedDiagnostic(stderr)...), err)
}
func (op darwinSystemOps) JobDisabled(ctx context.Context, label string) (bool, error) {
	out, err := op.output(ctx, "/bin/launchctl", "print-disabled", "system")
	if err != nil {
		return false, err
	}
	needle := `"` + label + `" => true`
	return strings.Contains(string(out), needle), nil
}
func classifyLaunchctlPrint(out []byte, err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	message := strings.ToLower(string(out))
	if strings.Contains(message, "could not find service") || strings.Contains(message, "no such process") {
		return false, nil
	}
	return false, fmt.Errorf("launchctl job state unavailable: %w", err)
}
func (darwinSystemOps) ExecAs(_ context.Context, uid, gid uint32, groups []uint32, path string, args []string) error {
	if path != SystemRoot+"/home/controller/bin/openduck-codex-login" {
		return errors.New("invalid service login executable")
	}
	gs := make([]int, len(groups))
	for n, g := range groups {
		gs[n] = int(g)
	}
	if err := syscall.Setgroups(gs); err != nil {
		return err
	}
	if err := syscall.Setgid(int(gid)); err != nil {
		return err
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		return err
	}
	return syscall.Exec(path, append([]string{path}, args...), []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"})
}
func (op darwinSystemOps) Bootout(ctx context.Context, label string) error {
	err := op.run(ctx, "/bin/launchctl", "bootout", "system/"+label)
	if err != nil && !commandOutputContains(err, "No such process") && !commandOutputContains(err, "Could not find service") {
		return err
	}
	return nil
}
func (op darwinSystemOps) VerifyPrincipal(ctx context.Context, user, group string) error {
	out, err := op.output(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+user, "UniqueID", "GeneratedUID", "PrimaryGroupID", "UserShell", "NFSHomeDirectory", "IsHidden")
	if err != nil {
		return err
	}
	s := string(out)
	for _, want := range []string{"UserShell: /usr/bin/false", "NFSHomeDirectory: /var/empty", "IsHidden: 1"} {
		if !strings.Contains(s, want) {
			return fmt.Errorf("principal %s has unsafe %s", user, want)
		}
	}
	uid, err := parseDSCLID(out, "UniqueID")
	if err != nil || uid == 0 {
		return fmt.Errorf("principal %s has invalid UniqueID", user)
	}
	generatedUID, err := parseDSCLAttribute(out, "GeneratedUID")
	if err != nil || !canonicalGeneratedUID(generatedUID) {
		return fmt.Errorf("principal %s has invalid GeneratedUID", user)
	}
	if err := op.verifyGeneratedUIDOwner(ctx, user, generatedUID); err != nil {
		return err
	}
	groupOut, err := op.output(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+group, "PrimaryGroupID")
	if err != nil {
		return err
	}
	wantGID, err := parseDSCLID(groupOut, "PrimaryGroupID")
	if err != nil {
		return err
	}
	gotGID, err := parseDSCLID(out, "PrimaryGroupID")
	if err != nil || gotGID != wantGID {
		return fmt.Errorf("principal %s primary group mismatch", user)
	}
	return nil
}
func (op darwinSystemOps) VerifyMembership(ctx context.Context, group, user string) error {
	exists, err := op.MemberExists(ctx, group, user)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("local membership for %s in %s is missing", user, group)
	}
	return nil
}
func (op darwinSystemOps) PrincipalIDs(ctx context.Context, user, group string) (uint32, uint32, error) {
	u, e := op.output(ctx, "/usr/bin/id", "-u", user)
	if e != nil {
		return 0, 0, e
	}
	g, e := op.output(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+group, "PrimaryGroupID")
	if e != nil {
		return 0, 0, e
	}
	var uid, gid uint32
	if _, e = fmt.Sscan(strings.TrimSpace(string(u)), &uid); e != nil {
		return 0, 0, e
	}
	if gid, e = parseDSCLID(g, "PrimaryGroupID"); e != nil {
		return 0, 0, e
	}
	return uid, gid, nil
}

func parseDSCLID(out []byte, attribute string) (uint32, error) {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && strings.TrimSuffix(fields[0], ":") == attribute {
			n, err := strconv.ParseUint(fields[1], 10, 32)
			if err == nil && n != 0 {
				return uint32(n), nil
			}
		}
	}
	return 0, fmt.Errorf("%s unavailable", attribute)
}

func parseDSCLAttribute(out []byte, attribute string) (string, error) {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && strings.TrimSuffix(fields[0], ":") == attribute && fields[1] != "" {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("%s unavailable", attribute)
}

func canonicalGeneratedUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for i, r := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

type localMembershipState struct {
	generatedUID string
	byName       bool
	byUUID       bool
}

func (op darwinSystemOps) localMembership(ctx context.Context, group, user string) (localMembershipState, error) {
	if !canonicalLocalRecordName(group) || !canonicalLocalRecordName(user) {
		return localMembershipState{}, errors.New("invalid local principal name")
	}
	userOut, err := op.output(ctx, "/usr/bin/dscl", ".", "-read", "/Users/"+user, "GeneratedUID")
	if err != nil {
		return localMembershipState{}, err
	}
	generatedUID, err := parseDSCLAttribute(userOut, "GeneratedUID")
	if err != nil || !canonicalGeneratedUID(generatedUID) {
		return localMembershipState{}, fmt.Errorf("principal %s has invalid GeneratedUID", user)
	}
	groupOut, err := op.output(ctx, "/usr/bin/dscl", ".", "-read", "/Groups/"+group)
	if err != nil {
		return localMembershipState{}, err
	}
	return localMembershipState{
		generatedUID: strings.ToUpper(generatedUID),
		byName:       dsclAttributeContains(groupOut, "GroupMembership", user, false),
		byUUID:       dsclAttributeContains(groupOut, "GroupMembers", generatedUID, true),
	}, nil
}

func canonicalLocalRecordName(value string) bool {
	if len(value) < 2 || len(value) > 64 || value[0] != '_' {
		return false
	}
	for _, r := range value[1:] {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_') {
			return false
		}
	}
	return true
}

func dsclAttributeContains(out []byte, attribute, wanted string, foldCase bool) bool {
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || strings.TrimSuffix(fields[0], ":") != attribute {
			continue
		}
		for _, value := range fields[1:] {
			if (foldCase && strings.EqualFold(value, wanted)) || (!foldCase && value == wanted) {
				return true
			}
		}
	}
	return false
}

func randomGeneratedUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate principal UUID: %w", err)
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])), nil
}

func (op darwinSystemOps) uniqueGeneratedUID(ctx context.Context) (string, error) {
	out, err := op.output(ctx, "/usr/bin/dscl", ".", "-list", "/Users", "GeneratedUID")
	if err != nil {
		return "", err
	}
	used := make(map[string]struct{})
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && canonicalGeneratedUID(fields[len(fields)-1]) {
			used[strings.ToUpper(fields[len(fields)-1])] = struct{}{}
		}
	}
	source := op.uuidSource
	if source == nil {
		source = randomGeneratedUID
	}
	for attempt := 0; attempt < 16; attempt++ {
		value, err := source()
		if err != nil {
			return "", err
		}
		if !canonicalGeneratedUID(value) {
			return "", errors.New("generated principal UUID is not canonical")
		}
		value = strings.ToUpper(value)
		if _, exists := used[value]; !exists {
			return value, nil
		}
	}
	return "", errors.New("could not allocate collision-free GeneratedUID")
}

func (op darwinSystemOps) verifyGeneratedUIDOwner(ctx context.Context, user, generatedUID string) error {
	out, err := op.output(ctx, "/usr/bin/dscl", ".", "-list", "/Users", "GeneratedUID")
	if err != nil {
		return err
	}
	wanted := strings.ToUpper(generatedUID)
	owners := 0
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || strings.ToUpper(fields[len(fields)-1]) != wanted {
			continue
		}
		owners++
		if fields[0] != user {
			return fmt.Errorf("principal %s GeneratedUID collides with another user", user)
		}
	}
	if owners != 1 {
		return fmt.Errorf("principal %s GeneratedUID is not uniquely indexed", user)
	}
	return nil
}

func commandOutputContains(err error, text string) bool {
	var failure *commandFailure
	return errors.As(err, &failure) && strings.Contains(string(failure.output), text)
}

func (op darwinSystemOps) availablePrincipalID(ctx context.Context) (uint32, error) {
	used := map[uint32]bool{}
	for _, query := range [][2]string{{"/Users", "UniqueID"}, {"/Groups", "PrimaryGroupID"}} {
		out, err := op.output(ctx, "/usr/bin/dscl", ".", "-list", query[0], query[1])
		if err != nil {
			return 0, err
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			n, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
			if err == nil {
				used[uint32(n)] = true
			}
		}
	}
	for id := uint32(499); id >= 350; id-- {
		if !used[id] {
			return id, nil
		}
	}
	return 0, errors.New("no collision-free system principal id available")
}

func (op darwinSystemOps) PFStatus(ctx context.Context) ([]byte, error) {
	return op.output(ctx, "/sbin/pfctl", "-s", "info")
}
func (op darwinSystemOps) PFRules(ctx context.Context) ([]byte, error) {
	return op.output(ctx, "/sbin/pfctl", "-a", "com.openduck", "-sr")
}
func (op darwinSystemOps) PFLoad(ctx context.Context) error {
	return op.run(ctx, "/sbin/pfctl", "-a", "com.openduck", "-f", SystemRoot+"/pf/openduck.conf")
}
func (op darwinSystemOps) PFEnableLease(ctx context.Context) (string, error) {
	out, err := op.output(ctx, "/sbin/pfctl", "-E")
	if err != nil {
		return "", err
	}
	token := parsePFLeaseToken(out)
	if token == "" {
		return "", errors.New("pf enable lease unavailable")
	}
	return token, nil
}

func parsePFLeaseToken(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) == "Token" {
			t := strings.TrimSpace(parts[1])
			if t != "" && strings.Trim(t, "0123456789") == "" {
				return t
			}
		}
	}
	return ""
}
func (op darwinSystemOps) PFReleaseLease(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	return op.run(ctx, "/sbin/pfctl", "-X", token)
}
func (op darwinSystemOps) PFUnload(ctx context.Context) error {
	return op.run(ctx, "/sbin/pfctl", "-a", "com.openduck", "-F", "all")
}
func (op darwinSystemOps) PFRestore(ctx context.Context, rules []byte, enabled bool) error {
	// Restore only the OpenDuck anchor. Never touch global PF enablement: an
	// unrelated host firewall must remain under the operator's control.
	if err := op.PFUnload(ctx); err != nil {
		return err
	}
	if len(rules) != 0 {
		if err := op.input(ctx, rules, "/sbin/pfctl", "-a", "com.openduck", "-f", "-"); err != nil {
			return fmt.Errorf("pf restore: %w", err)
		}
	}
	_ = enabled // anchor state is scoped; global PF state is intentionally untouched.
	return nil
}
func (op darwinSystemOps) BootID(ctx context.Context) (string, error) {
	out, err := op.output(ctx, "/usr/sbin/sysctl", "-n", "kern.boottime")
	id := strings.TrimSpace(string(out))
	if err != nil || id == "" || strings.ContainsAny(id, "\r\n\x00") {
		return "", errors.New("boot identity unavailable")
	}
	return id, nil
}

type fakeSystemOps struct {
	users, groups, members, plists, booted, loaded map[string]bool
	plistData                                      map[string][]byte
	failAt                                         string
	failErr                                        error
	failed                                         map[string]bool
	mutateThenFailAt                               string
	bootoutFailAt                                  string
	restorePlistFailAt                             string
	readPlistTamperAt                              string
	pfRestoreErr                                   error
	pfReleaseErr                                   error
	pfEvents                                       []string
	pfLoaded                                       bool
	pfUnloadCount                                  int
	pfRules                                        []byte
	jobDisabledCalls                               int
	jobDisabledFalseAfter                          int
	jobDisabledFalseLabel                          string
	execUID, execGID                               uint32
	execGroups                                     []uint32
	execPath                                       string
	execArgs                                       []string
}

func newFakeSystemOps() *fakeSystemOps {
	f := &fakeSystemOps{users: map[string]bool{}, groups: map[string]bool{}, members: map[string]bool{}, plists: map[string]bool{}, plistData: map[string][]byte{}, booted: map[string]bool{}, loaded: map[string]bool{}, failed: map[string]bool{}}
	for _, s := range services {
		f.booted["disabled:com.openduck."+serviceLabel(s.Name)] = true
	}
	return f
}

func (f *fakeSystemOps) failOnce(point string) bool {
	if f.failAt != point || f.failed[point] {
		return false
	}
	f.failed[point] = true
	return true
}
func (f *fakeSystemOps) EnsureGroup(_ context.Context, n string) error {
	if f.failAt == "group:"+n {
		return errors.New("injected group failure")
	}
	f.groups[n] = true
	return nil
}
func (f *fakeSystemOps) GroupExists(_ context.Context, n string) (bool, error) {
	return f.groups[n], nil
}
func (f *fakeSystemOps) UserExists(_ context.Context, n string) (bool, error) { return f.users[n], nil }
func (f *fakeSystemOps) MemberExists(_ context.Context, g, u string) (bool, error) {
	return f.members[g+":"+u], nil
}
func (f *fakeSystemOps) EnsureUser(_ context.Context, n, g string) error {
	if f.failAt == "user:"+n {
		return errors.New("injected user failure")
	}
	if !f.groups[g] {
		return fmt.Errorf("group %s missing", g)
	}
	f.users[n] = true
	return nil
}
func (f *fakeSystemOps) AddGroupMember(_ context.Context, g, u string) (bool, error) {
	if f.failAt == "member:"+g+":"+u {
		if f.failErr != nil {
			return false, f.failErr
		}
		return false, errors.New("injected member failure")
	}
	if !f.groups[g] || !f.users[u] {
		return false, errors.New("principal missing")
	}
	added := !f.members[g+":"+u]
	f.members[g+":"+u] = true
	return added, nil
}
func (f *fakeSystemOps) RemoveGroupMember(_ context.Context, g, u string) error {
	delete(f.members, g+":"+u)
	return nil
}
func (f *fakeSystemOps) DeleteUser(_ context.Context, u string) error { delete(f.users, u); return nil }
func (f *fakeSystemOps) DeleteGroup(_ context.Context, g string) error {
	delete(f.groups, g)
	return nil
}
func (f *fakeSystemOps) Chown(context.Context, string, string, string) error    { return nil }
func (f *fakeSystemOps) PrepareNativeMCPBoundary(context.Context) (bool, error) { return true, nil }
func (f *fakeSystemOps) RemoveNativeMCPBoundary(context.Context) error          { return nil }
func (f *fakeSystemOps) InstallPlist(_ context.Context, n string, data []byte) error {
	if f.restorePlistFailAt == n && f.failed["plist:"+n] {
		return errors.New("injected plist compensation failure")
	}
	if f.failOnce("plist:" + n) {
		return errors.New("injected plist failure")
	}
	f.plists[n] = true
	f.plistData[n] = append([]byte(nil), data...)
	return nil
}
func (f *fakeSystemOps) ReadPlist(_ context.Context, n string) ([]byte, bool, error) {
	if data := f.plistData[n]; data != nil {
		if f.readPlistTamperAt == n {
			return append(append([]byte(nil), data...), '\n'), f.plists[n], nil
		}
		return append([]byte(nil), data...), f.plists[n], nil
	}
	return []byte("previous:" + n), f.plists[n], nil
}
func (f *fakeSystemOps) RemovePlist(_ context.Context, n string) error {
	delete(f.plists, n)
	delete(f.plistData, n)
	return nil
}
func (f *fakeSystemOps) EnableJob(_ context.Context, label string) error {
	if f.mutateThenFailAt == "enable:"+label {
		f.booted["enabled:"+label] = true
		f.booted["disabled:"+label] = false
		return errors.New("injected enable failure after mutation")
	}
	if f.failAt == "enable:"+label {
		return errors.New("injected enable failure")
	}
	f.booted["enabled:"+label] = true
	f.booted["disabled:"+label] = false
	return nil
}
func (f *fakeSystemOps) BootstrapPlist(_ context.Context, name string) error {
	if f.mutateThenFailAt == "bootstrap:"+name {
		f.booted["bootstrap:"+name] = true
		f.loaded[strings.TrimSuffix(name, ".plist")] = true
		return errors.New("injected bootstrap failure after mutation")
	}
	if f.failAt == "bootstrap:"+name {
		return errors.New("injected bootstrap failure")
	}
	f.booted["bootstrap:"+name] = true
	f.loaded[strings.TrimSuffix(name, ".plist")] = true
	return nil
}
func (f *fakeSystemOps) KickstartJob(_ context.Context, label string) error {
	if f.failAt == "kickstart:"+label {
		return errors.New("injected kickstart failure")
	}
	return nil
}
func (f *fakeSystemOps) VerifyJob(_ context.Context, label string) error {
	if f.failAt == "health:"+label {
		return errors.New("injected health failure")
	}
	f.booted[label] = true
	return nil
}
func (f *fakeSystemOps) DisableJob(_ context.Context, label string) error {
	f.booted["disabled:"+label] = true
	return nil
}
func (f *fakeSystemOps) JobDisabled(_ context.Context, label string) (bool, error) {
	f.jobDisabledCalls++
	if f.failAt == "job-disabled:"+label {
		return false, errors.New("injected disabled state failure")
	}
	if f.jobDisabledFalseAfter > 0 && f.jobDisabledCalls > f.jobDisabledFalseAfter && label == f.jobDisabledFalseLabel {
		return false, nil
	}
	return f.booted["disabled:"+label], nil
}
func (f *fakeSystemOps) JobLoaded(_ context.Context, label string) (bool, error) {
	if f.failAt == "job-loaded:"+label {
		return false, errors.New("injected job state failure")
	}
	return f.loaded[label], nil
}
func (f *fakeSystemOps) ExecAs(_ context.Context, uid, gid uint32, groups []uint32, path string, args []string) error {
	f.execUID, f.execGID, f.execGroups, f.execPath, f.execArgs = uid, gid, append([]uint32(nil), groups...), path, append([]string(nil), args...)
	return nil
}
func (f *fakeSystemOps) Bootout(_ context.Context, n string) error {
	if f.bootoutFailAt == n {
		return errors.New("injected bootout failure")
	}
	f.booted[n] = true
	delete(f.loaded, n)
	return nil
}
func (f *fakeSystemOps) VerifyPrincipal(_ context.Context, u, g string) error {
	if !f.users[u] || !f.groups[g] {
		return errors.New("principal missing")
	}
	return nil
}
func (f *fakeSystemOps) VerifyMembership(_ context.Context, g, u string) error {
	if !f.members[g+":"+u] {
		return errors.New("membership missing")
	}
	return nil
}
func (f *fakeSystemOps) PrincipalIDs(_ context.Context, user, group string) (uint32, uint32, error) {
	u := sha256.Sum256([]byte("uid:" + user))
	g := sha256.Sum256([]byte("gid:" + group))
	uid := uint32(u[0])<<24 | uint32(u[1])<<16 | uint32(u[2])<<8 | uint32(u[3])
	gid := uint32(g[0])<<24 | uint32(g[1])<<16 | uint32(g[2])<<8 | uint32(g[3])
	return uid%60000 + 1000, gid%60000 + 1000, nil
}
func (f *fakeSystemOps) PFStatus(context.Context) ([]byte, error) {
	if f.failAt == "pf-status" {
		return nil, errors.New("injected PF status failure")
	}
	if !f.pfLoaded {
		return []byte("Status: Disabled\n"), nil
	}
	return []byte("Status: Enabled\n"), nil
}
func (f *fakeSystemOps) PFRules(context.Context) ([]byte, error) {
	if !f.pfLoaded {
		return append([]byte(nil), f.pfRules...), nil
	}
	if len(f.pfRules) == 0 {
		f.pfRules = []byte("pass out anchor com.openduck\n")
	}
	return append([]byte(nil), f.pfRules...), nil
}
func (f *fakeSystemOps) PFLoad(context.Context) error {
	f.pfLoaded = true
	f.pfRules = []byte("pass out anchor com.openduck\n")
	return nil
}
func (f *fakeSystemOps) PFEnableLease(context.Context) (string, error) {
	if f.failAt == "pf-enable" {
		return "", errors.New("injected PF enable failure")
	}
	return "123", nil
}
func (f *fakeSystemOps) PFReleaseLease(_ context.Context, token string) error {
	f.pfEvents = append(f.pfEvents, "release:"+token)
	if f.pfReleaseErr != nil {
		return f.pfReleaseErr
	}
	return nil
}
func (f *fakeSystemOps) PFUnload(context.Context) error {
	f.pfLoaded = false
	f.pfUnloadCount++
	return nil
}
func (f *fakeSystemOps) PFRestore(_ context.Context, rules []byte, enabled bool) error {
	f.pfEvents = append(f.pfEvents, "restore")
	if f.pfRestoreErr != nil {
		return f.pfRestoreErr
	}
	f.pfUnloadCount++
	f.pfRules = append([]byte(nil), rules...)
	f.pfLoaded = enabled && len(rules) != 0
	return nil
}
func (f *fakeSystemOps) BootID(context.Context) (string, error) { return "boot-fixture-1", nil }
