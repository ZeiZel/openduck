package macosinstall

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

type recordedCommand struct {
	bin  string
	args []string
}

type recordingRunner struct {
	calls  []recordedCommand
	output func(string, []string) ([]byte, error)
}

type splitRunner struct {
	run func([]byte, string, []string) ([]byte, []byte, error)
}

func (r *splitRunner) Run(_ context.Context, stdin []byte, bin string, args ...string) ([]byte, []byte, error) {
	return r.run(append([]byte(nil), stdin...), bin, append([]string(nil), args...))
}

const testGeneratedUID = "5B4E3B04-04E9-4D47-A26D-B73C0D1D25A7"

type membershipRunner struct {
	calls       []recordedCommand
	byName      bool
	byUUID      bool
	failCommand string
}

func (r *membershipRunner) Run(_ context.Context, _ []byte, bin string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, recordedCommand{bin: bin, args: append([]string(nil), args...)})
	if bin != "/usr/bin/dscl" {
		return nil, nil, fmt.Errorf("unexpected binary %s", bin)
	}
	joined := strings.Join(args, " ")
	if joined == r.failCommand {
		return nil, []byte("private directory detail"), errors.New("exit status 40")
	}
	switch joined {
	case ". -read /Users/_openduck GeneratedUID":
		return []byte("GeneratedUID: " + testGeneratedUID + "\n"), nil, nil
	case ". -read /Groups/_openduck_channel":
		var out strings.Builder
		if r.byUUID {
			fmt.Fprintf(&out, "GroupMembers: %s\n", testGeneratedUID)
		}
		if r.byName {
			out.WriteString("GroupMembership: _openduck\n")
		}
		return []byte(out.String()), nil, nil
	case ". -append /Groups/_openduck_channel GroupMembership _openduck":
		r.byName = true
	case ". -append /Groups/_openduck_channel GroupMembers " + testGeneratedUID:
		r.byUUID = true
	case ". -delete /Groups/_openduck_channel GroupMembership _openduck":
		r.byName = false
	case ". -delete /Groups/_openduck_channel GroupMembers " + testGeneratedUID:
		r.byUUID = false
	default:
		return nil, nil, fmt.Errorf("unexpected command %s", joined)
	}
	return nil, nil, nil
}

func (r *recordingRunner) Run(_ context.Context, _ []byte, bin string, args ...string) ([]byte, []byte, error) {
	r.calls = append(r.calls, recordedCommand{bin: bin, args: append([]string(nil), args...)})
	if r.output == nil {
		return nil, nil, nil
	}
	out, err := r.output(bin, args)
	if err != nil {
		return nil, out, err
	}
	return out, nil, nil
}

func TestClassifyLaunchctlPrintDistinguishesAbsentLoadedAndUnknown(t *testing.T) {
	if loaded, err := classifyLaunchctlPrint([]byte("service = com.openduck.anchor\n"), nil); err != nil || !loaded {
		t.Fatal("loaded job not classified")
	}
	for _, out := range []string{"Could not find service com.openduck.anchor in domain for system", "Boot-out failed: 3: No such process"} {
		if loaded, err := classifyLaunchctlPrint([]byte(out), errors.New("exit status 113")); err != nil || loaded {
			t.Fatalf("absent job not classified: %q", out)
		}
	}
	if _, err := classifyLaunchctlPrint([]byte("permission denied"), errors.New("exit status 1")); err == nil {
		t.Fatal("unknown launchctl failure treated as absent")
	}
}

func TestParseDSCLIDRequiresCanonicalAttributeValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want uint32
		ok   bool
	}{
		{"group", "PrimaryGroupID: 498\n", 498, true},
		{"user-multiline", "NFSHomeDirectory: /var/empty\nUniqueID: 497\n", 497, true},
		{"label-not-number", "PrimaryGroupID: wheel\n", 0, false},
		{"unlabelled", "498\n", 0, false},
		{"zero", "UniqueID: 0\n", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attribute := "PrimaryGroupID"
			if tc.name == "user-multiline" || tc.name == "zero" {
				attribute = "UniqueID"
			}
			got, err := parseDSCLID([]byte(tc.out), attribute)
			if (err == nil) != tc.ok || got != tc.want {
				t.Fatalf("got=%d err=%v", got, err)
			}
		})
	}
}

func TestEnsureUserWritesGeneratedUIDBeforeLocalNodeMembership(t *testing.T) {
	const generatedUID = "5B4E3B04-04E9-4D47-A26D-B73C0D1D25A7"
	runner := &recordingRunner{output: func(bin string, args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case joined == ". -read /Users/_openduck_test":
			return []byte("eDSRecordNotFound\n"), errors.New("exit status 185")
		case joined == ". -read /Groups/_openduck_test PrimaryGroupID":
			return []byte("PrimaryGroupID: 498\n"), nil
		case joined == ". -list /Users UniqueID", joined == ". -list /Groups PrimaryGroupID":
			return nil, nil
		case joined == ". -list /Users GeneratedUID":
			return nil, nil
		default:
			return nil, nil
		}
	}}
	op := darwinSystemOps{runner: runner, uuidSource: func() (string, error) { return generatedUID, nil }}
	if err := op.EnsureUser(context.Background(), "_openduck_test", "_openduck_test"); err != nil {
		t.Fatal(err)
	}
	uuidCall := -1
	for index, call := range runner.calls {
		joined := strings.Join(call.args, " ")
		if joined == ". -create /Users/_openduck_test GeneratedUID "+generatedUID {
			uuidCall = index
		}
	}
	if uuidCall < 0 {
		t.Fatalf("GeneratedUID write missing: calls=%+v", runner.calls)
	}
}

func TestCommandFailureHasSafeDiagnosticAndSupportsRollback(t *testing.T) {
	runner := &recordingRunner{output: func(bin string, args []string) ([]byte, error) {
		if bin == "/usr/bin/dscl" && strings.Contains(strings.Join(args, " "), "GroupMembers") {
			return []byte("sensitive directory-service detail"), errors.New("exit status 67")
		}
		return nil, nil
	}}
	op := darwinSystemOps{runner: runner}
	err := op.run(context.Background(), "/usr/bin/dscl", ".", "-append", "/Groups/_openduck_channel", "GroupMembers", testGeneratedUID)
	if err == nil || !strings.Contains(err.Error(), "exit status 67") || !strings.Contains(err.Error(), `"GroupMembers"`) {
		t.Fatalf("unsafe or incomplete diagnostic: %v", err)
	}
	if strings.Contains(err.Error(), "sensitive directory-service detail") {
		t.Fatalf("command output leaked through diagnostic: %v", err)
	}
	diagnostic := (&commandFailure{bin: "/fixed/tool", args: []string{"-P", "literal-secret"}, err: errors.New("exit status 1")}).Error()
	if strings.Contains(diagnostic, "literal-secret") || !strings.Contains(diagnostic, "<redacted>") {
		t.Fatalf("sensitive argv was not redacted: %s", diagnostic)
	}
	if err := op.DeleteUser(context.Background(), "_openduck"); err != nil {
		t.Fatal(err)
	}
	last := runner.calls[len(runner.calls)-1]
	if last.bin != "/usr/bin/dscl" || !reflect.DeepEqual(last.args, []string{".", "-delete", "/Users/_openduck"}) {
		t.Fatalf("rollback command=%+v", last)
	}
}

func TestParsePFLeaseTokenRequiresAnchoredNumericToken(t *testing.T) {
	if got := parsePFLeaseToken([]byte("Token : 12345\n")); got != "12345" {
		t.Fatalf("token=%q", got)
	}
	for _, raw := range []string{"Token: abc\n", "prefix Token : 12\n", "Token : 12x\n"} {
		if got := parsePFLeaseToken([]byte(raw)); got != "" {
			t.Fatalf("unsafe token %q parsed as %q", raw, got)
		}
	}
}

func TestPFInspectionUsesOnlySuccessfulStdoutAndRestoreUsesExactRules(t *testing.T) {
	var restored []byte
	runner := &splitRunner{run: func(stdin []byte, bin string, args []string) ([]byte, []byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "-s info":
			return []byte("Status: Enabled\n"), []byte("pfctl: ALTQ support disabled\n"), nil
		case "-a com.openduck -sr":
			return []byte("pass out keep state\n"), []byte("pfctl: noisy notice\n"), nil
		case "-a com.openduck -F all":
			return nil, []byte("pfctl: unload notice\n"), nil
		case "-a com.openduck -f -":
			restored = append([]byte(nil), stdin...)
			return nil, []byte("pfctl: restore notice\n"), nil
		default:
			return nil, nil, fmt.Errorf("unexpected %s %s", bin, joined)
		}
	}}
	op := darwinSystemOps{runner: runner}
	status, err := op.PFStatus(context.Background())
	if err != nil || string(status) != "Status: Enabled\n" {
		t.Fatalf("status=%q err=%v", status, err)
	}
	rules, err := op.PFRules(context.Background())
	if err != nil || string(rules) != "pass out keep state\n" {
		t.Fatalf("rules=%q err=%v", rules, err)
	}
	if err := op.PFRestore(context.Background(), rules, true); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(restored, rules) {
		t.Fatalf("stderr notice contaminated restore: %q", restored)
	}
}

func TestVerifyJobPollsUntilSamePIDIsStable(t *testing.T) {
	responses := [][]byte{
		[]byte("state = waiting\n"),
		[]byte("state = running\npid = 41\n"),
		[]byte("state = running\npid = 42\n"),
		[]byte("state = running\npid = 42\n"),
	}
	calls := 0
	now := time.Unix(0, 0)
	runner := &splitRunner{run: func(_ []byte, _ string, _ []string) ([]byte, []byte, error) {
		index := calls
		if index >= len(responses) {
			index = len(responses) - 1
		}
		calls++
		return responses[index], []byte("launchctl notice\n"), nil
	}}
	op := darwinSystemOps{
		runner: runner, healthInterval: time.Second, healthTimeout: 10 * time.Second, healthStability: 5 * time.Second,
		healthNow:   func() time.Time { return now },
		healthSleep: func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil },
	}
	if err := op.VerifyJob(context.Background(), "com.openduck.anchor"); err != nil {
		t.Fatal(err)
	}
	if calls < 8 || now.Sub(time.Unix(0, 0)) < 7*time.Second {
		t.Fatalf("health polls=%d elapsed=%s", calls, now.Sub(time.Unix(0, 0)))
	}
}

func TestJobDisabledUsesSuccessfulStdoutOnly(t *testing.T) {
	runner := &splitRunner{run: func(_ []byte, _ string, _ []string) ([]byte, []byte, error) {
		return []byte(`"com.openduck.anchor" => true` + "\n"), []byte(`"com.openduck.anchor" => false` + "\n"), nil
	}}
	disabled, err := (darwinSystemOps{runner: runner}).JobDisabled(context.Background(), "com.openduck.anchor")
	if err != nil || !disabled {
		t.Fatalf("disabled=%v err=%v", disabled, err)
	}
}

func TestChownAndPrincipalIDsUseInjectedReceiverRunner(t *testing.T) {
	var transcript []string
	runner := &splitRunner{run: func(_ []byte, bin string, args []string) ([]byte, []byte, error) {
		entry := bin + " " + strings.Join(args, " ")
		transcript = append(transcript, entry)
		switch entry {
		case "/usr/sbin/chown root:wheel /fixed/path":
			return nil, nil, nil
		case "/usr/bin/id -u _openduck":
			return []byte("501\n"), []byte("id notice\n"), nil
		case "/usr/bin/dscl . -read /Groups/_openduck PrimaryGroupID":
			return []byte("PrimaryGroupID: 502\n"), []byte("dscl notice\n"), nil
		default:
			return nil, nil, fmt.Errorf("unexpected transcript %s", entry)
		}
	}}
	op := darwinSystemOps{runner: runner}
	if err := op.Chown(context.Background(), "/fixed/path", "root", "wheel"); err != nil {
		t.Fatal(err)
	}
	uid, gid, err := op.PrincipalIDs(context.Background(), "_openduck", "_openduck")
	if err != nil || uid != 501 || gid != 502 {
		t.Fatalf("uid=%d gid=%d err=%v", uid, gid, err)
	}
	if len(transcript) != 3 {
		t.Fatalf("transcript=%v", transcript)
	}
}

func TestLocalGroupMembershipAddExistingAndVerify(t *testing.T) {
	t.Run("new", func(t *testing.T) {
		runner := &membershipRunner{}
		op := darwinSystemOps{runner: runner}
		if exists, err := op.MemberExists(context.Background(), "_openduck_channel", "_openduck"); err != nil || exists {
			t.Fatalf("exists=%v err=%v", exists, err)
		}
		if added, err := op.AddGroupMember(context.Background(), "_openduck_channel", "_openduck"); err != nil || !added {
			t.Fatal(err)
		}
		if !runner.byName || !runner.byUUID {
			t.Fatalf("membership not written on both attributes: %+v", runner)
		}
		if err := op.VerifyMembership(context.Background(), "_openduck_channel", "_openduck"); err != nil {
			t.Fatal(err)
		}
		for _, call := range runner.calls {
			if call.bin != "/usr/bin/dscl" {
				t.Fatalf("unpinned membership tool: %+v", call)
			}
		}
	})
	t.Run("existing-no-duplicates", func(t *testing.T) {
		runner := &membershipRunner{byName: true, byUUID: true}
		op := darwinSystemOps{runner: runner}
		if added, err := op.AddGroupMember(context.Background(), "_openduck_channel", "_openduck"); err != nil || added {
			t.Fatal(err)
		}
		for _, call := range runner.calls {
			if strings.Contains(strings.Join(call.args, " "), " -append ") {
				t.Fatalf("existing membership duplicated: %+v", call)
			}
		}
	})
}

func TestLocalGroupMembershipUsesCanonicalDSCLWhenLegacyCheckmemberWouldBeAmbiguous(t *testing.T) {
	runner := &membershipRunner{byName: true, byUUID: true}
	op := darwinSystemOps{runner: runner}
	exists, err := op.MemberExists(context.Background(), "_openduck_channel", "_openduck")
	if err != nil || !exists {
		t.Fatalf("exists=%v err=%v", exists, err)
	}
	for _, call := range runner.calls {
		if strings.Contains(strings.Join(call.args, " "), "checkmember") {
			t.Fatalf("legacy checkmember was invoked: %+v", call)
		}
	}
}

func TestLocalGroupMembershipRejectsOneSidedRecords(t *testing.T) {
	for _, tc := range []struct {
		name   string
		byName bool
		byUUID bool
	}{{"name-only", true, false}, {"uuid-only", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &membershipRunner{byName: tc.byName, byUUID: tc.byUUID}
			op := darwinSystemOps{runner: runner}
			if _, err := op.MemberExists(context.Background(), "_openduck_channel", "_openduck"); err == nil || !strings.Contains(err.Error(), "inconsistent") {
				t.Fatalf("err=%v", err)
			}
			if _, err := op.AddGroupMember(context.Background(), "_openduck_channel", "_openduck"); err == nil || !strings.Contains(err.Error(), "inconsistent") {
				t.Fatalf("err=%v", err)
			}
			if runner.byName != tc.byName || runner.byUUID != tc.byUUID {
				t.Fatal("inconsistent pre-existing state was mutated")
			}
		})
	}
}

func TestLocalGroupMembershipAddCleansNameWhenUUIDAppendFails(t *testing.T) {
	runner := &membershipRunner{failCommand: ". -append /Groups/_openduck_channel GroupMembers " + testGeneratedUID}
	_, err := (darwinSystemOps{runner: runner}).AddGroupMember(context.Background(), "_openduck_channel", "_openduck")
	if err == nil || !strings.Contains(err.Error(), "exit status 40") {
		t.Fatalf("err=%v", err)
	}
	if runner.byName || runner.byUUID {
		t.Fatalf("partial membership survived: %+v", runner)
	}
}

func TestLocalGroupMembershipRemoveAndRestoreOnSecondFailure(t *testing.T) {
	t.Run("remove", func(t *testing.T) {
		runner := &membershipRunner{byName: true, byUUID: true}
		if err := (darwinSystemOps{runner: runner}).RemoveGroupMember(context.Background(), "_openduck_channel", "_openduck"); err != nil {
			t.Fatal(err)
		}
		if runner.byName || runner.byUUID {
			t.Fatalf("membership survived removal: %+v", runner)
		}
	})
	t.Run("restore", func(t *testing.T) {
		runner := &membershipRunner{byName: true, byUUID: true, failCommand: ". -delete /Groups/_openduck_channel GroupMembership _openduck"}
		err := (darwinSystemOps{runner: runner}).RemoveGroupMember(context.Background(), "_openduck_channel", "_openduck")
		if err == nil || !strings.Contains(err.Error(), "exit status 40") {
			t.Fatalf("err=%v", err)
		}
		if !runner.byName || !runner.byUUID {
			t.Fatalf("failed removal was not restored: %+v", runner)
		}
	})
}

func TestEnsurePreexistingUserRequiresGeneratedUIDWithoutMutation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		generatedUID string
		wantError    bool
	}{
		{name: "valid", generatedUID: "5B4E3B04-04E9-4D47-A26D-B73C0D1D25A7"},
		{name: "missing", wantError: true},
		{name: "invalid", generatedUID: "not-a-uuid", wantError: true},
		{name: "duplicate", generatedUID: "5B4E3B04-04E9-4D47-A26D-B73C0D1D25A7", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingRunner{output: func(_ string, args []string) ([]byte, error) {
				joined := strings.Join(args, " ")
				switch {
				case joined == ". -read /Users/_existing":
					return []byte("record exists\n"), nil
				case strings.Contains(joined, ". -read /Users/_existing UniqueID GeneratedUID"):
					return []byte(fmt.Sprintf("UniqueID: 497\nGeneratedUID: %s\nPrimaryGroupID: 498\nUserShell: /usr/bin/false\nNFSHomeDirectory: /var/empty\nIsHidden: 1\n", tc.generatedUID)), nil
				case joined == ". -list /Users GeneratedUID":
					owner := "_existing"
					if tc.name == "duplicate" {
						owner = "_another_user"
					}
					return []byte(owner + " " + tc.generatedUID + "\n"), nil
				case joined == ". -read /Groups/_existing PrimaryGroupID":
					return []byte("PrimaryGroupID: 498\n"), nil
				default:
					return nil, fmt.Errorf("unexpected command: %s", joined)
				}
			}}
			err := (darwinSystemOps{runner: runner}).EnsureUser(context.Background(), "_existing", "_existing")
			if (err != nil) != tc.wantError {
				t.Fatalf("err=%v", err)
			}
			for _, call := range runner.calls {
				if strings.Contains(strings.Join(call.args, " "), " -create ") {
					t.Fatalf("preexisting user mutated: %+v", call)
				}
			}
		})
	}
}

func TestUniqueGeneratedUIDRejectsInvalidAndRetriesCollision(t *testing.T) {
	const duplicate = "5B4E3B04-04E9-4D47-A26D-B73C0D1D25A7"
	const unique = "A67F2193-1F5A-4F2A-B0F3-7E6B4D923A18"
	runner := &recordingRunner{output: func(_ string, args []string) ([]byte, error) {
		if strings.Join(args, " ") != ". -list /Users GeneratedUID" {
			return nil, fmt.Errorf("unexpected command")
		}
		return []byte("_existing " + strings.ToLower(duplicate) + "\n"), nil
	}}
	values := []string{duplicate, unique}
	op := darwinSystemOps{runner: runner, uuidSource: func() (string, error) {
		value := values[0]
		values = values[1:]
		return value, nil
	}}
	got, err := op.uniqueGeneratedUID(context.Background())
	if err != nil || got != unique {
		t.Fatalf("got=%q err=%v", got, err)
	}
	op.uuidSource = func() (string, error) { return "invalid", nil }
	if _, err := op.uniqueGeneratedUID(context.Background()); err == nil {
		t.Fatal("invalid generated UUID accepted")
	}
	for _, value := range []string{"", "5B4E3B0404E94D47A26DB73C0D1D25A7", "5B4E3B04-04E9-4D47-A26D-B73C0D1D25AZ"} {
		if canonicalGeneratedUID(value) {
			t.Fatalf("invalid UUID accepted: %q", value)
		}
	}
	if value, err := randomGeneratedUID(); err != nil || !canonicalGeneratedUID(value) || value[14] != '4' || !strings.Contains("89AB", string(value[19])) {
		t.Fatalf("random RFC4122 v4 UUID=%q err=%v", value, err)
	}
}
