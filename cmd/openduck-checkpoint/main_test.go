package main

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"openduck/internal/macoschannel"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseCheckpointRejectsIncompleteProductionInputs(t *testing.T) {
	if _, err := parse(nil); err == nil {
		t.Fatal("incomplete checkpoint configuration accepted")
	}
	if _, err := parse([]string{"unexpected"}); err == nil {
		t.Fatal("positional argument accepted")
	}
}

func TestInstallerCheckpointPlistParsesCompleteJournalContractAndFailsClosed(t *testing.T) {
	f, err := os.Open(filepath.Join("..", "..", "deploy", "macos", "com.openduck.checkpoint.plist"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	args, err := checkpointPlistArguments(f)
	if err != nil || len(args) < 2 {
		t.Fatalf("plist arguments: %v", err)
	}
	digest := strings.Repeat("a", 64)
	values := map[string]string{
		"CHECKPOINT_UID":               "4101",
		"CHECKPOINT_GID":               "4201",
		"ANCHOR_UID":                   "4102",
		"ANCHOR_GID":                   "4202",
		"CHECKPOINT_CHANNEL_GID":       "4301",
		"KEY_EPOCH":                    "1",
		"CHECKPOINT_RELEASE_ID":        "checkpoint-r",
		"ANCHOR_CHECKPOINT_RELEASE_ID": "anchor-r",
		"JOURNAL_IC_RELEASE":           "installer-r",
		"JOURNAL_CP_SOCKET":            digest,
		"JOURNAL_CP_MANIFEST":          digest,
		"JOURNAL_IC_BINARY":            digest,
		"JOURNAL_IC_SOCKET":            digest,
		"JOURNAL_IC_MANIFEST":          digest,
		"JOURNAL_INSTALLER_UID":        "0",
		"JOURNAL_INSTALLER_GID":        "0",
		"JOURNAL_IC_GID":               "4302",
	}
	for n := 1; n < len(args); n++ {
		args[n] = strings.ReplaceAll(args[n], "RELEASE_ID", "checkpoint-r")
		if v, ok := values[args[n]]; ok {
			args[n] = v
		} else if strings.HasSuffix(args[n], "_DIGEST") {
			args[n] = digest
		}
	}
	if _, err := parse(args[1:]); err != nil {
		t.Fatalf("complete checkpoint plist contract rejected: %v", err)
	}
	trimmed := append([]string(nil), args[1:]...)
	for n := 0; n < len(trimmed); n++ {
		if trimmed[n] == "-journal-key-root" {
			trimmed = append(trimmed[:n], trimmed[n+2:]...)
			break
		}
	}
	if _, err := parse(trimmed); err == nil {
		t.Fatal("checkpoint plist accepted without mandatory installer-journal key root")
	}
}

func checkpointPlistArguments(r io.Reader) ([]string, error) {
	d := xml.NewDecoder(r)
	inArguments := false
	var args []string
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return args, nil
		}
		if err != nil {
			return nil, err
		}
		switch v := tok.(type) {
		case xml.StartElement:
			if v.Name.Local == "array" {
				inArguments = true
			} else if inArguments && v.Name.Local == "string" {
				var s string
				if err := d.DecodeElement(&s, &v); err != nil {
					return nil, err
				}
				args = append(args, s)
			}
		case xml.EndElement:
			if v.Name.Local == "array" && inArguments {
				return args, nil
			}
		}
	}
}

func TestParseCheckpointRejectsSharedPrimaryGroup(t *testing.T) {
	o := validOptions()
	o.channelGID = o.localGID
	args := BuildProductionArgs(o)
	if _, err := parse(args); err == nil {
		t.Fatal("primary group reused as channel group")
	}
}

func TestBuildProductionArgsContainsCompleteContract(t *testing.T) {
	o := validOptions()
	args := BuildProductionArgs(o)
	for _, required := range []string{"-state", "-socket-root", "-socket", "-key-root", "-release-root", "-channel", "-local-role", "-peer-role", "-local-uid", "-peer-uid", "-channel-gid", "-key-epoch", "-journal-socket-root", "-journal-socket", "-journal-key-root", "-journal-key-file", "-journal-release-root", "-journal-local-role", "-journal-peer-role", "-journal-peer-uid", "-journal-peer-gid", "-journal-channel-gid"} {
		found := false
		for _, arg := range args {
			if arg == required {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing %s in %v", required, args)
		}
	}
	got, err := parse(args)
	if err != nil {
		t.Fatalf("canonical args rejected: %v", err)
	}
	got.specified = nil
	o.specified = nil
	if !reflect.DeepEqual(got, o) {
		t.Fatalf("round trip mismatch\n got: %#v\nwant: %#v", got, o)
	}
}

func TestParseRejectsJournalOverlapAndIdentityContract(t *testing.T) {
	for name, mutate := range map[string]func(*options){
		"shared socket root":    func(o *options) { o.journalSocketRoot = o.socketRoot },
		"state overlaps key":    func(o *options) { o.state = o.keyRoot },
		"journal roots overlap": func(o *options) { o.journalReleaseRoot = o.journalKeyRoot },
		"nested key root":       func(o *options) { o.journalKeyRoot = o.keyRoot + "/journal" },
		"same socket leaf":      func(o *options) { o.journalSocket = o.socket },
		"wrong channel":         func(o *options) { o.journalRole = "installer" },
		"repurposed primary":    func(o *options) { o.channel = "other" },
		"wrong peer role":       func(o *options) { o.journalPeerRole = "anchor" },
		"same uid":              func(o *options) { o.journalPeerUID = o.localUID },
		"shared channel gid":    func(o *options) { o.journalChannelGID = o.localGID },
	} {
		t.Run(name, func(t *testing.T) {
			o := validOptions()
			mutate(&o)
			if _, err := parse(BuildProductionArgs(o)); err == nil {
				t.Fatal("invalid journal contract accepted")
			}
		})
	}
}

func TestParseRejectsOmittedJournalInputs(t *testing.T) {
	for _, omitted := range []string{"-journal-socket-root", "-journal-socket", "-journal-key-root", "-journal-key-file", "-journal-release-root", "-journal-local-role", "-journal-peer-role", "-journal-peer-uid", "-journal-peer-gid", "-journal-channel-gid", "-journal-local-release", "-journal-peer-release"} {
		t.Run(omitted, func(t *testing.T) {
			args := BuildProductionArgs(validOptions())
			for i := range args {
				if args[i] == omitted {
					args = append(args[:i], args[i+2:]...)
					break
				}
			}
			if _, err := parse(args); err == nil {
				t.Fatalf("omitted %s accepted", omitted)
			}
		})
	}
}

func validOptions() options {
	d := strings.Repeat("a", 64)
	p := func(id string) macoschannel.ReleasePin {
		return macoschannel.ReleasePin{ReleaseID: id, BinaryDigest: d, SocketDigest: d, ManifestDigest: d}
	}
	return options{state: "/state", socketRoot: "/checkpoint-socket", socket: "checkpoint.sock", keyRoot: "/checkpoint-key", keyFile: "service.key", releaseRoot: "/checkpoint-release", journalSocketRoot: "/journal-socket", journalSocket: "journal.sock", journalKeyRoot: "/journal-key", journalKeyFile: "journal.key", journalReleaseRoot: "/journal-release", channel: "platform-checkpoint", localRole: "checkpoint", peerRole: "anchor", journalRole: journalLocalRole, journalPeerRole: journalPeerRole, localRelease: p("checkpoint"), peerRelease: p("anchor"), journalLocalRelease: p("checkpoint-journal"), journalPeerRelease: p("installer"), localUID: 1001, localGID: 1002, peerUID: 1003, peerGID: 1004, channelGID: 1005, journalPeerUID: 0, journalPeerGID: 1006, journalChannelGID: 1007, keyEpoch: 1, numeric: map[string]bool{"local-uid": true, "local-gid": true, "peer-uid": true, "peer-gid": true, "channel-gid": true, "key-epoch": true, "journal-peer-uid": true, "journal-peer-gid": true, "journal-channel-gid": true}}
}

type fakeListener struct {
	started chan struct{}
	fail    error
	closed  chan struct{}
	once    sync.Once
}

func (l *fakeListener) AcceptAuthenticated(ctx context.Context) (macoschannel.Conn, error) {
	select {
	case l.started <- struct{}{}:
	default:
	}
	if l.fail != nil {
		return nil, l.fail
	}
	<-ctx.Done()
	return nil, ctx.Err()
}
func (l *fakeListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }

type unusedServer struct{}

func (unusedServer) ServeConn(context.Context, macoschannel.Conn) error { return nil }

func TestServeBothStartsBothAuthenticatedListeners(t *testing.T) {
	checkpoint := &fakeListener{started: make(chan struct{}, 1), closed: make(chan struct{})}
	journal := &fakeListener{started: make(chan struct{}, 1), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveBoth(ctx, unusedServer{}, checkpoint, unusedServer{}, journal) }()
	for _, l := range []*fakeListener{checkpoint, journal} {
		select {
		case <-l.started:
		case <-time.After(time.Second):
			t.Fatal("listener was not served")
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("signal cancellation: %v", err)
	}
}

func TestServeBothFailureClosesSibling(t *testing.T) {
	failure := errors.New("accept failed")
	checkpoint := &fakeListener{started: make(chan struct{}, 1), fail: failure, closed: make(chan struct{})}
	journal := &fakeListener{started: make(chan struct{}, 1), closed: make(chan struct{})}
	if err := serveBoth(context.Background(), unusedServer{}, checkpoint, unusedServer{}, journal); err == nil || !strings.Contains(err.Error(), "checkpoint accept failed") {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case <-checkpoint.closed:
	case <-time.After(time.Second):
		t.Fatal("failed listener not closed")
	}
	select {
	case <-journal.closed:
	case <-time.After(time.Second):
		t.Fatal("sibling listener not closed")
	}
}
