package beadsview

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	output map[Operation][]byte
	args   []string
	ns     Namespace
	query  string
	err    error
}

func (f *fakeRunner) Run(ctx context.Context, ns Namespace, op Operation, q string) (CommandOutput, error) {
	if err := ctx.Err(); err != nil {
		return CommandOutput{}, err
	}
	f.ns = ns
	f.query = q
	f.args = []string{string(op)}
	if f.err != nil {
		return CommandOutput{}, f.err
	}
	return CommandOutput{Stdout: f.output[op]}, nil
}

func TestProviderStableDedupAndSort(t *testing.T) {
	f := &fakeRunner{output: map[Operation][]byte{opGraph: []byte(`{"nodes":[{"id":"b","namespace":"project","kind":"issue","title":"B","status":"open","sensitivity":"safe","provenance":"fixture"},{"id":"a","namespace":"project","kind":"issue","title":"A","status":"open","sensitivity":"safe","provenance":"fixture"},{"id":"a","namespace":"project","kind":"issue","title":"duplicate","status":"open","sensitivity":"safe","provenance":"fixture"}],"edges":[]}`)}}
	p, _ := NewProvider(f)
	g, err := p.Graph(context.Background(), Project)
	if err != nil || len(g.Nodes) != 2 || g.Nodes[0].ID != "project:a" || g.Nodes[1].ID != "project:b" {
		t.Fatalf("unexpected graph: %#v %v", g, err)
	}
}

func TestProviderAcceptsBDArrayShape(t *testing.T) {
	f := &fakeRunner{output: map[Operation][]byte{opGraph: []byte(`[{"id":"od-1","title":"Issue","description":"","acceptance_criteria":"","notes":"","status":"open","priority":1,"issue_type":"task","assignee":"","owner":"","created_at":"2026-08-20T00:00:00Z","created_by":"fixture","updated_at":"2026-08-20T00:00:00Z","started_at":"","dependencies":[],"dependency_count":0,"dependent_count":0,"comment_count":0,"parent":""}]`)}}
	p, _ := NewProvider(f)
	g, err := p.Graph(context.Background(), Project)
	if err != nil || len(g.Nodes) != 1 || g.Nodes[0].ID != "project:od-1" {
		t.Fatalf("array adapter failed: %#v %v", g, err)
	}
}

func TestGlobalProjectionRedactsSentinel(t *testing.T) {
	f := &fakeRunner{output: map[Operation][]byte{opGraph: []byte(`{"nodes":[{"id":"PRIVATE-CLAIM","namespace":"global","kind":"secret","title":"PRIVATE-SENTINEL","status":"private","sensitivity":"PRIVATE","provenance":"claim"}],"edges":[]}`), opSearch: []byte(`{"items":[{"id":"PRIVATE-KEY","namespace":"global","kind":"secret","title":"PRIVATE-SENTINEL","status":"private","sensitivity":"PRIVATE","provenance":"claim"}]}`), opChats: []byte(`{"items":[{"id":"PRIVATE-CHAT","namespace":"global","category":"PRIVATE","sensitivity":"PRIVATE","status":"private","provenance":"claim","updated_at":"2026-08-20T00:00:00Z"}]}`)}}
	p, _ := NewProvider(f)
	g, err := p.Graph(context.Background(), Global)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustJSON(g)), "PRIVATE-SENTINEL") || strings.Contains(g.Nodes[0].ID, "PRIVATE") {
		t.Fatalf("private sentinel escaped: %#v", g)
	}
	n := g.Nodes[0]
	if n.Title != "global memory metadata" || n.Kind != "memory" || n.Status != "metadata" || n.Sensitivity != "private" || n.Provenance != "controller:beads/global-metadata" {
		t.Fatalf("global graph source metadata escaped: %#v", n)
	}
	s, err := p.Search(context.Background(), Global, "memory")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s[0].ID, "PRIVATE") || s[0].Title != "global memory metadata" {
		t.Fatalf("private search escaped: %#v", s)
	}
	if s[0].Kind != "memory" || s[0].Status != "metadata" || s[0].Sensitivity != "private" || s[0].Provenance != "controller:beads/global-metadata" {
		t.Fatalf("global search source metadata escaped: %#v", s[0])
	}
	c, err := p.MemoryChats(context.Background(), Global)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c[0].ID, "PRIVATE") || c[0].Category != "global memory metadata" {
		t.Fatalf("private chat escaped: %#v", c)
	}
	if c[0].Sensitivity != "private" || c[0].Status != "metadata" || c[0].Provenance != "controller:beads/global-metadata" {
		t.Fatalf("global chat source metadata escaped: %#v", c[0])
	}
}

func TestStrictJSONAndBounds(t *testing.T) {
	f := &fakeRunner{output: map[Operation][]byte{opGraph: []byte(`{"nodes":[],"edges":[],"unknown":true`)}}
	p, _ := NewProvider(f)
	if _, err := p.Graph(context.Background(), Project); !errors.Is(err, ErrProtocol) {
		t.Fatalf("unknown fields must fail closed: %v", err)
	}
	item := `{"id":"x","namespace":"project","kind":"i","title":"t","status":"s","sensitivity":"safe","provenance":"p"}`
	f.output[opGraph] = []byte(`{"nodes":[` + strings.TrimSuffix(strings.Repeat(item+`,`, MaxItems+1), `,`) + `],"edges":[]}`)
	if _, err := p.Graph(context.Background(), Project); !errors.Is(err, ErrBounds) {
		t.Fatalf("oversized list must fail: %v", err)
	}
	f.output[opGraph] = []byte(`{"nodes":[],"nodes":[],"edges":[]}`)
	if _, err := p.Graph(context.Background(), Project); !errors.Is(err, ErrProtocol) {
		t.Fatalf("duplicate keys must fail: %v", err)
	}
	deep := strings.Repeat(`[`, maxJSONDepth+2) + `null` + strings.Repeat(`]`, maxJSONDepth+2)
	if err := validateJSON([]byte(deep), 0); !errors.Is(err, ErrProtocol) && !errors.Is(err, ErrBounds) {
		t.Fatalf("deep JSON must fail: %v", err)
	}
}

func TestSearchRejectsInjectionAndCancelledContext(t *testing.T) {
	f := &fakeRunner{output: map[Operation][]byte{opSearch: []byte(`{"items":[]`)}}
	p, _ := NewProvider(f)
	if _, err := p.Search(context.Background(), Project, "x\n--global"); !errors.Is(err, ErrBounds) {
		t.Fatalf("query injection not rejected: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Search(ctx, Project, "x"); err == nil {
		t.Fatal("cancelled query must fail")
	}
}

func TestExecRunnerArgumentAndRootValidation(t *testing.T) {
	if _, err := NewExecRunner(Config{Binary: "bd", ProjectRoot: "/tmp/project", GlobalDatabase: "/tmp/global"}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("relative binary must fail: %v", err)
	}
	if !validateString("x") || validateString(strings.Repeat("x", MaxString+1)) {
		t.Fatal("string bounds broken")
	}
	if _, err := RedactPrivate("project", "k", "c", "s", "p"); err == nil {
		t.Fatal("project private ref must fail")
	}
	ref, err := RedactPrivate("global", "PRIVATE-KEY", "PRIVATE-CATEGORY", "PRIVATE-SENSITIVITY", "PRIVATE-PROVENANCE")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mustJSON(ref)), "PRIVATE") || ref.Category != "redacted" || ref.Sensitivity != "private" || ref.Provenance != "controller-approved" {
		t.Fatalf("unsafe private ref: %#v", ref)
	}
}

func TestNewExecRunnerCleansPinnedExecutableOnProjectRootErrors(t *testing.T) {
	type setup func(t *testing.T, base string) string
	cases := []struct {
		name  string
		setup setup
	}{
		{name: "missing", setup: func(_ *testing.T, base string) string {
			return filepath.Join(base, "missing")
		}},
		{name: "symlink", setup: func(t *testing.T, base string) string {
			target := t.TempDir()
			root := filepath.Join(base, "symlink")
			if err := os.Symlink(target, root); err != nil {
				t.Fatal(err)
			}
			return root
		}},
		{name: "unsafe ancestor", setup: func(t *testing.T, base string) string {
			target := t.TempDir()
			link := filepath.Join(base, "unsafe-link")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "project")
		}},
		{name: "not directory", setup: func(t *testing.T, base string) string {
			root := filepath.Join(base, "not-directory")
			if err := os.WriteFile(root, []byte("fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			return root
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for attempt := 0; attempt < 3; attempt++ {
				base := t.TempDir()
				binary := filepath.Join(base, "bd")
				if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0700); err != nil {
					t.Fatal(err)
				}
				root := tc.setup(t, base)
				_, err := NewExecRunner(Config{
					Binary:              binary,
					ProjectRoot:         root,
					GlobalDatabase:      filepath.Join(base, "global"),
					AllowedProjectRoots: []string{base},
				})
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("NewExecRunner error=%v, want ErrInvalidConfig", err)
				}
				leaks, globErr := filepath.Glob(filepath.Join(base, ".openduck-bd-*"))
				if globErr != nil {
					t.Fatal(globErr)
				}
				if len(leaks) != 0 {
					t.Fatalf("constructor leaked pinned hardlinks: %v", leaks)
				}
			}
		})
	}
}

func TestProjectCLIArgsAreClosedAndReadOnly(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "testdata", "bd")
	identity, execPath, err := pinExecutable(binary)
	if err != nil {
		t.Fatal(err)
	}
	cwdIdentity, _ := pinDirectory(root)
	r := &ExecRunner{binary: binary, execPath: execPath, projectRoot: root, globalDatabase: "/private/tmp/beads-global", timeout: time.Second, maxOutput: MaxOutput, identity: identity, cwdIdentity: cwdIdentity}
	defer r.Close()
	var got []string
	r.command = func(_ context.Context, _ string, args []string, cwd string, env []string, _ int) ([]byte, []byte, error) {
		got = append([]string(nil), args...)
		if cwd != root || len(env) != 3 {
			t.Fatalf("unsafe launch metadata: %q %q", cwd, env)
		}
		return []byte(`[]`), []byte("private stderr"), nil
	}
	o, err := r.Run(context.Background(), Project, opGraph, "")
	if err != nil {
		t.Fatal(err)
	}
	if o.Stderr != nil {
		t.Fatal("stderr must never be returned")
	}
	want := []string{"--json", "--readonly", "--sandbox", "--dolt-auto-commit=off", "list", "--status=all", "--flat", "--no-pager"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv=%q want %q", got, want)
	}
	if _, err := r.Run(context.Background(), Global, opGraph, ""); !errors.Is(err, ErrGlobalDisabled) {
		t.Fatalf("global must fail closed: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(execPath); !os.IsNotExist(err) {
		t.Fatalf("pinned hardlink was not cleaned: %v", err)
	}
}

func TestExecRunnerCloseDoesNotRemoveReplacement(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	identity, execPath, err := pinExecutable(filepath.Join(root, "testdata", "bd"))
	if err != nil {
		t.Fatal(err)
	}
	r := &ExecRunner{execPath: execPath, identity: identity}
	if err := os.Remove(execPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(execPath, []byte("replacement"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(execPath); err != nil {
		t.Fatalf("replacement removed: %v", err)
	}
	_ = os.Remove(execPath)
	_ = os.Remove(filepath.Dir(execPath))
}

func TestExecRunnerCloseDoesNotRemoveReplacementAtRemovalBarrier(t *testing.T) {
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	identity, execPath, err := pinExecutable(filepath.Join(root, "testdata", "bd"))
	if err != nil {
		t.Fatal(err)
	}
	r := &ExecRunner{execPath: execPath, identity: identity}
	replaced := false
	pinnedRemoveBarrier = func(path string) {
		replaced = true
		if err := os.Remove(path); err != nil {
			t.Fatalf("replace barrier remove: %v", err)
		}
		if err := os.WriteFile(path, []byte("replacement"), 0700); err != nil {
			t.Fatalf("replace barrier write: %v", err)
		}
	}
	defer func() { pinnedRemoveBarrier = nil }()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if !replaced {
		t.Fatal("replacement barrier was not invoked")
	}
	if b, err := os.ReadFile(execPath); err != nil || string(b) != "replacement" {
		t.Fatalf("replacement was removed or altered: %q, %v", b, err)
	}
	_ = os.Remove(execPath)
	_ = os.Remove(filepath.Dir(execPath))
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestSchemaParityDeclarations(t *testing.T) {
	b, err := os.ReadFile("../../schemas/beads-view/contracts.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Defs map[string]json.RawMessage `json:"$defs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"scope", "node", "edge", "search_result", "memory_chat", "private_ref"} {
		if _, ok := doc.Defs[name]; !ok {
			t.Fatalf("schema missing %s", name)
		}
	}
	for _, value := range []any{Scope{}, Graph{}, SearchResult{}, MemoryChatMetadata{}, PrivateMemoryRef{}} {
		if len(mustJSON(value)) == 0 {
			t.Fatal("projection failed to marshal")
		}
	}
}

func TestRunCommandKillsInheritedPipeDescendantsOnTimeout(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hang.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n(sleep 30)&\nwait\n"), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, _, err := runCommand(ctx, "/bin/sh", []string{script}, dir, []string{"PATH=/bin"}, 1024)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error=%v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("descendant kept command alive: %v", time.Since(started))
	}
}

func TestRunCommandKillsInheritedPipeDescendantsOnOverflow(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "spam.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n(while :; do echo x; done)&\nwait\n"), 0700); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, _, err := runCommand(context.Background(), "/bin/sh", []string{script}, dir, []string{"PATH=/bin"}, 1024)
	if !errors.Is(err, ErrBounds) {
		t.Fatalf("overflow error=%v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("grandchild kept command alive: %v", time.Since(started))
	}
}
