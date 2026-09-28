// Package beadsview exposes a Controller-owned, read-only Beads projection.
// It intentionally has no filesystem, DSH, browser, or mutation surface.
package beadsview

import (
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	SchemaVersion = "beads-view.v1"
	MaxItems      = 128
	MaxEdges      = 256
	MaxString     = 512
	MaxOutput     = 1 << 20
)

var (
	ErrInvalidConfig  = errors.New("invalid beads view configuration")
	ErrProtocol       = errors.New("invalid beads view response")
	ErrBounds         = errors.New("beads view bounds exceeded")
	ErrUnsupported    = errors.New("unsupported beads view operation")
	ErrGlobalDisabled = errors.New("global beads content provider disabled")
	// pinnedRemoveBarrier is test-only synchronization for proving that
	// cleanup refuses an inode replacement between validation and unlink.
	pinnedRemoveBarrier func(string)
)

type Namespace string

const (
	Project Namespace = "project"
	Global  Namespace = "global"
)

type Scope struct {
	Namespace  Namespace `json:"namespace"`
	ID         string    `json:"id"`
	Root       string    `json:"root,omitempty"`
	Provenance string    `json:"provenance"`
	ItemCount  int       `json:"item_count"`
}

type GraphNode struct {
	ID          string    `json:"id"`
	Namespace   Namespace `json:"namespace"`
	Kind        string    `json:"kind"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Sensitivity string    `json:"sensitivity"`
	Provenance  string    `json:"provenance"`
}
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}
type Graph struct {
	SchemaVersion string      `json:"schema_version"`
	Scope         Scope       `json:"scope"`
	Nodes         []GraphNode `json:"nodes"`
	Edges         []GraphEdge `json:"edges"`
}
type SearchResult struct {
	ID          string    `json:"id"`
	Namespace   Namespace `json:"namespace"`
	Kind        string    `json:"kind"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Sensitivity string    `json:"sensitivity"`
	Provenance  string    `json:"provenance"`
}
type MemoryChatMetadata struct {
	ID          string    `json:"id"`
	Namespace   Namespace `json:"namespace"`
	Category    string    `json:"category"`
	Sensitivity string    `json:"sensitivity"`
	Status      string    `json:"status"`
	Provenance  string    `json:"provenance"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Provider interface {
	Scopes(context.Context) ([]Scope, error)
	Graph(context.Context, Namespace) (Graph, error)
	Search(context.Context, Namespace, string) ([]SearchResult, error)
	MemoryChats(context.Context, Namespace) ([]MemoryChatMetadata, error)
}

type Operation string

const (
	opGraph  Operation = "graph"
	opSearch Operation = "search"
	opChats  Operation = "chats"
)

type CommandOutput struct {
	Stdout []byte
	Stderr []byte
}
type CommandRunner interface {
	Run(context.Context, Namespace, Operation, string) (CommandOutput, error)
}

type Config struct {
	Binary              string
	ProjectRoot         string
	GlobalDatabase      string
	AllowedProjectRoots []string
	Timeout             time.Duration
	MaxOutput           int
	Runner              CommandRunner
}

// ExecRunner is the only production command adapter. Arguments are generated
// from a closed operation set; callers cannot provide a command or environment.
type ExecRunner struct {
	binary, projectRoot, globalDatabase string
	timeout                             time.Duration
	maxOutput                           int
	identity                            fileIdentity
	cwdIdentity                         fileIdentity
	execPath                            string
	command                             func(context.Context, string, []string, string, []string, int) ([]byte, []byte, error)
	closeMu                             sync.Mutex
	closed                              bool
}

func NewExecRunner(c Config) (*ExecRunner, error) {
	base := filepath.Base(c.Binary)
	if c.Binary == "" || base != "bd" && base != "bd.js" || !filepath.IsAbs(c.Binary) || filepath.Clean(c.Binary) != c.Binary || c.ProjectRoot == "" || !filepath.IsAbs(c.ProjectRoot) || filepath.Clean(c.ProjectRoot) != c.ProjectRoot || c.GlobalDatabase == "" || !filepath.IsAbs(c.GlobalDatabase) || filepath.Clean(c.GlobalDatabase) != c.GlobalDatabase {
		return nil, ErrInvalidConfig
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
	if c.Timeout > 30*time.Second {
		return nil, ErrInvalidConfig
	}
	if c.MaxOutput <= 0 {
		c.MaxOutput = MaxOutput
	}
	if c.MaxOutput > MaxOutput {
		return nil, ErrInvalidConfig
	}
	if len(c.AllowedProjectRoots) == 0 || !withinAnyRoot(c.ProjectRoot, c.AllowedProjectRoots) {
		return nil, ErrInvalidConfig
	}
	identity, execPath, err := pinExecutable(c.Binary)
	if err != nil {
		return nil, err
	}
	cwdIdentity, err := pinDirectory(c.ProjectRoot)
	if err != nil {
		// pinExecutable creates a same-directory hardlink which owns the
		// executable inode for the lifetime of the runner.  Nothing owns that
		// link until the runner is returned, so release it on every constructor
		// failure after pinning (including an invalid project root).
		_ = removePinnedExecutable(execPath, identity)
		return nil, err
	}
	if _, err := os.Stat(c.ProjectRoot); err != nil {
		_ = removePinnedExecutable(execPath, identity)
		return nil, ErrInvalidConfig
	}
	return &ExecRunner{binary: c.Binary, projectRoot: c.ProjectRoot, globalDatabase: c.GlobalDatabase, timeout: c.Timeout, maxOutput: c.MaxOutput, identity: identity, cwdIdentity: cwdIdentity, execPath: execPath, command: runCommand}, nil
}

func (r *ExecRunner) Run(ctx context.Context, ns Namespace, op Operation, query string) (CommandOutput, error) {
	r.closeMu.Lock()
	closed := r.closed
	r.closeMu.Unlock()
	if closed {
		return CommandOutput{}, ErrInvalidConfig
	}
	if ctx == nil {
		return CommandOutput{}, ErrProtocol
	}
	if op != opGraph && op != opSearch {
		return CommandOutput{}, ErrUnsupported
	}
	if ns == Global {
		return CommandOutput{}, ErrGlobalDisabled
	}
	if ns != Project {
		return CommandOutput{}, ErrUnsupported
	}
	if len(query) > MaxString || strings.ContainsAny(query, "\x00\r\n") {
		return CommandOutput{}, ErrBounds
	}
	if err := verifyExecutable(r.binary, r.execPath, r.identity); err != nil {
		return CommandOutput{}, err
	}
	if err := verifyDirectory(r.projectRoot, r.cwdIdentity); err != nil {
		return CommandOutput{}, err
	}
	args := []string{"--json", "--readonly", "--sandbox", "--dolt-auto-commit=off", "list", "--status=all", "--flat", "--no-pager"}
	if op == opSearch {
		args = []string{"--json", "--readonly", "--sandbox", "--dolt-auto-commit=off", "search", "--status=all", "--query=" + query}
	}
	cwd := r.projectRoot
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	out, errOut, err := r.command(ctx, r.execPathOrBinary(), args, cwd, []string{"PATH=" + filepath.Dir(r.binary), "LC_ALL=C", "LANG=C"}, r.maxOutput)
	if len(out) > r.maxOutput || len(errOut) > r.maxOutput {
		return CommandOutput{}, ErrBounds
	}
	if err != nil {
		return CommandOutput{}, fmt.Errorf("beads command failed: %w", err)
	}
	_ = errOut
	return CommandOutput{Stdout: out}, nil
}
func (r *ExecRunner) execPathOrBinary() string {
	if r.execPath != "" {
		return r.execPath
	}
	return r.binary
}

// Close removes only the hardlink created by pinExecutable. It is idempotent
// and never removes a replacement inode at the pinned pathname.
func (r *ExecRunner) Close() error {
	r.closeMu.Lock()
	defer r.closeMu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return removePinnedExecutable(r.execPath, r.identity)
}

// removePinnedExecutable removes only the hardlink for the expected inode.
// It is deliberately idempotent and replacement-safe so it can be used both
// by ExecRunner.Close and while unwinding NewExecRunner construction.
func removePinnedExecutable(execPath string, identity fileIdentity) error {
	if execPath == "" {
		return nil
	}
	pinDir := filepath.Dir(execPath)
	// The pinned link lives in a private, unique directory.  Keep the
	// directory opened while validating and unlinking so a replacement of an
	// ancestor pathname cannot redirect cleanup to another location.
	root, err := os.OpenRoot(pinDir)
	if err != nil {
		return err
	}
	defer root.Close()
	fi, err := root.Lstat(filepath.Base(execPath))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != identity.dev || uint64(st.Ino) != identity.ino {
		return nil
	}
	if pinnedRemoveBarrier != nil {
		pinnedRemoveBarrier(execPath)
		fi, err = root.Lstat(filepath.Base(execPath))
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		st, ok = fi.Sys().(*syscall.Stat_t)
		if !ok || uint64(st.Dev) != identity.dev || uint64(st.Ino) != identity.ino {
			return nil
		}
	}
	if err := root.Remove(filepath.Base(execPath)); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Removing the private directory is intentionally best-effort: if an
	// unexpected replacement is present, leave it in place rather than
	// deleting an inode that this runner does not own.
	if err := os.Remove(pinDir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func runCommand(ctx context.Context, binary string, args []string, cwd string, env []string, limit int) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Dir = cwd
	cmd.Env = append([]string(nil), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	outDone := make(chan collectorResult, 1)
	errDone := make(chan collectorResult, 1)
	go collectStream(outPipe, limit, outDone)
	go collectStream(errPipe, limit, errDone)
	var outRes, errRes collectorResult
	var waitErr error
	gotOut, gotErr, gotWait := false, false, false
	killed := false
	var terminalErr error
	kill := func(reason error) {
		if killed {
			return
		}
		killed = true
		terminalErr = reason
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Process.Kill()
		}
		_ = outPipe.Close()
		_ = errPipe.Close()
	}
	for !(gotOut && gotErr && gotWait) {
		select {
		case outRes = <-outDone:
			gotOut = true
			if outRes.err != nil {
				kill(ErrBounds)
			}
		case errRes = <-errDone:
			gotErr = true
			if errRes.err != nil {
				kill(ErrBounds)
			}
		case waitErr = <-waitDone:
			gotWait = true
		case <-ctx.Done():
			kill(ctx.Err())
		}
		if killed && !gotWait {
			select {
			case waitErr = <-waitDone:
				gotWait = true
			case <-time.After(500 * time.Millisecond):
				return nil, nil, terminalErr
			}
		}
	}
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if terminalErr != nil {
		return nil, nil, terminalErr
	}
	if outRes.err != nil || errRes.err != nil {
		return nil, nil, ErrBounds
	}
	return outRes.data, nil, waitErr
}

type collectorResult struct {
	data []byte
	err  error
}

func collectStream(r io.Reader, limit int, ch chan<- collectorResult) {
	b := &boundedBuffer{limit: limit}
	_, err := io.Copy(b, r)
	ch <- collectorResult{data: b.Bytes(), err: err}
}

type boundedBuffer struct {
	b     []byte
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(b.b)+len(p) > b.limit {
		return 0, ErrBounds
	}
	b.b = append(b.b, p...)
	return len(p), nil
}
func (b *boundedBuffer) Bytes() []byte { return append([]byte(nil), b.b...) }

type fileIdentity struct {
	dev, ino uint64
	uid      uint32
	mode     os.FileMode
	digest   [32]byte
}

func pinExecutable(path string) (fileIdentity, string, error) {
	if err := validateDirectoryComponents(filepath.Dir(path)); err != nil {
		return fileIdentity{}, "", ErrInvalidConfig
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fileIdentity{}, "", ErrInvalidConfig
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0111 == 0 {
		return fileIdentity{}, "", ErrInvalidConfig
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uint32(os.Getuid()) {
		return fileIdentity{}, "", ErrInvalidConfig
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, 32<<20+1)); err != nil {
		return fileIdentity{}, "", ErrInvalidConfig
	}
	pinDir, err := os.MkdirTemp(filepath.Dir(path), ".openduck-bd-")
	if err != nil {
		return fileIdentity{}, "", ErrInvalidConfig
	}
	if err := os.Chmod(pinDir, 0700); err != nil {
		_ = os.Remove(pinDir)
		return fileIdentity{}, "", ErrInvalidConfig
	}
	link := filepath.Join(pinDir, filepath.Base(path))
	if err := os.Link(path, link); err != nil {
		_ = os.Remove(pinDir)
		return fileIdentity{}, "", ErrInvalidConfig
	}
	linked, err := os.Stat(link)
	if err != nil || !os.SameFile(fi, linked) {
		_ = os.Remove(link)
		_ = os.Remove(pinDir)
		return fileIdentity{}, "", ErrInvalidConfig
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), uid: uint32(st.Uid), mode: fi.Mode(), digest: digest}, link, nil
}
func verifyExecutable(path, execPath string, want fileIdentity) error {
	check := execPath
	if check == "" {
		check = path
	}
	fi, err := os.Lstat(check)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidConfig
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != want.dev || uint64(st.Ino) != want.ino || uint32(st.Uid) != want.uid || fi.Mode() != want.mode {
		return ErrInvalidConfig
	}
	f, err := os.OpenFile(check, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return ErrInvalidConfig
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, 32<<20+1)); err != nil {
		return ErrInvalidConfig
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	if digest != want.digest {
		return ErrInvalidConfig
	}
	return nil
}
func pinDirectory(path string) (fileIdentity, error) {
	if err := validateDirectoryComponents(path); err != nil {
		return fileIdentity{}, ErrInvalidConfig
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return fileIdentity{}, ErrInvalidConfig
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || uint32(st.Uid) != uint32(os.Getuid()) {
		return fileIdentity{}, ErrInvalidConfig
	}
	return fileIdentity{dev: uint64(st.Dev), ino: uint64(st.Ino), uid: uint32(st.Uid), mode: fi.Mode()}, nil
}
func verifyDirectory(path string, want fileIdentity) error {
	got, err := pinDirectory(path)
	if err != nil || got != want {
		return ErrInvalidConfig
	}
	return nil
}
func validateDirectoryComponents(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrInvalidConfig
	}
	cur := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" || part == "." || part == ".." {
			return ErrInvalidConfig
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return ErrInvalidConfig
		}
	}
	return nil
}
func withinAnyRoot(path string, roots []string) bool {
	for _, root := range roots {
		if filepath.IsAbs(root) && filepath.Clean(root) == root && (path == root || strings.HasPrefix(path, root+string(filepath.Separator))) {
			return true
		}
	}
	return false
}

type ProviderFromRunner struct{ runner CommandRunner }

func NewProvider(r CommandRunner) (*ProviderFromRunner, error) {
	if r == nil {
		return nil, ErrInvalidConfig
	}
	return &ProviderFromRunner{runner: r}, nil
}
func (p *ProviderFromRunner) Scopes(context.Context) ([]Scope, error) {
	return []Scope{{Namespace: Project, ID: "project", Provenance: "controller:beads/project"}, {Namespace: Global, ID: "global", Provenance: "controller:beads/global-metadata"}}, nil
}
func (p *ProviderFromRunner) Graph(ctx context.Context, ns Namespace) (Graph, error) {
	o, e := p.runner.Run(ctx, ns, opGraph, "")
	if e != nil {
		return Graph{}, e
	}
	var raw graphWire
	if e = decode(o.Stdout, &raw); e != nil {
		var issues []bdIssue
		if e2 := decode(o.Stdout, &issues); e2 != nil {
			return Graph{}, e
		}
		raw = graphFromIssues(issues)
	}
	provenance := "controller:beads/project"
	if ns == Global {
		provenance = "controller:beads/global-metadata"
	}
	g := Graph{SchemaVersion: SchemaVersion, Scope: Scope{Namespace: ns, ID: string(ns), Provenance: provenance}, Nodes: raw.Nodes, Edges: raw.Edges}
	if ns == Global {
		sanitizeGlobalGraph(&g)
	}
	return normalizeGraph(g)
}
func (p *ProviderFromRunner) Search(ctx context.Context, ns Namespace, q string) ([]SearchResult, error) {
	if q == "" || len(q) > MaxString || strings.ContainsAny(q, "\x00\r\n") {
		return nil, ErrBounds
	}
	o, e := p.runner.Run(ctx, ns, opSearch, q)
	if e != nil {
		return nil, e
	}
	var raw searchWire
	if e = decode(o.Stdout, &raw); e != nil {
		var issues []bdIssue
		if e2 := decode(o.Stdout, &issues); e2 != nil {
			return nil, e
		}
		raw = searchFromIssues(issues)
	}
	for i := range raw.Items {
		raw.Items[i].Namespace = ns
	}
	if ns == Global {
		sanitizeGlobalSearch(raw.Items)
	}
	return normalizeSearch(raw.Items)
}
func (p *ProviderFromRunner) MemoryChats(ctx context.Context, ns Namespace) ([]MemoryChatMetadata, error) {
	o, e := p.runner.Run(ctx, ns, opChats, "")
	if e != nil {
		return nil, e
	}
	var raw chatsWire
	if e = decode(o.Stdout, &raw); e != nil {
		return nil, e
	}
	for i := range raw.Items {
		raw.Items[i].Namespace = ns
	}
	if ns == Global {
		for i := range raw.Items {
			raw.Items[i].ID = opaqueGlobalID(raw.Items[i].ID)
			raw.Items[i].Category = "global memory metadata"
			raw.Items[i].Sensitivity = "private"
			raw.Items[i].Status = "metadata"
			raw.Items[i].Provenance = "controller:beads/global-metadata"
		}
	}
	return normalizeChats(raw.Items)
}

type graphWire struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}
type searchWire struct {
	Items []SearchResult `json:"items"`
}
type chatsWire struct {
	Items []MemoryChatMetadata `json:"items"`
}
type bdDependency struct {
	IssueID     string `json:"issue_id"`
	DependsOnID string `json:"depends_on_id"`
	Type        string `json:"type"`
	CreatedAt   string `json:"created_at"`
	CreatedBy   string `json:"created_by"`
	Metadata    string `json:"metadata"`
}
type bdIssue struct {
	ID              string          `json:"id"`
	Title           string          `json:"title"`
	Description     string          `json:"description"`
	Acceptance      string          `json:"acceptance_criteria"`
	Notes           string          `json:"notes"`
	Status          string          `json:"status"`
	Priority        json.RawMessage `json:"priority"`
	IssueType       string          `json:"issue_type"`
	Assignee        string          `json:"assignee"`
	Owner           string          `json:"owner"`
	CreatedAt       string          `json:"created_at"`
	CreatedBy       string          `json:"created_by"`
	UpdatedAt       string          `json:"updated_at"`
	StartedAt       string          `json:"started_at"`
	Dependencies    []bdDependency  `json:"dependencies"`
	DependencyCount int             `json:"dependency_count"`
	DependentCount  int             `json:"dependent_count"`
	CommentCount    int             `json:"comment_count"`
	Parent          string          `json:"parent"`
}

func graphFromIssues(issues []bdIssue) graphWire {
	out := graphWire{}
	for _, x := range issues {
		out.Nodes = append(out.Nodes, GraphNode{ID: x.ID, Namespace: Project, Kind: x.IssueType, Title: x.Title, Status: x.Status, Sensitivity: "safe", Provenance: "bd:list"})
		for _, d := range x.Dependencies {
			out.Edges = append(out.Edges, GraphEdge{From: x.ID, To: d.DependsOnID, Kind: d.Type})
		}
	}
	return out
}
func searchFromIssues(issues []bdIssue) searchWire {
	out := searchWire{}
	for _, x := range issues {
		out.Items = append(out.Items, SearchResult{ID: x.ID, Namespace: Project, Kind: x.IssueType, Title: x.Title, Status: x.Status, Sensitivity: "safe", Provenance: "bd:search"})
	}
	return out
}

func decode(b []byte, v any) error {
	if len(b) > MaxOutput {
		return ErrBounds
	}
	if err := validateJSON(b, 0); err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	return nil
}

const maxJSONDepth = 12

func validateJSON(b []byte, depth int) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	if err := validateJSONValue(d, depth); err != nil {
		return fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrProtocol
	}
	return nil
}
func validateJSONValue(d *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return ErrBounds
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				keyToken, keyErr := d.Token()
				key, ok := keyToken.(string)
				if keyErr != nil {
					return keyErr
				}
				if !ok || seen[key] {
					return ErrProtocol
				}
				seen[key] = true
				if err := validateJSONValue(d, depth+1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err := validateJSONValue(d, depth+1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
	}
	return nil
}
func validateString(s string) bool {
	return s != "" && len(s) <= MaxString && !strings.ContainsAny(s, "\x00\r\n")
}
func namespaceID(ns Namespace, id string) string { return string(ns) + ":" + id }
func validNamespacedID(ns Namespace, id string) bool {
	return validateString(id) && len(namespaceID(ns, id)) <= MaxString
}
func normalizeGraph(g Graph) (Graph, error) {
	if len(g.Nodes) > MaxItems || len(g.Edges) > MaxEdges {
		return Graph{}, ErrBounds
	}
	if g.Scope.Namespace != Project && g.Scope.Namespace != Global || !validateString(g.Scope.ID) || !validateString(g.Scope.Provenance) {
		return Graph{}, ErrProtocol
	}
	seen := map[string]bool{}
	nodes := make([]GraphNode, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		if n.Namespace != g.Scope.Namespace || !validNamespacedID(n.Namespace, n.ID) || !validateString(n.Title) || !validateString(n.Kind) || !validateString(n.Status) || !validateString(n.Sensitivity) || !validateString(n.Provenance) {
			return Graph{}, ErrProtocol
		}
		n.ID = namespaceID(n.Namespace, n.ID)
		if seen[n.ID] {
			continue
		}
		seen[n.ID] = true
		nodes = append(nodes, n)
	}
	g.Nodes = nodes
	for _, e := range g.Edges {
		if !validNamespacedID(g.Scope.Namespace, e.From) || !validNamespacedID(g.Scope.Namespace, e.To) || !validateString(e.Kind) {
			return Graph{}, ErrProtocol
		}
	}
	for i := range g.Edges {
		g.Edges[i].From = namespaceID(g.Scope.Namespace, g.Edges[i].From)
		g.Edges[i].To = namespaceID(g.Scope.Namespace, g.Edges[i].To)
	}
	sort.Slice(g.Nodes, func(i, j int) bool { return g.Nodes[i].ID < g.Nodes[j].ID })
	sort.Slice(g.Edges, func(i, j int) bool {
		if g.Edges[i].From != g.Edges[j].From {
			return g.Edges[i].From < g.Edges[j].From
		}
		return g.Edges[i].To < g.Edges[j].To
	})
	g.Scope.ItemCount = len(g.Nodes)
	return g, nil
}

func opaqueGlobalID(id string) string {
	sum := sha256.Sum256([]byte("beads-global-id:" + id))
	return "private:" + hex.EncodeToString(sum[:])
}

func sanitizeGlobalGraph(g *Graph) {
	ids := make(map[string]string, len(g.Nodes))
	for i := range g.Nodes {
		old := g.Nodes[i].ID
		ids[old] = opaqueGlobalID(old)
		g.Nodes[i].ID = ids[old]
		g.Nodes[i].Title = "global memory metadata"
		g.Nodes[i].Kind = "memory"
		g.Nodes[i].Status = "metadata"
		g.Nodes[i].Sensitivity = "private"
		g.Nodes[i].Provenance = "controller:beads/global-metadata"
	}
	for i := range g.Edges {
		if v, ok := ids[g.Edges[i].From]; ok {
			g.Edges[i].From = v
		} else {
			g.Edges[i].From = opaqueGlobalID(g.Edges[i].From)
		}
		if v, ok := ids[g.Edges[i].To]; ok {
			g.Edges[i].To = v
		} else {
			g.Edges[i].To = opaqueGlobalID(g.Edges[i].To)
		}
		g.Edges[i].Kind = "metadata-link"
	}
}

func sanitizeGlobalSearch(items []SearchResult) {
	for i := range items {
		items[i].ID = opaqueGlobalID(items[i].ID)
		items[i].Title = "global memory metadata"
		items[i].Kind = "memory"
		items[i].Status = "metadata"
		items[i].Sensitivity = "private"
		items[i].Provenance = "controller:beads/global-metadata"
	}
}
func normalizeSearch(items []SearchResult) ([]SearchResult, error) {
	if len(items) > MaxItems {
		return nil, ErrBounds
	}
	out := items[:0]
	seen := map[string]bool{}
	for _, x := range items {
		if !validNamespacedID(x.Namespace, x.ID) || !validateString(x.Title) || !validateString(x.Kind) || !validateString(x.Status) || !validateString(x.Sensitivity) || !validateString(x.Provenance) || x.Namespace != Project && x.Namespace != Global {
			return nil, ErrProtocol
		}
		if !seen[x.ID] {
			seen[x.ID] = true
			x.ID = namespaceID(x.Namespace, x.ID)
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func normalizeChats(items []MemoryChatMetadata) ([]MemoryChatMetadata, error) {
	if len(items) > MaxItems {
		return nil, ErrBounds
	}
	out := items[:0]
	seen := map[string]bool{}
	for _, x := range items {
		if !validNamespacedID(x.Namespace, x.ID) || !validateString(x.Category) || !validateString(x.Sensitivity) || !validateString(x.Status) || !validateString(x.Provenance) || x.Namespace != Project && x.Namespace != Global {
			return nil, ErrProtocol
		}
		if !seen[x.ID] {
			seen[x.ID] = true
			x.ID = namespaceID(x.Namespace, x.ID)
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// PrivateMemoryRef returns only an opaque, stable identifier. It is suitable
// for a global-memory card and never contains claim, value, path, or key text.
type PrivateMemoryRef struct {
	OpaqueID    string `json:"opaque_id"`
	Category    string `json:"category"`
	Sensitivity string `json:"sensitivity"`
	Provenance  string `json:"provenance"`
}

func RedactPrivate(namespace, key, category, sensitivity, provenance string) (PrivateMemoryRef, error) {
	if namespace != "global" || !validateString(key) {
		return PrivateMemoryRef{}, ErrProtocol
	}
	sum := sha256.Sum256([]byte(namespace + "\x00" + key))
	return PrivateMemoryRef{OpaqueID: "private:" + hex.EncodeToString(sum[:]), Category: "redacted", Sensitivity: "private", Provenance: "controller-approved"}, nil
}
