// openduck-provider-catalog compiles verified provider imports into disabled
// release catalog leaves and finalizes separately approved evidence.  It never
// signs, logs in, reaches a provider, starts a daemon, or accepts owner
// lifecycle authority.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"openduck/internal/providercatalog"
	"openduck/internal/releasecatalog"
)

const maxInput = 8 << 20

type generateConfig struct {
	ImportRoot string           `json:"import_root"`
	BundleID   string           `json:"bundle_id"`
	RevisionID string           `json:"revision_id"`
	Providers  []providerConfig `json:"providers"`
}
type providerConfig struct {
	Provider      string            `json:"provider"`
	Compatibility string            `json:"compatibility"`
	Evidence      string            `json:"evidence"`
	Limits        string            `json:"limits"`
	Daemon        string            `json:"daemon"`
	HostBinary    string            `json:"host_binary"`
	HostIdentity  string            `json:"host_identity"`
	HostClosure   map[string]string `json:"host_closure,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("subcommand required"))
	}
	switch os.Args[1] {
	case "generate":
		generate(os.Args[2:])
	case "finalize-evidence":
		finalize(os.Args[2:])
	default:
		fail(errors.New("unknown subcommand"))
	}
}

func generate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var input, output string
	fs.StringVar(&input, "input", "", "canonical generation input JSON")
	fs.StringVar(&output, "output-root", "", "new output directory")
	if fs.Parse(args) != nil || input == "" || output == "" {
		fail(errors.New("input and output-root required"))
	}
	raw, err := readFile(input)
	if err != nil {
		fail(err)
	}
	var config generateConfig
	if decodeCanonical(raw, &config) != nil || !filepath.IsAbs(config.ImportRoot) || len(config.Providers) == 0 {
		fail(errors.New("invalid generate input"))
	}
	importRoot, err := os.OpenRoot(config.ImportRoot)
	if err != nil {
		fail(errors.New("untrusted import root"))
	}
	defer importRoot.Close()
	imports := make([]providercatalog.Import, 0, len(config.Providers))
	for _, p := range config.Providers {
		one := providercatalog.Import{Provider: p.Provider}
		if one.Compatibility, err = readImported(importRoot, p.Compatibility); err != nil {
			fail(err)
		}
		if one.Evidence, err = readImported(importRoot, p.Evidence); err != nil {
			fail(err)
		}
		if one.Limits, err = readImported(importRoot, p.Limits); err != nil {
			fail(err)
		}
		if one.Daemon, err = readImported(importRoot, p.Daemon); err != nil {
			fail(err)
		}
		if p.Provider != "deepseek" {
			if one.HostBinary, err = readImported(importRoot, p.HostBinary); err != nil {
				fail(err)
			}
			if one.HostIdentity, err = readImported(importRoot, p.HostIdentity); err != nil {
				fail(err)
			}
			if len(p.HostClosure) > 0 {
				one.HostClosure = map[string][]byte{}
				for leaf, source := range p.HostClosure {
					if filepath.Base(leaf) != leaf || leaf == "" {
						fail(errors.New("invalid host closure leaf"))
					}
					if one.HostClosure[leaf], err = readImported(importRoot, source); err != nil {
						fail(err)
					}
				}
			}
		}
		imports = append(imports, one)
	}
	result, err := providercatalog.Generate(providercatalog.GenerateInput{BundleID: config.BundleID, RevisionID: config.RevisionID, Imports: imports})
	if err != nil {
		fail(err)
	}
	if !filepath.IsAbs(output) || filepath.Clean(output) != output {
		fail(errors.New("output-root must be absolute canonical"))
	}
	targetOutput := output
	stage, err := os.MkdirTemp(filepath.Dir(output), ".openduck-provider-catalog-")
	if err != nil {
		fail(errors.New("unable to create private staging"))
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(stage)
		}
	}()
	output = stage
	for path, bytes := range result.Artifacts {
		if err := writeNew(filepath.Join(output, path), bytes); err != nil {
			fail(err)
		}
	}
	material, _ := json.Marshal(result.Material)
	if err := writeNew(filepath.Join(output, "provider-catalog-material.json"), material); err != nil {
		fail(err)
	}
	for _, request := range result.Requests {
		raw, _ := json.Marshal(request)
		if err := writeNew(filepath.Join(output, "evidence", request.ProfileID+"."+request.Role+".signing-request.json"), raw); err != nil {
			fail(err)
		}
	}
	if err := providercatalog.PublishNewDirectory(stage, targetOutput); err != nil {
		fail(err)
	}
	published = true
}

func finalize(args []string) {
	fs := flag.NewFlagSet("finalize-evidence", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var materialPath, trustPath, stageRoot, at string
	var approvals values
	fs.StringVar(&materialPath, "material", "", "canonical material JSON")
	fs.StringVar(&trustPath, "trust", "", "canonical evidence trust JSON")
	fs.StringVar(&stageRoot, "stage-root", "", "generated provider stage root")
	fs.StringVar(&at, "at", "", "RFC3339 validation instant")
	fs.Var(&approvals, "approved-evidence", "PROFILE=PATH (repeatable)")
	if fs.Parse(args) != nil || materialPath == "" || trustPath == "" || stageRoot == "" || at == "" {
		fail(errors.New("material, trust, stage-root and at required"))
	}
	now, err := time.Parse(time.RFC3339, at)
	if err != nil {
		fail(err)
	}
	raw, err := readFile(materialPath)
	if err != nil {
		fail(err)
	}
	var material providercatalog.Material
	if decodeCanonical(raw, &material) != nil {
		fail(errors.New("invalid material"))
	}
	trust, err := readFile(trustPath)
	if err != nil {
		fail(err)
	}
	approved := map[string][]byte{}
	for _, v := range approvals {
		k, p, ok := strings.Cut(v, "=")
		if !ok || k == "" || p == "" {
			fail(errors.New("invalid approved-evidence"))
		}
		if _, ok := approved[k]; ok {
			fail(errors.New("duplicate approved evidence"))
		}
		b, e := readFile(p)
		if e != nil {
			fail(e)
		}
		approved[k] = b
	}
	existing, err := readStage(stageRoot)
	if err != nil {
		fail(err)
	}
	final, err := providercatalog.FinalizeEvidence(material, trust, approved, now.UTC(), existing)
	if err != nil {
		fail(err)
	}
	for _, leaf := range []string{"provider-bundle.json", "provider-trust.json"} {
		if err := writeNew(filepath.Join(stageRoot, leaf), final[leaf]); err != nil {
			fail(err)
		}
	}
}

type values []string

func (v *values) String() string     { return strings.Join(*v, ",") }
func (v *values) Set(s string) error { *v = append(*v, s); return nil }
func decodeCanonical(raw []byte, out any) error {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid json")
	}
	canonical, e := json.Marshal(out)
	if e != nil || string(canonical) != string(raw) {
		return errors.New("noncanonical json")
	}
	return nil
}
func readFile(path string) ([]byte, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errors.New("unreadable file")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxInput {
		return nil, errors.New("invalid file")
	}
	return io.ReadAll(io.LimitReader(f, maxInput+1))
}
func readImported(root *os.Root, leaf string) ([]byte, error) {
	if leaf == "" || filepath.IsAbs(leaf) || filepath.Clean(leaf) != leaf || strings.HasPrefix(leaf, "..") {
		return nil, errors.New("invalid import leaf")
	}
	for _, component := range strings.Split(filepath.ToSlash(leaf), "/") {
		if component == "" || component == "." || component == ".." {
			return nil, errors.New("invalid import leaf")
		}
	}
	parts := strings.Split(filepath.ToSlash(leaf), "/")
	for index := range parts[:len(parts)-1] {
		prefix := strings.Join(parts[:index+1], "/")
		info, err := root.Lstat(prefix)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("unsafe imported parent")
		}
	}
	info, err := root.Lstat(leaf)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxInput {
		return nil, errors.New("unsafe imported leaf")
	}
	f, err := root.OpenFile(leaf, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("unsafe imported leaf")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("import leaf changed")
	}
	return io.ReadAll(io.LimitReader(f, maxInput+1))
}
func writeNew(path string, b []byte) error {
	if len(b) == 0 {
		return errors.New("empty output")
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return errors.New("output exists or unsafe")
	}
	if _, e = f.Write(b); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	return ce
}
func readStage(root string) (map[string][]byte, error) {
	out := map[string][]byte{}
	e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("stage links forbidden")
		}
		rel, e := filepath.Rel(root, path)
		if e != nil || filepath.IsAbs(rel) || strings.HasPrefix(rel, "..") {
			return errors.New("invalid stage path")
		}
		// Review material and signing requests live beside the stage but are
		// deliberately not release payloads.  Only the closed catalog leaves
		// may be handed to macosrelease.ValidateCatalogPayloads.
		if _, known := releasecatalog.EntryFor(filepath.ToSlash(rel)); !known {
			return nil
		}
		b, e := readFile(path)
		if e != nil {
			return e
		}
		out[filepath.ToSlash(rel)] = b
		return nil
	})
	return out, e
}
func fail(err error) { fmt.Fprintln(os.Stderr, "openduck-provider-catalog:", err); os.Exit(2) }
