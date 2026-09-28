package platformcheckpoint

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func testDigest(n byte) string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = n
	}
	var h [32]byte
	copy(h[:], b)
	return "sha256:" + fmtHex(h[:])
}
func fmtHex(b []byte) string {
	const x = "0123456789abcdef"
	o := make([]byte, len(b)*2)
	for i, v := range b {
		o[i*2] = x[v>>4]
		o[i*2+1] = x[v&15]
	}
	return string(o)
}
func privateDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if e := os.Chmod(d, 0700); e != nil {
		t.Fatal(e)
	}
	return d
}
func TestStoreInitialCASReplayRestart(t *testing.T) {
	d := privateDir(t)
	s, e := NewStore(d)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	g, v, e := s.Load()
	if e != nil || g != 0 || v != "" {
		t.Fatalf("load=%d %q %v", g, v, e)
	}
	dig := testDigest(1)
	if e = s.CAS("r1", 0, 1, dig); e != nil {
		t.Fatal(e)
	}
	if e = s.CAS("r1", 0, 1, dig); e != nil {
		t.Fatalf("replay: %v", e)
	}
	if e = s.CAS("r1", 0, 1, testDigest(2)); !errors.Is(e, ErrReplay) {
		t.Fatalf("equivocation=%v", e)
	}
	if e = s.CAS("lost-cas", 9, 10, testDigest(2)); !errors.Is(e, ErrCAS) {
		t.Fatalf("cas=%v", e)
	}
	if e = s.CAS("lost-cas", 9, 10, testDigest(2)); !errors.Is(e, ErrCAS) {
		t.Fatalf("cas replay=%v", e)
	}
	s.Close()
	s, e = NewStore(d)
	if e != nil {
		t.Fatal(e)
	}
	g, v, e = s.Load()
	if e != nil || g != 1 || v != dig {
		t.Fatalf("restart=%d %q %v", g, v, e)
	}
}

func TestStoreMigratesAuthenticatedLegacyStateExactlyOnce(t *testing.T) {
	d := privateDir(t)
	s, err := NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyDiskState{SchemaVersion: SchemaVersion, Requests: map[string]replay{}, Order: []string{}}
	state, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(record{SchemaVersion: SchemaVersion, MAC: s.mac(0, ""), StateMAC: s.legacyStateMAC(&legacy)})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d, "checkpoint.state"), state, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d, "checkpoint.json"), meta, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(d)
	if err != nil {
		t.Fatalf("migration=%v", err)
	}
	if _, _, err = s.Load(); err != nil {
		t.Fatalf("migrated load=%v", err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	// The rewritten schema is self-authenticating and restarts without another
	// compatibility path.
	if s, err = NewStore(d); err != nil {
		t.Fatalf("restart=%v", err)
	}
	defer s.Close()
	state, err = os.ReadFile(filepath.Join(d, "checkpoint.state"))
	if err != nil || !bytes.Contains(state, []byte(`"journal_requests":{}`)) || !bytes.Contains(state, []byte(`"journal_order":[]`)) {
		t.Fatalf("upgraded state=%s err=%v", state, err)
	}
}

func TestStoreRejectsUnauthenticatedOrNonExactLegacyState(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"extra":   func(b []byte) []byte { return append(bytes.TrimSuffix(b, []byte("}")), []byte(`,"extra":true}`)...) },
		"missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"order":[]`), []byte(`"gone":[]`), 1) },
		"wrong mac": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"value_digest":""`), []byte(`"value_digest":"sha256:`+strings.Repeat("a", 64)+`"`), 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := privateDir(t)
			s, err := NewStore(d)
			if err != nil {
				t.Fatal(err)
			}
			legacy := legacyDiskState{SchemaVersion: SchemaVersion, Requests: map[string]replay{}, Order: []string{}}
			state, _ := json.Marshal(legacy)
			meta, _ := json.Marshal(record{SchemaVersion: SchemaVersion, MAC: s.mac(0, ""), StateMAC: s.legacyStateMAC(&legacy)})
			_ = s.Close()
			if err = os.WriteFile(filepath.Join(d, "checkpoint.state"), mutate(state), 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(d, "checkpoint.json"), meta, 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := NewStore(d); !errors.Is(err, ErrUnavailable) {
				if got != nil {
					_ = got.Close()
				}
				t.Fatalf("err=%v", err)
			}
		})
	}
}
func TestStoreConcurrentSingleWinner(t *testing.T) {
	s, e := NewStore(privateDir(t))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var wg sync.WaitGroup
	out := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); out <- s.CAS("id-"+string(rune(i+1)), 0, 1, testDigest(byte(i+1))) }(i)
	}
	wg.Wait()
	close(out)
	wins := 0
	for e := range out {
		if e == nil {
			wins++
		} else if !errors.Is(e, ErrCAS) {
			t.Fatalf("unexpected %v", e)
		}
	}
	if wins != 1 {
		t.Fatalf("wins=%d", wins)
	}
}
func TestStoreDeletionRollbackAndTornFailClosed(t *testing.T) {
	d := privateDir(t)
	s, e := NewStore(d)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CAS("x", 0, 1, testDigest(3)); e != nil {
		t.Fatal(e)
	}
	s.Close()
	if e = os.Remove(filepath.Join(d, "checkpoint.state")); e != nil {
		t.Fatal(e)
	}
	if _, e = NewStore(d); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("deletion=%v", e)
	}
	// Retaining the old secret does not make a deleted state recoverable.
	del := privateDir(t)
	q, e := NewStore(del)
	if e != nil {
		t.Fatal(e)
	}
	_ = q.Close()
	if e = os.Remove(filepath.Join(del, "checkpoint.secret")); e != nil {
		t.Fatal(e)
	}
	if _, e = NewStore(del); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("secret deletion=%v", e)
	}
	d2 := privateDir(t)
	s, e = NewStore(d2)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	for _, name := range []string{"checkpoint.next", "checkpoint.state.next", "checkpoint.json.next"} {
		if e = os.WriteFile(filepath.Join(d2, name), []byte("torn"), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = NewStore(d2); !errors.Is(e, ErrUnavailable) {
			t.Fatalf("torn %s=%v", name, e)
		}
		if e = os.Remove(filepath.Join(d2, name)); e != nil {
			t.Fatal(e)
		}
	}
}
func TestProtocolBoundsAndDuplicates(t *testing.T) {
	r := Request{SchemaVersion: SchemaVersion, RequestID: "x", Operation: "load"}
	if e := r.validate(); e != nil {
		t.Fatal(e)
	}
	if e := decode([]byte(`{"schema_version":"platform-checkpoint.v1","schema_version":"platform-checkpoint.v1","request_id":"x","operation":"load","expected":0,"next":0,"digest":""}`), &r); !errors.Is(e, ErrProtocol) {
		t.Fatalf("duplicate=%v", e)
	}
	b, _ := json.Marshal(r)
	if len(b) > MaxFrameSize {
		t.Fatal("fixture")
	}
	if e := decode(make([]byte, MaxFrameSize+1), &r); !errors.Is(e, ErrProtocol) {
		t.Fatalf("oversize=%v", e)
	}
}

func TestWireDecodeRequiresExactPresenceAndCanonicalEncoding(t *testing.T) {
	tests := map[string]string{
		"request omitted expected zero": `{"schema_version":"platform-checkpoint.v1","request_id":"x","operation":"load","next":0,"digest":""}`,
		"response omitted ok false":     `{"schema_version":"platform-checkpoint.v1","request_id":"x","generation":0,"digest":"","error":"platform checkpoint unavailable"}`,
		"response omitted generation":   `{"schema_version":"platform-checkpoint.v1","request_id":"x","ok":false,"digest":"","error":"platform checkpoint unavailable"}`,
		"request reordered":             `{"request_id":"x","schema_version":"platform-checkpoint.v1","operation":"load","expected":0,"next":0,"digest":""}`,
		"request whitespace":            ` {"schema_version":"platform-checkpoint.v1","request_id":"x","operation":"load","expected":0,"next":0,"digest":""}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var target any
			if strings.HasPrefix(name, "response") {
				target = &Response{}
			} else {
				target = &Request{}
			}
			if err := decode([]byte(input), target); !errors.Is(err, ErrProtocol) {
				t.Fatalf("err=%v", err)
			}
		})
	}

	request := Request{SchemaVersion: SchemaVersion, RequestID: "x", Operation: "load"}
	canonical, err := marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Request
	if err := decode(canonical, &decoded); err != nil {
		t.Fatalf("canonical request=%v", err)
	}
	frame, err := marshal(envelope{Request: request, Tag: "tag"})
	if err != nil {
		t.Fatal(err)
	}
	frame = bytes.Replace(frame, []byte(`,"tag":"tag"`), nil, 1)
	var decodedEnvelope envelope
	if err := decode(frame, &decodedEnvelope); !errors.Is(err, ErrProtocol) {
		t.Fatalf("omitted envelope tag=%v", err)
	}
}
func TestStoreLoadDoesNotRewriteDurableFiles(t *testing.T) {
	d := privateDir(t)
	s, err := NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CAS("first", 0, 1, testDigest(1)); err != nil {
		t.Fatal(err)
	}
	type snapshot struct {
		data  []byte
		mtime time.Time
	}
	before := make(map[string]snapshot)
	for _, name := range []string{"checkpoint.secret", "checkpoint.state", "checkpoint.json", "checkpoint.lock"} {
		path := filepath.Join(d, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = snapshot{data: data, mtime: info.ModTime()}
	}
	if generation, digest, err := s.Load(); err != nil || generation != 1 || digest != testDigest(1) {
		t.Fatalf("load=(%d,%q,%v)", generation, digest, err)
	}
	for name, want := range before {
		path := filepath.Join(d, name)
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want.data) || !info.ModTime().Equal(want.mtime) {
			t.Fatalf("Load changed %s bytes or mtime", name)
		}
	}
}

func TestStoreCloseIsIdempotentAndZeroizesSecret(t *testing.T) {
	s, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	backing := s.secret
	if len(backing) != 32 || bytes.Equal(backing, make([]byte, 32)) {
		t.Fatal("test seam has no live secret")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backing, make([]byte, 32)) || s.secret != nil {
		t.Fatal("secret was not zeroized")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second close=%v", err)
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("load after close=%v", err)
	}
}

func TestStrictDurableDecodeRejectsMalformedObjects(t *testing.T) {
	validRecord := `{"schema_version":"platform-checkpoint.v1","generation":0,"digest":"","mac":"x","state_mac":"y"}`
	tests := map[string]string{
		"empty":      "",
		"duplicate":  `{"schema_version":"platform-checkpoint.v1","generation":0,"generation":0,"digest":"","mac":"x","state_mac":"y"}`,
		"unknown":    `{"schema_version":"platform-checkpoint.v1","generation":0,"digest":"","mac":"x","state_mac":"y","extra":true}`,
		"trailing":   validRecord + ` {}`,
		"missing":    `{"schema_version":"platform-checkpoint.v1","generation":0,"digest":"","mac":"x"}`,
		"oversized":  strings.Repeat(" ", (1<<20)+1),
		"nested dup": `{"schema_version":"platform-checkpoint.v1","generation":0,"value_digest":"","requests":{"r":{"fingerprint":"x","fingerprint":"y","response":{}}},"order":["r"]}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			var target record
			if err := strictUnmarshal([]byte(input), &target, "schema_version", "generation", "digest", "mac", "state_mac"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestStoreRejectsInvalidModesSymlinksAndTornArtifacts(t *testing.T) {
	tests := []struct {
		name   string
		target string
		mutate func(*testing.T, string)
	}{
		{"secret mode", "checkpoint.secret", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Chmod(p, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"state mode", "checkpoint.state", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Chmod(p, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"metadata mode", "checkpoint.json", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Chmod(p, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"lock mode", "checkpoint.lock", func(t *testing.T, p string) {
			t.Helper()
			if err := os.Chmod(p, 0644); err != nil {
				t.Fatal(err)
			}
		}},
		{"secret special bits", "checkpoint.secret", func(t *testing.T, p string) {
			t.Helper()
			if err := syscall.Chmod(p, 04600); err != nil {
				t.Fatal(err)
			}
		}},
		{"state special bits", "checkpoint.state", func(t *testing.T, p string) {
			t.Helper()
			if err := syscall.Chmod(p, 04600); err != nil {
				t.Fatal(err)
			}
		}},
		{"metadata special bits", "checkpoint.json", func(t *testing.T, p string) {
			t.Helper()
			if err := syscall.Chmod(p, 04600); err != nil {
				t.Fatal(err)
			}
		}},
		{"lock special bits", "checkpoint.lock", func(t *testing.T, p string) {
			t.Helper()
			if err := syscall.Chmod(p, 04600); err != nil {
				t.Fatal(err)
			}
		}},
		{"secret symlink", "checkpoint.secret", replaceWithSymlink},
		{"state symlink", "checkpoint.state", replaceWithSymlink},
		{"metadata symlink", "checkpoint.json", replaceWithSymlink},
		{"lock symlink", "checkpoint.lock", replaceWithSymlink},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := privateDir(t)
			s, err := NewStore(d)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			tc.mutate(t, filepath.Join(d, tc.target))
			if strings.Contains(tc.name, "special bits") {
				info, statErr := os.Lstat(filepath.Join(d, tc.target))
				if statErr != nil {
					t.Fatal(statErr)
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || stat == nil || uint32(stat.Mode)&07000 == 0 {
					t.Skip("test filesystem did not retain requested special mode bits")
				}
			}
			if reopened, err := NewStore(d); !errors.Is(err, ErrUnavailable) {
				if reopened != nil {
					_ = reopened.Close()
				}
				t.Fatalf("err=%v", err)
			}
		})
	}
	t.Run("directory special bits", func(t *testing.T) {
		d := privateDir(t)
		if err := os.Chmod(d, 0700|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		if s, err := NewStore(d); !errors.Is(err, ErrUnavailable) {
			if s != nil {
				_ = s.Close()
			}
			t.Fatalf("err=%v", err)
		}
	})
}

func TestStoreActualDurableFilesRejectMalformedEncoding(t *testing.T) {
	tests := []struct {
		name   string
		target string
		data   func([]byte) []byte
	}{
		{"state duplicate", "checkpoint.state", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"generation":0`), []byte(`"generation":0,"generation":0`), 1)
		}},
		{"state unknown", "checkpoint.state", func(b []byte) []byte {
			return append(bytes.TrimSuffix(b, []byte("}")), []byte(`,"unknown":true}`)...)
		}},
		{"state trailing", "checkpoint.state", func(b []byte) []byte { return append(b, []byte(` {}`)...) }},
		{"state missing", "checkpoint.state", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"order":[]`), []byte(`"omitted":[]`), 1)
		}},
		{"state oversized", "checkpoint.state", func([]byte) []byte {
			return []byte(strings.Repeat(" ", (1<<20)+1))
		}},
		{"metadata duplicate", "checkpoint.json", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"generation":0`), []byte(`"generation":0,"generation":0`), 1)
		}},
		{"metadata unknown", "checkpoint.json", func(b []byte) []byte {
			return append(bytes.TrimSuffix(b, []byte("}")), []byte(`,"unknown":true}`)...)
		}},
		{"metadata trailing", "checkpoint.json", func(b []byte) []byte { return append(b, []byte(` {}`)...) }},
		{"metadata missing", "checkpoint.json", func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"digest":"",`), nil, 1)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := privateDir(t)
			s, err := NewStore(d)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			path := filepath.Join(d, tc.target)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tc.data(original), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.Load(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestDurableReplayResponseRequiresExplicitZeroFieldsBeforeMAC(t *testing.T) {
	for _, field := range []string{`"ok":false,`, `"generation":0,`} {
		t.Run(field, func(t *testing.T) {
			d := privateDir(t)
			s, err := NewStore(d)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := s.CAS("mismatch", 7, 8, testDigest(1)); !errors.Is(err, ErrCAS) {
				t.Fatal(err)
			}
			path := filepath.Join(d, "checkpoint.state")
			state, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := bytes.Replace(state, []byte(field), nil, 1)
			if bytes.Equal(mutated, state) {
				t.Fatalf("fixture does not contain %s: %s", field, state)
			}
			// StateMAC was computed from the decoded logical value. Omitting a
			// zero field used to normalize back to that same authenticated value.
			if err := os.WriteFile(path, mutated, 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := s.Load(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("omitted nested field accepted: %v", err)
			}
		})
	}
}

func TestDurableReadsRejectHugeSparseFilesBeforeAllocation(t *testing.T) {
	const huge = int64(1 << 34)
	for _, target := range []string{"checkpoint.state", "checkpoint.json"} {
		t.Run(target, func(t *testing.T) {
			d := privateDir(t)
			s, err := NewStore(d)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if err := os.Truncate(filepath.Join(d, target), huge); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			if _, _, err := s.Load(); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("err=%v", err)
			}
			if time.Since(started) > time.Second {
				t.Fatalf("oversized sparse file was read: %s", time.Since(started))
			}
		})
	}
	t.Run("checkpoint.secret", func(t *testing.T) {
		d := privateDir(t)
		s, err := NewStore(d)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(filepath.Join(d, "checkpoint.secret"), huge); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		if reopened, err := NewStore(d); !errors.Is(err, ErrUnavailable) {
			if reopened != nil {
				_ = reopened.Close()
			}
			t.Fatalf("err=%v", err)
		}
		if time.Since(started) > time.Second {
			t.Fatalf("oversized sparse secret was read: %s", time.Since(started))
		}
	})
}

func replaceWithSymlink(t *testing.T, path string) {
	t.Helper()
	backup := path + ".target"
	if err := os.Rename(path, backup); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Base(backup), path); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedSecretPriorPairRollbackIsExplicitlyOutOfScope(t *testing.T) {
	d := privateDir(t)
	s, err := NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CAS("one", 0, 1, testDigest(1)); err != nil {
		t.Fatal(err)
	}
	oldState, err := os.ReadFile(filepath.Join(d, "checkpoint.state"))
	if err != nil {
		t.Fatal(err)
	}
	oldMeta, err := os.ReadFile(filepath.Join(d, "checkpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CAS("two", 1, 2, testDigest(2)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A privileged actor able to restore both authenticated files while
	// retaining the service secret is outside the documented threat model.
	if err := os.WriteFile(filepath.Join(d, "checkpoint.state"), oldState, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "checkpoint.json"), oldMeta, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = NewStore(d)
	if err != nil {
		t.Fatalf("documented out-of-scope rollback unexpectedly detected: %v", err)
	}
	defer s.Close()
	if generation, digest, err := s.Load(); err != nil || generation != 1 || digest != testDigest(1) {
		t.Fatalf("restored prior authenticated pair=(%d,%q,%v)", generation, digest, err)
	}
}

func TestStoreRejectsGenerationOverflow(t *testing.T) {
	s, err := NewStore(privateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CAS("overflow", math.MaxUint64, 0, testDigest(1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v", err)
	}
}

func TestMultipleStoresSerializeCAS(t *testing.T) {
	d := privateDir(t)
	first, err := NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := NewStore(d)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	for i, store := range []*Store{first, second} {
		go func(i int, store *Store) {
			<-start
			results <- store.CAS(string(rune('a'+i)), 0, 1, testDigest(byte(i+1)))
		}(i, store)
	}
	close(start)
	wins := 0
	for range 2 {
		if err := <-results; err == nil {
			wins++
		} else if !errors.Is(err, ErrCAS) {
			t.Fatalf("err=%v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("wins=%d", wins)
	}
}
