package qwenclosure

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDerivedProductionGoldenIsCanonicalAndPinned(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "qwen-code-darwin-arm64.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := Decode(raw)
	if err != nil {
		t.Fatalf("derived golden rejected: %v", err)
	}
	if m.ArchiveDigest != PinnedArchiveDigest || len(m.Entries) != FileCount || m.NodeTeamID != "HX7739G8FX" {
		t.Fatalf("golden drift: %+v", m)
	}
}

func TestFullUnicodeCaseFoldRejectsAliases(t *testing.T) {
	if foldKey("lib/ß") != foldKey("lib/ss") || foldKey("lib/ς") != foldKey("lib/σ") {
		t.Fatal("full Unicode case-fold key regressed")
	}
	for _, names := range [][]string{{"lib/ß", "lib/ss"}, {"lib/ς", "lib/σ"}} {
		archive := writeArchiveFixture(t, 0755, 0755, 0644, names...)
		if _, err := streamArchive(archive, nil, nil); err == nil {
			t.Fatalf("case-fold aliases admitted: %#v", names)
		}
	}
}

func TestStreamArchiveRejectsModeBitsOutsidePermissions(t *testing.T) {
	if _, err := streamArchive(writeArchiveFixture(t, 0755, 0755, 0644, "lib/only"), nil, nil); err != nil {
		t.Fatalf("safe control archive rejected: %v", err)
	}
	for _, tc := range []struct {
		name            string
		root, dir, file int64
	}{
		{"root-setuid", 0755 | 04000, 0755, 0644},
		{"directory-sticky", 0755, 0755 | 01000, 0644},
		{"file-setgid", 0755, 0755, 0644 | 02000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := streamArchive(writeArchiveFixture(t, tc.root, tc.dir, tc.file, "lib/only"), nil, nil); err == nil {
				t.Fatal("tar mode bits outside 0777 admitted")
			}
		})
	}
}

func writeArchiveFixture(t *testing.T, rootMode, directoryMode, fileMode int64, names ...string) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "fixture.tar.gz")
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	write := func(header *tar.Header, body string) {
		t.Helper()
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if body != "" {
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(&tar.Header{Name: "qwen-code/", Mode: rootMode, Typeflag: tar.TypeDir}, "")
	seenDirectories := map[string]bool{}
	for _, item := range names {
		directory := filepath.ToSlash(filepath.Dir(item))
		if directory != "." && !seenDirectories[directory] {
			seenDirectories[directory] = true
			write(&tar.Header{Name: "qwen-code/" + directory + "/", Mode: directoryMode, Typeflag: tar.TypeDir}, "")
		}
		write(&tar.Header{Name: "qwen-code/" + item, Mode: fileMode, Typeflag: tar.TypeReg, Size: 1}, "x")
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestTinyPolicyCannotChangeProductionDecode(t *testing.T) {
	// This intentionally has no archive: its only purpose is to make the
	// injectable grammar policy explicit for same-package unit tests. Decode
	// itself continues to require PinnedArchiveDigest/FileCount.
	policy := Policy{ArchiveDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", FileCount: 1}
	m := Manifest{SchemaVersion: SchemaV1, ArchiveDigest: policy.ArchiveDigest, NodePath: "node/bin/node", NodeDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", NodeCDHash: "0123456789abcdef0123456789abcdef01234567", NodeTeamID: "HX7739G8FX", HostIdentityDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", Entries: []Entry{{Path: "node/bin/node", Type: "file", Mode: "0755", Size: 1, Digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}
	// Match the exact inventory aggregate for the deterministic one-file schema.
	m.InventoryDigest = DigestBytes([]byte(m.Entries[0].Digest + "\x00" + m.Entries[0].Mode + "\x00" + "1\x00" + m.Entries[0].Path + "\x00"))
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeWithPolicy(raw, policy); err != nil {
		t.Fatalf("test policy fixture rejected: %v", err)
	}
	if _, err := Decode(raw); err == nil {
		t.Fatal("test policy changed fixed production decode")
	}
}

func TestPinnedArchiveMatchesDerivedGoldenWhenInputIsPresent(t *testing.T) {
	archive := filepath.Join("..", "..", ".openduck", "provider-inputs", "qwen-code-darwin-arm64.tar.gz")
	if _, err := os.Stat(archive); errors.Is(err, os.ErrNotExist) {
		t.Skip("private provider input is intentionally absent from source control")
	} else if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "qwen-code-darwin-arm64.manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArchive(archive, manifest); err != nil {
		t.Fatalf("pinned archive/golden mismatch: %v", err)
	}
}
