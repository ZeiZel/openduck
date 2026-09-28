package workspacegroup

import (
	"path/filepath"
	"sync"
)

// Test-only constructors deliberately live outside ordinary builds. They are
// the sole memory-checkpoint and raw-path seam for this package.
var testCheckpoints sync.Map

func newTestRegistry(path string, key []byte, allowedPaths ...string) (*Registry, error) {
	cp := &memoryCheckpointStore{}
	if old, ok := testCheckpoints.Load(path); ok {
		cp = old.(*memoryCheckpointStore)
	} else {
		testCheckpoints.Store(path, cp)
	}
	return newTestRegistryWithCheckpoint(path, key, cp, allowedPaths...)
}

func newTestRegistryWithCheckpoint(path string, key []byte, cp CheckpointStore, allowedPaths ...string) (*Registry, error) {
	allowed := make([]trustedRoot, 0, len(allowedPaths))
	for _, allowedPath := range allowedPaths {
		if hasUnsafePathComponent(allowedPath) {
			return nil, ErrUnsafePath
		}
		clean := canonicalMacAlias(filepath.Clean(allowedPath))
		if !safeWorkspaceBase(clean) {
			return nil, ErrUnsafePath
		}
		root, err := openNoFollowRoot(clean)
		if err != nil {
			return nil, err
		}
		fi, err := root.Lstat(".")
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		id, err := identityOf(fi)
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		allowed = append(allowed, trustedRoot{path: clean, root: root, id: id})
	}
	return newRegistry(path, key, cp, allowed)
}
