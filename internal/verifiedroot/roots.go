// Package verifiedroot opens pre-provisioned service roots one component at a
// time and binds every pathname observation to the directory descriptor that
// is subsequently used. It also rejects physically identical or nested roots.
package verifiedroot

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type identity struct{ dev, ino uint64 }

type Requirement struct {
	Name     string
	Path     string
	UID, GID uint32
	Mode     os.FileMode
}

type Root struct {
	name        string
	path        string
	root        *os.Root
	identity    identity
	ancestry    map[identity]struct{}
	requirement Requirement
}

func (r Root) Path() string     { return r.path }
func (r Root) Handle() *os.Root { return r.root }

// Revalidate binds the current pathname to the descriptor identity opened by
// OpenAll. Call it immediately before an API that still accepts a pathname.
func (r Root) Revalidate() error {
	if r.root == nil {
		return errors.New("production root unavailable")
	}
	fdInfo, err := r.root.Lstat(".")
	fdID, ok := identityOf(fdInfo)
	if err != nil || !ok || fdID != r.identity || !metadataMatches(fdInfo, r.requirement) {
		return errors.New("production root descriptor changed")
	}
	fresh, err := open(r.requirement)
	if err != nil {
		return err
	}
	defer fresh.root.Close()
	if fresh.identity != r.identity {
		return errors.New("production root pathname changed")
	}
	return nil
}

func OpenAll(requirements []Requirement) ([]Root, error) {
	if len(requirements) == 0 {
		return nil, errors.New("production roots required")
	}
	roots := make([]Root, 0, len(requirements))
	for _, requirement := range requirements {
		r, err := open(requirement)
		if err != nil {
			CloseAll(roots)
			return nil, err
		}
		roots = append(roots, r)
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			_, iContainsJ := roots[i].ancestry[roots[j].identity]
			_, jContainsI := roots[j].ancestry[roots[i].identity]
			if roots[i].identity == roots[j].identity || iContainsJ || jContainsI {
				CloseAll(roots)
				return nil, fmt.Errorf("production roots physically overlap: %s and %s", roots[i].name, roots[j].name)
			}
		}
	}
	return roots, nil
}

func CloseAll(roots []Root) {
	for i := range roots {
		if roots[i].root != nil {
			_ = roots[i].root.Close()
		}
	}
}

func open(requirement Requirement) (Root, error) {
	if requirement.Name == "" || !absoluteClean(requirement.Path) || requirement.Mode.Perm() == 0 || requirement.Mode&^os.FileMode(0777) != 0 {
		return Root{}, fmt.Errorf("production %s root unavailable", requirement.Name)
	}
	volumeRoot := filepath.VolumeName(requirement.Path) + string(filepath.Separator)
	current, err := os.OpenRoot(volumeRoot)
	if err != nil {
		return Root{}, fmt.Errorf("production %s root unavailable", requirement.Name)
	}
	ancestry := make(map[identity]struct{})
	rootInfo, err := current.Lstat(".")
	rootID, ok := identityOf(rootInfo)
	if err != nil || !ok {
		_ = current.Close()
		return Root{}, fmt.Errorf("production %s root unavailable", requirement.Name)
	}
	ancestry[rootID] = struct{}{}
	rest := strings.TrimPrefix(requirement.Path, volumeRoot)
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		info, statErr := current.Lstat(part)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			_ = current.Close()
			return Root{}, fmt.Errorf("production %s root unavailable", requirement.Name)
		}
		next, openErr := current.OpenRoot(part)
		if openErr != nil {
			_ = current.Close()
			return Root{}, fmt.Errorf("production %s root unavailable", requirement.Name)
		}
		opened, openedErr := next.Lstat(".")
		pathID, pathOK := identityOf(info)
		openedID, openedOK := identityOf(opened)
		_ = current.Close()
		if openedErr != nil || !pathOK || !openedOK || pathID != openedID {
			_ = next.Close()
			return Root{}, fmt.Errorf("production %s root unavailable", requirement.Name)
		}
		ancestry[openedID] = struct{}{}
		current = next
	}
	info, err := current.Lstat(".")
	id, ok := identityOf(info)
	if err != nil || !ok || !metadataMatches(info, requirement) {
		_ = current.Close()
		return Root{}, fmt.Errorf("production %s root metadata mismatch", requirement.Name)
	}
	return Root{name: requirement.Name, path: requirement.Path, root: current, identity: id, ancestry: ancestry, requirement: requirement}, nil
}

func absoluteClean(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func identityOf(info os.FileInfo) (identity, bool) {
	if info == nil {
		return identity{}, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return identity{}, false
	}
	return identity{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true
}

func metadataMatches(info os.FileInfo, requirement Requirement) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != requirement.Mode.Perm() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st != nil && uint32(st.Uid) == requirement.UID && uint32(st.Gid) == requirement.GID && uint32(st.Mode)&07000 == 0
}
