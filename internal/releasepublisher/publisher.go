package releasepublisher

import (
	"errors"
	"path/filepath"
	"strings"
)

var ErrRejected = errors.New("release publisher: publication rejected")

// ValidatePaths enforces the invariant required by the descriptor-relative
// Darwin rename: both leaves are siblings in the same absolute parent.
func ValidatePaths(staging, target string) (string, string, error) {
	if !filepath.IsAbs(staging) || !filepath.IsAbs(target) {
		return "", "", ErrRejected
	}
	cleanStaging := filepath.Clean(staging)
	cleanTarget := filepath.Clean(target)
	if staging != cleanStaging || target != cleanTarget || cleanStaging == cleanTarget || filepath.Dir(cleanStaging) != filepath.Dir(cleanTarget) {
		return "", "", ErrRejected
	}
	if !validLeaf(filepath.Base(cleanStaging)) || !validLeaf(filepath.Base(cleanTarget)) {
		return "", "", ErrRejected
	}
	return cleanStaging, cleanTarget, nil
}

func validLeaf(leaf string) bool {
	return leaf != "" && leaf != "." && leaf != ".." && !filepath.IsAbs(leaf) && filepath.VolumeName(leaf) == "" && !strings.ContainsAny(leaf, `/\\`)
}
