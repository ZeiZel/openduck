//go:build !darwin

package macosattest

func renameNoReplace(string, string) error { return ErrUnavailable }
