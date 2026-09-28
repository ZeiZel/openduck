//go:build !darwin

package releasepublisher

func PublishDirectory(_, _ string) error { return ErrRejected }
