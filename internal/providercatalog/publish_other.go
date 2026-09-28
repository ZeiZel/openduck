//go:build !darwin

package providercatalog

func PublishNewDirectory(string, string) error { return ErrInvalid }
