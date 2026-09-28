//go:build !darwin

package macosattest

func SampleProcess(int) (Process, error) { return Process{}, ErrUnavailable }
