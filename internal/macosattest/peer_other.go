//go:build !darwin

package macosattest

import "net"

func socketPeer(net.Conn) (Process, error) { return Process{}, ErrUnavailable }
