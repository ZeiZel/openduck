//go:build !darwin

package macoschannel

import "net"

func platformAvailable() bool { return false }

func peerCredentials(net.Conn) (Peer, error) { return Peer{}, ErrUnavailable }
