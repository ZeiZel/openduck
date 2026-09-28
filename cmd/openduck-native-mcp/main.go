// Command openduck-native-mcp is deliberately Controller-launched only.  A
// native host registration must pass a Controller-owned in-memory Backend and
// platform peer attestor; this standalone binary therefore refuses to invent a
// file/env/bearer fallback.  It is retained as the fixed release identity and
// explicit integration boundary for the Controller launcher.
package main

import (
	"errors"
	"flag"
	"io"
	"net"
	"os"

	"openduck/internal/nativemcp"
)

func main() {
	if run(os.Args[1:]) != nil {
		os.Exit(1)
	}
}
func run(args []string) error {
	fs := flag.NewFlagSet("openduck-native-mcp", flag.ContinueOnError)
	socket := fs.String("controller-socket", nativemcp.ShimSocketPath, "fixed Controller native MCP socket")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *socket != nativemcp.ShimSocketPath {
		return errors.New("invalid native mcp invocation")
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: nativemcp.ShimSocketPath, Net: "unix"})
	if err != nil {
		return errors.New("controller native mcp unavailable")
	}
	defer conn.Close()
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(conn, os.Stdin); errCh <- e }()
	go func() { _, e := io.Copy(os.Stdout, conn); errCh <- e }()
	if err := <-errCh; err != nil && !errors.Is(err, io.EOF) {
		return errors.New("controller native mcp unavailable")
	}
	return nil
}
