package providertransport

import "openduck/internal/macoschannel"

// NewTestServerLoopDialer is test-only plumbing for external integration
// tests. Production composition must use BoundDialer with the macOS channel
// boundary; this helper is absent from non-test builds.
func NewTestServerLoopDialer(server *Server, descriptor Descriptor, controller macoschannel.ReleasePin) Dialer {
	return serverLoopDialer{server: server, descriptor: descriptor, controller: controller}
}
